# Storage Design

Two platform stores are used, each for the role it is designed for, plus the Secrets Manager for credentials. Nothing else is introduced.

## Edge Storage (durable system of record)

**Verified semantics:** durable; writes go through the account REST API → central SQL DB → replication to **every** edge location (typically 1–2 s); reads are served from the local replica; application code is read-only. Key limit 256 B; value limit ~1 MB (base64 `encoded_value`).

### Key layout (all keys are flat, 1–2 segments)

| Key pattern | Value | Written by |
|---|---|---|
| `users/{uid}` | `UserRecord` JSON (schema v1) | control plane |
| `subs/{uid}` | `SubscriptionRecord` JSON (schema v1, bounded history ≤ 50) | control plane |
| `email/{normalized_email}` | `uid` (uniqueness index) | control plane |
| `tok/{sha256(token)}` | `TokenIndexEntry {uid, cred_id, cred_version, revoked}` — O(1) hot-path lookup | control plane |
| `admins/{username}` | `AdminRecord` JSON (PBKDF2 hash only) | control plane |
| `audit/e{ULID}` | `AuditEvent` JSON — ULID ids make key order = time order | control plane |
| `config/app` | `AppConfig` JSON (operational settings; secrets NEVER here) | control plane |
| `sys/session_epoch` | monotonically increasing integer | control plane |
| `sys/srev/{jti}` | marker (session deny-list) | control plane |

Why flat patterns matter: the platform glob `*` matches **within a single key segment** (verified). Every listing uses patterns with exactly one wildcard segment (`users/*`, `admins/*`, `audit/e*`) so scans are complete by construction — mirrored in `platform::glob_match` and unit-tested.

### Record discipline

- Every record carries `schema_version`; loaders reject unknown versions or malformed JSON **fail-closed** (deny the request, surface "malformed" only to admins).
- History arrays are bounded (subscription history ≤ 50 entries).
- Users are never hard-deleted (revocation is terminal); this preserves audit references and index integrity. Deletion of admin accounts removes the record but is guarded against removing the last super-admin.

## Write path (control plane)

Writes never touch Edge Storage directly — impossible by platform design. `GcoreControlPlane` builds `modify_store_data_entry` payloads (`op:add` with base64 values / `op:del_key`) and issues **one batched** `PUT /fastedge/v1/kv/{store_id}/data` per operation (user creation = 3 records in one call; bulk renew of N users = one call; import = ≤ `import_batch_max` records per call). The request envelope is probed once per instance (bare array → `{"data":[…]}` fallback) and cached. Upstream failures map to coarse `CONTROL_PLANE_UNAVAILABLE` (502) or auth-config errors — upstream bodies never reach clients.

## Read-your-writes bridge

`ReadYourWritesStore` wraps the read-only Edge Storage handle and the control plane:

- `get`: fresh buffer hit → buffered value; fresh tombstone → `None`; else local-replica read.
- `scan`: replica scan − tombstones ∪ fresh buffered keys.
- `put/delete`: control-plane batch first, then buffer update (15 s TTL, pruned at 256 entries).

Bound: the acting instance is always coherent; **other** instances/PoPs converge within the platform's 1–2 s replication window. Both behaviors are unit-tested with `LaggingReplica`, a deterministic replication simulator.

## Per-POP cache (transient)

Used strictly for what its semantics allow: fixed-window login/exchange rate limits (`incr` + `expire`, ms TTL) and per-day approximate counters (45-day TTL), which the dashboard labels as per-POP approximations. Cache unavailability degrades these features gracefully and is surfaced live on the health page. It is **never** a source of truth: authorization reads only Edge Storage.

## Recovery

- **Export/import** is the backup/restore mechanism (the platform provides no point-in-time restore): sanitized export by default; sensitive export (fingerprints + token indexes) requires super-admin + step-up. Imports are idempotent per email.
- **Interrupted writes**: a failed control-plane call returns 502 with zero records written (single batch); audit-critical events failing abort the operation — no silent partial state. Re-running a bulk/import reports exactly which rows landed.
- **Bootstrap recovery**: with zero admin records, deployment secrets (`ADMIN_USERNAME` + `ADMIN_PASSWORD_HASH`) may seed the first super_admin exactly once; the path is disabled permanently once any admin record exists.

## Retention

Audit retention (default 90 days, config-tunable 7–3650) is enforced by `POST /api/system/prune-audit` — a batched delete of expired keys. Rate/counter keys expire automatically (45 days).
