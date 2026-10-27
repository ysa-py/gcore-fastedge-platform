# Operations Runbook

## Monitoring

- **Public liveness**: `GET /healthz` (status/time/version — wire into any uptime monitor).
- **In-panel**: Dashboard (aggregates + recent security events), Health & diagnostics (component probes), Storage & integrity (read probe ms, store binding, cache availability, live account limits), Analytics (per-POP approximations + authoritative Gcore stats).
- **Platform logs**: FastEdge app logs capture **stdout** only (stderr is discarded platform-wide). This app emits one sanitized diagnostic per request: `method=… path=… status=…`. Nothing sensitive is ever logged.
- **Audit trail**: the panel's Security & audit page is the system of record for administrative actions; filters by category/outcome/actor/target.

## Routine tasks

| Task | How |
|---|---|
| Review expiring subscriptions | Subscriptions → "Expiring ≤ 7 days" → select → bulk renew +30 d |
| Review failed logins | Dashboard "Recent auth failures" / Audit → category=auth, outcome=denied |
| Onboard a user | Users → New user (email, name, role, entitlement, expiry) → issue credential on the user page |
| Rotate a user's credential | User page → Issue credential (bumps cred_version; old token dies for new exchanges immediately; live access tokens die on next request) |
| Adjust TTLs/limits | Configuration (server-side validated; versioned) |
| Create operators/auditors | Roles & permissions → New admin (least privilege by role) |
| Backup | Backup & recovery → Export (sensitive form needs super-admin + step-up) |
| Restore | Backup & recovery → Import (dry-run first; apply is idempotent per email) |
| Audit retention | Storage & integrity → Run audit pruning |

## Incident response

### 1. Suspected admin credential compromise
1. **Roles & permissions** → change the affected admin's password (or delete the account if malicious).
2. **Configuration → Revoke all sessions** (epoch bump — every session, including the attacker's, dies within the propagation bound ~1–2 s + next request).
3. Audit → actor=<username> → review every action taken.
4. Rotate `SESSION_SIGNING_KEY` and `APP_TOKEN_SIGNING_KEY` in Secrets Manager if forgery cannot be ruled out (invalidates all sessions and app tokens at once).

### 2. Leaked user API token
User page → revoke the credential (rotates cred_version). New exchanges die immediately; already-issued access tokens die on their next request (they re-check every request). The raw token was never stored, so no further exposure exists beyond its display moment.

### 3. Unexpected authorization decision
1. Audit → target=user:<uid> → inspect the change history (every mutation records actor + before/after summary in the subscription history).
2. Verify the record in the portal's Edge Storage view (`users/<uid>`, `subs/<uid>`) — byte-level source of truth.
3. Health & diagnostics → confirm storage/config state; a degraded state fail-closes (denies), it never grants.

### 4. Storage / control-plane outage
Symptoms: writes return 502 `CONTROL_PLANE_UNAVAILABLE`; logins 503 `STORAGE_UNAVAILABLE`; authorization requests are denied (fail-closed by design).
1. Check Gcore status (status.gcore.com) and the panel's Health page.
2. Do NOT attempt schema "repairs" through the portal while the app is failing writes — the app reports per-record outcomes for every batch; re-running any bulk operation after recovery is safe.
3. After recovery, re-run an export to verify data completeness.

### 5. Defective deployment (bad binary)
1. Keep the previous binary (binaries are immutable and retained in the account).
2. Portal → app → replace binary with the last known-good `.wasm` → Save and deploy. Data is untouched; the panel's ETag revalidation means browsers pick up the matching assets immediately (no stale JS).
3. Verify `GET /healthz` and the 40-step smoke suite against the app URL.

### 6. Secret rotation (planned)
Secrets Manager supports versioned retrieval (`get_effective_at`). Recommended sequence: add the new value, verify both versions readable, switch the active slot, then remove the old value. Session/app-token keys invalidate existing tokens when rotated — schedule during a maintenance window.

## Escalation data to collect

`GET /healthz` output, `GET /api/system/health` JSON, the request IDs from failing client responses (present on every response/error), the relevant audit records, and the app version. This is exactly the evidence set the runbooks above reference.
