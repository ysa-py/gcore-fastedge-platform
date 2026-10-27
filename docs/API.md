# API Contract

All request/response bodies are JSON (`Content-Type: application/json; charset=utf-8`). Errors use one envelope everywhere:

```json
{
  "error": { "code": "MACHINE_CODE", "message": "safe human text", "details": [{"field": "email", "message": "..."}] },
  "request_id": "hex"
}
```

Error codes → HTTP: `INVALID_REQUEST` 400 · `UNAUTHENTICATED` 401 · `PERMISSION_DENIED` 403 · `STEP_UP_REQUIRED` 403 · `NOT_FOUND` 404 · `METHOD_NOT_ALLOWED` 405 (+`Allow`) · `CONFLICT` 409 · `VALIDATION_FAILED` 422 (+details) · `PAYLOAD_TOO_LARGE` 413 · `RATE_LIMITED` 429 (+`Retry-After`) · `CONTROL_PLANE_UNAVAILABLE` 502 · `STORAGE_UNAVAILABLE` 503 · `INTERNAL_ERROR` 500.

## Conventions

- **Mutations** (`POST/PUT/PATCH/DELETE`) require `X-Requested-With: fastedge-admin` (CSRF) — same-origin browsers only.
- **Admin auth**: `fes_session` cookie (HttpOnly, SameSite=Strict). `__Host-` prefixed in production.
- **App auth**: `Authorization: Bearer <access_token>`.
- **Timestamps** in requests must be RFC3339 **UTC** (`2026-12-31T23:59:59Z`); responses return the same format.
- All API responses carry `Cache-Control: no-store` and `X-Request-ID`.
- A **step-up** badge (🔑) marks routes that additionally require recent re-authentication (`POST /api/auth/stepup`).

## Authentication

| Method | Path | Access | Body → Response |
|---|---|---|---|
| POST | `/api/auth/login` | public (rate-limited 10/15min per identity) | `{username, password}` → `{username, role, permissions[], session_ttl_s, step_up_ttl_s}` + `Set-Cookie` |
| GET | `/api/auth/session` | session | → `{username, role, permissions[], step_up_active, session_expires_at, session_ttl_s}` |
| POST | `/api/auth/logout` 🔑* | session | `{}` → `{ok:true}`; session revoked (jti deny-list) + cookie cleared (*no step-up required) |
| POST | `/api/auth/stepup` | session + password | `{password}` → `{ok, step_up_ttl_s}` + refreshed cookie |
| POST | `/api/auth/revoke-all` 🔑 | config:manage | `{}` → `{ok, epoch}` — invalidates ALL sessions |

## Users

| Method | Path | Access | Notes |
|---|---|---|---|
| GET | `/api/users?limit&offset&status&q&sort` | users:read | limit ≤ 100 (default 25); `sort=newest`; response includes `total`, `truncated` |
| POST | `/api/users` 🔑 | users:manage | `{email, display_name, app_role?, entitlement_id?, expires_at?, metadata?}` → 201 user view (creates subscription too) |
| GET | `/api/users/{uid}` | users:read | full sanitized view incl. credentials + subscription |
| PATCH | `/api/users/{uid}` 🔑 | users:manage | `{display_name?, app_role?, metadata?}` — editable fields only |
| POST | `/api/users/{uid}/status` 🔑 | users:manage | `{action: "suspend"\|"reactivate"\|"revoke"}` (state machine; revoke terminal; idempotent) |
| POST | `/api/users/{uid}/credentials` 🔑 | creds:manage | `{label?, ttl_s? (60..31536000)}` → 201 `{credential:{token (shown ONCE), cred_id, fingerprint, …}}`; bumps `cred_version` |
| DELETE | `/api/users/{uid}/credentials/{cred_id}` 🔑 | creds:manage | revokes + rotates `cred_version` (idempotent) |

## Subscriptions

| Method | Path | Access | Notes |
|---|---|---|---|
| GET | `/api/users/{uid}/subscription` | subs:read | includes `derived_status` (active/suspended/revoked/expired computed) |
| PUT | `/api/users/{uid}/subscription` 🔑 | subs:manage | `{status?, expires_at? (RFC3339 or null to clear), entitlement_id?}`; ≥ 60 s future floor |
| POST | `/api/users/{uid}/subscription/renew` 🔑 | subs:manage | `{extend_days (1..3650)}` or `{until: RFC3339}`; reactivates |
| POST | `/api/bulk` 🔑 | users:manage / subs:manage | `{action, uids[1..100], extend_days?, until?}` → per-record `{uid, outcome, reason?}`; ONE batched control-plane write |

## Governance

| Method | Path | Access | Notes |
|---|---|---|---|
| GET | `/api/audit?category&outcome&actor&target&limit&offset` | audit:read | newest-first; `has_more`; scan capped at 500 |
| GET | `/api/config` | config:read | operational configuration |
| PUT | `/api/config` 🔑 | config:manage | full-object update; range-validated; bumps `version` |
| GET | `/api/roles` | session | role descriptions + full permission matrix |
| GET | `/api/admins` | system:read | admin accounts (never hashes) |
| POST | `/api/admins` 🔑 | config:manage | `{username, password ≥ 12, role}` |
| PATCH | `/api/admins/{username}` 🔑 | config:manage | `{role}` — not self; last-super-admin guarded |
| POST | `/api/admins/{username}/password` 🔑 | config:manage | `{password}` |
| DELETE | `/api/admins/{username}` 🔑 | config:manage | not self; guarded |

## Data / platform

| Method | Path | Access | Notes |
|---|---|---|---|
| POST | `/api/export` | export:run | `{include_credentials?}` → sanitized snapshot; `include_credentials:true` needs super-admin + step-up and adds fingerprints + token indexes (never raw tokens) |
| POST | `/api/import` | import:run | `{options:{apply}, payload:{users:[…]}}` — dry-run returns per-row report; `apply` requires step-up; emails deduped (skipped, never overwritten) |
| GET | `/api/overview` | overview:read | dashboard aggregates with provenance labels |
| GET | `/api/metrics?days (1..31)` | metrics:read | per-POP counter series (approximate, labeled) + authoritative platform stats or explicit `available:false` |
| GET | `/api/system/health` | system:read | live component probes |
| GET | `/api/system/limits` | system:read | live `GET /fastedge/v1/me` proxy |
| POST | `/api/system/prune-audit` 🔑 | system:read | run audit retention now |

## Application API (end users)

| Method | Path | Access | Notes |
|---|---|---|---|
| POST | `/api/v1/token` | public (30/min per token fingerprint) | `{token: "sk_live_…"}` → `{access_token, token_type:"Bearer", expires_at, expires_in, scope}` — only while user active + subscription active + `now < expires_at` |
| GET | `/api/v1/me` | Bearer | profile + **live** entitlement decision |
| GET | `/api/v1/entitlements` | Bearer | entitlement + boundary rule metadata |
| GET | `/healthz` | public | `{status, time, version}` — no internals |

## Caching & idempotency

- Every API response: `Cache-Control: no-store`.
- Repeated `status`/`revoke` actions are idempotent (no-op success without a second version bump).
- Bulk/import operations report per-record outcomes; re-running imports skips existing emails.

## Example: the entitlement boundary

```bash
# with subscription expiring at 2027-01-15T08:00:00Z
curl -s https://app.example/api/v1/me -H "Authorization: Bearer $T"   # 08:00:01 → 200
# … one second past expiry …
curl -s https://app.example/api/v1/me -H "Authorization: Bearer $T"
# → 403 {"error":{"code":"PERMISSION_DENIED","message":"Access expired.",…}}
```
