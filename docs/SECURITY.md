# Security Design

## Authentication

**Admin sessions.** Username + password → PBKDF2-HMAC-SHA256 verification (self-describing hashes `pbkdf2-sha256$iters$salt$hash`; verification floor 10,000 iterations to block downgrade; default 100,000 ≈ 150 ms in wasm). On success the server mints an HS256 JWT (`iss=fap`, `aud=admin`, `purpose=admin-session`, `jti`, session epoch, optional step-up expiry) and sets it as an `HttpOnly; SameSite=Strict; Secure; Path=/` cookie (`__Host-` prefixed in production).

**Bootstrap.** With *zero* admin records, the `ADMIN_USERNAME`/`ADMIN_PASSWORD_HASH` deployment secrets may sign in once as super_admin; the record is then persisted and the bootstrap path is permanently disabled (re-verified on every attempt).

**End users.** Long-lived API tokens (`sk_live_…`, 256 bits CSPRNG) exist in storage only as SHA-256 fingerprints. `POST /api/v1/token` exchanges a token for a short-lived signed access token (default 300 s) — only if the user is active and the subscription is active and unexpired.

## Authorization

- **RBAC**: 5 roles (super_admin, admin, subscription_manager, operator, auditor) × 14 explicit permissions. Routes declare the permission; the router enforces it server-side for every request. The panel mirrors the matrix but is never trusted.
- **Step-up**: destructive operations (create/update/revoke, credentials, config, imports, revoke-all) require a session with recent re-authentication (default 15 min). The API returns `STEP_UP_REQUIRED` and the panel opens a password-confirm dialog.
- **Entitlement engine**: on every protected app request the server re-reads the user + subscription records and applies the exact UTC rule — **allow iff `now < expires_at`** (equality rejects; tested at ±1 s and at the instant). Storage failure, missing records, malformed records, unknown schema versions, or credential-version mismatch are all **denials** (fail-closed).
- **Anti-enumeration**: unknown user and wrong password produce byte-identical 401 responses.

## CSRF & browser hardening

Two independent defenses on every `/api/*` mutation: (1) a required custom header `X-Requested-With: fastedge-admin` (cross-site requests cannot carry custom headers without a CORS preflight this API never grants); (2) when `Origin` is present it must match `Host`. Cookies are `SameSite=Strict`. Responses always carry `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, `Cross-Origin-Opener-Policy: same-origin`, `X-Robots-Tag: noindex`. The SPA shell is served with `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'` — no inline script/style anywhere.

## Token security

HS256 with a pinned byte-exact header (`{"alg":"HS256","typ":"JWT"}`) — `alg:none`, algorithm confusion, and header tampering fail structurally. Signatures compared in constant time. Issuer/audience/purpose/not-before/expiry all verified. Domain separation: admin sessions (`aud=admin`) can never act as app tokens (`aud=app`) and vice versa (tested). Keys live only in the Secrets Manager (≥ 32-byte enforced), one for sessions, one for app tokens.

## Credential lifecycle

Issue → raw token shown exactly once → stored as fingerprint + token index; Revoke → `revoked_at` set + token index flagged + `cred_version` rotated (invalidates all prior-version tokens and live access tokens on their next request); every mutation audited with fingerprints (first 8 hex chars) only.

## Audit trail

One record per event (`audit/e{ULID}`), newest-first by key order. Fields: timestamp (ms), category (auth/user/subscription/credential/config/security/import/export/system), action, actor (`admin:{username}` / `user:{uid}` / `system`), target, outcome (ok/denied/error), correlation `request_id`, redacted `details` (≤ 256 chars, control characters stripped, secrets/tokens never recorded — enforced by `redact()` + tested). **Critical** events (admin mutations) must persist before the operation reports success; **best-effort** events (auth failures) never block.

## Fail-closed rules (tested)

| Failure | Behavior |
|---|---|
| Edge Storage read error during authz | deny (403 generic) — never success, never 5xx for the caller to "retry into" |
| Edge Storage read error during login | 503 STORAGE_UNAVAILABLE |
| Control-plane write error | 502, zero records written, no partial state |
| Malformed / unknown-schema record | deny (or 404/422 for admin reads) |
| Missing secrets (signing keys) | login/exchange refuse with 403 generic — no degraded auth |
| Cache unavailable | rate limiting/counters degrade (labeled); authz unaffected |

## Rate limiting

Fixed-window counters in the per-POP cache using atomic `incr` + `expire`: login per-username (default 10 / 15 min) and per-IP (200 / 15 min), token exchange per-token-fingerprint (30/min). 429 responses include `Retry-After`. Counters are per-POP by platform design — an honest approximation, labeled as such.

## Input validation

Strict JSON with `deny_unknown_fields`; all identifiers match `^[A-Za-z0-9_-]{1,128}$` before any storage access (kills traversal/glob injection); emails normalized + RFC-lite validated (no CR/LF); display names control-character-free; timestamps strict RFC3339 UTC with non-UTC offsets rejected; body cap 256 KB (413 pre-parse); all numeric query params range-checked; a single 422 collects every field error.

## Secrets inventory (all via Gcore Secrets Manager)

`SESSION_SIGNING_KEY`, `APP_TOKEN_SIGNING_KEY` (≥32 B each), `GCORE_API_KEY` (control plane), `ADMIN_USERNAME` + `ADMIN_PASSWORD_HASH` (bootstrap only). None are ever returned by any endpoint, logged, embedded in the SPA, or included in exports. Operational configuration (TTLs, limits) lives in Edge Storage and contains no secrets.
