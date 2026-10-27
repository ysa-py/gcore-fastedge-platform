# Testing — Commands, Results, and Honest Gaps

All results below were produced on this machine (Linux x86_64, Rust 1.99.1, Node 24.21.0) against this exact source tree. Nothing is simulated inside the application; the only test double is the **local Gcore control-plane mock** (`scripts/dev/local_gcore_mock.py`), which mirrors the documented REST shapes and writes to the same Redis the real runtime reads.

## 1. Unit + integration tests (host)

```
$ cargo test
test result: ok.  71 passed;  0 failed   (lib — timeutil, crypto/JWT, validation, ids,
                                             datastore read-your-writes + lag simulation,
                                             auth RBAC/lockout/step-up/epoch, models)
test result: ok.  13 passed;  0 failed   (tests/auth_session_tests.rs)
test result: ok.  11 passed;  0 failed   (tests/authorization_tests.rs)
test result: ok.  18 passed;  0 failed   (tests/security_regression_tests.rs)
test result: ok.   9 passed;  0 failed   (tests/users_subscriptions_tests.rs)
                                       ── 122/122 total ──
```

Coverage highlights (each requirement category from the brief has dedicated tests):

- **Expiration boundary**: exact-instant rejection (`now == exp` → deny), ±1 s, per-request re-check after suspension/revocation, renewal restoration.
- **Fail-closed**: missing/malformed/unknown-schema records, storage read failures (403 generic), control-plane write failures (502, no partial writes), missing signing keys.
- **JWT attacks**: `alg:none`, key confusion, tampered payloads, wrong audience/issuer, expiry boundaries — all rejected.
- **CSRF**: missing custom header → 403; cross-origin → 403 (both integration-tested through the router).
- **Session lifecycle**: cookie hardening flags, logout deny-list, epoch revocation of all sessions, step-up enforcement and expiry.
- **RBAC**: each role × permission matrix behavior; self-role-change and last-super-admin guards; privilege-escalation attempts denied + audited.
- **Workflows**: user CRUD with collected field errors, duplicate-email conflict (case/whitespace normalized), state machines (suspend/reactivate/revoke terminal/idempotent), credential rotation, bulk operations with per-record outcomes and **one** batched write, two-phase import (dry-run writes nothing), sanitized export.
- **Hygiene**: security headers on every response, `no-store` on all API responses (error responses included), request-id sanitization (CRLF injection attempt), oversized bodies 413, malformed JSON 400, unknown fields 400, path-traversal/glob corpus 404, method 405 + `Allow`, error bodies never contain internals (`src/`, `panic`, `.rs`).

## 2. Static quality gates

```
$ cargo clippy --all-targets     → 0 warnings
$ cargo fmt --check              → clean
```

## 3. Real WASM build

```
$ cargo build --release --target wasm32-wasip1
→ target/wasm32-wasip1/release/fastedge_admin_platform.wasm  (726,429 bytes)
```

## 4. Runtime E2E — the REAL FastEdge runtime (fastedge-run v0.22.0)

Stack: real wasm binary + `fastedge-run` + Redis (Edge Storage stand-in) + local control-plane mock + real PBKDF2/HS256 inside the wasm.

```
$ scripts/run_local.sh        # or: python3 scripts/dev/smoke_e2e.py http://127.0.0.1:8080
== E2E SMOKE: 40/40 steps passed ==
```

The 40 steps include: liveness, SPA shell with strict CSP, asset ETag revalidation (200 → 304), 401 without session, **login with real PBKDF2 (100k iterations)**, cookie hardening flags, CSRF rejection with a valid session but no custom header, `STEP_UP_REQUIRED` before destructive ops, step-up → create user, searchable listing, credential issuance (token visible once, never echoed again), token exchange → `/api/v1/me` with live entitlement, **real-clock expiration boundary** (expiry set +75 s → allowed before → waited → `403 "Access expired."` → renew restores access), credential revocation (exchange denied), audit trail contents (actions present, raw tokens absent), config get/put versioning, overview aggregates, two-phase import, sanitized export, health probes, limits proxy, logout → session dead.

Measured (local, honest context — fastedge-run re-instantiates the module per request, so absolute numbers include that harness overhead):

- `GET /healthz`: ~0.48 s (harness overhead dominated)
- Login (PBKDF2 100k): ~0.61–0.64 s → hashing ≈ 150 ms
- Observed clock skew between fastedge-run and the host: ≈ 1 s (test margins account for it)

## 5. Real browser verification (Chromium, headless)

- Login form submit → 200, session cookie set, router redirected to the dashboard.
- All 13 pages DOM-verified with live data, e.g. `Dashboard | panels=5 | rows=10 | kpis=5`, `Audit | rows=25`, `Roles | rows=15`, `Help | rows=27`.
- **Three real defects were found and fixed by this testing**: (1) `fmtUtc` crashed on the API's RFC3339 strings ("Invalid time value" — blank pages), (2) the `.boot-screen` CSS `display:grid` defeated the `[hidden]` attribute so the splash covered the app, (3) `dashboard.js` missed the `fmtUtcMs` import and `config.js` imported `has` from the wrong module. All fixed; a static import audit now runs as part of review.
- Environment limitation (disclosed): direct **screenshots** render black in this headless runner (compositing quirk); DOM assertions were used as the verification channel instead.

## 6. Frontend unit tests

```
$ npm test --prefix frontend        # node --test
ℹ tests 11  ℹ pass 11  ℹ fail 0
```

(Pure helpers: UTC formatting for numbers AND RFC3339 strings, relative time, durations, email sanity, clamps, derived status, unavailability markers, attribute escaping.)

## NOT RUN (requires a Gcore account)

1. Production deployment (`api.gcore.com` upload/app creation) — scripted in `scripts/deploy.sh`, instructions in `DEPLOYMENT.md`.
2. Real control-plane writes/reads against production Edge Storage (the mock mirrors documented shapes; the envelope auto-probe covers both documented forms).
3. Real Secrets Manager storage/encryption; real Edge Storage replication timing (1–2 s is the documented figure); production stats/limits endpoints.
4. Production CPU/memory budget behavior (plan `max_duration`/`mem_limit`) — PBKDF2 iteration count is config-tunable with a 10k floor to adapt if a plan enforces tighter budgets.

## Re-running everything

```bash
scripts/build.sh        # tests + clippy + fmt + frontend tests + wasm build
scripts/run_local.sh    # real-runtime E2E (40 steps)
```
