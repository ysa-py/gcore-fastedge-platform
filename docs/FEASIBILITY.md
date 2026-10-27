# No-VPS Feasibility Assessment

**Question:** can the full system (application API, authorization engine, admin console) run with **no self-managed VPS, no dedicated origin server, and no continuously running backend**?

**Answer: YES — verified feasible**, with each requirement mapped to a platform capability below. The single external dependency is the Gcore account itself (the control-plane API + Secrets Manager), which is the platform this project targets — not an added infrastructure component.

## Requirement mapping

| Requirement | Mechanism | Status |
|---|---|---|
| Run application logic at the edge | FastEdge wasm32-wasip1 runtime, `#[fastedge::http]` | VERIFIED locally (real runtime) |
| Serve the admin console without hosting | SPA embedded in the wasm binary (`include_bytes!`), served with CSP + ETag revalidation | VERIFIED locally |
| Durable user/subscription/audit records | Edge Storage (durable, globally replicated, local-replica reads) | VERIFIED (docs) / NOT TESTED in production |
| **Write** those records without a server | The app calls the account REST API (`PUT /fastedge/v1/kv/{id}/data`) via `send_request`, authenticated by a `GCORE_API_KEY` **secret** that never reaches the browser | VERIFIED against a faithful local mock; production NOT TESTED |
| Bridge the 1–2 s replication window for admin UX | Per-instance read-your-writes buffer (15 s TTL, unit-tested with deterministic lag) | VERIFIED (tests) |
| Rate limiting / lockouts / counters | Per-POP cache with atomic `incr` + TTL (ms) | VERIFIED locally; plan-dependent in production (graceful degradation) |
| Secret storage (signing keys, password hashes, API key) | Gcore Secrets Manager (`secret::get`; `get_effective_at` available for future rotation) | VERIFIED interface; production storage NOT TESTED |
| Short-lived signed access tokens | HS256 JWT implemented in-wasm (pure-Rust crates) | VERIFIED (unit + E2E tests) |
| Password verification without a DB of plaintext | PBKDF2-SHA256 self-describing hashes | VERIFIED (~150 ms @ 100k iterations locally) |
| Platform metrics for the dashboard | Live proxy of `GET /fastedge/v1/stats/calls` and `GET /fastedge/v1/me` | VERIFIED against mock; production NOT TESTED |
| No secrets in the browser | All privileged operations happen server-side (wasm); CSP forbids any other origin; cookies are HttpOnly | VERIFIED (tests + CSP on every response) |

## Explicitly rejected alternatives

- **A second managed service (e.g., a hosted Redis/Upstash) for writes** — unnecessary: the platform's own control-plane API is the documented write path for Edge Storage. Adding a database would introduce a second trust domain, cost, and a new failure mode for zero capability gain.
- **BYOD ("bring your own database") Edge Storage** — supported by the platform (BYOD URL + prefix), but it reintroduces an external store to operate. Documented as an option, not used.
- **Client-side administration against the Gcore API directly** — would leak the account API key into the browser. All control-plane traffic is proxied through the wasm app with the key held in Secrets Manager.

## Known operational costs

| Item | Nature |
|---|---|
| FastEdge monthly call allowance | Plan-dependent (Free plan exists; account-level tracking). The panel shows live limits via `/fastedge/v1/me` instead of guessing. |
| Outbound control-plane calls | One REST call per admin write batch (bulk operations batch many records into a single call). Reads are local-replica and free of this path. |
| CPU per login | One PBKDF2 verification (~150 ms at default 100k iterations locally). Tunable via config with a 10k floor. |

## Deployment blockers (none at code level)

Deployment itself requires privileges this repository does not have: uploading the binary, creating the app, creating/linking the Edge Storage store, and entering secrets. `scripts/deploy.sh` automates the API steps for an authorized operator; `docs/DEPLOYMENT.md` is the complete checklist.
