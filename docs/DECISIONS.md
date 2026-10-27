# Architecture Decision Records

## ADR-001 — Single wasm artifact serves the SPA and the API

**Status:** ACCEPTED
**Context:** The admin panel could be deployed as a separate static site (another FastEdge app or hosting product), or embedded in the application binary.
**Decision:** Embed the SPA via `include_bytes!` in the same wasm artifact.
**Consequences:** (+) one deployable, zero version skew between panel and API, no second origin to harden or pay for, simpler CSP (same-origin only). (−) binary grows by ~190 KB (726 KB total — comfortably within expectations); panel updates require an app redeploy. Mitigation: ETag revalidation guarantees browsers can never mix panel/API versions (ADR-005).

## ADR-002 — Sync `wasm32-wasip1` (`#[fastedge::http]`) over async `wstd`/`wasm32-wasip2`

**Status:** ACCEPTED
**Context:** Current docs showcase the async path for new HTTP apps; the sync reactor world is described as the basic/legacy path.
**Decision:** Build on the reactor world.
**Rationale:** the canonical WIT (`FastEdge-wit/world.wit`) bundles every host service this app needs — `key-value`, `secret`, `dictionary`, `utils`, `cache-sync`, `http-client` — into the **reactor** world. A component has exactly one world; the async path could not import the same service set. The sync path is fully documented, all official examples for host services use it, and it produced a working artifact verified end-to-end.
**Consequences:** (+) every capability in one binary. (−) if the sync path is ever retired, porting to the async world is mechanical (the router/handlers are runtime-agnostic).

## ADR-003 — Writes via the Gcore control-plane REST API with a read-your-writes buffer

**Status:** ACCEPTED
**Context:** Edge Storage is application read-only (verified at WIT, host-implementation, and SDK level). Options: (a) skip writable admin features, (b) add an external database, (c) use the account REST API as the write path.
**Decision:** (c) — `GcoreControlPlane` issues batched `PUT /fastedge/v1/kv/{id}/data` calls through `send_request`, authenticated by a Secrets-Manager-held `GCORE_API_KEY`; `ReadYourWritesStore` layers a 15 s per-instance buffer over local-replica reads.
**Consequences:** (+) fully no-VPS, one control-plane call per batch, coherent admin UX despite 1–2 s replication. (−) admin writes depend on the control-plane API's availability (502, fail-loud); stale reads on other instances are bounded by the replication window (documented).

## ADR-004 — JWT sessions (HS256) with three revocation surfaces

**Status:** ACCEPTED
**Context:** Admin session state could be stored per-session in Edge Storage (stateful) or signed tokens (stateless).
**Decision:** Stateless HS256 JWTs with: hard expiry (default 30 min), per-session jti deny-list, and a global session-epoch. App access tokens (aud=app) are separate and always re-evaluated against storage on every request.
**Consequences:** (+) reads need no session store; revocation coverage: logout ≤ ~2 s (deny-list write) + immediate client cookie clear; revoke-all ≤ ~2 s (epoch); app entitlements immediate per-request. (−) revocation propagation is bounded by storage replication — stated, never overstated.

## ADR-005 — ETag revalidation (`no-cache` + 304) for panel assets

**Status:** ACCEPTED (replaced an earlier `max-age=3600` decision)
**Context:** Assets are embedded with stable URLs; long-lived caches would serve a stale panel after binary upgrades.
**Decision:** Content-hash ETags + `Cache-Control: no-cache`; browsers revalidate per load and receive 304s when unchanged (regression-tested).
**Consequences:** (+) correct after every deploy, cheap in steady state. (−) one revalidation request per asset per load (same-origin, tiny).

## ADR-006 — PBKDF2 for admin passwords, iterations config-tunable with a hard floor

**Status:** ACCEPTED
**Context:** Edge runtimes impose per-request CPU budgets; password hashing must be strong but bounded.
**Decision:** PBKDF2-HMAC-SHA256 with self-describing hashes; default 100,000 iterations (≈150 ms measured in wasm); verification enforces a 10,000-iteration floor (blocks downgrade); the default is admin-configurable up to 600,000 to fit each plan's CPU budget.
**Consequences:** (+) tunable per deployment, no C dependencies, pure Rust. (−) weaker than Argon2 on native hardware — an accepted platform trade-off, compensated by lockouts, monitoring, and short sessions.

## ADR-007 — Fail-closed everywhere

**Status:** ACCEPTED
**Context:** Authorization decisions depend on storage reads that can fail.
**Decision:** Any inability to establish authorization (storage error, missing record, malformed record, unknown schema version, credential-version mismatch, missing signing key) is a denial — never a default-allow, and never a 5xx on protected app routes (avoids "retry into access" ambiguity). Login/exchange return honest 503 when their dependencies are down.
**Consequences:** (+) no failure mode grants access. (−) outages deny service (correct trade for an authorization system); tests cover every failure injection.

## ADR-008 — Two independent CSRF defenses + `SameSite=Strict`

**Status:** ACCEPTED
**Decision:** All `/api/*` mutations require `X-Requested-With: fastedge-admin` (custom header ⇒ no cross-site forgery without a CORS preflight this API never grants) **and** origin/Host matching whenever `Origin` is present.
**Consequences:** (+) defense in depth; non-browser clients simply add the header. (−) document the header requirement prominently (done: API.md + in-console help).

## ADR-009 — Local verification stack: real runtime + faithful control-plane mock

**Status:** ACCEPTED
**Context:** True E2E verification was required without an account.
**Decision:** Run the real wasm under `fastedge-run` with Redis-backed Edge Storage and a local mock that implements the documented REST shapes (`scripts/dev/local_gcore_mock.py`) against the same Redis — plus a 40-step smoke suite (`scripts/dev/smoke_e2e.py`) that also works against production URLs.
**Consequences:** (+) the real binary, real runtime, real crypto, and real clock are all exercised locally; three genuine frontend bugs were caught this way. (−) production API nuances (envelope form, error shapes) are verified at first deployment; the mock is clearly marked LOCAL-ONLY.

## ADR-010 — ULID-shaped identifiers and flat key patterns

**Status:** ACCEPTED
**Decision:** User/subscription/credential/event IDs are ULIDs (48-bit ms timestamp + 80 random bits, Crockford base32) → lexicographic order equals creation order; storage keys stay within one wildcard segment per listing (`users/*`, `admins/*`, `audit/e*`) because the platform glob `*` does not cross `/` (verified).
**Consequences:** (+) chronological audit listing without indexes; complete scans by construction. (−) IDs embed creation time (visible to admins — acceptable, documented).
