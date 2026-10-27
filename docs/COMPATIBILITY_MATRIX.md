# SDK / Platform Compatibility Matrix

Legend — **VERIFIED**: direct primary-source evidence (source code, WIT contract, or executed locally). **VERIFIED w/ RESTRICTIONS**: verified within documented limits. **PLAN/CONFIG DEPENDENT**: requires a specific plan/setting. **UNVERIFIED**: insufficient evidence. **UNSUPPORTED**: ruled out. **NOT TESTED**: implemented, but not executed against production.

| # | Capability | Status | Evidence / Notes |
|---|---|---|---|
| 1 | Sync HTTP handler (`#[fastedge::http]`, wasm32-wasip1) | **VERIFIED** | Built and executed locally (hello_world + this project, 726 KB artifact) |
| 2 | `fastedge` crate from crates.io (0.4.5) | **VERIFIED** | Resolved, compiled, linked against host services |
| 3 | Outbound HTTP (`fastedge::send_request`) | **VERIFIED w/ RESTRICTIONS** | Verified in fastedge-run against the local control-plane mock; production `api.gcore.com` calls NOT TESTED (account required). Request limits per plan: PLAN DEPENDENT (`Plan.max_subrequests`) |
| 4 | Edge Storage reads (`key_value::Store::get/scan`) | **VERIFIED w/ RESTRICTIONS** | Verified via fastedge-run + Redis. Glob `*` is segment-scoped (WIT + tests) |
| 5 | Edge Storage writes (REST `PUT /fastedge/v1/kv/{id}/data`) | **VERIFIED w/ RESTRICTIONS** | Entry schema from official OpenAPI (`schemas.yml`); envelope auto-probe implemented; verified against a faithful local mock; production NOT TESTED |
| 6 | Edge Storage replication semantics (1–2 s, durable, per-POP replicas) | **VERIFIED** (docs) / **NOT TESTED** (timing) | how-it-works documentation; timing not measurable without a production account |
| 7 | Per-POP cache (`cache_sync`) incl. atomic `incr` | **VERIFIED w/ RESTRICTIONS** | Works in fastedge-run; "available on paid plans" → PLAN DEPENDENT in production; graceful degradation implemented |
| 8 | Secrets Manager (`secret::get`, `get_effective_at`) | **VERIFIED w/ RESTRICTIONS** | Interface verified in WIT + SDK; `--secret` works with fastedge-run; production secret storage NOT TESTED |
| 9 | Environment variables / dictionary | **VERIFIED** | `--env` verified locally; portal env vars documented |
| 10 | `utils::set_user_diag` (stdout diagnostics) | **VERIFIED** | SDK docs; stderr is discarded platform-wide |
| 11 | Account/plan limits via `GET /fastedge/v1/me` | **VERIFIED w/ RESTRICTIONS** | Schema from official SDK types; proxied live in the panel; production NOT TESTED |
| 12 | Platform stats via `GET /fastedge/v1/stats/calls` | **VERIFIED w/ RESTRICTIONS** | Params from official Python SDK; proxied in the panel; production NOT TESTED |
| 13 | Binary upload + app creation (`POST /fastedge/v1/binaries/raw`, `POST /fastedge/v1/apps`) | **VERIFIED** (docs/SDK) / **NOT TESTED** (executed) | Scripted in `scripts/deploy.sh`; official curl examples |
| 14 | Session/cookie handling in the runtime | **VERIFIED** | Full login/logout flows over HTTP in fastedge-run |
| 15 | `SystemTime::now()` at the edge | **VERIFIED w/ RESTRICTIONS** | Works locally; observed fastedge-run clock ≈ 1 s ahead of system clock → smoke suite keeps ≥ 14 s safety margins around time boundaries |
| 16 | WASI `random_get` via `getrandom 0.2` | **VERIFIED w/ RESTRICTIONS** | Compiled for wasm32-wasip1; runtime behavior verified locally (all issued tokens are unique CSPRNG output); NOT TESTED on production PoPs |
| 17 | PBKDF2-HMAC-SHA256 at the edge | **VERIFIED w/ RESTRICTIONS** | 100k iterations ≈ 150 ms locally (wasm, fastedge-run); production CPU budget = PLAN DEPENDENT (`Plan.max_duration` ms) — iterations are config-tunable with a 10k floor |
| 18 | Arbitrary TCP/UDP sockets, VPN/tunneling | **UNSUPPORTED** | No such WIT imports exist; HTTP-only outbound. See LIMITATIONS.md §DPI |
| 19 | Edge Storage writes from app code | **UNSUPPORTED** | By design (verified in WIT + host implementation) — control-plane writes are the platform's intended path |
| 20 | Point-in-time restore / snapshots of Edge Storage | **UNSUPPORTED** (no evidence any exists) | Export/import via this app is the recovery path |

## Dependency compatibility (Rust, both host and wasm32-wasip1)

| Crate | Version | WASM-compatible | Notes |
|---|---|---|---|
| `serde` + `serde_json` | 1.x | ✅ (pure Rust) | record + wire serialization |
| `sha2` | 0.10 | ✅ | SHA-256 fingerprints, ETags |
| `hmac` | 0.12 | ✅ | HS256 JWT + HMAC |
| `pbkdf2` | 0.12 | ✅ | password hashing (no C, no asm) |
| `base64` | 0.22 | ✅ | token/entry encoding |
| `getrandom` | 0.2 | ✅ (WASI backend) | CSPRNG for ids/tokens |
| `fastedge` | 0.4 | ✅ (wasm only) | gated behind `cfg(target_arch = "wasm32")` |
