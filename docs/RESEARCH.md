# Research Notes

**Method:** every capability claim below was verified against primary sources on **2026-10-27 (UTC)** — official repository source code at specific commits, the published crates.io crate, and official documentation pages. Where a capability could not be verified, it is marked UNVERIFIED and never used by this project.

## Sources inspected

| Source | Ref | Date |
|---|---|---|
| FastEdge Rust SDK (`fastedge` crate) | repo `G-Core/FastEdge-sdk-rust` @ `e7f446a4b40b791b932ab36b2c7a0c85fd24104d` (branch `main`); **published crate `fastedge = "0.4.5"`** (crates.io, updated 2026-10-13) resolved during our build | 2026-10-27 |
| FastEdge WIT contracts (canonical) | repo `G-Core/FastEdge-wit` @ `main`: `world.wit`, `key-value.wit`, `secret.wit`, `cache-sync.wit`, `http-client.wit`, `http-handler.wit` | 2026-10-27 |
| FastEdge runtime + CLI | repo `G-Core/FastEdge-lib` @ `f2df90aae1f4e3a33207272d7f0c010f5863573e`; release `fastedge-run v0.22.0` (x86_64-unknown-linux-gnu, published 2026-10-21) — downloaded and executed locally | 2026-10-27 |
| Official examples | repo `G-Core/FastEdge-examples` @ `065dc6ff6ccf869ff65c70afe368a18c040ba90a` (examples now live in the SDK repo) | 2026-10-27 |
| Gcore REST API (official SDK) | repo `G-Core/gcore-python` @ `main` (`src/gcore/resources/fastedge/*`, `src/gcore/types/fastedge/*`) | 2026-10-27 |
| FastEdge API surface (OpenAPI schemas) | repo `G-Core/FastEdge-client-sdk-go` @ `main`: `schemas.yml` (`modify_store_data_entry`, `encoded_value`, `store_kv_pair_value`, `plan`) | 2026-10-27 |
| Documentation pages | `docs.gcore.com/fastedge/...` — llms.txt index, kv-stores (how-it-works, manage-kv-store, byod), cache, secrets-manager, fastedge-cli, create-fastedge-apps | 2026-10-27 |

## Verified facts this project depends on

### 1. Application model (HTTP apps, sync path)

- Entry point: `#[fastedge::http]` proc macro over `fn(req: http::Request<Body>) -> Result<http::Response<Body>, _>`; build target **`wasm32-wasip1`**; `[lib] crate-type = ["cdylib"]`. *Evidence: SDK README, `docs/SDK_API.md`, `examples/http/basic/*` — and our own successful build of `hello_world` and this project.*
- The `reactor` WIT world imports exactly: `http`, `http-client`, `dictionary`, `secret`, `key-value`, `utils`, `cache-sync`; exports `http-handler`. *Evidence: `FastEdge-wit/world.wit`.*
- Outbound HTTP: `fastedge::send_request(Request<Body>) -> Result<Response<Body>, Error>`. *Evidence: SDK `src/http_client.rs:75`, `examples/http/basic/backend`.*

### 2. Edge Storage (key-value)

- **Application code can only READ**: `Store::open(label)` → `get`, `scan(glob)`, `zrange_by_score`, `zscan`, `bf_exists`. There is **no put/delete** in the WIT contract, the host implementation (`FastEdge-lib/crates/key-value-store`), or the SDK. *Evidence: three independent sources above.*
- Writes happen via the account REST API: `PUT /fastedge/v1/kv/{store_id}/data` with `modify_store_data_entry` objects: `{"op":"add"|"del_key"|"del_entries", "key", "datatype":"kv", "payload":{"value", "encoding":"plain"|"base64", "expiry"?}}`; value ≤ **1,048,576** chars; key ≤ **256** bytes. *Evidence: `manage-kv-store` doc + `schemas.yml`.*
- Consistency: writes go through a central SQL database and replicate to **every** edge location, typically within **1–2 seconds**; reads are served from the local replica. Durable. *Evidence: `docs.gcore.com/fastedge/kv-stores/how-it-works`.*
- Glob semantics: `*` matches **within one key segment** (does not cross `/`). *Evidence: `key-value.wit` doc comments + our unit tests mirror this.*

### 3. Cache (per-POP)

- Writable from app code: `get/set/delete/exists/incr(atomic)/expire/purge/purge_prefix`; TTL in **milliseconds**; scope is a **single POP**, strongly consistent within it, evictable, non-durable. *Evidence: `cache-sync.wit`, `docs.gcore.com/fastedge/cache`.*
- Docs note cache provisioning is "available at runtime on paid plans" → PLAN/CONFIGURATION DEPENDENT. The app degrades gracefully and reports `cache: unavailable` when operations fail.

### 4. Secrets

- `fastedge::secret::get(key) -> Result<Option<String>, Error>` and `get_effective_at(key, at: u32)` (versioned retrieval for rotation). Errors: `access-denied`, `decrypt-error`, `other(string)`. *Evidence: `secret.wit` (string return), SDK example `examples/http/basic/secret`.*
- Portal secrets can also be attached as environment variables; our implementation tries `secret::get` first, then falls back to `env::var`.

### 5. Gcore control-plane REST API

- Base: `https://api.gcore.com`; auth header: **`Authorization: APIKey <token>`** (permanent API token from the portal). *Evidence: official curl examples in `create-fastedge-apps`.*
- Used by this project:
  - `POST /fastedge/v1/binaries/raw` (octet-stream) → `{id, api_type, checksum}` — deployment.
  - `POST /fastedge/v1/apps` `{name, binary, status}` → `{id, url: "https://<name>-<acct>.fastedge.app", plan}` — deployment.
  - `PUT /fastedge/v1/kv/{store_id}/data` — Edge Storage writes (see above).
  - `GET /fastedge/v1/me` — account/plan limits (mirrors the `Plan` schema: `max_duration` ms, `mem_limit` bytes, `max_subrequests`).
  - `GET /fastedge/v1/stats/calls?from&to&step[&id]` — authoritative call series (RFC3339 bounds, step seconds).
- The exact request envelope for the `data` endpoint is documented as an array of entries; the official generated SDKs contain the entry schema but not a client function for `data`. Our client therefore probes once per instance (bare array first, `{"data": [...]}` fallback) and caches the accepted form. **VERIFIED WITH RESTRICTIONS** — the exact envelope used by a given account is confirmed at first write; the local mock accepts both.

### 6. Local runtime (`fastedge-run v0.22.0`)

- `fastedge-run http -w app.wasm --port N` runs the **real** FastEdge runtime locally; supports `--env K=V`, `--secret K=V`, `--kv-stores <label>=redis://...` (Redis-backed Edge Storage), `--max-duration`, `-m` memory limit, `--geo`. *Evidence: `--help` output captured locally; full E2E suite executed against it.*

### 7. Plans and pricing

- A **Free plan exists** (the documented app-creation response shows `"plan": "Free"`); plans carry a monthly call allowance tracked account-wide ("Request call limits", overview page). Exact current quotas and prices are **PLAN/CONFIGURATION DEPENDENT / UNVERIFIED** — they are account-specific and the portal is authoritative. The panel surfaces live account limits via `GET /fastedge/v1/me` instead of hardcoding anything.

## Findings that shaped the architecture

1. **Edge Storage is read-only from app code.** This is not a limitation to work around — it is the platform's data-plane/control-plane separation. Writes go through the account API; the app reads the local replica. Our `ReadYourWritesStore` composes both sides and bridges the 1–2 s replication window with a 15 s per-instance buffer (unit-tested with a deterministic `LaggingReplica`).
2. **The cache is per-POP.** Counters are approximate by construction; the UI labels them as such and separately surfaces the authoritative Gcore stats.
3. **The sync world (`wasm32-wasip1`, `#[fastedge::http]`) contains every host service this app needs.** The async `wstd`/`wasip2` path is the docs' current showcase for pure HTTP apps, but the reactor world is the one that bundles `key-value`, `secret`, `dictionary`, `utils`, and `cache-sync` for a single component — recorded as ADR-002 in `DECISIONS.md`.

## Corrections made during research

- The SDK's `key_value::Store::new()` (documented in repo docs) does **not** exist in the published 0.4.5 crate; only `Store::open(label)` / `from_handle`. Our wasm layer opens the store by the configured `FE_STORE_NAME` label.
- `secret::get` returns `Option<String>` on the component path (not bytes) per `secret.wit`.
