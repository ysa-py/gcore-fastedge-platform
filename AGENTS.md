# Working in this repository (Base44 sandbox notes)

Project-specific notes for running this repo in the Base44 sandbox. Everything
about the application itself (architecture, deployment, testing matrix) is in
`README.md` and `docs/`; this file only records what is non-obvious here.

## Run it

```bash
docker compose -f docker-compose.base44.yml up -d --build
docker compose -f docker-compose.base44.yml ps
curl -s http://localhost:3000/healthz
```

Admin panel: <http://localhost:3000> — sign in with `bootstrap-admin` /
`bootstrap-secret-1` (the documented local-only test credential).

Three services:

| Service | What it is |
| --- | --- |
| `app` | The real WASM artifact, built from the bind-mounted source, executed by the real FastEdge runtime (`fastedge-run`). Publishes host port 3000. |
| `control-plane` | The project's local Gcore control-plane mock **and** the Redis-backed Edge Storage stand-in (redislite) it embeds. Local testing only — never deployed. |
| (image only) | `.base44/Dockerfile.app` / `.base44/Dockerfile.control-plane` provide toolchains and the runtime; **no application code is baked in**. |

## Non-obvious things that will bite you

1. **`fastedge-run` listens on loopback only.** Its `HttpConfig::all_interfaces`
   is `false`, so it binds `127.0.0.1:<port>` inside its container and Docker can
   never reach it through a published port. The `app` service therefore runs
   `socat TCP-LISTEN:8080,fork,reuseaddr TCP:127.0.0.1:8081` as a forwarder
   (`fastedge-run` itself listens on 8081). Health checks and the published port
   both go through the forwarder.
2. **The mock needed `--redis-bind` / `--http-bind`.** `scripts/dev/local_gcore_mock.py`
   starts redislite's Redis and its HTTP server on `127.0.0.1` by default, which is
   unreachable from another container. The compose file passes `0.0.0.0` for both.
   One Redis instance serves both the mock's writes and `fastedge-run`'s KV reads —
   that is exactly the architecture `scripts/run_local.sh` uses on a bare machine.
3. **There is no hot-reload dev server.** The panel is embedded in the WASM binary
   with `include_bytes!` (`src/assets.rs`), so *both* Rust and frontend edits need a
   wasm rebuild. The `app` service polls `src/`, `frontend/`, `Cargo.toml` and
   `Cargo.lock` and rebuilds + restarts `fastedge-run` on change; a failed rebuild
   keeps the previous artifact serving. Rebuilds are fast only because `target/`
   lives in the bind mount — do not delete it casually.
4. **Session cookies.** Production uses `__Host-fes` with `Secure`. The sandbox
   preview terminates TLS at its proxy, so under `BASE44_PREVIEW_MODE=1` the entry
   point passes `FE_COOKIE_INSECURE=true` (plain `fes_session` cookie). Unset or any
   other value keeps the production behaviour. `scripts/dev/smoke_e2e.py` also
   assumes the plain cookie name.
5. **Credentials are development values.** `SESSION_SIGNING_KEY`,
   `APP_TOKEN_SIGNING_KEY` and `GCORE_API_KEY` come from `.env.base44-defaults`
   first and `/run/base44/app.env` last (so real secrets win). The admin password
   hash is derived at container start-up from `ADMIN_PASSWORD`
   (default `bootstrap-secret-1`) by `scripts/generate_admin_credentials.py`; no
   hash or secret value is committed.
6. **Storage is throwaway.** Redis state lives inside the `control-plane`
   container, so recreating that container resets Edge Storage to the bootstrap
   admin.
7. **The preview proxy rewrites iframe-related response headers.** The app's strict
   CSP (`frame-ancestors 'none'`) is intentionally left untouched — do not relax it
   to embed the preview.
8. **The preview proxy also rewrites `Host`.** The browser sends
   `Origin: https://3000-<$BASE44_PUBLIC_HOST_SUFFIX>` (forwarded untouched) while
   the app sees `Host: 3000-<sandbox id>.$BASE44_SANDBOX_HOST_DOMAIN`, so the
   same-origin check in `csrf_guard` rejected every mutation with
   `403 Cross-site requests are not accepted.` — login included. `EnvConfig` gained
   `public_origin` (`FE_PUBLIC_ORIGIN`), and `csrf_guard` accepts that one exact
   origin in addition to `Host`. The compose entry point sets it from
   `BASE44_PUBLIC_HOST_SUFFIX`, but only while `BASE44_PREVIEW_MODE` is exactly
   `"1"`; unset, the check is byte-for-byte the production behaviour. It is an
   exact-match allowlist, never a wildcard, and `X-Requested-With` is still
   required.
9. **The console was invisible in a real browser before this setup** (found while
   verifying here): `frontend/assets/js/main.js` hid the boot screen at the end of
   boot but never removed `hidden` from `#app`, so every page rendered with
   `display: none` — a blank dark screen. Fixed by setting `app.hidden = false`
   after boot (both the normal and the failure path) and covered by the browser
   verification below. DOM-only checks cannot catch this class of defect; load the
   page and look at it.

## Verify a change

```bash
# the project's own quality gates, inside the app container
docker compose -f docker-compose.base44.yml exec -T app cargo test
docker compose -f docker-compose.base44.yml exec -T app cargo clippy --all-targets
docker compose -f docker-compose.base44.yml exec -T app npm test --prefix frontend

# the 40-step runtime E2E suite (~3 min: it waits out a real expiration boundary)
docker compose -f docker-compose.base44.yml exec -T app python3 scripts/dev/smoke_e2e.py http://127.0.0.1:8080
```

`cargo build`/`cargo test` need the `stable` toolchain and the `wasm32-wasip1`
target, both present in the `app` image.
