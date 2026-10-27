# Deployment Guide

Two environments are supported: **local** (real runtime, mock control plane — for development/verification) and **production** (your Gcore account). The same artifact is used in both.

## Prerequisites

- Rust stable + `wasm32-wasip1` target (`rustup target add wasm32-wasip1`)
- Node ≥ 18 (frontend tests only)
- Python 3 (helper scripts; `redislite` for local runs)
- Production: a Gcore account with FastEdge access and a **permanent API token** (Customer Portal → Account settings → API tokens). The token needs FastEdge permissions (binaries/apps/KV data).

## Build

```bash
scripts/build.sh
# → target/wasm32-wasip1/release/fastedge_admin_platform.wasm (~726 KB)
```

The script runs the full verification pipeline (122 Rust tests, clippy, fmt, 11 frontend tests) before producing the artifact. Do not deploy an artifact that fails any gate.

## Local verification (real runtime)

```bash
pip install redislite
# install fastedge-run from https://github.com/G-Core/FastEdge-lib/releases
scripts/run_local.sh          # http://127.0.0.1:8080 — bootstrap-admin / bootstrap-secret-1
```

This runs the real wasm binary under the real FastEdge runtime with Redis-backed Edge Storage and a local control-plane mock, then executes the 40-step E2E suite. `scripts/dev/local_gcore_mock.py` is LOCAL TESTING ONLY — never deploy it.

## Production deployment

### Step 1 — generate credentials (never paste real secrets anywhere else)

```bash
python3 scripts/generate_admin_credentials.py --all --password '<your-strong-password>'
# → SESSION_SIGNING_KEY, APP_TOKEN_SIGNING_KEY, ADMIN_USERNAME, ADMIN_PASSWORD_HASH
# GCORE_API_KEY comes from your portal.
```

### Step 2 — create an Edge Storage store

Customer Portal → **FastEdge → Edge Storage → Create store**:
- Name it (e.g. `fastedge-admin-data`) and note BOTH the **name** and the numeric **store id** (shown in the store list/URL).
- Leave it empty — the application writes all records itself.

### Step 3 — upload the binary and create the app

```bash
export GCORE_API_KEY='<your token>'
GCORE_API_KEY=... scripts/deploy.sh          # uploads binary + creates the app
# → deployed: https://fastedge-admin-platform-<account>.fastedge.app
```

(Or manually: portal → FastEdge → HTTP Applications → Create new application → Upload binary, name it, Save and deploy. `POST /fastedge/v1/binaries/raw` + `POST /fastedge/v1/apps` are the API equivalents.)

### Step 4 — attach the Edge Storage store

On the app's settings page → **Edge Storage → Add Edge Storage** → select the store from Step 2. This grants the app read access to the local replicas.

### Step 5 — set environment variables (app settings → Environment variables)

| Variable | Value |
|---|---|
| `FE_STORE_NAME` | store **name** from Step 2 (used for `Store::open`) |
| `FE_STORE_ID` | numeric store **id** from Step 2 (used for REST writes) |
| `FE_API_BASE` | `https://api.gcore.com` (default; override only for testing) |
| `FE_COOKIE_NAME` | leave empty (uses `__Host-fes` over HTTPS) |
| `FE_COOKIE_INSECURE` | must be empty/false in production |

### Step 6 — attach secrets (app settings → Secrets; create them in Secrets Manager first)

| Secret | Value |
|---|---|
| `SESSION_SIGNING_KEY` | from Step 1 (≥ 32 bytes) |
| `APP_TOKEN_SIGNING_KEY` | from Step 1 (different value) |
| `GCORE_API_KEY` | your permanent API token (FastEdge permissions) |
| `ADMIN_USERNAME` | e.g. `bootstrap-admin` |
| `ADMIN_PASSWORD_HASH` | from Step 1 |

**Why the API key is safe here:** it lives encrypted in Secrets Manager, is read only by the wasm at runtime, and is used exclusively for server-side calls to the control plane. It never reaches the browser, the SPA bundle, or any response.

### Step 7 — first login (bootstrap)

Open the app URL. Sign in with your bootstrap username + the password from Step 1. The first successful login persists a proper super_admin record and the bootstrap path disables itself permanently. Go to **Roles & permissions** to create named administrator accounts (with step-up), then keep or rotate the bootstrap secret (its hash remains valid only until you change it in Secrets Manager — you may simply delete the `ADMIN_*` secrets afterwards; the stored admin record no longer depends on them).

### Step 8 — post-deployment smoke tests

```bash
BASE="https://<your-app>.fastedge.app"
curl -s "$BASE/healthz"                                   # {"status":"ok",...}
curl -s "$BASE/" -o /dev/null -w '%{http_code}\n'          # 200 (SPA)
python3 scripts/dev/smoke_e2e.py "$BASE"                  # full 40-step suite (uses your real control plane)
```

The suite is idempotent (unique emails per run) and safe: it only creates/updates records under `smoke-*@example.io` / `import-smoke-*@example.io`.

### Verifying Edge Storage writes worked

Portal → FastEdge → Edge Storage → your store: you should see keys like `admins/…`, `config/app`, `users/…`, `audit/e…`. The panel's **Storage & integrity** page shows live probes (read latency, store binding, cache availability) and **Health** shows overall state.

## Rollback

1. **Application code**: upload the previous binary (binaries are immutable; keep the last known-good `.wasm`) and update the app (`PUT /fastedge/v1/apps` equivalent: portal → app → replace binary → Save and deploy). Records are untouched.
2. **Data**: restore from a sanitized/sensitive export via the panel's two-phase import (duplicates are skipped, never overwritten).
3. **Secrets**: rotate via Secrets Manager (slot-based `get_effective_at` supports overlap); sessions die on the next epoch bump or token expiry.

## Cost & quota checklist

- FastEdge calls are metered account-wide per plan (a **Free** plan exists; the docs expose the allowance there). Typical usage of this app: every request counts once; admin mutations add one control-plane call per batch.
- The panel surfaces live plan limits (`GET /fastedge/v1/me` proxy) — check **Storage & integrity → Account & plan limits** after deployment.
- No other services are required; there is nothing else to pay for.

## Production hardening checklist

- [ ] `FE_COOKIE_INSECURE` empty; cookie shows `__Host-` prefix
- [ ] Secrets Manager values are unique (never reuse the two signing keys)
- [ ] Bootstrap `ADMIN_*` secrets removed after the first named admin exists
- [ ] Audit retention reviewed (default 90 days)
- [ ] `pbkdf2_iterations` reviewed against your plan's CPU budget (default 100k ≈ 150 ms locally)
- [ ] A recent export stored outside the platform
