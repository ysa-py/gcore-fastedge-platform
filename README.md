# FastEdge Admin Platform

An **edge-native authorization platform and intelligent administration panel** for [Gcore FastEdge](https://gcore.com/fastedge) — one WebAssembly binary that serves both the admin console and the application API, with **no VPS, no origin server, and no continuously running backend**.

```
┌────────────────────────────  one WASM artifact  ───────────────────────────┐
│  admin SPA (embedded)  │  admin API (/api/*)  │  app API (/api/v1/*)      │
│  login·users·subs·RBAC │  audit·config·stats  │  token exchange·entitlements│
└──────────┬─────────────────────┬──────────────────────┬───────────────────┘
           │ reads: local replica│ writes: Gcore REST   │ cache: rate limits
           ▼                     ▼ (1–2 s replication)  ▼
      Edge Storage (KV) ──────────────► per-POP cache   Secrets Manager
```

## What it does

- **Per-user authorization with an exact UTC boundary**: access is granted iff `now < expires_at`. The exact instant `now == expires_at` rejects. Re-checked on **every** protected request against the authoritative storage records — signed tokens alone never suffice.
- **Full admin console** (13 screens): dashboard with provenance-labeled metrics, user/subscription/credential lifecycle with confirmations, audit explorer, per-POP analytics + authoritative Gcore stats, configuration, storage diagnostics, RBAC with an explicit permission matrix, two-phase import/export, and an in-console API reference.
- **Real security controls**: HS256 JWT sessions in `HttpOnly; SameSite=Strict` cookies, PBKDF2 password hashing, step-up re-authentication for destructive operations, per-identity login lockouts, dual CSRF defenses, strict CSP (`default-src 'self'`), fail-closed authorization, SHA-256-only credential storage (tokens are displayed exactly once), and a write-once audit trail with redaction.
- **Read-your-writes across replication**: Edge Storage replicates writes globally in 1–2 s; a 15-second per-instance buffer keeps administrative workflows coherent anyway (unit-tested with a deterministic lag simulation).

## Verified status (not claims)

Every statement below was executed on this machine against the real artifact:

| Check | Command | Result |
|---|---|---|
| Unit + integration tests | `cargo test` | **122/122 passed** (71 unit, 51 integration) |
| Lint / format | `cargo clippy --all-targets` / `cargo fmt --check` | **0 warnings / clean** |
| Frontend unit tests | `npm test --prefix frontend` | **11/11 passed** |
| WASM build | `cargo build --release --target wasm32-wasip1` | **✅ 726,429 bytes** |
| Runtime E2E (real FastEdge runtime v0.22.0 + Redis + control-plane mock) | `scripts/run_local.sh` | **40/40 steps passed**, incl. a real-clock expiration-boundary test |
| Browser verification (Chromium) | manual + DOM assertions | login (real PBKDF2, ~0.62 s), all 13 pages rendering live data |

Not tested (requires an account): deployment to production `api.gcore.com`, real Secrets Manager, real Edge Storage replication timing. The local control-plane mock mirrors the documented API shapes exactly — see `docs/TESTING.md` for the full honest matrix.

## Quickstart (local, real runtime)

```bash
# prerequisites: rustup (stable + wasm32-wasip1), node 18+, python3, redislite
rustup target add wasm32-wasip1
pip install redislite

# grab fastedge-run from https://github.com/G-Core/FastEdge-lib/releases
# then build + run the full local stack:
scripts/build.sh
scripts/run_local.sh          # serves http://127.0.0.1:8080 and runs the 40-step E2E suite
```

Sign in with `bootstrap-admin` / `bootstrap-secret-1` (local test credentials).

## Deploy (production)

```bash
python3 scripts/generate_admin_credentials.py --all --password '<your-password>'   # values → Secrets Manager
GCORE_API_KEY=... scripts/deploy.sh                                              # upload binary + create app
```

Then attach the secrets, create + link an Edge Storage store, and set the `FE_*` environment variables — the complete checklist with portal screenshots-level detail is in **[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)**.

## Documentation

| Doc | Contents |
|---|---|
| [docs/RESEARCH.md](docs/RESEARCH.md) | Evidence-linked research on every FastEdge interface (URLs, commits, dates) |
| [docs/COMPATIBILITY_MATRIX.md](docs/COMPATIBILITY_MATRIX.md) | VERIFIED / RESTRICTED / PLAN-DEPENDENT classification of all required capabilities |
| [docs/FEASIBILITY.md](docs/FEASIBILITY.md) | How each requirement maps to verified platform capabilities (no-VPS) |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Components, data flow, trust boundaries |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Threat agents, attack paths, mitigations, residual risk |
| [docs/API.md](docs/API.md) | Complete route/permission/error contract |
| [docs/STORAGE.md](docs/STORAGE.md) | Edge Storage key layout, consistency semantics, recovery |
| [docs/SECURITY.md](docs/SECURITY.md) | Authentication, CSRF, tokens, redaction, fail-closed rules |
| [docs/TESTING.md](docs/TESTING.md) | Every test executed, with real output and NOT-RUN honesty |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Production deployment walkthrough + rollback |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | Incident-response runbooks |
| [docs/LIMITATIONS.md](docs/LIMITATIONS.md) | Everything this platform honestly cannot do |
| [docs/ADMIN_PANEL.md](docs/ADMIN_PANEL.md) | Admin console screens & workflows |
| [docs/DECISIONS.md](docs/DECISIONS.md) | Architecture Decision Records |
| [docs/PROGRESS.md](docs/PROGRESS.md) | Phase-by-phase execution log |

## Repository layout

```
├── src/                    # Rust core (host-testable) + wasm layer
│   ├── wasm.rs             # FastEdge entrypoint (#[fastedge::http], wasip1)
│   ├── router.rs           # request pipeline (CSRF → session → permission → step-up)
│   ├── auth.rs             # RBAC matrix, sessions, step-up, lockouts, bootstrap
│   ├── authorization.rs    # per-user entitlement engine (UTC boundary, fail-closed)
│   ├── datastore.rs        # read-your-writes store over Edge Storage + control plane
│   └── …                   # models, validation, crypto, audit, metrics, users
├── frontend/               # admin SPA (no build step; embedded into the wasm)
├── tests/                  # 51 integration tests (auth, boundary, security, workflows)
├── scripts/                # build / run_local / deploy / credentials / mock / smoke
└── docs/                   # 15 documents
```

## License

MIT — see [LICENSE](LICENSE).
