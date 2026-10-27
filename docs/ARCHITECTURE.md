# System Architecture

## Components

```text
                        ┌──────────────────────────────────────────────┐
                        │        ONE WebAssembly ARTIFACT               │
                        │  target: wasm32-wasip1  ·  ~726 KB            │
                        │                                              │
  Browser ──HTTPS──►    │  router.rs (pipeline)                        │
  (admin console)       │   ├─ static assets (embedded SPA, CSP)       │
                        │   ├─ /api/*   admin API  ── auth.rs ──┐       │
  Apps/Scripts ──►      │   ├─ /api/v1/* app API ── authorization.rs  │
  (token exchange,      │   └─ /healthz  liveness                   │   │
   Bearer calls)        │                                          │   │
                        │  datastore.rs  ReadYourWritesStore ◄──────┘   │
                        │   reads: Edge Storage local replica          │
                        │   writes: control-plane REST (batched)        │
                        │   + 15 s per-instance write buffer            │
                        └───────┬────────────────┬───────────┬─────────┘
                                │ get/scan       │ send_request        │ secret::get / cache
                                ▼                ▼                     ▼
                     Edge Storage (KV)    Gcore control plane    Secrets Manager
                     durable · replicated REST API (account)     encrypted at rest
                     local replica reads   └─► central SQL DB        │
                                ▲                    │               │
                                └── replication 1–2 s┘───────────────┘
                                                        per-POP cache: rate limits,
                                                        lockouts, ~counters
```

## Request pipeline (every request, same order)

1. **Request ID** — validated client `X-Request-ID` or fresh CSPRNG id; echoed on every response.
2. **Size caps** — body ≤ 256 KB (413 before parsing).
3. **Route + method** — unknown routes 404; unsupported methods 405 + `Allow` (OPTIONS rejected pre-auth, avoiding a session oracle).
4. **CSRF** — mutations require `X-Requested-With: fastedge-admin` **and**, when `Origin` is present, it must match `Host` (403 otherwise).
5. **Session** (admin routes) — HS256 JWT in `HttpOnly; SameSite=Strict` cookie; issuer/audience pinned; per-session jti deny-list; global session-epoch check. Storage failures deny (fail-closed).
6. **Permission** — explicit `permission` per route from the role→permission matrix; denials are audited.
7. **Step-up** — destructive routes additionally require recent re-authentication (`STEP_UP_REQUIRED` otherwise).
8. **Handler** — strict JSON (`deny_unknown_fields`), field-level validation, business state machines.
9. **Audit + metrics** — critical events must persist before the mutation is reported successful; best-effort events never block.
10. **Response** — security headers everywhere, `Cache-Control: no-store` on all API responses, structured error envelope with `request_id` and no internals.

## Data flow: an admin mutation (create user)

```text
panel → POST /api/users
  → csrf ✔ → session ✔ → users:manage ✔ → step-up ✔
  → validate (email/display_name/expiry collected into ONE 422)
  → email-uniqueness read (Edge Storage local replica)
  → build UserRecord + SubscriptionRecord + email index
  → datastore.put_batch  ──► control plane PUT /fastedge/v1/kv/{id}/data
                              (one batched REST call, base64 values)
  → write buffer updated (this instance reads it back instantly)
  → audit event persisted (critical; failure aborts the operation)
  → 201 + sanitized user view
        (1–2 s later every PoP serves the new record)
```

## Data flow: an end-user protected request

```text
app → GET /api/v1/me  (Bearer access token)
  → JWT verify (HS256, aud=app, pinned header, exp/nbf)
  → load user record        ┐
  → load subscription       ├─ local replica reads, every request
  → status + expiry check   ┘   (deny when now >= expires_at; fail-closed on any error)
  → 200 profile + live entitlement
```

## Trust boundaries

| Boundary | Controls |
|---|---|
| Internet → edge app | TLS (platform), size caps, strict validation, rate limits, no CORS (same-origin only), CSP |
| Browser → admin API | Session cookie (HttpOnly/Strict), CSRF dual defense, RBAC, step-up |
| Admin panel → user data | Server-side permission checks only; the UI mirrors, never enforces |
| Edge app → Gcore control plane | `GCORE_API_KEY` held in Secrets Manager; single-purpose REST calls; upstream errors never echoed to clients (coarse 502 categories) |
| Edge app → Edge Storage | Read-only by platform design; malformed/unknown-schema records fail closed |
| Edge app → cache | Per-POP; used only for approximations and lockouts; unavailability is survivable |

## Security-relevant time

- All timestamps are UTC unix seconds. Wire format is RFC3339 with mandatory `Z`/`+00:00`; non-UTC offsets are rejected at validation.
- The expiration rule is exact and tested at ±1 s and at the boundary instant: allow iff `now < expires_at`.

## Consistency model (documented, bounded)

- Edge Storage: eventually consistent globally (1–2 s), durable; reads are local.
- Read-your-writes buffer: per wasm instance, 15 s TTL — bounded staleness for other instances/PoPs = replication window.
- Revocation: credential revocation is immediate for new exchanges on a fresh read (control-plane write + local read); previously issued **access tokens** die within their TTL (≤ app_token_ttl_s, default 300 s) or immediately on credential-version mismatch — both re-checked per request.
- Session logout: jti deny-list write propagates like any write (≤ ~2 s) + cookie cleared client-side; "revoke all sessions" bumps the epoch (same bound). These bounds are stated, not hidden.
