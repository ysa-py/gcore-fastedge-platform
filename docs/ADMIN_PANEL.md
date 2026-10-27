# Admin Console Documentation

The console is a single-page application **embedded in the wasm binary** (no external hosting, no build step, native ES modules, CSP `default-src 'self'` — zero third-party origins, fonts, or scripts). Dark professional theme, system font stack, fully keyboard-operable.

## Screens

| Route | Screen | What it does |
|---|---|---|
| `#/login` | Sign-in | Username + password; lockout and error states; hardened cookie set server-side |
| `#/` | Dashboard | KPIs (total/active/suspended/revoked users, expiring ≤ 7 d) each labeled with its source; recent auth failures; recent events; live service health (storage probe, config, cache, control plane, version); "how to read this console" facts |
| `#/users` | Users | Search (debounced server query), status filter, newest-first pagination, create drawer (email/name/role/entitlement/expiry with live local→UTC preview) |
| `#/users/:uid` | User detail | Profile (editable metadata only), status actions with confirmations (suspend / reactivate / revoke with type-to-confirm), subscription editor (status/entitlement/absolute UTC expiry or clear), renewal (days or absolute), credentials (issue — token shown ONCE with copy button; revoke), full record IDs with copy chips |
| `#/subscriptions` | Subscriptions | Expiring-soon queue and filters (active/expired/suspended/all); multi-select bulk renew +30 d (one batched server write, per-record outcomes) |
| `#/credentials` | Credentials | Credential policy reference + recent issuance/revocation events from the audit trail |
| `#/audit` | Security & audit | Category/outcome filters, newest-first pagination, per-page sanitized export, correlation IDs |
| `#/analytics` | Analytics | 14-day per-POP counter charts (explicitly labeled approximate; "unavailable" days are never drawn as zero) + the authoritative Gcore Stats API panel (or an explicit unavailable reason) |
| `#/config` | Configuration | Server-validated operational settings (TTLs, lockout, retention, PBKDF2 iterations), versioned saves, **Revoke all sessions** (type-to-confirm) |
| `#/storage` | Storage & integrity | Live Edge Storage read-probe latency, store binding, cache availability, live account/plan limits via the Gcore API, audit-retention pruning |
| `#/system` | Health & diagnostics | Overall + component status with live probes, server UTC time, config version |
| `#/roles` | Roles & permissions | Admin accounts CRUD (role change, password reset, delete — self and last-super-admin guarded) + the full permission matrix mirrored from the server |
| `#/backup` | Backup & recovery | Export (sanitized by default; sensitive form requires super-admin + step-up) and two-phase import (dry-run report → apply), plus the recovery playbook |
| `#/help` | Help & API | Complete in-console API contract summary, operational notes, platform status links |

## Behaviors worth knowing

- **Step-up interception**: any `STEP_UP_REQUIRED` API response opens a re-authentication dialog automatically; after confirming, retry the action.
- **Session awareness**: the top bar shows the live step-up state; the sidebar shows the role and session expiry; permission-gated navigation items are hidden, but every route is *also* enforced server-side (the UI states this explicitly on its "Not permitted" page).
- **UTC discipline**: every timestamp is displayed in UTC with the zone labeled; datetime inputs are entered in your local timezone with a live "will be stored as …Z" preview — no silent interpretation.
- **Destructive safety**: confirmations for status changes, credential revocation, imports, config changes; type-to-confirm for user revocation, session-wide revocation, admin deletion, and sensitive exports.
- **Real data only**: every number carries its provenance; unavailable metrics are rendered as unavailable with the reason — the console never fabricates.
- **Accessibility**: skip link, focus-visible outlines, ARIA roles on dialogs/toasts/tables, `Escape` closes dialogs, keyboard-operable tables and forms, `prefers-reduced-motion` respected.

## Frontend architecture

```
frontend/
├── index.html                # shell (boot splash, toasts, modal root)
└── assets/
    ├── styles.css            # design system (tokens, components, responsive)
    └── js/
        ├── main.js           # hash router, app shell, auth gate, step-up interception
        ├── api.js            # fetch client (CSRF header, error envelope → ApiError)
        ├── state.js          # session/permission store with pub-sub
        ├── ui.js             # el() DOM builder, icons, modals, toasts, tables, forms
        ├── utils.js          # pure helpers (node --test covered)
        ├── charts.js         # SVG sparkline/bar charts (real data only)
        └── pages/*.js        # 14 screen modules, lazy-loaded per route
```

No framework, no bundler, no external asset — the panel is exactly what the wasm serves, and the ETag revalidation scheme guarantees the browser can never execute a panel version that does not match the API version that served it.
