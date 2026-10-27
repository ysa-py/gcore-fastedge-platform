# Limitations & Unresolved Risks

Honest inventory, per the engineering brief. "Blocked" means a hard platform fact; "bounded" means supported with a disclosed limit.

## Platform-imposed

| # | Limitation | Nature |
|---|---|---|
| 1 | **Edge Storage is read-only from app code** — writes must go through the account REST API | By design. Architecture is built around it; each admin write costs one outbound REST call (batched) |
| 2 | **Global eventual consistency 1–2 s** for storage writes | Bounded: acting instance is coherent via the read-your-writes buffer; other PoPs converge within the documented window. Revocation semantics quote this bound explicitly |
| 3 | **No arbitrary TCP/UDP, no raw sockets, no VPN/tunneling** | UNSUPPORTED by the verified interface set (HTTP-only WIT imports). No claims of DPI resistance are made (see THREAT_MODEL.md §DPI) |
| 4 | **Per-POP cache** — rate limits and counters are approximations; availability is plan-dependent | Graceful degradation: cache-unavailable mode disables lockouts/counters (labeled live) while authorization remains unaffected |
| 5 | **No point-in-time restore for Edge Storage** | Export/import is the recovery path; retained exports are the operator's responsibility |
| 6 | **Plan quotas (calls, binary size, CPU ms, memory, subrequests) are account-specific** | Not hardcoded anywhere; surfaced live via `/api/system/limits`. The 726 KB artifact fits documented size expectations; PBKDF2 iterations are tunable if a plan's CPU budget is tight |
| 7 | **Audit trail is not tamper-proof against account-level access** | The application channel is write-once from the app's perspective, but anyone with control-plane access can modify keys. Disclosed as a residual account-level risk |

## Design trade-offs (deliberate)

| # | Decision | Rationale |
|---|---|---|
| 1 | Listing endpoints scan + read with caps (1000 users / 500 audit) | No query language exists on the platform; caps bound worst-case latency and cost. Responses carry an explicit `truncated` flag; refine with the filters provided |
| 2 | Read-modify-write without CAS | The platform offers no compare-and-swap. Concurrency is mitigated by: administrative-scale assumption, per-record idempotency, batched single-call writes, and `updated_by` provenance. Racing admins can last-write-win — documented, not hidden |
| 3 | Users are never hard-deleted (revocation is terminal) | Preserves audit referential integrity and index consistency |
| 4 | Raw API tokens are unrecoverable by design | Storage keeps fingerprints only; the issuance modal is the single display moment |
| 5 | Approximate per-POP counters shown next to authoritative stats | Two clearly-labeled sources beat one fabricated number |
| 6 | Sync `wasm32-wasip1` path instead of async `wstd`/`wasip2` | The reactor world bundles every host service this app needs in one component (see DECISIONS.md ADR-002) |

## Not yet verified against production

1. Real `api.gcore.com` calls (deployment, control-plane writes, stats/limits proxies) — verified against a faithful local mock of the documented shapes; the write-envelope probe covers both documented forms.
2. Real Secrets Manager behavior (encryption at rest, slot rotation).
3. Real Edge Storage replication timing (1–2 s is the documented figure; not measurable without deployment).
4. Production CPU/memory budgets for PBKDF2 at 100k iterations (≈150 ms locally).
5. Real-world browser rendering across the full support matrix (verified in Chromium; the SPA uses only baseline ES modules + `Intl`).

## Known minor issues

- Direct screenshots inside this development environment's headless runner render black (a runner compositing quirk, not an app defect — DOM-level assertions verify every page). Does not affect users.
- `fastedge-run`'s clock was observed ~1 s ahead of the host in local testing; all time-boundary tests keep ≥ 14 s margins. Production PoP clocks are NTP-synced by the platform.
- The audit page's "Export page" button exports the currently loaded page (not the full trail) — deliberate, to keep exports bounded; use repeated pagination or the API for bulk collection.

## Explicitly NOT provided (no fake versions exist)

Real uptime/latency/traffic SLAs, quota dashboards beyond the live `/fastedge/v1/me` proxy, "AI risk scores" (the panel only surfaces rule-grounded, recorded evidence), multi-factor authentication (no verified mechanism on this platform — reported honestly instead of faked), and global rate limiting (per-POP cache semantics only, labeled).
