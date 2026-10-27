# Threat Model

Assets: admin accounts, user PII (email/display name), credential fingerprints, subscription records, audit trail, signing keys, the Gcore API key, session integrity, service availability.

Trust boundaries: internet→edge, browser→admin API, edge→control plane, edge→Edge Storage/cache.

Severity scale: **Critical** (system compromise / authz bypass), **High** (major control or data compromise), **Medium** (limited impact or requires unusual preconditions), **Low** (hardening).

## Findings

| # | Threat | Path | Mitigation (implemented) | Severity / Residual |
|---|---|---|---|---|
| 1 | Unauthorized admin access | Stolen/weak password | PBKDF2 (100k default, ≥12 chars enforced at creation, 10k verification floor), per-identity lockout (10/15 min default) + per-IP limit, generic error text (anti-enumeration), short sessions, audit trail | Medium→Low |
| 2 | Session theft (XSS) | Script in panel reading tokens | Tokens never exposed to JS (`HttpOnly` cookie), strict CSP `default-src 'self'` (no inline script/style), `el()` DOM builder escapes text nodes, React-free code with no `innerHTML` | Low |
| 3 | CSRF | Cross-site form/fetch | Two independent defenses: required custom header on ALL `/api/*` mutations + server-side same-origin check when `Origin` present; `SameSite=Strict` | Low |
| 4 | Token forgery / algorithm confusion | `alg:none`, key confusion, tampering | Pinned byte-exact JWT header, constant-time HMAC compare, issuer/audience/purpose checks; tested attack corpus in `crypto::tests` + integration | Low |
| 5 | Token replay after revocation | Old access token reuse | Short TTL (default 300 s) **and** per-request re-evaluation of user + subscription + credential version — revocation kills exchanges immediately, live tokens at next request | Medium→Low (bounded by TTL for the *no-recheck* path; there is none — every request re-checks) |
| 6 | Privilege escalation via UI | Hidden-but-reachable endpoints | Permission enforced in the router for every route; UI-only hiding never used; denials audited; self-role-change and last-super-admin guards server-side | Low |
| 7 | Entitlement manipulation by users | Client claims roles/expiry | All authorization inputs come from server-side Edge Storage reads; JWT claims are only identity hints; boundary re-checked per request | Low |
| 8 | Stale authorization | Read lag after admin write | Writes are control-plane durable; read-your-writes buffer for the acting instance; global bound 1–2 s (documented); fail-closed on read errors | Low (bounded staleness disclosed) |
| 9 | Storage failure | Read/write errors during authz | Fail-closed everywhere: reads fail → deny (403/503, never success); audit-critical write failure aborts mutations; no partial silent states | Low |
| 10 | Brute force / DoS on login | Many guesses | Per-username + per-IP fixed-window counters (cache `incr`), 429 + `Retry-After`; body-size caps; unknown routes cheap | Medium→Low (per-POP counters make limits approximate; disclosed) |
| 11 | Credential database leak | Edge Storage compromise | Tokens stored as SHA-256 fingerprints only; raw value displayed exactly once; exports sanitized by default; sensitive export needs super-admin + step-up | Low |
| 12 | Secret exposure | Secrets in bundle/logs | All secrets via Secrets Manager (encrypted at rest); never in the SPA bundle, responses, or audit details; redaction enforces fingerprints-only | Low |
| 13 | SSRF via outbound HTTP | App fetches attacker URL | Outbound calls are hard-coded to the configured control-plane base URL; no user-influenced URLs exist | Low |
| 14 | Path traversal / glob injection | IDs interpolated into keys | All route IDs match `^[A-Za-z0-9_-]{1,128}$` (no `/`, `.`, `*`); record IDs are Crockford-ULIDs; tested traversal corpus | Low |
| 15 | Header/log injection | CR/LF in inputs | Validation rejects control characters in emails/names; audit `redact()` strips controls; request IDs sanitized; values never placed in headers unvalidated | Low |
| 16 | Information leakage in errors | Stack/internal details | Fixed error taxonomy with static messages; upstream bodies never forwarded; leak-hunting tests (`src/`, `.rs`, `panic` absent from all error bodies) | Low |
| 17 | Authenticated-response caching | Shared caches storing private data | `Cache-Control: no-store` on every API response (error responses included); assets are ETag-revalidated but public | Low |
| 18 | Audit tampering | Admin edits history | Audit records are individual keys written once; edits would require control-plane access (out of app scope) — integrity of the *app channel* is one-way; documented honestly: Edge Storage is not tamper-proof against account-level access | Medium (account-level risk, out of app scope) |
| 19 | Supply chain | Malicious crate | Minimal, well-known dependency set (serde, sha2, hmac, pbkdf2, base64, getrandom, fastedge); lockfile committed; no JS dependencies at all | Low |
| 20 | Deployment regression | Stale cached panel after upgrade | Content-hash ETags + `no-cache` revalidation — browsers can never run JS newer/older than the binary that served it (regression-tested 304 path) | Low |
| 21 | DoS via expensive endpoints | Large scans | Scan caps (1000 records users, 500 audit) with explicit `truncated` flags; bounded pagination; import payload caps | Medium→Low |
| 22 | Clock skew | Boundary evaluated with bad clock | All time from the runtime's `SystemTime` (single source); 60-second future floor on expiry writes absorbs skew; local runtime observed ±1 s (documented) | Low |

## Residual risks (accepted, disclosed)

1. **Account-level control plane compromise** — an attacker with the Gcore API token can read/write Edge Storage directly, including audit records. Out of scope for application code; mitigated operationally (least-privilege token, secret rotation via slots, incident runbook).
2. **Per-POP cache availability** — on plans without cache, lockouts/counters degrade to unavailable; login remains password-protected but rate limiting is absent in that mode. The health page states cache availability live.
3. **Audit retention vs. unbounded growth** — retention pruning exists (default 90 days) but must be run from the panel; unattended growth could slow scans (capped at 500/1000 records per request regardless).

## DPI / tunneling posture (requirement §14 of the brief)

This platform is an **HTTP application**, not a proxy. It performs HTTP request filtering, TLS terminates at the platform, and no TCP/UDP sockets, raw IP, or VPN primitives exist in the verified FastEdge interface set (`world.wit` imports are HTTP-only). Therefore: no claims of tunneling, protocol obfuscation, or DPI resistance are made — those would be unsupported (see LIMITATIONS.md). What TLS gives users here is standard: network observers see the SNI/domain and traffic timing, not content; operators (Gcore account) can observe request metadata as logged by the platform.
