// Help: API reference summary, deployment notes, platform status guidance.
import { el, icon } from "../ui.js";

const API_DOCS = [
  ["POST", "/api/auth/login", "public (rate-limited)", "Admin sign-in. Sets an HttpOnly SameSite=Strict session cookie."],
  ["POST", "/api/auth/logout", "session", "Revokes the current session (jti deny-list)."],
  ["GET", "/api/auth/session", "session", "Current identity, role, permissions, step-up state."],
  ["POST", "/api/auth/stepup", "session + password", "Extends a session with step-up privileges for the configured window."],
  ["POST", "/api/auth/revoke-all", "config:manage + step-up", "Bumps the session epoch — every session dies within seconds."],
  ["GET", "/api/overview", "overview:read", "Dashboard aggregates with provenance labels."],
  ["GET", "/api/users", "users:read", "Paginated, searchable, filterable listing."],
  ["POST", "/api/users", "users:manage + step-up", "Create user + subscription (email is the unique index)."],
  ["GET", "/api/users/{uid}", "users:read", "Full record incl. sanitized credentials + subscription."],
  ["PATCH", "/api/users/{uid}", "users:manage + step-up", "Editable metadata only (never roles/status)."],
  ["POST", "/api/users/{uid}/status", "users:manage + step-up", "suspend / reactivate / revoke (terminal)."],
  ["POST", "/api/users/{uid}/credentials", "creds:manage + step-up", "Issues a token shown EXACTLY ONCE; bumps cred_version."],
  ["DELETE", "/api/users/{uid}/credentials/{cred_id}", "creds:manage + step-up", "Revokes + rotates the version."],
  ["PUT", "/api/users/{uid}/subscription", "subs:manage + step-up", "Status, entitlement, absolute UTC expiry."],
  ["POST", "/api/users/{uid}/subscription/renew", "subs:manage + step-up", "Extend by days or set an absolute instant."],
  ["POST", "/api/bulk", "users:manage / subs:manage + step-up", "Batched action with per-record outcomes."],
  ["GET", "/api/audit", "audit:read", "Filtered, newest-first audit trail (capped scan)."],
  ["GET/PUT", "/api/config", "config:read / config:manage + step-up", "Operational configuration (versioned, validated)."],
  ["GET", "/api/metrics", "metrics:read", "Per-POP counters + authoritative platform stats."],
  ["GET", "/api/system/health", "system:read", "Live component probes — no synthesis."],
  ["GET", "/api/system/limits", "system:read", "Live account/plan limits via the Gcore API."],
  ["POST", "/api/export", "export:run", "Sanitized snapshot (credential export needs super-admin + step-up)."],
  ["POST", "/api/import", "import:run (+ step-up to apply)", "Two-phase: dry-run validation report, then apply."],
  ["POST", "/api/v1/token", "public (rate-limited)", "Exchange a user API token for a short-lived signed access token."],
  ["GET", "/api/v1/me", "app access token", "Identity + live entitlement decision (re-checked every request)."],
  ["GET", "/api/v1/entitlements", "app access token", "Entitlement with the UTC boundary rule spelled out."],
  ["GET", "/healthz", "public", "Liveness only: status, UTC time, version."],
];

export async function render(root) {
  const rows = API_DOCS.map(([m, p, auth, desc]) => {
    const tr = el("tr", {});
    tr.append(
      el("td", {}, el("span", { class: "mono-chip" }, m)),
      el("td", { class: "mono small" }, p),
      el("td", { class: "small" }, auth),
      el("td", { class: "small muted" }, desc),
    );
    return tr;
  });

  root.replaceChildren(
    el("div", { class: "panel" },
      el("div", { class: "panel-head" }, el("h2", {}, "API contract summary"),
        el("span", { class: "hint" }, "complete machine-readable details live in docs/API.md of the repository")),
      el("div", { class: "table-wrap" }, el("table", { class: "tbl" },
        el("thead", {}, el("tr", {}, el("th", {}, "Method"), el("th", {}, "Path"), el("th", {}, "Access"), el("th", {}, "Purpose"))),
        el("tbody", {}, ...rows),
      )),
    ),
    el("div", { class: "grid-2 mt-2" },
      el("div", { class: "panel" },
        el("div", { class: "panel-head" }, el("h2", {}, "Operational notes")),
        el("div", { class: "panel-pad small muted" },
          el("ul", {},
            el("li", {}, "The expiration rule is UTC-exact: ", el("code", {}, "now >= expires_at"), " rejects. Boundary-tested at ±1 s."),
            el("li", {}, "All admin mutations pass CSRF (custom header + same-origin), permission, and (for destructive ops) step-up checks — server-side."),
            el("li", {}, "Edge Storage replicates writes globally in 1–2 s; this app adds a 15 s per-instance read-your-writes buffer so your own changes appear instantly."),
            el("li", {}, "Per-POP cache counters are approximations; treat them as trends. The Gcore Stats API is the authoritative source."),
          ),
        ),
      ),
      el("div", { class: "panel" },
        el("div", { class: "panel-head" }, el("h2", {}, "Platform status & support")),
        el("div", { class: "panel-pad small muted" },
          el("ul", {},
            el("li", {}, "Gcore status page: ", el("a", { href: "https://status.gcore.com/", target: "_blank", rel: "noopener noreferrer" }, "status.gcore.com")),
            el("li", {}, "FastEdge docs: ", el("a", { href: "https://docs.gcore.com/fastedge", target: "_blank", rel: "noopener noreferrer" }, "docs.gcore.com/fastedge")),
            el("li", {}, "This console never calls third-party origins (CSP: ", el("code", {}, "default-src 'self'"), "), so an outage of this app equals an outage of the edge app."),
            el("li", {}, "Incident response runbooks: docs/OPERATIONS.md in the repository."),
          ),
        ),
      ),
    ),
  );
}
