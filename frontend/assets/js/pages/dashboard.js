// Overview dashboard — every metric sourced from a real endpoint, with its
// scope/limitations labeled explicitly.
import { api } from "../api.js";
import { el, icon, table, statusPill, skeletonRows, emptyState } from "../ui.js";
import { fmtUtc, fmtUtcMs, fmtRelative, isUnavailable } from "../utils.js";

export async function render(root) {
  const kpis = el("div", { class: "kpis" });
  for (let i = 0; i < 5; i++) {
    kpis.appendChild(el("div", { class: "kpi" }, el("div", { class: "kpi-label" }, "…"), el("div", { class: "kpi-value" }, el("div", { class: "skeleton" }))));
  }
  root.replaceChildren(kpis, el("div", { class: "panel", id: "dash-panels" }));

  let data;
  try {
    data = await api.get("/api/overview");
  } catch (e) {
    root.replaceChildren(
      emptyState("Overview unavailable", e.message || "The overview endpoint could not be loaded. Check your session and retry."),
    );
    return;
  }

  const u = data.users;
  const svc = data.service;
  const kpiDefs = [
    { label: "Total users", value: u.total, note: `Edge Storage scan${u.scan_truncated ? " (capped at 1000)" : ""}`, cls: "" },
    { label: "Active", value: u.active, note: "user.status = active", cls: "ok" },
    { label: "Suspended", value: u.suspended, note: "login + token use blocked", cls: "warn" },
    { label: "Revoked", value: u.revoked, note: "terminal state", cls: "danger" },
    { label: "Expiring ≤ 7 days", value: u.expiring_within_7d, note: "active subs ending this week", cls: u.expiring_within_7d ? "warn" : "" },
  ];
  kpis.replaceChildren(...kpiDefs.map((k) =>
    el("div", { class: `kpi ${k.cls}` },
      el("div", { class: "kpi-label" }, k.label),
      el("div", { class: "kpi-value" }, isUnavailable(k.value) ? "n/a" : String(k.value)),
      el("div", { class: "kpi-note" }, k.note),
    ),
  ));

  const eventsRows = (events) => events.map((ev) => {
    const tr = el("tr", {});
    tr.append(
      el("td", { class: "mono small" }, fmtUtcMs(ev.at)),
      el("td", {}, statusPill(ev.outcome)),
      el("td", {}, ev.action),
      el("td", { class: "small muted" }, ev.actor),
      el("td", { class: "small muted mono" }, ev.target),
    );
    return tr;
  });

  root.appendChild(el("div", { class: "grid-2 mt-2", id: "dash-panels" },
    el("div", { class: "panel" },
      el("div", { class: "panel-head" }, el("h2", {}, "Recent auth failures"), el("span", { class: "hint" }, "audit trail · live")),
      data.recent_auth_failures.length
        ? table([{ label: "When" }, { label: "Result" }, { label: "Action" }, { label: "Actor" }, { label: "Target" }], eventsRows(data.recent_auth_failures))
        : el("div", { class: "panel-pad" }, emptyState("No recorded failures", "Authentication denials recorded by the edge will appear here.", "shield")),
    ),
    el("div", { class: "panel" },
      el("div", { class: "panel-head" }, el("h2", {}, "Recent events"), el("span", { class: "hint" }, "latest 10")),
      data.recent_events.length
        ? table([{ label: "When" }, { label: "Result" }, { label: "Action" }, { label: "Actor" }, { label: "Target" }], eventsRows(data.recent_events))
        : el("div", { class: "panel-pad" }, emptyState("Nothing yet", "Administrative actions and security events are recorded here.", "activity")),
    ),
    el("div", { class: "panel" },
      el("div", { class: "panel-head" }, el("h2", {}, "Service health"), el("span", { class: "hint" }, fmtRelative(Date.now(), Date.parse(data.generated_at)) + " (" + fmtUtc(Date.parse(data.generated_at) / 1000) + ")")),
      el("div", { class: "panel-pad" },
        el("dl", { class: "kv" },
          el("dt", {}, "Edge Storage"), el("dd", {}, statusPill(svc.storage)),
          el("dt", {}, "Configuration"), el("dd", {}, statusPill(svc.config)),
          el("dt", {}, "Per-POP cache"), el("dd", {}, statusPill(svc.cache?.available ? "ok" : "unavailable"), el("span", { class: "faint small" }, " " + (svc.cache?.note || ""))),
          el("dt", {}, "Control plane"), el("dd", {}, statusPill(svc.store_id_configured ? "configured" : "missing")),
          el("dt", {}, "Version"), el("dd", {}, el("span", { class: "mono-chip" }, svc.version)),
        ),
        el("div", { class: "note mt-2" }, icon("clock", 13), " Storage reads are served from the local edge replica; writes replicate globally in 1–2 s (documented bound)."),
      ),
    ),
    el("div", { class: "panel" },
      el("div", { class: "panel-head" }, el("h2", {}, "Key facts"), el("span", { class: "hint" }, "how to read this console")),
      el("div", { class: "panel-pad small muted" },
        el("ul", {},
          el("li", {}, "Every number on this page comes from a live API response — nothing is simulated."),
          el("li", {}, "Authorization rejects the instant ", el("code", {}, "now >= expires_at"), " (UTC) on every protected request."),
          el("li", {}, "Destructive actions require recent re-authentication (step-up) — enforced server-side."),
          el("li", {}, "Credential tokens are shown exactly once at issuance and stored only as SHA-256 fingerprints."),
        ),
      ),
    ),
  ));
}
