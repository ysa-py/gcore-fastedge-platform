// Subscriptions overview: expiring-soon queue, filters, bulk renewal.
import { api } from "../api.js";
import { el, icon, table, statusPill, pager, confirmDialog, toast, emptyState } from "../ui.js";
import { daysUntil, fmtUtc } from "../utils.js";
import { has } from "../state.js";

const PER_PAGE = 25;
let state_ = { offset: 0, filter: "expiring", selected: new Set() };

export async function render(root, { navigate }) {
  state_.selected = new Set();
  const filterSel = el("select", { class: "select", "aria-label": "Subscription filter" });
  for (const [v, l] of [["expiring", "Expiring ≤ 7 days"], ["active", "Active"], ["expired", "Expired (derived)"], ["suspended", "Suspended"], ["all", "All"]]) {
    const o = el("option", { value: v }, l);
    if (state_.filter === v) o.selected = true;
    filterSel.appendChild(o);
  }

  const bulkBar = el("div", { class: "toolbar", hidden: "" });
  const panel = el("div", { class: "panel" });
  const refresh = () => load();

  root.replaceChildren(
    el("div", { class: "toolbar" },
      el("div", { class: "search" }, icon("search", 15), el("input", { class: "input", placeholder: "Subscriptions derive from user records", disabled: "" })),
      filterSel,
      el("button", { class: "btn", onclick: refresh, "aria-label": "Refresh" }, icon("refresh", 14)),
    ),
    bulkBar,
    panel,
  );
  filterSel.addEventListener("change", () => { state_.filter = filterSel.value; state_.offset = 0; refresh(); });

  async function load() {
    panel.replaceChildren(el("div", { class: "table-wrap" },
      table([{ label: "User" }, { label: "Entitlement" }, { label: "Status" }, { label: "Expires (UTC)" }, { label: "In" }], [])));
    try {
      const data = await api.get(`/api/users?limit=100&offset=0&sort=newest&status=active`);
      const now = Math.floor(Date.now() / 1000);
      let subs = data.users.filter((u) => u.subscription);
      const derived = (s) => s.derived_status;
      if (state_.filter === "expiring") subs = subs.filter((u) => derived(u.subscription) === "active" && u.subscription.expires_at && daysUntil(now, Math.floor(Date.parse(u.subscription.expires_at) / 1000)) <= 7 && daysUntil(now, Math.floor(Date.parse(u.subscription.expires_at) / 1000)) >= 0);
      else if (state_.filter === "active") subs = subs.filter((u) => derived(u.subscription) === "active");
      else if (state_.filter === "expired") subs = subs.filter((u) => derived(u.subscription) === "expired");
      else if (state_.filter === "suspended") subs = subs.filter((u) => derived(u.subscription) === "suspended");
      state_.total = subs.length;
      const page = subs.slice(state_.offset, state_.offset + PER_PAGE);

      const rows = page.map((u) => {
        const s = u.subscription;
        const tr = el("tr", {});
        const chk = el("input", { type: "checkbox", "aria-label": "Select " + u.email });
        if (state_.selected.has(u.uid)) chk.checked = true;
        chk.addEventListener("change", () => {
          if (chk.checked) state_.selected.add(u.uid); else state_.selected.delete(u.uid);
          updateBulkBar();
        });
        tr.append(
          el("td", {}, el("div", { class: "flex" },
            chk,
            el("div", {},
              el("div", { class: "clickable", onclick: () => navigate("#/users/" + u.uid) }, u.display_name || u.email),
              el("div", { class: "small faint" }, u.email),
            ),
          )),
          el("td", {}, s.entitlement_id),
          el("td", {}, statusPill(s.derived_status)),
          el("td", { class: "small mono" }, (s.expires_at || "no expiry").replace("T", " ")),
          el("td", { class: "small" }, s.expires_at ? fmtIn(daysUntil(now, Math.floor(Date.parse(s.expires_at) / 1000))) : "—"),
        );
        return tr;
      });
      panel.replaceChildren(
        el("div", { class: "table-wrap" }, table(
          [{ label: "User" }, { label: "Entitlement" }, { label: "Status" }, { label: "Expires (UTC)" }, { label: "In" }],
          rows.length ? rows : [el("tr", {}, el("td", { colspan: "5" }, emptyState("Nothing here", "No subscriptions match the current filter.", "calendar")))],
        )),
        pager({ total: state_.total, limit: PER_PAGE, offset: state_.offset, truncated: data.truncated, onPage: (o) => { state_.offset = o; load(); } }),
      );
    } catch (e) {
      toast(e.message || "Failed to load subscriptions", "err");
    }
  }

  function fmtIn(d) {
    if (d === 0) return "expired";
    if (d > 0) return d + "d";
    return Math.abs(d) + "d ago";
  }

  function updateBulkBar() {
    const n = state_.selected.size;
    bulkBar.hidden = n === 0;
    bulkBar.replaceChildren(
      el("span", {}, el("strong", {}, String(n)), ` user${n === 1 ? "" : "s"} selected`),
      el("span", { class: "spacer" }),
      el("button", {
        class: "btn",
        disabled: has("subs:manage") ? null : "true",
        onclick: async () => {
          const ok = await confirmDialog({
            title: "Bulk renew?",
            message: `Extend each selected subscription by 30 days from its current expiry (or from now, whichever is later).`,
            confirmLabel: "Renew selected",
          });
          if (!ok) return;
          try {
            const res = await api.post("/api/bulk", { action: "renew", uids: [...state_.selected], extend_days: 30 });
            toast(`Renewed ${res.ok}/${res.total}`, res.ok === res.total ? "ok" : "err");
            state_.selected = new Set();
            load();
          } catch (e) { toast(e.message || "Bulk renew failed", "err"); }
        },
      }, icon("refresh", 13), "Renew +30d"),
    );
  }

  load();
}
