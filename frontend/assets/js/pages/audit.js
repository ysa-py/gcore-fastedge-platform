// Audit explorer with safe filters and sanitized export.
import { api } from "../api.js";
import { el, icon, table, statusPill, pager, toast, emptyState, copyChip } from "../ui.js";
import { fmtUtcMs } from "../utils.js";

const PER_PAGE = 25;
let q = { category: "", outcome: "", offset: 0 };

export async function render(root) {
  const catSel = el("select", { class: "select", "aria-label": "Category" });
  const outSel = el("select", { class: "select", "aria-label": "Outcome" });
  for (const [v, l] of [["", "All categories"], ["auth", "auth"], ["user", "user"], ["subscription", "subscription"], ["credential", "credential"], ["config", "config"], ["security", "security"], ["import", "import"], ["export", "export"], ["system", "system"]]) {
    const o = el("option", { value: v }, l);
    if (q.category === v) o.selected = true;
    catSel.appendChild(o);
  }
  for (const [v, l] of [["", "All outcomes"], ["ok", "ok"], ["denied", "denied"], ["error", "error"]]) {
    const o = el("option", { value: v }, l);
    if (q.outcome === v) o.selected = true;
    outSel.appendChild(o);
  }
  const panel = el("div", { class: "panel" });
  root.replaceChildren(
    el("div", { class: "toolbar" },
      catSel, outSel,
      el("button", { class: "btn", "aria-label": "Refresh", onclick: load }, icon("refresh", 14)),
    ),
    panel,
  );
  catSel.addEventListener("change", () => { q.category = catSel.value; q.offset = 0; load(); });
  outSel.addEventListener("change", () => { q.outcome = outSel.value; q.offset = 0; load(); });

  async function load() {
    try {
      const params = new URLSearchParams({ limit: String(PER_PAGE), offset: String(q.offset) });
      if (q.category) params.set("category", q.category);
      if (q.outcome) params.set("outcome", q.outcome);
      const data = await api.get("/api/audit?" + params.toString());
      const rows = data.events.map((ev) => {
        const tr = el("tr", {});
        tr.append(
          el("td", { class: "small mono" }, fmtUtcMs(ev.at)),
          el("td", {}, el("span", { class: "mono-chip" }, ev.category)),
          el("td", {}, statusPill(ev.outcome)),
          el("td", { class: "small" }, ev.action),
          el("td", { class: "small" }, ev.actor),
          el("td", { class: "small mono" }, ev.target),
          el("td", { class: "small muted" }, ev.details || "—"),
          el("td", { class: "small faint mono" }, ev.request_id),
        );
        return tr;
      });
      panel.replaceChildren(
        el("div", { class: "panel-head" },
          el("h2", {}, "Security & audit events"),
          el("span", { class: "hint" }, "write-once records · pre-redacted details"),
          el("span", { class: "spacer" }),
          el("button", {
            class: "btn sm",
            onclick: async () => {
              try {
                const blob = new Blob([JSON.stringify({ exported_at: new Date().toISOString(), filter: q, events: data.events }, null, 2)], { type: "application/json" });
                const a = el("a", { href: URL.createObjectURL(blob), download: "audit-export.json" });
                document.body.appendChild(a);
                a.click();
                a.remove();
                URL.revokeObjectURL(a.href);
              } catch { toast("Export failed", "err"); }
            },
          }, icon("upload", 13), "Export page"),
        ),
        el("div", { class: "table-wrap" }, table(
          [{ label: "When" }, { label: "Category" }, { label: "Result" }, { label: "Action" }, { label: "Actor" }, { label: "Target" }, { label: "Details" }, { label: "Req ID" }],
          rows.length ? rows : [el("tr", {}, el("td", { colspan: "8" }, emptyState("No events", "No audit records match the current filters.", "shield")))],
        )),
        pager({ total: 1e9, limit: PER_PAGE, offset: q.offset, truncated: false, onPage: (o) => { q.offset = o; load(); } }),
      );
      if (!data.has_more) {
        panel.lastChild.replaceChildren(el("span", {}, `${data.events.length} record${data.events.length === 1 ? "" : "s"} on this page`));
      }
    } catch (e) {
      toast(e.message || "Failed to load audit trail", "err");
    }
  }
  load();
}
