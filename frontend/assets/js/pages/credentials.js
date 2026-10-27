// Credentials governance view: recent issuance/revocation events from the
// audit trail + the token lifecycle documented for operators.
import { api } from "../api.js";
import { el, icon, table, statusPill, pager, toast, emptyState } from "../ui.js";
import { fmtUtcMs } from "../utils.js";

const PER_PAGE = 20;
let offset = 0;

export async function render(root, { navigate }) {
  const panel = el("div", { class: "panel" });
  root.replaceChildren(
    el("div", { class: "panel panel-pad mb-2" },
      el("h2", { class: "mt-0" }, "Credential policy"),
      el("dl", { class: "kv small" },
        el("dt", {}, "Format"), el("dd", {}, el("code", {}, "sk_live_…"), " — 256 bits of CSPRNG entropy"),
        el("dt", {}, "Storage"), el("dd", {}, "SHA-256 fingerprint only; the raw token is never persisted, logged, or exported"),
        el("dt", {}, "Display"), el("dd", {}, "Exactly once, at issuance"),
        el("dt", {}, "Rotation"), el("dd", {}, "Revoke or re-issue bumps the user's credential version; old access tokens die within their TTL (≤ 5 min default)"),
        el("dt", {}, "Revocation"), el("dd", {}, "Immediate for new exchanges; propagation is bounded by the 1–2 s Edge Storage replication"),
      ),
    ),
    panel,
  );

  async function load() {
    try {
      const data = await api.get(`/api/audit?category=credential&limit=${PER_PAGE}&offset=${offset}`);
      const rows = data.events.map((ev) => {
        const tr = el("tr", {});
        const uid = ev.target.match(/user:([^/]+)/)?.[1];
        tr.append(
          el("td", { class: "small mono" }, fmtUtcMs(ev.at)),
          el("td", {}, statusPill(ev.outcome)),
          el("td", {}, ev.action),
          el("td", { class: "small" }, ev.details || "—"),
          el("td", { class: "small mono" },
            uid ? el("span", { class: "clickable", onclick: () => navigate("#/users/" + uid) }, uid) : ev.target,
          ),
        );
        return tr;
      });
      panel.replaceChildren(
        el("div", { class: "panel-head" }, el("h2", {}, "Recent credential events"),
          el("span", { class: "hint" }, "audit trail · category=credential")),
        el("div", { class: "table-wrap" }, table(
          [{ label: "When" }, { label: "Result" }, { label: "Action" }, { label: "Details" }, { label: "User" }],
          rows.length ? rows : [el("tr", {}, el("td", { colspan: "5" }, emptyState("No credential events", "Issue or revoke a credential to populate this view.", "key")))],
        )),
        pager({ total: 1e9, limit: PER_PAGE, offset, has_more: data.has_more, onPage: (o) => { offset = o; load(); } }),
      );
      if (!data.has_more) {
        panel.replaceChildren(
          el("div", { class: "panel-head" }, el("h2", {}, "Recent credential events"),
            el("span", { class: "hint" }, "audit trail · category=credential")),
          el("div", { class: "table-wrap" }, table(
            [{ label: "When" }, { label: "Result" }, { label: "Action" }, { label: "Details" }, { label: "User" }],
            rows.length ? rows : [el("tr", {}, el("td", { colspan: "5" }, emptyState("No credential events", "Issue or revoke a credential to populate this view.", "key")))],
          )),
          el("div", { class: "pager" }, el("span", {}, `${data.events.length} event${data.events.length === 1 ? "" : "s"}`)),
        );
      }
    } catch (e) {
      toast(e.message || "Failed to load credential events", "err");
    }
  }
  load();
}
