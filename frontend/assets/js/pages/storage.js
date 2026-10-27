// Storage & data integrity: health, plan limits, retention tools.
import { api } from "../api.js";
import { el, icon, statusPill, toast, confirmDialog, emptyState } from "../ui.js";
import { has } from "../state.js";

export async function render(root) {
  const holder = el("div", {});
  root.replaceChildren(el("div", { class: "panel" }, el("div", { class: "panel-pad" }, el("div", { class: "skeleton" }))), holder);
  let health, limits = null, limitsErr = null;
  try {
    health = await api.get("/api/system/health");
  } catch (e) {
    holder.replaceChildren(emptyState("Health unavailable", e.message || "", "database"));
    return;
  }
  try {
    limits = await api.get("/api/system/limits");
  } catch (e) {
    limitsErr = e.message || "unavailable";
  }

  const healthPanel = el("div", { class: "panel" },
    el("div", { class: "panel-head" }, el("h2", {}, "Edge Storage & runtime"),
      el("span", { class: "hint" }, health.generated_at)),
    el("div", { class: "panel-pad" },
      el("dl", { class: "kv" },
        el("dt", {}, "Read probe"), el("dd", {}, statusPill(health.storage.read_probe), ` ${health.storage.read_probe_ms} ms (local replica)`),
        el("dt", {}, "Consistency"), el("dd", {}, el("span", { class: "small muted" }, health.storage.consistency)),
        el("dt", {}, "Store id configured"), el("dd", {}, statusPill(health.storage.store_id_configured ? "configured" : "missing")),
        el("dt", {}, "Per-POP cache"), el("dd", {}, statusPill(health.cache.available ? "ok" : "unavailable"), el("span", { class: "faint small" }, " " + health.cache.note)),
        el("dt", {}, "Session signing key"), el("dd", {}, statusPill(health.secrets.session_signing_key)),
        el("dt", {}, "App signing key"), el("dd", {}, statusPill(health.secrets.app_token_signing_key)),
        el("dt", {}, "Config record"), el("dd", {}, statusPill(health.config)),
        el("dt", {}, "Control plane"), el("dd", {}, statusPill(health.control_plane)),
        el("dt", {}, "App version"), el("dd", {}, el("span", { class: "mono-chip" }, health.version)),
      ),
      el("div", { class: "note mt-2 small" },
        icon("clock", 12), " Writes go through the Gcore REST control plane into the central database and replicate to every POP within the documented 1–2 s window. This app additionally keeps a 15 s read-your-writes buffer per instance."),
    ),
  );

  const limitsPanel = el("div", { class: "panel" },
    el("div", { class: "panel-head" }, el("h2", {}, "Account & plan limits"),
      el("span", { class: "hint" }, "live from GET /fastedge/v1/me"),
      el("span", { class: "spacer" }),
      el("button", { class: "btn sm", onclick: () => render(root) }, icon("refresh", 13), "Refresh"),
    ),
    el("div", { class: "panel-pad" },
      limits
        ? el("pre", { class: "mono small" }, JSON.stringify(limits.account, null, 2))
        : el("div", {},
            el("p", { class: "muted small" }, "Limits proxy unavailable: " + (limitsErr || "unknown") + "."),
            el("p", { class: "faint small" }, "Requires the GCORE_API_KEY secret and outbound HTTP. Nothing is shown in its place."),
          ),
    ),
  );

  const retentionPanel = el("div", { class: "panel" },
    el("div", { class: "panel-head" }, el("h2", {}, "Retention & recovery")),
    el("div", { class: "panel-pad" },
      el("p", { class: "muted small mt-0" }, "Audit retention runs against the configured window. Pruning is a batched control-plane delete — safe to re-run, idempotent."),
      el("div", { class: "flex" },
        el("button", {
          class: "btn",
          disabled: has("system:read") ? null : "true",
          onclick: async () => {
            const ok = await confirmDialog({ title: "Prune old audit events?", message: "Events older than the configured retention window are deleted permanently from Edge Storage.", confirmLabel: "Prune now" });
            if (!ok) return;
            try {
              const res = await api.post("/api/system/prune-audit", {});
              toast(`Pruned ${res.pruned} event(s) (retention ${res.retention_days}d)`, "ok");
            } catch (e) { toast(e.message || "Prune failed", "err"); }
          },
        }, icon("trash", 13), "Run audit pruning"),
      ),
      el("div", { class: "note warn mt-2 small" },
        icon("alert", 12), " Backup/restore for Edge Storage is export/import based (Backup & Recovery page). The platform does not provide point-in-time snapshots."),
    ),
  );

  holder.replaceChildren(el("div", { class: "grid-2" }, healthPanel, limitsPanel), el("div", { class: "mt-2" }, retentionPanel));
}
