// Health & operational diagnostics.
import { api } from "../api.js";
import { el, icon, statusPill, emptyState } from "../ui.js";
import { fmtUtc } from "../utils.js";

export async function render(root) {
  const holder = el("div", {});
  root.replaceChildren(el("div", { class: "panel" }, el("div", { class: "panel-pad" }, el("div", { class: "skeleton" }))), holder);
  let health;
  try {
    health = await api.get("/api/system/health");
  } catch (e) {
    holder.replaceChildren(emptyState("Diagnostics unavailable", e.message || "You may lack the system:read permission.", "heartbeat"));
    return;
  }
  let cfg = null;
  try { cfg = await api.get("/api/config"); } catch { /* permission-gated */ }

  const okItems = [
    ["storage", health.storage.read_probe === "ok"],
    ["cache", health.cache.available],
    ["session key", health.secrets.session_signing_key === "configured"],
    ["app key", health.secrets.app_token_signing_key === "configured"],
    ["config record", health.config === "ok"],
  ];
  const allOk = okItems.every(([, ok]) => ok);

  holder.replaceChildren(
    el("div", { class: "kpis" },
      el("div", { class: `kpi ${allOk ? "ok" : "warn"}` },
        el("div", { class: "kpi-label" }, "Overall"),
        el("div", { class: "kpi-value" }, allOk ? "Healthy" : "Degraded"),
        el("div", { class: "kpi-note" }, "measured " + health.generated_at),
      ),
      el("div", { class: "kpi" },
        el("div", { class: "kpi-label" }, "Storage read probe"),
        el("div", { class: "kpi-value" }, health.storage.read_probe_ms + " ms"),
        el("div", { class: "kpi-note" }, "local edge replica"),
      ),
      el("div", { class: "kpi" },
        el("div", { class: "kpi-label" }, "Control plane"),
        el("div", { class: "kpi-value" }, health.control_plane),
        el("div", { class: "kpi-note" }, "Gcore REST API (writes + proxies)"),
      ),
      el("div", { class: "kpi" },
        el("div", { class: "kpi-label" }, "Server time (UTC)"),
        el("div", { class: "kpi-value" }, fmtUtc(Date.now() / 1000).split(" ")[1]),
        el("div", { class: "kpi-note" }, fmtUtc(Date.now() / 1000)),
      ),
    ),
    el("div", { class: "panel" },
      el("div", { class: "panel-head" }, el("h2", {}, "Component status"), el("span", { class: "hint" }, "live values — no synthesis")),
      el("div", { class: "panel-pad" },
        el("dl", { class: "kv" },
          el("dt", {}, "Edge Storage"), el("dd", {}, statusPill(health.storage.read_probe)),
          el("dt", {}, "Per-POP cache"), el("dd", {}, statusPill(health.cache.available ? "ok" : "unavailable")),
          el("dt", {}, "Session signing key"), el("dd", {}, statusPill(health.secrets.session_signing_key)),
          el("dt", {}, "App token key"), el("dd", {}, statusPill(health.secrets.app_token_signing_key)),
          el("dt", {}, "Configuration"), el("dd", {}, statusPill(health.config)),
          el("dt", {}, "Store binding"), el("dd", {}, statusPill(health.storage.store_id_configured ? "configured" : "missing")),
          cfg ? el("dt", {}, "Config version") : el("dt", {}, "Config version"),
          cfg ? el("dd", {}, el("span", { class: "mono-chip" }, "v" + cfg.version)) : el("dd", {}, el("span", { class: "faint small" }, "read requires config:read")),
          el("dt", {}, "App version"), el("dd", {}, el("span", { class: "mono-chip" }, health.version)),
        ),
        el("div", { class: "note mt-2 small" },
          icon("activity", 12), " The public liveness probe is available at ", el("code", {}, "GET /healthz"), " without authentication — it exposes only status, time, and version."),
      ),
    ),
  );
}
