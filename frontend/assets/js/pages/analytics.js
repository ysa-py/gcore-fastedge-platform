// Analytics: approximate per-POP counters + authoritative Gcore stats.
import { api } from "../api.js";
import { el, icon, toast, emptyState } from "../ui.js";
import { sparkline, barChart, SERIES_COLORS, SERIES_LABELS } from "../charts.js";
import { isUnavailable } from "../utils.js";

export async function render(root) {
  const holder = el("div", {});
  root.replaceChildren(
    el("div", { class: "panel panel-pad mb-2" },
      el("h2", { class: "mt-0" }, "Measurement provenance"),
      el("p", { class: "muted small" },
        "Two independent sources are shown and never mixed: (1) per-POP cache counters — approximate aggregates maintained by this app at each point of presence, and (2) the authoritative Gcore FastEdge Stats API measured at the platform level. When the stats proxy is unavailable, the panel says so — nothing is simulated."),
    ),
    holder,
  );

  try {
    const data = await api.get("/api/metrics?days=14");
    const counters = data.counters;
    const dayList = data.days;

    const counterPanels = counters.series.map((s) => {
      const values = s.values;
      const anyUnavailable = values.some(isUnavailable);
      const total = values.reduce((acc, v) => (typeof v === "number" ? acc + v : acc), 0);
      return el("div", { class: "panel" },
        el("div", { class: "panel-head" },
          el("h2", {}, SERIES_LABELS[s.metric] || s.metric),
          el("span", { class: "hint" }, "14 days · per-POP approximation"),
          el("span", { class: "spacer" }),
          el("span", { class: "badge b-mute" }, `Σ ≈ ${total}`),
        ),
        el("div", { class: "panel-pad" },
          el("div", { class: "chart-legend mb-2" },
            el("span", {}, el("span", { class: "dot" }), "daily totals (UTC days)"),
          ),
          barChart(dayList, values, { color: SERIES_COLORS[s.metric] || "#818cf8" }),
          anyUnavailable ? el("p", { class: "small faint mt-1" }, "Some days show “unavailable” — the per-POP cache could not be read for them; they are NOT zero.") : null,
        ),
      );
    });

    const ps = data.platform_stats;
    const platformPanel = el("div", { class: "panel" },
      el("div", { class: "panel-head" },
        el("h2", {}, "Platform stats (authoritative)"),
        el("span", { class: "hint" }, ps.available ? "Gcore FastEdge Stats API · last 24 h · hourly" : "unavailable"),
      ),
      el("div", { class: "panel-pad" },
        ps.available
          ? el("pre", { class: "mono small" }, JSON.stringify(ps.data, null, 2))
          : emptyState("Stats proxy unavailable", "Reason: " + (ps.reason || "unknown") + ". Configure the GCORE_API_KEY secret and ensure outbound HTTP is available on this deployment.", "activity"),
      ),
    );

    const reqSeries = counters.series.find((s) => s.metric === "req");
    holder.replaceChildren(
      counters.available
        ? el("div", { class: "grid-2" }, ...counterPanels, platformPanel)
        : el("div", { class: "panel" }, emptyState("Counters unavailable", "The per-POP cache is not available on this plan/deployment; the platform stats panel below remains authoritative.", "activity"), platformPanel),
    );
    if (reqSeries) {
      holder.prepend(el("div", { class: "panel mb-2" },
        el("div", { class: "panel-head" }, el("h2", {}, "Request volume trend"), el("span", { class: "hint" }, "per-POP approximation")),
        el("div", { class: "panel-pad" }, sparkline(reqSeries.values, { color: SERIES_COLORS.req })),
      ));
    }
  } catch (e) {
    holder.replaceChildren(emptyState("Metrics unavailable", e.message || "The metrics endpoint could not be loaded.", "activity"));
    toast(e.message || "Failed to load metrics", "err");
  }
}
