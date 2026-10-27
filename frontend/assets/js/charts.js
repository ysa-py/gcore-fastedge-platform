// Tiny SVG charts — real data only. Sparklines and bar rows.

/** Line sparkline over SVG. values: array of numbers or "unavailable". */
export function sparkline(values, { width = 560, height = 120, color = "#6366f1", fill = "#6366f120" } = {}) {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.setAttribute("width", "100%");
  svg.setAttribute("class", "sparkline");
  svg.setAttribute("role", "img");
  const nums = values.filter((v) => typeof v === "number");
  if (!nums.length) {
    const t = document.createElementNS(ns, "text");
    t.setAttribute("x", width / 2);
    t.setAttribute("y", height / 2);
    t.setAttribute("text-anchor", "middle");
    t.setAttribute("fill", "#64748b");
    t.setAttribute("font-size", "13");
    t.textContent = "no data available";
    svg.appendChild(t);
    return svg;
  }
  const max = Math.max(1, ...nums);
  const n = values.length;
  const x = (i) => (n === 1 ? width / 2 : (i / (n - 1)) * (width - 8) + 4);
  const y = (v) => height - 8 - ((v / max) * (height - 22)) - 2;
  let path = "";
  let area = `M${x(0)},${height - 6}`;
  let started = false;
  values.forEach((v, i) => {
    if (typeof v !== "number") return;
    const cmd = started ? "L" : "M";
    path += `${cmd}${x(i).toFixed(1)},${y(v).toFixed(1)} `;
    area += `L${x(i).toFixed(1)},${y(v).toFixed(1)} `;
    started = true;
  });
  area += `L${x(n - 1).toFixed(1)},${height - 6} Z`;
  // gridlines
  for (const frac of [0.25, 0.5, 0.75]) {
    const gy = document.createElementNS(ns, "line");
    gy.setAttribute("x1", 0); gy.setAttribute("x2", width);
    gy.setAttribute("y1", height * frac); gy.setAttribute("y2", height * frac);
    gy.setAttribute("stroke", "#1e293b"); gy.setAttribute("stroke-dasharray", "3 5");
    svg.appendChild(gy);
  }
  const areaEl = document.createElementNS(ns, "path");
  areaEl.setAttribute("d", area); areaEl.setAttribute("fill", fill);
  svg.appendChild(areaEl);
  const lineEl = document.createElementNS(ns, "path");
  lineEl.setAttribute("d", path); lineEl.setAttribute("fill", "none");
  lineEl.setAttribute("stroke", color); lineEl.setAttribute("stroke-width", "2");
  lineEl.setAttribute("stroke-linecap", "round"); lineEl.setAttribute("stroke-linejoin", "round");
  svg.appendChild(lineEl);
  return svg;
}

/** Vertical bar chart with day labels. */
export function barChart(days, values, { height = 120, color = "#818cf8" } = {}) {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  const width = 560;
  svg.setAttribute("viewBox", `0 0 ${width} ${height + 22}`);
  svg.setAttribute("width", "100%");
  svg.setAttribute("class", "sparkline");
  svg.setAttribute("role", "img");
  const nums = values.filter((v) => typeof v === "number");
  const max = Math.max(1, ...nums);
  const n = values.length;
  const bw = width / n;
  values.forEach((v, i) => {
    const x = i * bw;
    const rect = document.createElementNS(ns, "rect");
    if (typeof v === "number") {
      const h = Math.max(1.5, (v / max) * (height - 8));
      rect.setAttribute("x", x + bw * 0.18);
      rect.setAttribute("y", height - 6 - h);
      rect.setAttribute("width", bw * 0.64);
      rect.setAttribute("height", h);
      rect.setAttribute("rx", 2.5);
      rect.setAttribute("fill", color);
      const t = document.createElementNS(ns, "title");
      t.textContent = `${days[i]}: ${v}`;
      rect.appendChild(t);
    } else {
      rect.setAttribute("x", x + bw * 0.18);
      rect.setAttribute("y", height - 10);
      rect.setAttribute("width", bw * 0.64);
      rect.setAttribute("height", 4);
      rect.setAttribute("rx", 2);
      rect.setAttribute("fill", "#334155");
    }
    svg.appendChild(rect);
    if (n <= 16 || i % Math.ceil(n / 8) === 0) {
      const label = document.createElementNS(ns, "text");
      label.setAttribute("x", x + bw / 2);
      label.setAttribute("y", height + 14);
      label.setAttribute("text-anchor", "middle");
      label.setAttribute("font-size", "9.5");
      label.setAttribute("fill", "#64748b");
      label.textContent = (days[i] || "").slice(5); // MM-DD
      svg.appendChild(label);
    }
  });
  return svg;
}

export const SERIES_COLORS = {
  req: "#818cf8",
  err4xx: "#f59e0b",
  err5xx: "#f43f5e",
  authok: "#10b981",
  authfail: "#f43f5e",
  adminops: "#38bdf8",
  tokissue: "#c084fc",
};

export const SERIES_LABELS = {
  req: "API requests",
  err4xx: "4xx responses",
  err5xx: "5xx responses",
  authok: "Successful logins",
  authfail: "Auth failures",
  adminops: "Admin operations",
  tokissue: "Tokens issued",
};
