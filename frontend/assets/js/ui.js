// UI component kit: DOM builders, icons, modals, toasts, tables.
// CSP-safe: markup is constructed via document.createElement/textContent,
// never innerHTML with untrusted strings.

import { copyText } from "./utils.js";

/* ---------- icons (stroke paths, lucide-style, no external font) ---------- */
const ICONS = {
  dashboard: "M3 13h8V3H3zM13 21h8V11h-8zM3 21h8v-6H3zM13 9h8V3h-8z",
  users: "M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2M9 7a4 4 0 1 0 0 8 4 4 0 0 0 0-8zM22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75",
  key: "M21 2l-2 2m-7.6 7.6a5.5 5.5 0 1 1-7.78 7.78 5.5 5.5 0 0 1 7.78-7.78zm0 0L15.5 7.5m3 3L21 8m-3-3 3 3",
  calendar: "M8 2v4M16 2v4M3 10h18M5 4h14a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2z",
  shield: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z",
  activity: "M22 12h-4l-3 9L9 3l-3 9H2",
  settings: "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15H4.6a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 6.1 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68V4.6a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9v.09a2 2 0 1 1 0 4h-.09z",
  database: "M12 8c4.97 0 9-1.34 9-3s-4.03-3-9-3-9 1.34-9 3 4.03 3 9 3zM3 5v14c0 1.66 4.03 3 9 3s9-1.34 9-3V5M3 12c0 1.66 4.03 3 9 3s9-1.34 9-3",
  heartbeat: "M20.8 4.6a5.5 5.5 0 0 0-7.8 0L12 5.6l-1-1a5.5 5.5 0 0 0-7.8 7.8l1 1L12 21.2l7.8-7.8 1-1a5.5 5.5 0 0 0 0-7.8z M3 12h4l2-3 3 6 2-3h4",
  roles: "M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2M9 3a4 4 0 1 1 0 8 4 4 0 0 1 0-8zM22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75",
  backup: "M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M17 8l-5-5-5 5M12 3v12",
  help: "M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM9.1 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3M12 17h.01",
  logout: "M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9",
  search: "M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16zM21 21l-4.35-4.35",
  plus: "M12 5v14M5 12h14",
  x: "M18 6 6 18M6 6l12 12",
  check: "M20 6 9 17l-5-5",
  alert: "M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0zM12 9v4M12 17h.01",
  clock: "M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 6v6l4 2",
  refresh: "M23 4v6h-6M1 20v-6h6M3.5 9a9 9 0 0 1 14.9-3.4L23 10M1 14l4.6 4.4A9 9 0 0 0 20.5 15",
  copy: "M20 9h-9a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h9a2 2 0 0 0 2-2v-9a2 2 0 0 0-2-2zM5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1",
  trash: "M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6",
  edit: "M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7M18.5 2.5a2.12 2.12 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z",
  menu: "M3 12h18M3 6h18M3 18h18",
  chevronL: "M15 18l-6-6 6-6",
  chevronR: "M9 18l6-6-6-6",
  upload: "M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5-5 5 5M12 15V3",
  file: "M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6",
};

export function icon(name, size = 16) {
  const d = ICONS[name] || ICONS.alert;
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("width", size);
  svg.setAttribute("height", size);
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "2");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");
  // Split only at absolute moveto commands: splitting on any uppercase letter
  // cuts a path mid-command (e.g. "…V5l-8-3-8 3v7c0…") into segments that no
  // longer start with a moveto, which the browser rejects as an invalid path.
  for (const seg of d.split(/(?=M(?=\s*[-\d.]))/)) {
    if (!seg.trim()) continue;
    const p = document.createElementNS(ns, "path");
    p.setAttribute("d", seg.trim());
    svg.appendChild(p);
  }
  return svg;
}

/* ---------- element builder ---------- */
/**
 * el("div.panel", {onclick}, child1, child2) — fast, safe DOM construction.
 * Class shorthand in tag: "div.cls1.cls2". Text children are textContent.
 */
export function el(spec, attrs, ...children) {
  const [tag, ...classes] = spec.split(".");
  const node = document.createElement(tag);
  for (const c of classes) if (c) node.classList.add(c);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v === null || v === undefined || v === false) continue;
      if (k.startsWith("on") && typeof v === "function") node.addEventListener(k.slice(2), v);
      else if (k === "dataset") Object.assign(node.dataset, v);
      else if (k === "html") ; // never allow
      else if (v === true) node.setAttribute(k, "");
      else node.setAttribute(k, String(v));
    }
  }
  appendChildren(node, children);
  return node;
}

export function appendChildren(node, children) {
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    if (c instanceof Node) node.appendChild(c);
    else node.appendChild(document.createTextNode(String(c)));
  }
}

/* ---------- toasts ---------- */
export function toast(message, kind = "info", ms = 4200) {
  const host = document.getElementById("toasts");
  const t = el("div", { class: `toast ${kind === "ok" ? "ok" : kind === "err" ? "err" : ""}`, role: "status" },
    kind === "ok" ? icon("check", 15) : kind === "err" ? icon("alert", 15) : icon("activity", 15),
    el("span", {}, message),
    el("button", { class: "btn ghost sm t-close", "aria-label": "Dismiss", onclick: () => t.remove() }, icon("x", 13)),
  );
  host.appendChild(t);
  setTimeout(() => t.remove(), ms);
}

/* ---------- modal ---------- */
let activeModal = null;

export function openModal({ title, body, actions, wide, onClose }) {
  closeModal();
  const overlay = el("div", { class: "modal-overlay" });
  const closeBtn = el("button", { class: "btn ghost sm", "aria-label": "Close dialog", onclick: () => closeModal() }, icon("x", 14));
  const modal = el("div", { class: "modal" + (wide ? " wide" : ""), role: "dialog", "aria-modal": "true", "aria-label": title },
    el("div", { class: "modal-head" }, el("h2", {}, title), closeBtn),
    el("div", { class: "modal-body" }, body),
    actions && actions.length ? el("div", { class: "modal-foot" }, ...actions) : null,
  );
  overlay.appendChild(modal);
  overlay.addEventListener("mousedown", (e) => { if (e.target === overlay) closeModal(); });
  document.getElementById("modal-root").appendChild(overlay);
  const prevFocus = document.activeElement;
  activeModal = { overlay, onClose, prevFocus };
  const first = modal.querySelector("input, select, textarea, button.btn:not(.t-close):not(.ghost)");
  (first || closeBtn).focus();
  return modal;
}

export function closeModal() {
  if (!activeModal) return;
  const { overlay, onClose, prevFocus } = activeModal;
  activeModal = null;
  overlay.remove();
  if (onClose) onClose();
  if (prevFocus && prevFocus.focus) prevFocus.focus();
}

export function modalOpen() { return !!activeModal; }

/** Standard confirm dialog. Returns a promise<boolean>. */
export function confirmDialog({ title, message, danger, confirmLabel = "Confirm", requireText }) {
  return new Promise((resolve) => {
    const body = el("div", {},
      el("p", { class: "muted mt-0" }, message),
      requireText ? el("div", { class: "field mt-2" },
        el("label", {}, `Type "${requireText}" to confirm`),
        Object.assign(el("input", { class: "input", autocomplete: "off", spellcheck: "false" })),
      ) : null,
    );
    const input = body.querySelector("input");
    const done = (ok) => { closeModal(); resolve(ok); };
    const actions = [
      el("button", { class: "btn", onclick: () => done(false) }, "Cancel"),
      el("button", {
        class: "btn " + (danger ? "danger" : "primary"),
        disabled: !!requireText,
        onclick: () => done(true),
      }, confirmLabel),
    ];
    const m = openModal({ title, body, actions, onClose: () => resolve(false) });
    const btn = m.querySelector(".modal-foot .btn:last-child");
    if (input) {
      input.addEventListener("input", () => {
        btn.disabled = input.value.trim() !== requireText;
      });
      input.addEventListener("keydown", (e) => {
        if (e.key === "Enter" && !btn.disabled) done(true);
      });
    }
  });
}

/* ---------- copy chip ---------- */
export function copyChip(text, label = "Copy") {
  const btn = el("button", {
    class: "btn sm",
    "aria-label": label,
    onclick: async () => {
      const ok = await copyText(text);
      toast(ok ? "Copied to clipboard" : "Copy failed — select the text manually", ok ? "ok" : "err");
    },
  }, icon("copy", 13), label);
  return btn;
}

/* ---------- table helpers ---------- */
export function table(headers, rows) {
  const thead = el("thead", {}, el("tr", {}, ...headers.map((h) => el("th", { class: h.cls || "" }, h.label))));
  const tbody = el("tbody");
  for (const r of rows) tbody.appendChild(r);
  return el("div", { class: "table-wrap" }, el("table", { class: "tbl" }, thead, tbody));
}

export function statusPill(status) {
  const map = {
    active: "b-ok", ok: "b-ok", valid: "b-ok", configured: "b-ok",
    suspended: "b-warn", warn: "b-warn", warning: "b-warn", stale: "b-warn", unavailable: "b-warn", missing: "b-warn", invalid: "b-warn", malformed: "b-warn",
    revoked: "b-danger", expired: "b-danger", danger: "b-danger", denied: "b-danger", error: "b-danger", none: "b-mute", unknown: "b-mute",
  };
  const cls = map[String(status).toLowerCase()] || "b-mute";
  return el("span", { class: `badge ${cls}` }, el("span", { class: "dot" }), String(status));
}

export function pager({ total, limit, offset, truncated, onPage }) {
  const page = Math.floor(offset / limit) + 1;
  const pages = Math.max(1, Math.ceil(total / limit));
  return el("div", { class: "pager" },
    el("span", {}, `${total}${truncated ? "+" : ""} record${total === 1 ? "" : "s"}`, truncated ? el("span", { class: "faint small" }, " (scan cap reached — refine filters)") : null),
    el("span", { class: "grow" }),
    el("button", { class: "btn sm", disabled: offset === 0 ? "true" : null, "aria-label": "Previous page", onclick: () => onPage(Math.max(0, offset - limit)) }, icon("chevronL", 14)),
    el("span", {}, `Page ${page} / ${pages}`),
    el("button", { class: "btn sm", disabled: offset + limit >= total ? "true" : null, "aria-label": "Next page", onclick: () => onPage(offset + limit) }, icon("chevronR", 14)),
  );
}

export function skeletonRows(cols, rows = 5) {
  const out = [];
  for (let i = 0; i < rows; i++) {
    const tr = el("tr", {});
    for (let c = 0; c < cols; c++) tr.appendChild(el("td", {}, el("div", { class: "skeleton" })));
    out.push(tr);
  }
  return out;
}

export function emptyState(title, subtitle, icon_ = "file") {
  return el("div", { class: "empty" },
    icon(icon_, 30),
    el("h3", {}, title),
    subtitle ? el("p", { class: "small" }, subtitle) : null,
  );
}

/* ---------- form helpers ---------- */
export function field(labelText, inputEl, opts = {}) {
  const wrap = el("div", { class: "field" });
  const label = el("label", { for: inputEl.id || undefined }, labelText, opts.required ? el("span", { class: "req" }, " *") : null);
  wrap.appendChild(label);
  wrap.appendChild(inputEl);
  if (opts.hint) wrap.appendChild(el("div", { class: "field-hint" }, opts.hint));
  const err = el("div", { class: "field-error", role: "alert" });
  err.hidden = true;
  wrap.appendChild(err);
  wrap.setValidationError = (msg) => {
    err.textContent = msg || "";
    err.hidden = !msg;
    if (msg) inputEl.setAttribute("aria-invalid", "true");
    else inputEl.removeAttribute("aria-invalid");
  };
  return wrap;
}

/** Render API 422 details onto matching fields by name. */
export function applyFieldErrors(fields, details) {
  for (const d of details || []) {
    const f = fields[d.field];
    if (f) f.setValidationError(d.message);
  }
}

export function clearFieldErrors(fields) {
  for (const f of Object.values(fields)) f.setValidationError("");
}

export function input(attrs = {}) {
  return el("input", { class: "input", ...attrs });
}

export function select(options, attrs = {}) {
  const s = el("select", { class: "select", ...attrs });
  for (const o of options) {
    const opt = el("option", { value: o.value }, o.label);
    if (o.selected) opt.selected = true;
    s.appendChild(opt);
  }
  return s;
}

let uidCounter = 0;
export function withId(inputEl) {
  inputEl.id = "f" + (++uidCounter) + Date.now().toString(36);
  return inputEl;
}
