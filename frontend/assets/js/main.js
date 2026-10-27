// App bootstrap: hash router, shell, auth gate, step-up interception.
import { api, ApiError } from "./api.js";
import { el, icon, toast, openModal, closeModal, field, input, withId } from "./ui.js";
import { state, loadSession, logout, subscribe, has } from "./state.js";
import { fmtUtc } from "./utils.js";

const ROUTES = [
  { hash: "#/", title: "Dashboard", crumb: "Console", perm: null, icon: "dashboard", group: "Console", render: () => import("./pages/dashboard.js") },
  { hash: "#/users", title: "Users", crumb: "Access", perm: "users:read", icon: "users", group: "Access", render: () => import("./pages/users.js") },
  { hash: "#/subscriptions", title: "Subscriptions", crumb: "Access", perm: "subs:read", icon: "calendar", group: "Access", render: () => import("./pages/subscriptions.js") },
  { hash: "#/credentials", title: "Credentials", crumb: "Access", perm: "creds:read", icon: "key", group: "Access", render: () => import("./pages/credentials.js") },
  { hash: "#/audit", title: "Security & audit", crumb: "Governance", perm: "audit:read", icon: "shield", group: "Governance", render: () => import("./pages/audit.js") },
  { hash: "#/analytics", title: "Analytics", crumb: "Governance", perm: "metrics:read", icon: "activity", group: "Governance", render: () => import("./pages/analytics.js") },
  { hash: "#/config", title: "Configuration", crumb: "Platform", perm: "config:read", icon: "settings", group: "Platform", render: () => import("./pages/config.js") },
  { hash: "#/storage", title: "Storage & integrity", crumb: "Platform", perm: "system:read", icon: "database", group: "Platform", render: () => import("./pages/storage.js") },
  { hash: "#/system", title: "Health & diagnostics", crumb: "Platform", perm: "system:read", icon: "heartbeat", group: "Platform", render: () => import("./pages/system.js") },
  { hash: "#/roles", title: "Roles & permissions", crumb: "Administration", perm: null, icon: "roles", group: "Administration", render: () => import("./pages/roles.js") },
  { hash: "#/backup", title: "Backup & recovery", crumb: "Administration", perm: null, icon: "backup", group: "Administration", render: () => import("./pages/backup.js") },
  { hash: "#/help", title: "Help & API", crumb: "Administration", perm: null, icon: "help", group: "Administration", render: () => import("./pages/help.js") },
];

const app = document.getElementById("app");
const boot = document.getElementById("boot");
let navOpen = false;

function navigate(hash) {
  if (location.hash === hash) route();
  else location.hash = hash;
}

window.addEventListener("hashchange", route);

function matchRoute() {
  const h = location.hash || "#/";
  // exact match first
  let base = ROUTES.find((r) => r.hash === h);
  if (base) return { route: base, params: [] };
  // prefix match (e.g. #/users/uXXX)
  base = ROUTES.find((r) => h.startsWith(r.hash + "/"));
  if (base) return { route: base, params: h.slice(base.hash.length + 1).split("/") };
  return null;
}

async function route() {
  const matched = matchRoute();
  if (!state.session) {
    // Only the login screen renders without a session.
    document.querySelector(".shell")?.remove();
    (await import("./pages/login.js")).render(app, { navigate });
    return;
  }
  if (!matched) { navigate("#/"); return; }
  if (matched.route.perm && !has(matched.route.perm)) {
    renderShell(matched.route);
    const main = document.getElementById("main");
    main.replaceChildren(el("div", { class: "panel panel-pad" },
      el("h2", {}, "Not permitted"),
      el("p", { class: "muted small" }, `Your role (${state.session.role}) does not include the ${matched.route.perm} permission. The server enforces this too — this is not a UI-only gate.`),
    ));
    return;
  }
  renderShell(matched.route);
  const main = document.getElementById("main");
  const mod = await matched.route.render();
  mod.render(main, { navigate, route_params: matched.params });
}

function renderShell(activeRoute) {
  const existing = document.querySelector(".shell");
  if (existing) {
    updateActive(activeRoute);
    return;
  }
  const session = state.session;

  const nav = el("nav", { class: "nav", "aria-label": "Primary" });
  let lastGroup = "";
  for (const r of ROUTES) {
    if (r.perm && !has(r.perm)) continue;
    if (r.group !== lastGroup) {
      nav.appendChild(el("div", { class: "nav-group-title" }, r.group));
      lastGroup = r.group;
    }
    nav.appendChild(el("a", {
      class: "nav-item",
      href: r.hash,
      dataset: { route: r.hash },
      onclick: (e) => { e.preventDefault(); closeNav(); navigate(r.hash); },
    }, icon(r.icon), r.title));
  }

  const shell = el("div", { class: "shell" },
    el("aside", { class: "sidebar" },
      el("div", { class: "brand" },
        el("img", { src: "/assets/logo.svg", alt: "" }),
        el("div", {},
          el("div", { class: "brand-name" }, "FastEdge Admin"),
          el("div", { class: "brand-sub" }, "edge console"),
        ),
      ),
      nav,
      el("div", { class: "sidebar-footer" },
        el("div", { class: "session-card" },
          el("div", { class: "avatar" }, session.username[0].toUpperCase()),
          el("div", { class: "session-meta" },
            el("div", { class: "session-user" }, session.username),
            el("div", { class: "session-role" }, session.role + " · session ends " + fmtUtc(session.session_expires_at)),
          ),
          el("button", {
            class: "btn ghost sm",
            "aria-label": "Sign out",
            title: "Sign out",
            onclick: async () => { await logout(); navigate("#/login"); location.reload(); },
          }, icon("logout", 14)),
        ),
      ),
    ),
    el("div", { class: "main-col" },
      el("header", { class: "topbar" },
        el("button", {
          class: "btn ghost hamburger",
          "aria-label": "Toggle navigation",
          onclick: (e) => { navOpen = !navOpen; shell.classList.toggle("nav-open", navOpen); },
        }, icon("menu", 16)),
        el("div", {},
          el("h1", { id: "page-title" }, activeRoute.title),
          el("div", { class: "crumb", id: "page-crumb" }, activeRoute.crumb),
        ),
        el("div", { class: "topbar-actions" },
          el("span", { class: "badge " + (state.session.step_up_active ? "b-ok" : "b-mute"), title: state.session.step_up_active ? "Step-up active" : "Destructive operations will ask to re-authenticate" },
            el("span", { class: "dot" }), state.session.step_up_active ? "step-up active" : "read-only session"),
          el("a", { class: "btn sm", href: "#/help" }, icon("help", 13), "API & help"),
        ),
      ),
      el("main", { class: "content", id: "main", tabindex: "-1" }),
    ),
  );
  app.replaceChildren(shell);
  updateActive(activeRoute);
}

function updateActive(activeRoute) {
  document.getElementById("page-title").textContent = activeRoute.title;
  document.getElementById("page-crumb").textContent = activeRoute.crumb;
  document.querySelectorAll(".nav-item").forEach((a) => {
    a.classList.toggle("active", a.dataset.route === activeRoute.hash || location.hash.startsWith(a.dataset.route + "/"));
  });
}

function closeNav() {
  navOpen = false;
  document.querySelector(".shell")?.classList.remove("nav-open");
}

/* ---------- step-up interception ---------- */
// API errors with code STEP_UP_REQUIRED open a re-authentication dialog;
// the original action can then be retried by the user.
subscribe(() => { /* re-render chrome badges */ });

let stepUpPending = false;
window.addEventListener("unhandledrejection", (e) => {
  const err = e.reason;
  if (err instanceof ApiError && err.code === "STEP_UP_REQUIRED" && !stepUpPending) {
    e.preventDefault();
    openStepUp();
  }
});

// Patch fetch to catch step-up in-flight rather than relying on unhandled rejections.
const origFetch = window.fetch.bind(window);
window.fetch = async (...args) => {
  const resp = await origFetch(...args);
  if (resp.status === 403) {
    try {
      const clone = resp.clone();
      const body = await clone.json();
      if (body?.error?.code === "STEP_UP_REQUIRED" && !stepUpPending && state.session) {
        openStepUp();
      }
    } catch { /* not JSON */ }
  }
  return resp;
};

function openStepUp() {
  stepUpPending = true;
  const passI = withId(input({ type: "password", autocomplete: "current-password" }));
  const f = { password: field("Confirm your password", passI, { hint: "Grants step-up for the configured window (server enforces it)." }) };
  const btn = el("button", {
    class: "btn primary",
    onclick: async () => {
      try {
        const res = await api.post("/api/auth/stepup", { password: passI.value });
        await loadSession();
        toast("Step-up granted", "ok");
        closeModal();
        route();
      } catch (e) {
        toast(e.message || "Re-authentication failed", "err");
      }
    },
  }, "Re-authenticate");
  openModal({
    title: "Re-authentication required",
    body: el("div", {},
      el("p", { class: "muted small mt-0" }, "This operation is destructive, so the server requires proof that this is really you. Confirm your password to continue."),
      f.password),
    actions: [
      el("button", { class: "btn", onclick: closeModal }, "Cancel"),
      btn,
    ],
    onClose: () => { stepUpPending = false; },
  });
  passI.focus();
}

/* ---------- session refresh on demand ---------- */
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && document.querySelector(".modal-overlay")) closeModal();
  // Cmd/Ctrl+K focuses nothing yet; reserved for global search later.
});

/* ---------- boot ---------- */
(async function boot_app() {
  try {
    const s = await loadSession();
    boot.hidden = true;
    app.hidden = false;
    if (!s) {
      if ((location.hash || "") !== "#/login") location.hash = "#/login";
      else route();
    } else {
      route();
    }
  } catch (e) {
    boot.hidden = true;
    app.hidden = false;
    app.replaceChildren(el("div", { class: "panel panel-pad", style: "" },
      el("h2", {}, "Console failed to start"),
      el("p", { class: "muted" }, e.message || "The session endpoint is unreachable."),
    ));
    toast("Failed to load session state", "err");
  }
})();
