// Login screen.
import { api, ApiError } from "../api.js";
import { el, icon, field, input, withId, toast } from "../ui.js";
import { setSession } from "../state.js";

export function render(root, { navigate }) {
  const userInput = withId(input({ autocomplete: "username", spellcheck: "false", required: "" }));
  const passInput = withId(input({ type: "password", autocomplete: "current-password", required: "" }));
  const fields = { username: field("Username", userInput), password: field("Password", passInput) };
  const btn = el("button", { class: "btn primary", type: "submit" }, "Sign in");

  const form = el("form", {
    onsubmit: async (e) => {
      e.preventDefault();
      Object.values(fields).forEach((f) => f.setValidationError(""));
      btn.disabled = true;
      btn.textContent = "Signing in…";
      try {
        const s = await api.post("/api/auth/login", {
          username: userInput.value.trim(),
          password: passInput.value,
        });
        setSession(s);
        toast(`Welcome, ${s.username}`, "ok");
        navigate("#/");
      } catch (err) {
        if (err instanceof ApiError && err.details?.length) {
          err.details.forEach((d) => fields[d.field]?.setValidationError(d.message));
        }
        toast(err.status === 429 ? err.message : err.message || "Sign-in failed", err.status === 429 ? "warn" : "err");
        btn.disabled = false;
        btn.textContent = "Sign in";
      }
    },
  },
    fields.username,
    fields.password,
    el("div", { class: "mt-2" }, btn),
  );

  root.replaceChildren(
    el("div", { class: "login-wrap" },
      el("div", { class: "login-orb", "aria-hidden": "true" }),
      el("div", { class: "login-orb b", "aria-hidden": "true" }),
      el("div", { class: "login-card" },
        el("div", { class: "login-logo" },
          el("img", { src: "/assets/logo.svg", alt: "" }),
          el("div", {},
            el("h1", { class: "login-title" }, "FastEdge Admin"),
            el("p", { class: "login-sub" }, "Edge-native authorization platform"),
          ),
        ),
        el("div", { class: "panel panel-pad" },
          el("p", { class: "muted small mt-0" }, "Sign in with your administrator account. Sessions are short-lived, HttpOnly cookies."),
          form,
        ),
        el("p", { class: "small faint mt-2" },
          icon("shield", 12), " Two independent CSRF defenses protect every action on this console.",
        ),
      ),
    ),
  );
  userInput.focus();
}
