// Application configuration editor (server-side validated; step-up gated).
import { api } from "../api.js";
import { el, icon, field, input, withId, applyFieldErrors, clearFieldErrors, confirmDialog, toast } from "../ui.js";
import { has as hasPerm } from "../state.js";

export async function render(root) {
  let cfg;
  try {
    cfg = await api.get("/api/config");
  } catch (e) {
    root.replaceChildren(el("div", { class: "panel panel-pad" }, el("p", {}, e.message || "Failed to load configuration.")));
    return;
  }

  const mk = (label, hint, opts = {}) => {
    const i = withId(input({ type: "number", min: String(opts.min), max: String(opts.max), value: String(opts.value) }));
    return { input: i, wrap: field(label, i, { hint, required: true }) };
  };

  const F = {
    session_ttl_s: mk("Admin session TTL (s)", "300–86400. Cookie Max-Age matches.", { min: 300, max: 86400, value: cfg.session_ttl_s }),
    step_up_ttl_s: mk("Step-up window (s)", "60–3600. Destructive operations require a login inside this window.", { min: 60, max: 3600, value: cfg.step_up_ttl_s }),
    app_token_ttl_s: mk("App access-token TTL (s)", "60–3600. Short-lived tokens minted at exchange.", { min: 60, max: 3600, value: cfg.app_token_ttl_s }),
    login_max_attempts: mk("Login attempts per window", "1–100 failures before lockout.", { min: 1, max: 100, value: cfg.login_max_attempts }),
    login_window_s: mk("Login lockout window (s)", "60–86400.", { min: 60, max: 86400, value: cfg.login_window_s }),
    import_batch_max: mk("Import batch size", "1–100 records per control-plane write.", { min: 1, max: 100, value: cfg.import_batch_max }),
    audit_retention_days: mk("Audit retention (days)", "7–3650. Older events are pruned.", { min: 7, max: 3650, value: cfg.audit_retention_days }),
    pbkdf2_iterations: mk("PBKDF2 iterations (new hashes)", "10000–600000. Verification honors each stored hash's own parameters.", { min: 10000, max: 600000, value: cfg.pbkdf2_iterations }),
  };

  const save = el("button", {
    class: "btn primary",
    disabled: hasPerm("config:manage") ? null : "true",
    onclick: async () => {
      const ok = await confirmDialog({
        title: "Apply configuration?",
        message: "Values are validated server-side and versioned. New sessions and tokens pick the new limits up immediately.",
        confirmLabel: "Save configuration",
      });
      if (!ok) return;
      clearFieldErrors(Object.fromEntries(Object.entries(F).map(([k, v]) => [k, v.wrap])));
      const body = {};
      for (const [k, v] of Object.entries(F)) body[k] = parseInt(v.input.value, 10);
      try {
        const next = await api.put("/api/config", body);
        toast(`Configuration saved (version ${next.version})`, "ok");
        render(root);
      } catch (e) {
        if (e.status === 422) applyFieldErrors(Object.fromEntries(Object.entries(F).map(([k, v]) => [k, v.wrap])), e.details);
        else toast(e.message || "Save failed", "err");
      }
    },
  }, icon("check", 13), "Save configuration");

  root.replaceChildren(
    el("div", { class: "panel" },
      el("div", { class: "panel-head" },
        el("h2", {}, "Application configuration"),
        el("span", { class: "hint" }, `version ${cfg.version} · updated ${cfg.updated_at} by ${cfg.updated_by}`),
      ),
      el("div", { class: "panel-pad" },
        el("div", { class: "form-row" }, F.session_ttl_s.wrap, F.step_up_ttl_s.wrap),
        el("div", { class: "form-row" }, F.app_token_ttl_s.wrap, F.pbkdf2_iterations.wrap),
        el("div", { class: "form-row" }, F.login_max_attempts.wrap, F.login_window_s.wrap),
        el("div", { class: "form-row" }, F.import_batch_max.wrap, F.audit_retention_days.wrap),
        el("div", { class: "flex mt-2" }, save,
          hasPerm("config:manage") ? el("button", {
            class: "btn danger",
            onclick: async () => {
              const ok = await confirmDialog({
                title: "Revoke ALL sessions?",
                message: "Every administrator session — including this one — becomes invalid within seconds (session-epoch bump). You will need to sign in again.",
                danger: true,
                confirmLabel: "Revoke all sessions",
                requireText: "REVOKE",
              });
              if (!ok) return;
              try {
                await api.post("/api/auth/revoke-all", {});
                toast("All sessions revoked — redirecting to login", "ok");
                setTimeout(() => location.hash = "#/login", 600);
              } catch (e) { toast(e.message || "Failed", "err"); }
            },
          }, icon("logout", 13), "Revoke all sessions") : null,
        ),
        el("div", { class: "note mt-2 small" },
          icon("shield", 12), " Secrets (signing keys, API keys, admin bootstrap) are NOT part of this file — they live exclusively in the Gcore Secrets Manager."),
      ),
    ),
  );
}
