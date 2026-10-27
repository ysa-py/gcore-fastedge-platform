// User detail: profile, subscription, credentials, and destructive actions.
import { api } from "../api.js";
import { el, icon, statusPill, field, input, select, withId, applyFieldErrors, clearFieldErrors, openModal, closeModal, confirmDialog, toast, copyChip, emptyState } from "../ui.js";
import { fmtUtc } from "../utils.js";
import { has } from "../state.js";

export async function render(root, { navigate, route_params }) {
  const uid = route_params[0];
  root.replaceChildren(el("div", { class: "panel panel-pad" }, emptyState("Loading user…", "", "users")));

  let user;
  try {
    user = await api.get("/api/users/" + uid);
  } catch (e) {
    root.replaceChildren(emptyState("User not found", e.message || "This record does not exist or you lack permission to view it.", "users"));
    return;
  }

  const canManageUsers = has("users:manage");
  const canManageSubs = has("subs:manage");
  const canManageCreds = has("creds:manage");

  /* ---------- profile panel ---------- */
  const nameI = withId(input({ value: user.display_name }));
  const roleI = withId(select(["member", "premium", "service"].map((r) => ({ value: r, label: r })), { value: user.app_role }));
  const profileFields = {
    display_name: field("Display name", nameI),
    app_role: field("App role", roleI, { hint: "Application-facing claim (never an admin role)." }),
  };
  const saveProfile = el("button", {
    class: "btn primary",
    disabled: canManageUsers ? null : "true",
    onclick: async () => {
      clearFieldErrors(profileFields);
      try {
        await api.patch("/api/users/" + uid, { display_name: nameI.value.trim(), app_role: roleI.value });
        toast("Profile updated", "ok");
        render(root, { navigate, route_params: [uid] });
      } catch (e) {
        if (e.status === 422) applyFieldErrors(profileFields, e.details);
        else toast(e.message || "Update failed", "err");
      }
    },
  }, icon("edit", 13), "Save");

  const statusActions = el("div", { class: "flex" });
  const statusBtn = (action, label, danger) => el("button", {
    class: "btn sm " + (danger ? "danger" : ""),
    disabled: canManageUsers ? null : "true",
    onclick: async () => {
      const current = user.status;
      if (action === "revoke") {
        const ok = await confirmDialog({
          title: "Revoke user access?",
          message: `This permanently blocks ${user.email}. Revocation is terminal — it cannot be undone.`,
          danger: true,
          confirmLabel: "Revoke user",
          requireText: "REVOKE",
        });
        if (!ok) return;
      } else if (action === "suspend" && current === "suspended") {
        toast("User is already suspended");
        return;
      }
      try {
        await api.post(`/api/users/${uid}/status`, { action });
        toast(`User ${action} done`, "ok");
        render(root, { navigate, route_params: [uid] });
      } catch (e) {
        toast(e.message || "Status change failed", "err");
      }
    },
  }, label);
  if (user.status === "active") {
    statusActions.append(statusBtn("suspend", "Suspend access"));
    statusActions.append(statusBtn("revoke", "Revoke permanently", true));
  } else if (user.status === "suspended") {
    statusActions.append(statusBtn("reactivate", "Reactivate"));
    statusActions.append(statusBtn("revoke", "Revoke permanently", true));
  } else {
    statusActions.append(el("span", { class: "badge b-danger" }, el("span", { class: "dot" }), "terminal state"));
  }

  const profilePanel = el("div", { class: "panel" },
    el("div", { class: "panel-head" },
      el("h2", {}, "Profile"),
      el("span", { class: "badge " + (user.status === "active" ? "b-ok" : user.status === "suspended" ? "b-warn" : "b-danger") }, el("span", { class: "dot" }), user.status),
      el("span", { class: "spacer" }),
      el("button", { class: "btn ghost sm", "aria-label": "Back to users", onclick: () => navigate("#/users") }, icon("chevronL", 14), "Users"),
    ),
    el("div", { class: "panel-pad" },
      el("dl", { class: "kv" },
        el("dt", {}, "User ID"), el("dd", {}, el("span", { class: "mono-chip" }, user.uid), " ", copyChip(user.uid, "Copy")),
        el("dt", {}, "Email"), el("dd", {}, user.email),
        el("dt", {}, "Cred version"), el("dd", {}, String(user.cred_version), el("span", { class: "faint small" }, "  (bumping invalidates old tokens)")),
        el("dt", {}, "Created"), el("dd", {}, fmtUtc(user.created_at)),
        el("dt", {}, "Updated"), el("dd", {}, fmtUtc(user.updated_at)),
      ),
      el("hr", { class: "divider" }),
      ...Object.values(profileFields),
      el("div", { class: "flex" }, saveProfile, el("span", { class: "spacer" }), statusActions),
    ),
  );

  /* ---------- subscription panel ---------- */
  const sub = user.subscription;
  const subPanel = el("div", { class: "panel" },
    el("div", { class: "panel-head" },
      el("h2", {}, "Subscription"),
      sub ? statusPill(sub.derived_status) : statusPill("none"),
      el("span", { class: "spacer" }),
    ),
    el("div", { class: "panel-pad" },
      sub ? el("dl", { class: "kv" },
        el("dt", {}, "Subscription ID"), el("dd", {}, el("span", { class: "mono-chip" }, sub.sub_id)),
        el("dt", {}, "Entitlement"), el("dd", {}, sub.entitlement_id),
        el("dt", {}, "Expires (UTC)"), el("dd", {}, sub.expires_at ? sub.expires_at.replace("T", " ") + " — access rejects at now >= exp" : "no expiry"),
        el("dt", {}, "History entries"), el("dd", {}, String(sub.history_count)),
      ) : el("p", { class: "muted small" }, "No subscription record. Access decisions fail closed."),
      el("div", { class: "flex mt-2" },
        canManageSubs ? el("button", {
          class: "btn",
          onclick: () => openSubscriptionEditor(user, sub, () => render(root, { navigate, route_params: [uid] })),
        }, icon("calendar", 13), "Edit subscription") : null,
        canManageSubs ? el("button", {
          class: "btn",
          onclick: () => openRenew(user, () => render(root, { navigate, route_params: [uid] })),
        }, icon("refresh", 13), "Renew") : null,
      ),
    ),
  );

  /* ---------- credentials panel ---------- */
  const credsPanel = el("div", { class: "panel" },
    el("div", { class: "panel-head" },
      el("h2", {}, "Credentials"),
      el("span", { class: "hint" }, "shown once · SHA-256 fingerprints only"),
      el("span", { class: "spacer" }),
      el("button", {
        class: "btn primary sm",
        disabled: canManageCreds ? null : "true",
        onclick: () => openIssueCredential(user, () => render(root, { navigate, route_params: [uid] })),
      }, icon("key", 13), "Issue credential"),
    ),
    el("div", { class: "panel-pad" },
      (user.credentials || []).length === 0
        ? emptyState("No credentials yet", "Issue a long-lived API token to enable programmatic access.", "key")
        : el("div", { class: "flex" }, ...user.credentials.map((c) =>
            el("div", { class: "panel-2 panel-pad", style: "" },
              el("div", { class: "flex" },
                el("span", { class: "mono-chip" }, c.fingerprint + "…"),
                c.revoked_at ? statusPill("revoked") : statusPill("active"),
                el("span", { class: "spacer" }),
                !c.revoked_at && canManageCreds ? el("button", {
                  class: "btn sm danger",
                  onclick: async () => {
                    const ok = await confirmDialog({
                      title: "Revoke credential?",
                      message: "The token stops working immediately for new exchanges, and previously issued access tokens die within seconds (credential version rotation).",
                      danger: true,
                      confirmLabel: "Revoke credential",
                    });
                    if (!ok) return;
                    try {
                      await api.del(`/api/users/${uid}/credentials/${c.cred_id}`);
                      toast("Credential revoked", "ok");
                      render(root, { navigate, route_params: [uid] });
                    } catch (e) { toast(e.message || "Revoke failed", "err"); }
                  },
                }, icon("trash", 12), "Revoke") : null,
              ),
              el("dl", { class: "kv small mt-1" },
                el("dt", {}, "ID"), el("dd", {}, el("span", { class: "mono-chip" }, c.cred_id)),
                el("dt", {}, "Issued"), el("dd", {}, fmtUtc(c.issued_at)),
                el("dt", {}, "Expires"), el("dd", {}, c.expires_at ? fmtUtc(c.expires_at) : "no expiry"),
                c.label ? el("dt", {}, "Label") : el("dt", {}, "Label"), el("dd", {}, c.label || "—"),
              ),
            ),
          )),
      el("div", { class: "note mt-2 small" },
        icon("info", 12), " Exchange flow: POST /api/v1/token {\"token\": \"sk_live_…\"} → short-lived signed access token (default 300 s) → use as Bearer on /api/v1/*."),
    ),
  );

  root.replaceChildren(
    el("div", { class: "grid-2" }, profilePanel, subPanel),
    el("div", { class: "mt-2" }, credsPanel),
  );
}

/* ---------- subscription editor modal ---------- */
function openSubscriptionEditor(user, sub, onDone) {
  const statusI = withId(select([
    { value: "active", label: "active" },
    { value: "suspended", label: "suspended" },
    { value: "revoked", label: "revoked (terminal)" },
  ], { value: sub ? sub.status : "active" }));
  const entI = withId(input({ value: sub ? sub.entitlement_id : "ent-basic" }));
  const expI = withId(input({ type: "datetime-local", step: "1" }));
  const clearExp = withId(input({ type: "checkbox" }));
  const fields = {
    status: field("Status", statusI),
    entitlement_id: field("Entitlement", entI),
    expires_at: field("Expiration", expI, { hint: "Local input; stored as absolute UTC. Leave empty to keep the current value." }),
  };
  openModal({
    title: "Edit subscription — " + user.email,
    body: el("div", {},
      ...Object.values(fields),
      el("label", { class: "checkbox-row small muted", for: clearExp.id },
        clearExp, el("span", {}, "Clear expiration entirely (never expires)")),
    ),
    actions: [
      el("button", { class: "btn", onclick: closeModal }, "Cancel"),
      el("button", {
        class: "btn primary",
        onclick: async () => {
          clearFieldErrors(fields);
          const body = {};
          if (statusI.value !== (sub ? sub.status : null)) body.status = statusI.value;
          if (entI.value.trim() !== (sub ? sub.entitlement_id : null)) body.entitlement_id = entI.value.trim();
          if (clearExp.checked) body.expires_at = null;
          else if (expI.value) body.expires_at = new Date(expI.value).toISOString();
          if (!Object.keys(body).length) { toast("Nothing to change"); return; }
          try {
            await api.put(`/api/users/${user.uid}/subscription`, body);
            toast("Subscription updated", "ok");
            closeModal();
            onDone();
          } catch (e) {
            if (e.status === 422) applyFieldErrors(fields, e.details);
            else toast(e.message || "Update failed", "err");
          }
        },
      }, "Save subscription"),
    ],
  });
}

/* ---------- renew modal ---------- */
function openRenew(user, onDone) {
  const daysI = withId(input({ type: "number", min: "1", max: "3650", placeholder: "30" }));
  const absI = withId(input({ type: "datetime-local", step: "1" }));
  const fields = {
    extend_days: field("Extend by (days)", daysI, { hint: "Extends from max(now, current expiry)." }),
    until: field("Or set absolute instant", absI, { hint: "Local input → stored as UTC. Wins if both are filled." }),
  };
  openModal({
    title: "Renew subscription — " + user.email,
    body: el("div", {}, ...Object.values(fields)),
    actions: [
      el("button", { class: "btn", onclick: closeModal }, "Cancel"),
      el("button", {
        class: "btn primary",
        onclick: async () => {
          clearFieldErrors(fields);
          const body = {};
          if (absI.value) body.until = new Date(absI.value).toISOString();
          else if (daysI.value) body.extend_days = parseInt(daysI.value, 10);
          else { fields.extend_days.setValidationError("Provide days or an absolute instant."); return; }
          try {
            const s = await api.post(`/api/users/${user.uid}/subscription/renew`, body);
            toast(`Renewed — expires ${s.expires_at || "never"}`, "ok");
            closeModal();
            onDone();
          } catch (e) {
            if (e.status === 422) applyFieldErrors(fields, e.details);
            else toast(e.message || "Renew failed", "err");
          }
        },
      }, "Renew"),
    ],
  });
}

/* ---------- credential issuance modal (shows the raw token ONCE) ---------- */
function openIssueCredential(user, onDone) {
  const labelI = withId(input({ placeholder: "e.g. ci-pipeline", maxlength: "64" }));
  const ttlI = withId(input({ type: "number", min: "60", placeholder: "never expires" }));
  const fields = {
    label: field("Label (optional)", labelI),
    ttl_s: field("Credential lifetime seconds (optional)", ttlI, { hint: "60–31536000. Leave empty for no expiry." }),
  };
  openModal({
    title: "Issue credential — " + user.email,
    body: el("div", {}, ...Object.values(fields),
      el("div", { class: "note warn small" },
        icon("alert", 12), " The raw token is shown exactly ONCE, here. It is stored only as a SHA-256 fingerprint — even administrators cannot recover it later."),
    ),
    actions: [
      el("button", { class: "btn", onclick: closeModal }, "Cancel"),
      el("button", {
        class: "btn primary",
        onclick: async () => {
          clearFieldErrors(fields);
          const body = {};
          if (labelI.value.trim()) body.label = labelI.value.trim();
          if (ttlI.value) body.ttl_s = parseInt(ttlI.value, 10);
          try {
            const res = await api.post(`/api/users/${user.uid}/credentials`, body);
            const token = res.credential.token;
            openModal({
              title: "Credential created — copy it now",
              body: el("div", {},
                el("p", { class: "muted small mt-0" }, "This value will never be displayed again."),
                el("div", { class: "panel-2 panel-pad" },
                  el("div", { class: "flex" },
                    el("code", { class: "mono small" }, token),
                  ),
                  el("div", { class: "flex mt-1" }, copyChip(token, "Copy token")),
                ),
                el("p", { class: "faint small" }, "Fingerprint: " + res.credential.fingerprint + "…"),
              ),
              actions: [el("button", { class: "btn primary", onclick: () => { closeModal(); onDone(); } }, "Done — I saved it")],
            });
          } catch (e) {
            if (e.status === 422) applyFieldErrors(fields, e.details);
            else toast(e.message || "Issuance failed", "err");
          }
        },
      }, "Issue"),
    ],
  });
}
