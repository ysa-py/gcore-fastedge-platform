// Admin accounts (roles) + explicit permission matrix.
import { api } from "../api.js";
import { el, icon, statusPill, table, field, input, select, withId, applyFieldErrors, clearFieldErrors, openModal, closeModal, confirmDialog, toast, emptyState } from "../ui.js";
import { fmtUtc } from "../utils.js";
import { has, state } from "../state.js";

export async function render(root, ctx) {
  const holder = el("div", {});
  const matrixHolder = el("div", { class: "panel" });
  root.replaceChildren(holder, el("div", { class: "mt-2" }, matrixHolder));

  const canManage = has("config:manage");

  async function load() {
    let admins, rolesInfo;
    try {
      [admins, rolesInfo] = await Promise.all([api.get("/api/admins"), api.get("/api/roles")]);
    } catch (e) {
      holder.replaceChildren(emptyState("Not available", e.message || "You may lack the required permission.", "roles"));
      return;
    }

    const rows = admins.admins.map((a) => {
      const tr = el("tr", {});
      const self = a.username === state.session?.username;
      tr.append(
        el("td", {}, el("div", { class: "flex" },
          el("div", { class: "avatar" }, a.username[0].toUpperCase()),
          el("div", {}, el("div", {}, a.username), el("div", { class: "small faint" }, "last login: " + (a.last_login_at ? fmtUtc(a.last_login_at) : "never"))),
        )),
        el("td", {}, statusPill(a.role)),
        el("td", { class: "small faint mono" }, fmtUtc(a.created_at)),
        el("td", {}, el("div", { class: "row-actions" },
          canManage && !self ? el("button", {
            class: "btn sm",
            onclick: () => openEditRole(a),
          }, icon("edit", 12), "Role") : null,
          canManage && !self ? el("button", {
            class: "btn sm",
            onclick: () => openResetPassword(a),
          }, icon("key", 12), "Password") : null,
          canManage && !self ? el("button", {
            class: "btn sm danger",
            onclick: async () => {
              const ok = await confirmDialog({
                title: `Delete administrator ${a.username}?`,
                message: "Their sessions survive until expiry (~minutes). At least one super_admin must remain.",
                danger: true,
                confirmLabel: "Delete admin",
                requireText: a.username.toUpperCase(),
              });
              if (!ok) return;
              try {
                await api.del("/api/admins/" + a.username);
                toast("Administrator deleted", "ok");
                load();
              } catch (e) { toast(e.message || "Delete failed", "err"); }
            },
          }, icon("trash", 12), "Delete") : null,
          self ? el("span", { class: "badge b-mute" }, "you") : null,
        )),
      );
      return tr;
    });

    holder.replaceChildren(
      el("div", { class: "panel" },
        el("div", { class: "panel-head" },
          el("h2", {}, "Administrator accounts"),
          el("span", { class: "hint" }, `${admins.admins.length} account${admins.admins.length === 1 ? "" : "s"}`),
          el("span", { class: "spacer" }),
          el("button", {
            class: "btn primary sm",
            disabled: canManage ? null : "true",
            onclick: openCreateAdmin,
          }, icon("plus", 13), "New admin"),
        ),
        el("div", { class: "table-wrap" }, table(
          [{ label: "Administrator" }, { label: "Role" }, { label: "Created" }, { label: "", cls: "num" }],
          rows.length ? rows : [el("tr", {}, el("td", { colspan: "4" }, emptyState("No admins listed", "", "roles")))],
        )),
      ),
    );

    const roleDescriptions = {};
    for (const r of rolesInfo.roles) roleDescriptions[r.role] = r.description;
    const permRows = rolesInfo.permissions.map((p) => {
      const tr = el("tr", {});
      tr.append(
        el("td", { class: "mono small" }, p.permission),
        ...["super_admin", "admin", "subscription_manager", "operator", "auditor"].map((role) =>
          el("td", {}, p.roles.includes(role) ? icon("check", 14) : el("span", { class: "faint" }, "—")),
        ),
      );
      return tr;
    });
    matrixHolder.replaceChildren(
      el("div", { class: "panel-head" }, el("h2", {}, "Permission matrix"),
        el("span", { class: "hint" }, "enforced server-side; the UI only mirrors it"),
        el("span", { class: "spacer" }),
        el("span", { class: "badge b-accent" }, "your role: " + rolesInfo.your_role)),
      el("div", { class: "table-wrap" }, table(
        [{ label: "Permission" }, { label: "Super admin" }, { label: "Admin" }, { label: "Sub manager" }, { label: "Operator" }, { label: "Auditor" }],
        permRows,
      )),
      el("div", { class: "panel-pad small muted" },
        el("ul", {}, ...rolesInfo.roles.map((r) => el("li", {}, el("strong", {}, r.role), " — " + r.description))),
      ),
    );
  }

  function roleSelect(current) {
    return select(
      ["super_admin", "admin", "subscription_manager", "operator", "auditor"].map((r) => ({ value: r, label: r, selected: r === current })),
    );
  }

  function openCreateAdmin() {
    const uI = withId(input({ autocomplete: "off", spellcheck: "false" }));
    const pI = withId(input({ type: "password", autocomplete: "new-password" }));
    const rI = roleSelect("auditor");
    const f = {
      username: field("Username", uI, { required: true, hint: "3–32 chars, lowercase." }),
      password: field("Password", pI, { required: true, hint: "At least 12 characters. Hashed with PBKDF2 at the edge." }),
      role: field("Role", rI),
    };
    openModal({
      title: "New administrator",
      body: el("div", {}, ...Object.values(f)),
      actions: [
        el("button", { class: "btn", onclick: closeModal }, "Cancel"),
        el("button", {
          class: "btn primary",
          onclick: async () => {
            clearFieldErrors(f);
            try {
              await api.post("/api/admins", { username: uI.value.trim(), password: pI.value, role: rI.value });
              toast("Administrator created", "ok");
              closeModal();
              load();
            } catch (e) {
              if (e.status === 422) applyFieldErrors(f, e.details);
              else toast(e.message || "Creation failed", "err");
            }
          },
        }, "Create"),
      ],
    });
  }

  function openEditRole(a) {
    const rI = roleSelect(a.role);
    const f = { role: field("Role", rI) };
    openModal({
      title: "Change role — " + a.username,
      body: el("div", {}, ...Object.values(f), el("div", { class: "note warn small" }, " Role changes take effect on the admin's next request. You cannot edit your own role.")),
      actions: [
        el("button", { class: "btn", onclick: closeModal }, "Cancel"),
        el("button", {
          class: "btn primary",
          onclick: async () => {
            try {
              await api.patch("/api/admins/" + a.username, { role: rI.value });
              toast("Role updated", "ok");
              closeModal();
              load();
            } catch (e) {
              if (e.status === 422) applyFieldErrors(f, e.details);
              else toast(e.message || "Update failed", "err");
            }
          },
        }, "Save"),
      ],
    });
  }

  function openResetPassword(a) {
    const pI = withId(input({ type: "password", autocomplete: "new-password" }));
    const f = { password: field("New password", pI, { required: true, hint: "At least 12 characters." }) };
    openModal({
      title: "Reset password — " + a.username,
      body: el("div", {}, ...Object.values(f)),
      actions: [
        el("button", { class: "btn", onclick: closeModal }, "Cancel"),
        el("button", {
          class: "btn primary",
          onclick: async () => {
            clearFieldErrors(f);
            try {
              await api.post(`/api/admins/${a.username}/password`, { password: pI.value });
              toast("Password reset", "ok");
              closeModal();
            } catch (e) {
              if (e.status === 422) applyFieldErrors(f, e.details);
              else toast(e.message || "Reset failed", "err");
            }
          },
        }, "Reset"),
      ],
    });
  }

  load();
}
