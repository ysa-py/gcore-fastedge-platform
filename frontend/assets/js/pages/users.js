// Users list + creation drawer.
import { api } from "../api.js";
import { el, icon, table, statusPill, pager, field, input, select, withId, applyFieldErrors, clearFieldErrors, openModal, closeModal, confirmDialog, toast, emptyState, skeletonRows } from "../ui.js";
import { fmtUtc } from "../utils.js";
import { has } from "../state.js";

const PER_PAGE = 25;
let lastQuery = { q: "", status: "", offset: 0 };

export async function render(root, { navigate }) {
  const search = input({ value: lastQuery.q, placeholder: "Search email, name, or id…", "aria-label": "Search users" });
  const statusSel = select([
    { value: "", label: "All statuses" },
    { value: "active", label: "Active" },
    { value: "suspended", label: "Suspended" },
    { value: "revoked", label: "Revoked" },
  ], { value: lastQuery.status });
  const refreshBtn = el("button", { class: "btn", "aria-label": "Refresh", onclick: () => load() }, icon("refresh", 14));

  const listPanel = el("div", { class: "panel" }, el("div", { class: "table-wrap" },
    table([{ label: "User" }, { label: "Status" }, { label: "Subscription" }, { label: "Expires (UTC)" }, { label: "Credentials" }, { label: "Created" }], skeletonRows(6)),
  ));

  const createBtn = el("button", {
    class: "btn primary",
    disabled: has("users:manage") ? null : "true",
    title: has("users:manage") ? "" : "Requires users:manage",
    onclick: openCreate,
  }, icon("plus", 14), "New user");

  root.replaceChildren(
    el("div", { class: "toolbar" },
      el("div", { class: "search" }, icon("search", 15), search),
      statusSel,
      refreshBtn,
      el("span", { class: "grow" }),
      createBtn,
    ),
    listPanel,
  );

  let searchTimer;
  search.addEventListener("input", () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => { lastQuery.q = search.value; lastQuery.offset = 0; load(); }, 280);
  });
  statusSel.addEventListener("change", () => { lastQuery.status = statusSel.value; lastQuery.offset = 0; load(); });

  async function load() {
    const params = new URLSearchParams({ limit: String(PER_PAGE), offset: String(lastQuery.offset), sort: "newest" });
    if (lastQuery.q) params.set("q", lastQuery.q);
    if (lastQuery.status) params.set("status", lastQuery.status);
    try {
      const data = await api.get("/api/users?" + params.toString());
      const rows = data.users.map((u) => {
        const tr = el("tr", { class: "clickable", onclick: () => navigate("#/users/" + u.uid) });
        tr.append(
          el("td", {},
            el("div", { class: "flex" },
              el("div", { class: "avatar" }, (u.display_name || u.email)[0].toUpperCase()),
              el("div", {},
                el("div", {}, u.display_name || "—"),
                el("div", { class: "small faint" }, u.email),
              ),
            ),
          ),
          el("td", {}, statusPill(u.status)),
          el("td", {}, u.subscription ? statusPill(u.subscription.derived_status) : statusPill("none")),
          el("td", { class: "small mono" }, u.subscription?.expires_at ? u.subscription.expires_at.replace("T", " ") : "—"),
          el("td", {}, String((u.credentials || []).filter((c) => !c.revoked_at).length)),
          el("td", { class: "small faint mono" }, fmtUtc(u.created_at)),
        );
        return tr;
      });
      listPanel.replaceChildren(
        el("div", { class: "table-wrap" }, table(
          [{ label: "User" }, { label: "Status" }, { label: "Subscription" }, { label: "Expires (UTC)" }, { label: "Credentials" }, { label: "Created" }],
          rows,
        )),
        pager({ total: data.total, limit: data.limit, offset: data.offset, truncated: data.truncated, onPage: (off) => { lastQuery.offset = off; load(); } }),
      );
      if (!data.users.length) {
        listPanel.appendChild(el("div", { class: "empty" }, emptyState("No users match", "Adjust the filters or create a new user.", "users")));
      }
    } catch (e) {
      toast(e.message || "Failed to load users", "err");
    }
  }
  load();

  function openCreate() {
    const emailI = withId(input({ type: "email", autocomplete: "off", required: "" }));
    const nameI = withId(input({ required: "" }));
    const roleI = withId(select([
      { value: "member", label: "member" },
      { value: "premium", label: "premium" },
      { value: "service", label: "service" },
    ]));
    const entI = withId(input({ value: "ent-basic", required: "" }));
    const expI = withId(input({ type: "datetime-local", step: "1" }));
    // Live local→UTC preview so nobody misreads the stored instant.
    const utcPreview = el("div", { class: "field-hint mono" });
    const updatePreview = () => {
      utcPreview.textContent = expI.value
        ? "Will be stored as: " + new Date(expI.value).toISOString()
        : "Stored as an absolute UTC instant.";
    };
    expI.addEventListener("input", updatePreview);
    updatePreview();
    const f = {
      email: field("Email", emailI, { required: true, hint: "Lowercased and used as the unique identity index." }),
      display_name: field("Display name", nameI, { required: true }),
      app_role: field("App role", roleI, { hint: "Application-facing role embedded in access tokens (never an admin role)." }),
      entitlement_id: field("Entitlement", entI, { required: true }),
      expires_at: (function () {
        const wrap = field("Expiration", expI, { hint: "Entered in your local timezone; stored as the absolute UTC instant shown below." });
        wrap.appendChild(utcPreview);
        return wrap;
      })(),
    };
    const btn = el("button", {
      class: "btn primary",
      onclick: async () => {
        clearFieldErrors(f);
        const body = {
          email: emailI.value.trim(),
          display_name: nameI.value.trim(),
          app_role: roleI.value,
          entitlement_id: entI.value.trim(),
        };
        if (expI.value) body.expires_at = new Date(expI.value).toISOString(); // local input → true UTC instant
        try {
          const user = await api.post("/api/users", body);
          toast(`User ${user.email} created`, "ok");
          closeModal();
          navigate("#/users/" + user.uid);
        } catch (e) {
          if (e.status === 422) applyFieldErrors(f, e.details);
          else toast(e.message || "Creation failed", "err");
        }
      },
    }, "Create user");
    openModal({
      title: "New user",
      body: el("div", {}, ...Object.values(f), el("div", { class: "note mt-1" }, "A subscription record is created together with the user. Credentials are issued separately on the user page.")),
      actions: [el("button", { class: "btn", onclick: closeModal }, "Cancel"), btn],
    });
  }
}

export const staleHint = "Users page — client-side filters call the paginated server API.";
