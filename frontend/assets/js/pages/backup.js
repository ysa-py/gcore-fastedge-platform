// Import / export / recovery tools. Two-phase import: dry-run first.
import { api } from "../api.js";
import { el, icon, toast, confirmDialog, statusPill, copyChip } from "../ui.js";
import { has, isRole } from "../state.js";

export async function render(root) {
  let lastExport = null;

  /* ---------- export card ---------- */
  const includeCreds = el("input", { type: "checkbox", id: "exp-creds" });
  const credsBox = el("label", { class: "checkbox-row small muted", for: "exp-creds" },
    includeCreds,
    el("span", {}, "Include credential fingerprints and token indexes (sensitive)"),
  );
  credsBox.hidden = !(has("config:manage") && isRole("super_admin"));
  const exportBtn = el("button", {
    class: "btn",
    disabled: has("export:run") ? null : "true",
    onclick: async () => {
      exportBtn.disabled = true;
      try {
        lastExport = await api.post("/api/export", { include_credentials: includeCreds.checked });
        toast(`Exported ${lastExport.count} user(s)${includeCreds.checked ? " (sensitive form)" : ""}`, "ok");
        renderExport();
      } catch (e) {
        toast(e.message || "Export failed", "err");
      } finally { exportBtn.disabled = has("export:run") ? false : true; }
    },
  }, icon("upload", 13), "Generate export");

  const exportResult = el("div", { class: "mt-2" });
  function renderExport() {
    if (!lastExport) { exportResult.replaceChildren(); return; }
    const blob = new Blob([JSON.stringify(lastExport, null, 2)], { type: "application/json" });
    const dl = el("a", { href: URL.createObjectURL(blob), download: `fastedge-export-${new Date().toISOString().slice(0, 10)}.json`, class: "btn sm" }, icon("file", 13), "Download JSON");
    exportResult.replaceChildren(
      el("div", { class: "panel-2 panel-pad" },
        el("div", { class: "flex" },
          el("span", { class: "badge b-ok" }, el("span", { class: "dot" }), `${lastExport.count} records`),
          lastExport.include_credentials ? el("span", { class: "badge b-danger" }, el("span", { class: "dot" }), "sensitive: includes fingerprints") : el("span", { class: "badge b-mute" }, "sanitized"),
          el("span", { class: "spacer" }),
          dl,
        ),
        el("p", { class: "small faint mt-1" }, "Generated " + lastExport.exported_at + " UTC. Raw tokens never appear in exports — only fingerprints at most."),
      ),
    );
  }

  const exportPanel = el("div", { class: "panel" },
    el("div", { class: "panel-head" }, el("h2", {}, "Export"), el("span", { class: "hint" }, "server-side sanitized by default")),
    el("div", { class: "panel-pad" },
      el("p", { class: "muted small mt-0" }, "Produces a complete users+subscriptions snapshot from Edge Storage. Credential hashes are excluded unless you explicitly opt in with a stepped-up super-admin session."),
      credsBox,
      el("div", { class: "flex mt-1" }, exportBtn),
      exportResult,
    ),
  );

  /* ---------- import card (dry-run then apply) ---------- */
  const fileIn = el("input", { type: "file", accept: "application/json,.json", class: "input" });
  const importBtn = el("button", { class: "btn primary", disabled: true }, icon("backup", 13), "Validate (dry run)");
  const applyBtn = el("button", { class: "btn danger", disabled: true }, icon("check", 13), "Apply import");
  const report = el("div", { class: "mt-2" });
  let payload = null;

  fileIn.addEventListener("change", async () => {
    report.replaceChildren();
    importBtn.disabled = !fileIn.files.length;
    applyBtn.disabled = true;
    payload = null;
  });

  importBtn.addEventListener("click", async () => {
    if (!fileIn.files.length) return;
    let parsed;
    try {
      parsed = JSON.parse(await fileIn.files[0].text());
    } catch {
      toast("The file is not valid JSON", "err");
      return;
    }
    if (!parsed || !Array.isArray(parsed.users)) {
      toast('The payload must be an object with a "users" array', "err");
      return;
    }
    importBtn.disabled = true;
    importBtn.textContent = "Validating…";
    try {
      const res = await api.post("/api/import", { options: { apply: false }, payload: parsed });
      payload = parsed;
      renderReport(res, false);
      applyBtn.disabled = !(res.planned_creates > 0) || !has("import:run");
      if (res.errors > 0 || res.skipped > 0) {
        toast("Dry run finished — review the report before applying", "warn");
      } else {
        toast(`Dry run OK — ${res.planned_creates} user(s) ready`, "ok");
      }
    } catch (e) {
      toast(e.message || "Dry run failed", "err");
    } finally {
      importBtn.disabled = false;
      importBtn.replaceChildren(icon("backup", 13), "Re-validate (dry run)");
    }
  });

  applyBtn.addEventListener("click", async () => {
    if (!payload) return;
    const ok = await confirmDialog({
      title: "Apply import?",
      message: "Records that passed validation will be written through the control plane in batches. Duplicate emails are skipped, never overwritten.",
      danger: true,
      confirmLabel: "Apply now",
    });
    if (!ok) return;
    applyBtn.disabled = true;
    try {
      const res = await api.post("/api/import", { options: { apply: true }, payload });
      renderReport(res, true);
      toast(`Imported ${res.created} user(s)`, "ok");
    } catch (e) {
      if (e.code === "STEP_UP_REQUIRED") toast("Re-authentication required for imports", "warn");
      else toast(e.message || "Apply failed", "err");
    }
  });

  function renderReport(res, applied) {
    const fmt = (n) => el("span", { class: "badge b-mute" }, String(n));
    const row = (r) => {
      const tr = el("tr", {});
      tr.append(
        el("td", { class: "small" }, String(r.index + 1)),
        el("td", { class: "small mono" }, r.email || "—"),
        el("td", {}, statusPill(r.result === "created" ? (applied ? "ok" : "info") : r.result)),
        el("td", { class: "small muted" }, (r.issues || []).join("; ") || "—"),
      );
      return tr;
    };
    report.replaceChildren(
      el("div", { class: "panel-2 panel-pad" },
        el("div", { class: "flex" },
          el("span", {}, "Planned creates: ", fmt(res.planned_creates)),
          el("span", {}, "Skipped: ", fmt(res.skipped)),
          el("span", {}, "Errors: ", fmt(res.errors)),
          applied ? el("span", { class: "badge b-ok" }, el("span", { class: "dot" }), "applied") : null,
        ),
        (res.rows || []).length ? el("div", { class: "table-wrap mt-1" }, el("table", { class: "tbl" },
          el("thead", {}, el("tr", {}, el("th", {}, "#"), el("th", {}, "Email"), el("th", {}, "Result"), el("th", {}, "Issues"))),
          el("tbody", {}, ...(res.rows || []).map(row)),
        )) : el("p", { class: "small faint mt-1" }, "No rows."),
      ),
    );
  }

  const importPanel = el("div", { class: "panel" },
    el("div", { class: "panel-head" }, el("h2", {}, "Import"), el("span", { class: "hint" }, "two-phase: dry-run report → apply")),
    el("div", { class: "panel-pad" },
      el("p", { class: "muted small mt-0" },
        'Expected shape: ', el("code", {}, '{"users": [{"email": "...", "display_name": "...", "expires_at": "2027-01-01T00:00:00Z", "entitlement_id": "..."}]}'),
        ". A subscription record is created for every imported user; credentials are never imported."),
      fileIn,
      el("div", { class: "flex mt-1" }, importBtn, applyBtn),
      report,
    ),
  );

  /* ---------- recovery notes ---------- */
  const recoveryPanel = el("div", { class: "panel" },
    el("div", { class: "panel-head" }, el("h2", {}, "Recovery playbook")),
    el("div", { class: "panel-pad small muted" },
      el("ol", {},
        el("li", {}, "Export a sanitized snapshot before risky bulk operations."),
        el("li", {}, "If a write fails mid-way, the import report identifies exactly which rows landed — re-running the same file skips already-created emails (idempotent by design)."),
        el("li", {}, "Emergency session kill: Config → “Revoke all sessions”."),
        el("li", {}, "Emergency credential kill: revoke the user's credential (rotates the version) — new exchanges die immediately."),
        el("li", {}, "Edge Storage has no point-in-time restore; the export file is the recovery medium. Store it outside the platform."),
      ),
      el("div", { class: "note warn mt-2" }, icon("alert", 12), " Imports do not touch credentials or admin accounts on purpose — those are separate trust domains."),
    ),
  );

  root.replaceChildren(el("div", { class: "grid-2" }, exportPanel, importPanel), el("div", { class: "mt-2" }, recoveryPanel));
}
