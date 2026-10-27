//! User, subscription, credential, import/export, config, and admin-account
//! workflow tests against the full HTTP pipeline.

mod common;

use common::*;

#[test]
fn user_crud_and_validation_flow() {
    let h = Harness::new();
    let cookie = h.step_up(&h.login());

    // Create.
    let created = h.create_user(&cookie, "alice@example.io", Some("2100-01-01T00:00:00Z"));
    let uid = created["uid"].as_str().unwrap().to_string();
    assert!(uid.starts_with('u') && uid.len() == 27);
    assert_eq!(created["status"], "active");
    assert_eq!(created["subscription"]["status"], "active");

    // Duplicate email (case/whitespace normalized) → conflict.
    let dup = h.post_json(
        "/api/users",
        Some(&cookie),
        &serde_json::json!({
            "email": "  Alice@Example.IO ", "display_name": "Dup",
        }),
    );
    assert_eq!(dup.status, 409);
    assert_eq!(error_code(&dup), "CONFLICT");

    // Invalid email + name + past expiry → all field errors at once.
    let invalid = h.post_json(
        "/api/users",
        Some(&cookie),
        &serde_json::json!({
            "email": "not-an-email", "display_name": "bad\nname",
            "expires_at": "2020-01-01T00:00:00Z",
        }),
    );
    assert_eq!(invalid.status, 422);
    let fields: Vec<String> = json_of(&invalid)["error"]["details"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["field"].as_str().unwrap().to_string())
        .collect();
    for expected in ["email", "display_name", "expires_at"] {
        assert!(
            fields.contains(&expected.to_string()),
            "missing {expected} in {fields:?}"
        );
    }

    // Unknown fields are rejected (strict input schema).
    let sneaky = h.post_json(
        "/api/users",
        Some(&cookie),
        &serde_json::json!({
            "email": "sneak@example.io", "display_name": "Sneaky", "admin_role": "super_admin",
        }),
    );
    assert_eq!(sneaky.status, 400);

    // Patch metadata.
    let patched = h.patch_json(
        &format!("/api/users/{uid}"),
        &cookie,
        &serde_json::json!({"display_name": "Alice the Admin"}),
    );
    assert_eq!(patched.status, 200);
    assert_eq!(json_of(&patched)["display_name"], "Alice the Admin");
    // A user can never escalate to an admin role through metadata:
    assert_eq!(json_of(&patched)["app_role"], "member");

    // Detail read.
    let detail = h.get_auth(&format!("/api/users/{uid}"), &cookie);
    assert_eq!(detail.status, 200);
    assert_eq!(json_of(&detail)["email"], "alice@example.io");
}

#[test]
fn listing_pagination_sort_and_search() {
    let h = Harness::new();
    let cookie = h.step_up(&h.login());
    for i in 0..7 {
        h.create_user(&cookie, &format!("user{i:02}@example.io"), None);
    }
    // Page 1: default limit 25 → all users, total 7.
    let page = h.get_auth("/api/users?limit=3&offset=0&sort=newest", &cookie);
    assert_eq!(page.status, 200);
    let body = json_of(&page);
    assert_eq!(body["total"], 7);
    assert_eq!(body["users"].as_array().unwrap().len(), 3);
    assert_eq!(body["limit"], 3);
    assert_eq!(body["offset"], 0);

    // Newest first: UID order must be descending by creation.
    let uids: Vec<String> = body["users"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["uid"].as_str().unwrap().to_string())
        .collect();
    let sorted = {
        let mut v = uids.clone();
        v.sort();
        v.reverse();
        v
    };
    assert_eq!(uids, sorted, "newest-first ordering must hold");

    // Search filter.
    let found = h.get_auth("/api/users?q=user03", &cookie);
    assert_eq!(json_of(&found)["total"], 1);
    // Status filter.
    let none_revoked = h.get_auth("/api/users?status=revoked", &cookie);
    assert_eq!(json_of(&none_revoked)["total"], 0);
    // Invalid status value.
    let bad = h.get_auth("/api/users?status=weird", &cookie);
    assert_eq!(bad.status, 400);
    // Out-of-range limit.
    let badlimit = h.get_auth("/api/users?limit=1000", &cookie);
    assert_eq!(badlimit.status, 422);
}

#[test]
fn subscription_lifecycle_and_history() {
    let h = Harness::new();
    let cookie = h.step_up(&h.login());
    let user = h.create_user(&cookie, "subs@example.io", Some("2100-06-01T00:00:00Z"));
    let uid = user["uid"].as_str().unwrap().to_string();

    // Renew by 30 days from the current expiry (not from now).
    let renew = h.post_json(
        &format!("/api/users/{uid}/subscription/renew"),
        Some(&cookie),
        &serde_json::json!({"extend_days": 30}),
    );
    assert_eq!(renew.status, 200);
    assert_eq!(json_of(&renew)["expires_at"], "2100-07-01T00:00:00Z");

    // Absolute renewal.
    let abs = h.post_json(
        &format!("/api/users/{uid}/subscription/renew"),
        Some(&cookie),
        &serde_json::json!({"until": "2101-01-01T00:00:00Z"}),
    );
    assert_eq!(abs.status, 200);
    assert_eq!(json_of(&abs)["expires_at"], "2101-01-01T00:00:00Z");

    // Suspend the subscription (user stays active; entitlement dies).
    let sus = h.put_json(
        &format!("/api/users/{uid}/subscription"),
        &cookie,
        &serde_json::json!({"status": "suspended"}),
    );
    assert_eq!(sus.status, 200);
    assert_eq!(json_of(&sus)["derived_status"], "suspended");

    // Revoke is terminal.
    let rv = h.put_json(
        &format!("/api/users/{uid}/subscription"),
        &cookie,
        &serde_json::json!({"status": "revoked"}),
    );
    assert_eq!(rv.status, 200);
    let touch = h.put_json(
        &format!("/api/users/{uid}/subscription"),
        &cookie,
        &serde_json::json!({"expires_at": "2102-01-01T00:00:00Z"}),
    );
    assert_eq!(touch.status, 409, "revoked subscription must be immutable");

    // History is bounded and recorded.
    let detail = json_of(&h.get_auth(&format!("/api/users/{uid}"), &cookie));
    assert!(detail["subscription"]["history_count"].as_u64().unwrap() >= 3);

    // Clearing expiry requires a valid null.
    let user2 = h.create_user(&cookie, "subs2@example.io", Some("2100-06-01T00:00:00Z"));
    let uid2 = user2["uid"].as_str().unwrap().to_string();
    let clear = h.put_json(
        &format!("/api/users/{uid2}/subscription"),
        &cookie,
        &serde_json::json!({"expires_at": null}),
    );
    assert_eq!(clear.status, 200);
    assert!(json_of(&clear)["expires_at"].is_null());
}

#[test]
fn bulk_operations_report_per_record_outcomes() {
    let h = Harness::new();
    let cookie = h.step_up(&h.login());
    let mut uids = Vec::new();
    for i in 0..3 {
        let u = h.create_user(&cookie, &format!("bulk{i}@example.io"), None);
        uids.push(u["uid"].as_str().unwrap().to_string());
    }
    uids.push("uDOESNOTEXIST000000000000000".to_string());
    uids.push("bad id!".to_string());

    let stepped = h.step_up(&cookie);
    let resp = h.post_json(
        "/api/bulk",
        Some(&stepped),
        &serde_json::json!({"action": "renew", "uids": uids, "extend_days": 14}),
    );
    assert_eq!(resp.status, 200);
    let body = json_of(&resp);
    assert_eq!(body["ok"], 3);
    assert_eq!(body["total"], 5);
    let results = body["results"].as_array().unwrap();
    assert_eq!(results[0]["outcome"], "ok");
    assert_eq!(results[3]["outcome"], "error");
    assert_eq!(results[4]["outcome"], "error");
    assert_eq!(results[4]["reason"], "invalid_id");

    // Suspended/revoked state machine applies per record.
    let suspend = h.post_json(
        "/api/bulk",
        Some(&stepped),
        &serde_json::json!({"action": "suspend", "uids": body["results"].as_array().unwrap().iter()
            .filter(|r| r["outcome"] == "ok")
            .map(|r| r["uid"].clone()).collect::<Vec<_>>()}),
    );
    assert_eq!(suspend.status, 200);
    assert_eq!(json_of(&suspend)["ok"], 3);
}

#[test]
fn import_dry_run_validates_and_apply_persists() {
    let h = Harness::new();
    let cookie = h.step_up(&h.login());
    let stepped = h.step_up(&cookie);

    let payload = serde_json::json!({
        "users": [
            {"email": "imp1@example.io", "display_name": "Import One", "expires_at": "2100-01-01T00:00:00Z", "entitlement_id": "ent-import"},
            {"email": "imp2@example.io", "display_name": "Import Two"},
            {"email": "already@example.io", "display_name": "Existing"},
        ]
    });
    // Pre-create the conflicting user.
    h.create_user(&cookie, "already@example.io", None);

    let dry = h.post_json(
        "/api/import",
        Some(&stepped),
        &serde_json::json!({
            "options": {"apply": false}, "payload": payload,
        }),
    );
    assert_eq!(dry.status, 200);
    let dry_body = json_of(&dry);
    assert_eq!(dry_body["applied"], false);
    assert_eq!(dry_body["planned_creates"], 2);
    assert_eq!(dry_body["skipped"], 1);
    assert_eq!(dry_body["errors"], 0);
    // Nothing was written.
    assert_eq!(
        json_of(&h.get_auth("/api/users?limit=100", &cookie))["total"],
        1
    );

    let apply = h.post_json(
        "/api/import",
        Some(&stepped),
        &serde_json::json!({
            "options": {"apply": true}, "payload": payload,
        }),
    );
    assert_eq!(apply.status, 200);
    assert_eq!(json_of(&apply)["created"], 2);
    assert_eq!(
        json_of(&h.get_auth("/api/users?limit=100", &cookie))["total"],
        3
    );
}

#[test]
fn export_sanitized_by_default_and_credentials_with_super_admin_stepup() {
    let h = Harness::new();
    let cookie = h.step_up(&h.login());
    let user = h.create_user(&cookie, "exp@example.io", None);
    let uid = user["uid"].as_str().unwrap().to_string();
    let raw = h.issue_credential(&cookie, &uid);

    // Default export contains no token hashes and never the raw token.
    let plain = json_of(&h.post_json("/api/export", Some(&cookie), &serde_json::json!({})));
    let plain_s = plain.to_string();
    assert!(!plain_s.contains(&raw));
    assert!(!plain_s.contains("token_hash"));

    // include_credentials without step-up → falls back to sanitized but the
    // response must not leak hashes.
    let plain = h.login();
    let no_step = json_of(&h.post_json(
        "/api/export",
        Some(&plain),
        &serde_json::json!({"include_credentials": true}),
    ));
    assert!(!no_step.to_string().contains("token_hash"));

    // With step-up + super_admin → sensitive export includes hashes.
    let stepped = h.step_up(&cookie);
    let full = json_of(&h.post_json(
        "/api/export",
        Some(&stepped),
        &serde_json::json!({"include_credentials": true}),
    ));
    assert!(full.to_string().contains("token_hash"));
    assert!(
        !full.to_string().contains(&raw),
        "the raw token is NEVER exportable"
    );
}

#[test]
fn audit_trail_records_admin_actions_with_redaction() {
    let h = Harness::new();
    let cookie = h.step_up(&h.login());
    let user = h.create_user(&cookie, "audit@example.io", None);
    let uid = user["uid"].as_str().unwrap().to_string();
    let _ = h.issue_credential(&cookie, &uid);

    let resp = h.get_auth("/api/audit?limit=50", &cookie);
    assert_eq!(resp.status, 200);
    let events = json_of(&resp)["events"].as_array().unwrap().clone();
    assert!(!events.is_empty());
    // Credential issuance is audited with a FINGERPRINT, never a token.
    let issue = events
        .iter()
        .find(|e| e["action"] == "issue_credential")
        .expect("issuance audited");
    let details = issue["details"].as_str().unwrap_or("");
    assert!(details.starts_with("fingerprint=") && details.len() < 30);
    assert!(!events.iter().any(|e| e.to_string().contains("sk_live_")));

    // Filters work.
    let cred_only = h.get_auth("/api/audit?category=credential", &cookie);
    let arr = json_of(&cred_only)["events"].as_array().unwrap().clone();
    assert!(!arr.is_empty());
    assert!(arr.iter().all(|e| e["category"] == "credential"));
    let bad_cat = h.get_auth("/api/audit?category=nope", &cookie);
    assert_eq!(bad_cat.status, 400);
}

#[test]
fn config_get_put_and_validation() {
    let h = Harness::new();
    let cookie = h.step_up(&h.login());
    let stepped = h.step_up(&cookie);

    let initial = h.get_auth("/api/config", &cookie);
    assert_eq!(initial.status, 200);
    assert_eq!(json_of(&initial)["session_ttl_s"], 1800);

    // No step-up → rejected. (`cookie` is stepped, so mint a plain one.)
    let plain = h.login();
    let no_step = h.put_json(
        "/api/config",
        &plain,
        &serde_json::json!({
            "session_ttl_s": 1800, "step_up_ttl_s": 900, "app_token_ttl_s": 300,
            "login_max_attempts": 10, "login_window_s": 900, "import_batch_max": 100,
            "audit_retention_days": 90, "pbkdf2_iterations": 100000,
        }),
    );
    assert_eq!(no_step.status, 403);
    assert_eq!(error_code(&no_step), "STEP_UP_REQUIRED");

    // Out-of-range values are rejected with field errors.
    let bad = h.put_json(
        "/api/config",
        &stepped,
        &serde_json::json!({
            "session_ttl_s": 1, "step_up_ttl_s": 900, "app_token_ttl_s": 99999999,
            "login_max_attempts": 10, "login_window_s": 900, "import_batch_max": 100,
            "audit_retention_days": 90, "pbkdf2_iterations": 100000,
        }),
    );
    assert_eq!(bad.status, 422);
    let fields: Vec<String> = json_of(&bad)["error"]["details"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["field"].as_str().unwrap().to_string())
        .collect();
    assert!(fields.contains(&"session_ttl_s".to_string()));
    assert!(fields.contains(&"app_token_ttl_s".to_string()));

    // Valid update applies and bumps the version.
    let ok = h.put_json(
        "/api/config",
        &stepped,
        &serde_json::json!({
            "session_ttl_s": 3600, "step_up_ttl_s": 600, "app_token_ttl_s": 600,
            "login_max_attempts": 5, "login_window_s": 600, "import_batch_max": 50,
            "audit_retention_days": 120, "pbkdf2_iterations": 50000,
        }),
    );
    assert_eq!(ok.status, 200);
    assert_eq!(json_of(&ok)["version"], 2);
    assert_eq!(json_of(&ok)["session_ttl_s"], 3600);
}

#[test]
fn roles_matrix_and_admin_account_management() {
    let h = Harness::new();
    let cookie = h.step_up(&h.login());
    let stepped = h.step_up(&cookie);

    // Permission matrix content.
    let roles = h.get_auth("/api/roles", &cookie);
    assert_eq!(roles.status, 200);
    let body = json_of(&roles);
    assert_eq!(body["your_role"], "super_admin");
    let users_manage = body["permissions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["permission"] == "users:manage")
        .unwrap()
        .clone();
    assert!(users_manage["roles"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("super_admin")));
    assert!(!users_manage["roles"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("auditor")));

    // Create an auditor admin.
    let created = h.post_json(
        "/api/admins",
        Some(&stepped),
        &serde_json::json!({
            "username": "auditor1", "password": "long-password-for-auditor", "role": "auditor",
        }),
    );
    assert_eq!(created.status, 201);

    // The auditor can log in and read, but not create users.
    let auditor_cookie = h.login_as("auditor1", "long-password-for-auditor").unwrap();
    let list = h.get_auth("/api/users", &auditor_cookie);
    assert_eq!(list.status, 200, "auditor can read users");
    let create = h.post_json(
        "/api/users",
        Some(&auditor_cookie),
        &serde_json::json!({
            "email": "x@example.io", "display_name": "X",
        }),
    );
    assert_eq!(create.status, 403);
    assert_eq!(error_code(&create), "PERMISSION_DENIED");
    let cfg = h.get_auth("/api/config", &auditor_cookie);
    assert_eq!(cfg.status, 403, "auditor cannot read config");
    let audit_read = h.get_auth("/api/audit", &auditor_cookie);
    assert_eq!(audit_read.status, 200);

    // Weak password rejected.
    let weak = h.post_json(
        "/api/admins",
        Some(&stepped),
        &serde_json::json!({
            "username": "weak", "password": "short", "role": "auditor",
        }),
    );
    assert_eq!(weak.status, 422);

    // Cannot change your own role or delete yourself.
    let self_patch = h.patch_json(
        "/api/admins/admin",
        &stepped,
        &serde_json::json!({"role": "auditor"}),
    );
    assert_eq!(self_patch.status, 409);
    let self_delete = h.delete("/api/admins/admin", &stepped);
    assert_eq!(self_delete.status, 409);

    // Promote auditor, then delete: allowed.
    let promote = h.patch_json(
        "/api/admins/auditor1",
        &stepped,
        &serde_json::json!({"role": "admin"}),
    );
    assert_eq!(promote.status, 200);
    let del = h.delete("/api/admins/auditor1", &stepped);
    assert_eq!(del.status, 200);

    // Last-super-admin guard: demoting the only super_admin fails.
    let demote = h.patch_json(
        "/api/admins/admin",
        &stepped,
        &serde_json::json!({"role": "admin"}),
    );
    assert_eq!(demote.status, 409);
}
