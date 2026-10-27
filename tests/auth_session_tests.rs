//! Authentication and session-management integration tests.

mod common;

use common::*;
use fastedge_admin_platform::http::{Req, Resp};
use fastedge_admin_platform::platform::{Clock, StaticSecrets, Store};

fn is_unauthorized_generic(resp: &Resp) -> bool {
    resp.status == 401
        && json_of(resp)["error"]["message"]
            .as_str()
            .is_some_and(|m| m == "Invalid username or password.")
}

#[test]
fn login_sets_hardened_cookie() {
    let h = Harness::new();
    let resp = h.post_json(
        "/api/auth/login",
        None,
        &serde_json::json!({"username": ADMIN_USER, "password": ADMIN_PASS}),
    );
    assert_eq!(resp.status, 200);
    let cookie = cookie_of(&resp).expect("cookie set");
    assert!(!cookie.is_empty() && cookie.len() > 40);
    let raw = header_of(&resp, "Set-Cookie").unwrap();
    assert!(raw.contains("HttpOnly"), "cookie must be HttpOnly: {raw}");
    assert!(
        raw.contains("SameSite=Strict"),
        "cookie must be SameSite=Strict: {raw}"
    );
    assert!(
        raw.contains("Path=/"),
        "cookie must be scoped to Path=/: {raw}"
    );
    assert!(raw.contains("Max-Age="), "cookie must carry Max-Age: {raw}");
    assert_eq!(json_of(&resp)["role"], "super_admin");
    assert!(json_of(&resp)["permissions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p == "config:manage"));
}

#[test]
fn login_requires_json_body_and_known_fields() {
    let h = Harness::new();
    let bad = h.request(
        Req::post("/api/auth/login")
            .with_header("X-Requested-With", XRW)
            .with_body(br#"{"username": "admin"}"#.to_vec()),
    );
    assert_eq!(bad.status, 400);
    let unknown = h.request(
        Req::post("/api/auth/login")
            .with_header("X-Requested-With", XRW)
            .with_body(br#"{"username": "admin", "password": "x", "extra": 1}"#.to_vec()),
    );
    assert_eq!(unknown.status, 400); // deny_unknown_fields
}

#[test]
fn wrong_password_and_unknown_user_look_identical() {
    let h = Harness::new();
    let wrong = h.post_json(
        "/api/auth/login",
        None,
        &serde_json::json!({"username": ADMIN_USER, "password": "nope-nope-nope"}),
    );
    let ghost2 = h.post_json(
        "/api/auth/login",
        None,
        &serde_json::json!({"username": "ghost", "password": "nope-nope-nope"}),
    );
    assert!(is_unauthorized_generic(&wrong));
    assert!(is_unauthorized_generic(&ghost2));
    assert_eq!(
        json_of(&wrong)["error"]["message"],
        json_of(&ghost2)["error"]["message"]
    );
}

#[test]
fn login_lockout_after_configured_attempts() {
    let h = Harness::new();
    for i in 0..10 {
        let r = h.post_json(
            "/api/auth/login",
            None,
            &serde_json::json!({"username": ADMIN_USER, "password": format!("wrong-{i}")}),
        );
        assert_eq!(r.status, 401, "attempt {i} must be 401, not a lockout yet");
    }
    let locked = h.post_json(
        "/api/auth/login",
        None,
        &serde_json::json!({"username": ADMIN_USER, "password": ADMIN_PASS}),
    );
    assert_eq!(locked.status, 429);
    assert_eq!(error_code(&locked), "RATE_LIMITED");
    assert!(header_of(&locked, "Retry-After").is_some());
    // A different username is NOT affected (per-identity lockout).
    // (No other admin exists in this harness, but the endpoint must not
    // 404-vs-429 differently — it must remain 401 for unknown users.)
    let other = h.post_json(
        "/api/auth/login",
        None,
        &serde_json::json!({"username": "ghost", "password": "whatever-long-password"}),
    );
    assert_eq!(other.status, 401);
}

#[test]
fn session_endpoint_requires_valid_cookie() {
    let h = Harness::new();
    let no_cookie = h.get("/api/auth/session");
    assert_eq!(no_cookie.status, 401);
    assert_eq!(error_code(&no_cookie), "UNAUTHENTICATED");

    let garbage =
        h.request(Req::get("/api/auth/session").with_header("Cookie", "fes_session=garbage"));
    assert_eq!(garbage.status, 401);

    let cookie = h.login();
    let ok = h.get_auth("/api/auth/session", &cookie);
    assert_eq!(ok.status, 200);
    assert_eq!(json_of(&ok)["username"], ADMIN_USER);
}

#[test]
fn session_expiry_is_enforced() {
    let h = Harness::new();
    let cookie = h.login();
    h.advance(1_700); // session_ttl default = 1800 → 100s remain
    assert_eq!(h.get_auth("/api/auth/session", &cookie).status, 200);
    h.advance(100); // exactly at expiry → 1800s total → token exp == now
    assert_eq!(h.get_auth("/api/auth/session", &cookie).status, 401);
}

#[test]
fn logout_invalidates_session() {
    let h = Harness::new();
    let cookie = h.login();
    assert_eq!(h.get_auth("/api/auth/session", &cookie).status, 200);
    let out = h.post_json("/api/auth/logout", Some(&cookie), &serde_json::json!({}));
    assert_eq!(out.status, 200);
    assert!(header_of(&out, "Set-Cookie").unwrap().contains("Max-Age=0"));
    assert_eq!(
        h.get_auth("/api/auth/session", &cookie).status,
        401,
        "token must be dead after logout"
    );
}

#[test]
fn step_up_flow_and_enforcement() {
    let h = Harness::new();
    let cookie = h.login();
    // No step-up yet → destructive op returns STEP_UP_REQUIRED.
    let before = h.post_json(
        "/api/users",
        Some(&cookie),
        &serde_json::json!({
            "email": "step@example.io", "display_name": "Step",
        }),
    );
    assert_eq!(before.status, 403);
    assert_eq!(error_code(&before), "STEP_UP_REQUIRED");

    let stepped = h.step_up(&cookie);
    let after = h.post_json(
        "/api/users",
        Some(&stepped),
        &serde_json::json!({
            "email": "step@example.io", "display_name": "Step",
        }),
    );
    assert_eq!(after.status, 201);

    // Wrong step-up password is rejected.
    let h2 = Harness::new();
    let c2 = h2.login();
    let bad = h2.request(
        Req::post("/api/auth/stepup")
            .with_header("X-Requested-With", XRW)
            .with_header("Cookie", &format!("fes_session={c2}"))
            .with_body(br#"{"password":"totally-wrong"}"#.to_vec()),
    );
    assert_eq!(bad.status, 401);
}

#[test]
fn revoke_all_sessions_bumps_epoch() {
    let h = Harness::new();
    let c1 = h.login();
    let stepped = h.step_up(&c1);
    let revoke = h.post_json(
        "/api/auth/revoke-all",
        Some(&stepped),
        &serde_json::json!({}),
    );
    assert_eq!(revoke.status, 200);
    assert_eq!(h.get_auth("/api/auth/session", &c1).status, 401);
    assert_eq!(h.get_auth("/api/auth/session", &stepped).status, 401);
    // A fresh login mints a token at the new epoch and works.
    let c2 = h.login();
    assert_eq!(h.get_auth("/api/auth/session", &c2).status, 200);
}

#[test]
fn forged_and_tampered_sessions_are_rejected() {
    let h = Harness::new();
    // A token signed with a different key (simulating key confusion).
    let evil_key = b"attacker-controlled-key-material-32-bytes!!";
    let now = h.clock.now_unix();
    let claims = fastedge_admin_platform::crypto::Claims {
        iss: "fap".into(),
        aud: "admin".into(),
        sub: ADMIN_USER.into(),
        iat: now,
        exp: now + 600,
        jti: "evil".into(),
        purpose: Some("admin-session".into()),
        role: Some("super_admin".into()),
        cv: None,
        su: Some(now + 600),
        ep: Some(0),
        nbf: None,
    };
    let forged = fastedge_admin_platform::crypto::jwt_encode(&claims, evil_key);
    let resp = h.get_auth("/api/auth/session", &forged);
    assert_eq!(resp.status, 401);

    // Admin-token audience confusion: an APP token used as a session.
    let app_claims = fastedge_admin_platform::crypto::Claims {
        iss: "fap".into(),
        aud: "app".into(),
        sub: ADMIN_USER.into(),
        iat: now,
        exp: now + 600,
        jti: "x".into(),
        purpose: Some("app-access".into()),
        role: None,
        cv: Some(1),
        su: None,
        ep: None,
        nbf: None,
    };
    let app_jwt = fastedge_admin_platform::crypto::jwt_encode(&app_claims, SESSION_KEY.as_bytes());
    let resp2 = h.get_auth("/api/auth/session", &app_jwt);
    assert_eq!(resp2.status, 401);
}

#[test]
fn csrf_guards_block_cross_site_mutations() {
    let h = Harness::new();
    let cookie = h.login();

    // Missing X-Requested-With.
    let no_header = h.request(
        Req::post("/api/auth/logout")
            .with_header("Cookie", &format!("fes_session={cookie}"))
            .with_body(b"{}".to_vec()),
    );
    assert_eq!(no_header.status, 403);

    // Origin mismatch.
    let cross = h.request(
        Req::post("/api/auth/logout")
            .with_header("Cookie", &format!("fes_session={cookie}"))
            .with_header("X-Requested-With", XRW)
            .with_header("Origin", "https://evil.example")
            .with_header("Host", "panel.test")
            .with_body(b"{}".to_vec()),
    );
    assert_eq!(cross.status, 403);

    // Served behind a proxy that rewrites `Host` (preview sandbox, CDN): the
    // app's own declared public origin is a real same-origin request and must
    // still be able to mutate.
    let mut proxied = Harness::new();
    proxied.public_origin = "https://3000-preview.example.com".into();
    let login_body = || {
        serde_json::to_vec(&serde_json::json!({
            "username": ADMIN_USER,
            "password": ADMIN_PASS,
        }))
        .unwrap()
    };
    let through_proxy = proxied.request(
        Req::post("/api/auth/login")
            .with_header("Content-Type", "application/json")
            .with_header("X-Requested-With", XRW)
            .with_header("Origin", "https://3000-preview.example.com")
            .with_header("Host", "3000-abc123.internal.example")
            .with_body(login_body()),
    );
    assert_eq!(through_proxy.status, 200);

    // And declaring a public origin does not admit anybody else's origin.
    let other_origin = proxied.request(
        Req::post("/api/auth/login")
            .with_header("Content-Type", "application/json")
            .with_header("X-Requested-With", XRW)
            .with_header("Origin", "https://evil.example")
            .with_header("Host", "3000-abc123.internal.example")
            .with_body(login_body()),
    );
    assert_eq!(other_origin.status, 403);
}

#[test]
fn storage_outage_fails_closed_for_sessions() {
    let mut h = Harness::new();
    h.failing_reads = Some(FailingReads::wrap(h.mem.clone()));
    let f = h.failing_reads.as_ref().unwrap();
    f.fail_get_after(0); // every get fails

    // Login cannot read its dependencies → 503 STORAGE_UNAVAILABLE (an
    // honest denial; nothing about the outage is leaked beyond the status).
    let resp = h.post_json(
        "/api/auth/login",
        None,
        &serde_json::json!({"username": ADMIN_USER, "password": ADMIN_PASS}),
    );
    assert_eq!(
        resp.status, 503,
        "login must fail closed during storage outage"
    );
    assert_eq!(error_code(&resp), "STORAGE_UNAVAILABLE");
    let sess = h.get_auth("/api/auth/session", "any-token");
    assert_eq!(sess.status, 401, "sessions must not verify during outage");
}

#[test]
fn bootstrap_admin_from_secrets_when_store_empty() {
    let hash = fastedge_admin_platform::crypto::hash_password("bootstrap-secret-1", 10_000);
    let mut h = Harness::new();
    // Fresh deployment: no admin records exist at all.
    h.mem.delete("admins/admin").unwrap();
    // Deployment secrets carry the bootstrap identity.
    h.secrets = StaticSecrets::new(&[
        ("SESSION_SIGNING_KEY", SESSION_KEY),
        ("APP_TOKEN_SIGNING_KEY", APP_KEY),
        ("GCORE_API_KEY", GCORE_API_KEY),
        ("ADMIN_USERNAME", "bootstrap-admin"),
        ("ADMIN_PASSWORD_HASH", hash.as_str()),
    ]);
    let resp = h.post_json(
        "/api/auth/login",
        None,
        &serde_json::json!({"username": "bootstrap-admin", "password": "bootstrap-secret-1"}),
    );
    assert_eq!(resp.status, 200, "bootstrap login must work on empty store");
    // The admin record is now persisted.
    assert!(h.mem.get("admins/bootstrap-admin").unwrap().is_some());
    // Second login works from the STORED record (not the bootstrap path).
    let again = h.post_json(
        "/api/auth/login",
        None,
        &serde_json::json!({"username": "bootstrap-admin", "password": "bootstrap-secret-1"}),
    );
    assert_eq!(again.status, 200);
}
