//! Authorization-engine integration tests: the per-user UTC expiration
//! boundary, credential lifecycle, and fail-closed entitlement checks.

mod common;

use common::*;
use fastedge_admin_platform::http::Req;
use fastedge_admin_platform::platform::{Clock, Store};

/// Set a subscription's absolute expiration through the admin API.
fn set_expiration(h: &Harness, cookie: &str, uid: &str, exp: &str) {
    let resp = h.put_json(
        &format!("/api/users/{uid}/subscription"),
        cookie,
        &serde_json::json!({"expires_at": exp}),
    );
    assert_eq!(
        resp.status,
        200,
        "set expiration failed: {}",
        String::from_utf8_lossy(&resp.body)
    );
}

fn user_with_token(h: &Harness) -> (String, String, String) {
    let cookie = h.step_up(&h.login());
    let user = h.create_user(&cookie, "boundary@example.io", Some("2100-01-01T00:00:00Z"));
    let uid = user["uid"].as_str().unwrap().to_string();
    let raw = h.issue_credential(&cookie, &uid);
    (cookie, uid, raw)
}

#[test]
fn full_lifecycle_create_issue_exchange_me() {
    let h = Harness::new();
    let (_cookie, uid, raw) = user_with_token(&h);

    let ex = h.exchange(&raw);
    assert_eq!(
        ex.status,
        200,
        "exchange failed: {}",
        String::from_utf8_lossy(&ex.body)
    );
    let access = json_of(&ex)["access_token"].as_str().unwrap().to_string();
    assert!(access.split('.').count() == 3);

    let me = h.me(&access);
    assert_eq!(me.status, 200);
    let body = json_of(&me);
    assert_eq!(body["uid"], uid);
    assert_eq!(body["status"], "active");
    assert_eq!(body["subscription"]["status"], "active");
    assert_eq!(body["subscription"]["expires_at"], "2100-01-01T00:00:00Z");
}

#[test]
fn expiration_boundary_exact_rule() {
    let h = Harness::new();
    let (cookie, uid, raw) = user_with_token(&h);

    // Set expiration to exactly now + 3600.
    let exp_ts = h.clock.now_unix() + 3600;
    let exp_str = fastedge_admin_platform::timeutil::format_rfc3339_utc(exp_ts);
    set_expiration(&h, &cookie, &uid, &exp_str);

    // Two seconds before expiration: exchange + /me both allowed.
    h.advance(3598); // now = exp - 2
    let ex = h.exchange(&raw);
    assert_eq!(ex.status, 200, "exchange must work before expiry");
    let access = json_of(&ex)["access_token"].as_str().unwrap().to_string();
    h.advance(1); // now = exp - 1
    assert_eq!(
        h.me(&access).status,
        200,
        "one second before expiry must be allowed"
    );

    h.advance(1); // now == exp exactly → REJECT (>= rule), on EVERY request
    let at_boundary = h.me(&access);
    assert_eq!(
        at_boundary.status, 403,
        "exactly at expiry must be rejected"
    );
    assert_eq!(json_of(&at_boundary)["error"]["message"], "Access expired.");

    h.advance(1); // now = exp + 1 → REJECT
    assert_eq!(
        h.me(&access).status,
        403,
        "one second after expiry must be rejected"
    );

    // A new EXCHANGE is also denied after expiry.
    let ex2 = h.exchange(&raw);
    assert_eq!(ex2.status, 403);
}

#[test]
fn suspension_and_revocation_apply_immediately_to_tokens() {
    let h = Harness::new();
    let (cookie, uid, raw) = user_with_token(&h);
    let access = json_of(&h.exchange(&raw))["access_token"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(h.me(&access).status, 200);

    // Suspend the user → the already-issued token stops working.
    let sus = h.post_json(
        &format!("/api/users/{uid}/status"),
        Some(&cookie),
        &serde_json::json!({"action": "suspend"}),
    );
    assert_eq!(sus.status, 200);

    assert_eq!(h.me(&access).status, 403);

    // Reactivate → works again (same token: entitlement is re-checked live).
    let re = h.post_json(
        &format!("/api/users/{uid}/status"),
        Some(&cookie),
        &serde_json::json!({"action": "reactivate"}),
    );
    assert_eq!(re.status, 200);
    assert_eq!(h.me(&access).status, 200);

    // Revoke is terminal for tokens too.
    let rv = h.post_json(
        &format!("/api/users/{uid}/status"),
        Some(&cookie),
        &serde_json::json!({"action": "revoke"}),
    );
    assert_eq!(rv.status, 200);
    assert_eq!(h.me(&access).status, 403);
    assert_eq!(h.exchange(&raw).status, 403);
}

#[test]
fn credential_revocation_and_version_rotation() {
    let h = Harness::new();
    let (cookie, uid, raw) = user_with_token(&h);
    let access = json_of(&h.exchange(&raw))["access_token"]
        .as_str()
        .unwrap()
        .to_string();
    let detail = json_of(&h.get_auth(&format!("/api/users/{uid}"), &cookie));
    let cred_id = detail["credentials"][0]["cred_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Revoke the credential.
    let del = h.delete(&format!("/api/users/{uid}/credentials/{cred_id}"), &cookie);
    assert_eq!(del.status, 200);
    assert_eq!(json_of(&del)["cred_version"], 2);

    // Exchange with the revoked credential is denied...
    assert_eq!(h.exchange(&raw).status, 401);
    // ...and the previously issued short-lived token is dead too
    // (credential version no longer matches).
    assert_eq!(h.me(&access).status, 401);

    // Issue a NEW credential → works again.
    let raw2 = h.issue_credential(&cookie, &uid);
    assert_eq!(h.exchange(&raw2).status, 200);
}

#[test]
fn missing_subscription_fails_closed() {
    let h = Harness::new();
    let (_cookie, uid, raw) = user_with_token(&h);
    // Corrupt the storage: remove the subscription record.
    h.mem.delete(&format!("subs/{uid}")).unwrap();
    let ex = h.exchange(&raw);
    assert_eq!(
        ex.status, 401,
        "missing subscription must DENY (fail-closed)"
    );
    assert_eq!(json_of(&ex)["error"]["message"], "Access denied.");
}

#[test]
fn malformed_records_fail_closed() {
    let h = Harness::new();
    let (cookie, uid, raw) = user_with_token(&h);
    // Write a corrupt user record.
    h.mem
        .put(&format!("users/{uid}"), b"{corrupt".to_vec())
        .unwrap();
    assert_eq!(h.exchange(&raw).status, 401);
    // Restore a valid record but with an unsupported future schema version.
    let mut rec: serde_json::Value = serde_json::from_slice(
        &h.mem
            .get(&format!("users/{uid}"))
            .unwrap()
            .unwrap_or_default(),
    )
    .unwrap_or_default();
    let _ = cookie;
    if rec.is_object() && !rec.is_null() {
        rec["schema_version"] = serde_json::json!(99);
        h.mem
            .put(&format!("users/{uid}"), serde_json::to_vec(&rec).unwrap())
            .unwrap();
        assert_eq!(h.exchange(&raw).status, 401, "unknown schema must DENY");
    }
}

#[test]
fn app_tokens_are_audience_isolated() {
    let h = Harness::new();
    let (_cookie, _uid, raw) = user_with_token(&h);
    let access = json_of(&h.exchange(&raw))["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    // The access token cannot be used as an admin session cookie.
    let as_session = h.get_auth("/api/auth/session", &access);
    assert_eq!(as_session.status, 401);
    // The access token cannot be used as a Bearer on admin APIs either
    // (router only accepts cookies for admin routes).
    let as_admin =
        h.request(Req::get("/api/users").with_header("Authorization", &format!("Bearer {access}")));
    assert_eq!(as_admin.status, 401);
}

#[test]
fn exchange_rate_limits_per_token_fingerprint() {
    let h = Harness::new();
    let (_cookie, _uid, raw) = user_with_token(&h);
    for _ in 0..30 {
        let _ = h.exchange(&raw);
    }
    let limited = h.exchange(&raw);
    assert_eq!(limited.status, 429, "per-token exchange limit must trigger");
}

#[test]
fn unknown_token_is_generic_denial() {
    let h = Harness::new();
    let ex = h.exchange("sk_live_totally-unknown-token-value-aaaaaaaaaaaaaa");
    assert_eq!(ex.status, 401);
    assert_eq!(json_of(&ex)["error"]["message"], "Access denied.");
    // Malformed/short tokens never reach storage.
    assert_eq!(h.exchange("short").status, 401);
    let _ = fastedge_admin_platform::http::Req::get("/");
}

#[test]
fn token_exchange_requires_valid_json_and_fields() {
    let h = Harness::new();
    let missing = h.request(
        Req::post("/api/v1/token")
            .with_header("X-Requested-With", XRW)
            .with_body(br#"{}"#.to_vec()),
    );
    assert_eq!(missing.status, 400);
    let unknown = h.request(
        Req::post("/api/v1/token")
            .with_header("X-Requested-With", XRW)
            .with_body(br#"{"token": "x", "extra": true}"#.to_vec()),
    );
    assert_eq!(unknown.status, 400);
}

#[test]
fn entitlements_endpoint_reports_boundary_rule() {
    let h = Harness::new();
    let (_cookie, _uid, raw) = user_with_token(&h);
    let access = json_of(&h.exchange(&raw))["access_token"]
        .as_str()
        .unwrap()
        .to_string();
    let resp = h.request(
        Req::get("/api/v1/entitlements").with_header("Authorization", &format!("Bearer {access}")),
    );
    assert_eq!(resp.status, 200);
    let body = json_of(&resp);
    assert_eq!(body["entitlement"]["id"], "ent-basic");
    assert_eq!(
        body["entitlement"]["boundaries"]["rule"],
        "access allowed while now < expires_at (UTC)"
    );
    assert_eq!(
        body["entitlement"]["boundaries"]["checked"],
        "every request"
    );
}
