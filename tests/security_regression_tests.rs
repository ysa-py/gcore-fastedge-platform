//! Security regression tests: protocol-level abuse, injection, failure
//! modes, header hygiene, and fail-closed behavior.

mod common;

use common::*;
use fastedge_admin_platform::http::{Req, Resp};
use fastedge_admin_platform::platform::StaticSecrets;

fn has(resp_headers: &[(String, String)], name: &str, value: &str) -> bool {
    resp_headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case(name) && v.contains(value))
}

#[test]
fn security_headers_on_every_response() {
    let h = Harness::new();
    for resp in [
        h.get("/healthz"),
        h.get("/"),
        h.get("/api/users"),
        h.get("/api/auth/session"),
    ] {
        assert!(has(&resp.headers, "X-Content-Type-Options", "nosniff"));
        assert!(has(&resp.headers, "X-Frame-Options", "DENY"));
        assert!(has(&resp.headers, "Referrer-Policy", "no-referrer"));
        assert!(has(&resp.headers, "X-Robots-Tag", "noindex"));
    }
    // The HTML shell carries the strict CSP; APIs are never stored.
    let index = h.get("/");
    assert!(has(
        &index.headers,
        "Content-Security-Policy",
        "default-src 'self'"
    ));
    let api = h.get("/api/users");
    assert!(has(&api.headers, "Cache-Control", "no-store"));
}

#[test]
fn request_id_is_echoed_and_sanitized() {
    let h = Harness::new();
    let resp = h.get_with(|r| r.with_header("X-Request-ID", "abcd12345678"));
    assert_eq!(header_of(&resp, "X-Request-ID").unwrap(), "abcd12345678");
    // A malicious request id is replaced, never echoed.
    let evil = h.get_with(|r| r.with_header("X-Request-ID", "evil\r\nSet-Cookie: x=1"));
    let echoed = header_of(&evil, "X-Request-ID").unwrap();
    assert!(
        echoed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-'),
        "echoed id: {echoed}"
    );
    assert!(!evil
        .headers
        .iter()
        .any(|(k, _)| k.contains("set-cookieInjected")));
}

#[test]
fn oversized_bodies_are_rejected_before_parsing() {
    let h = Harness::new();
    let cookie = h.login();
    let big = vec![b'x'; 300 * 1024];
    let resp = h.request(
        Req::post("/api/users")
            .with_header("X-Requested-With", XRW)
            .with_header("Cookie", &format!("fes_session={cookie}"))
            .with_body(big),
    );
    assert_eq!(resp.status, 413);
    assert_eq!(error_code(&resp), "PAYLOAD_TOO_LARGE");
}

#[test]
fn malformed_json_and_bad_types_are_client_errors() {
    let h = Harness::new();
    let cookie = h.step_up(&h.login());
    let malformed = h.request(
        Req::post("/api/users")
            .with_header("X-Requested-With", XRW)
            .with_header("Cookie", &format!("fes_session={cookie}"))
            .with_body(br#"{"email": "x@y.z""#.to_vec()),
    );
    assert_eq!(malformed.status, 400);
    let wrong_type = h.request(
        Req::post("/api/users")
            .with_header("X-Requested-With", XRW)
            .with_header("Cookie", &format!("fes_session={cookie}"))
            .with_body(br#"{"email": 123, "display_name": "n"}"#.to_vec()),
    );
    assert_eq!(wrong_type.status, 400);
}

#[test]
fn path_traversal_and_glob_injection_are_neutralized() {
    let h = Harness::new();
    let cookie = h.login();
    for path in [
        "/api/users/../../etc/passwd",
        "/api/users/*",
        "/api/users/users/*",
        "/api/users/%2e%2e%2f",
    ] {
        let resp =
            h.request(Req::get(path).with_header("Cookie", &format!("fes_session={cookie}")));
        assert_eq!(resp.status, 404, "{path} must not reach storage");
    }
    // Deliberately valid-format but nonexistent id → 404 without details.
    let nonexistent = h.get_auth("/api/users/uAAAAABBBBBBBBBBBBBBBBBBBBBB", &cookie);
    assert_eq!(nonexistent.status, 404);
    assert_eq!(error_code(&nonexistent), "NOT_FOUND");
}

#[test]
fn method_handling_and_allow_headers() {
    let h = Harness::new();
    let cookie = h.login();
    let del_on_list = h.request(
        Req::new("DELETE", "/api/users")
            .with_header("X-Requested-With", XRW)
            .with_header("Cookie", &format!("fes_session={cookie}")),
    );
    assert_eq!(del_on_list.status, 405);
    assert!(header_of(&del_on_list, "Allow").unwrap().contains("GET"));
    assert!(header_of(&del_on_list, "Allow").unwrap().contains("POST"));

    let options = h.request(Req::new("OPTIONS", "/api/users"));
    assert_eq!(options.status, 405);

    let unknown = h.get_auth("/api/definitely/not/a/route", &cookie);
    assert_eq!(unknown.status, 404);
    let unknown_pub = h.get("/api/v1/unknown");
    assert_eq!(unknown_pub.status, 404);
}

#[test]
fn storage_read_failure_fails_closed_on_entitlements() {
    let mut h = Harness::new();
    let cookie = h.step_up(&h.login());
    let user = h.create_user(&cookie, "failclosed@example.io", None);
    let uid = user["uid"].as_str().unwrap().to_string();
    let raw = h.issue_credential(&cookie, &uid);

    // Mint an access token BEFORE the outage so we can also probe /me.
    let access = json_of(&h.exchange(&raw))["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    // Make every read fail.
    h.failing_reads = Some(FailingReads::wrap(h.mem.clone()));
    h.failing_reads.as_ref().unwrap().fail_get_after(0);

    // Token exchange cannot read its dependencies → honest 503, never success.
    let ex = h.exchange(&raw);
    assert_eq!(ex.status, 503, "exchange during outage must not succeed");
    assert_eq!(error_code(&ex), "STORAGE_UNAVAILABLE");

    // A VALID, unexpired access token is still FAIL-CLOSED (403, generic):
    // the entitlement chain cannot be established, so access is denied —
    // never a 500 and never a pass-through.
    let me = h.me(&access);
    assert_eq!(me.status, 403, "fail-closed: got {}", me.status);
    assert_eq!(json_of(&me)["error"]["message"], "Access denied.");
}

#[test]
fn control_plane_write_failure_surfaces_as_502_not_data_loss() {
    let mut h = Harness::new();
    let cookie = h.login();
    let stepped = h.step_up(&cookie);

    // All control-plane writes fail from the start.
    h.cp.fail_after(0);

    let create = h.post_json(
        "/api/users",
        Some(&stepped),
        &serde_json::json!({
            "email": "never@example.io", "display_name": "Never",
        }),
    );
    assert_eq!(create.status, 502);
    assert_eq!(error_code(&create), "CONTROL_PLANE_UNAVAILABLE");
    let body_s = String::from_utf8_lossy(&create.body).to_string();
    assert!(!body_s.contains("error:"));
    assert!(!body_s.to_lowercase().contains("rejected"));
}

#[test]
fn healthz_is_public_and_leaks_nothing() {
    let h = Harness::new();
    let resp = h.get("/healthz");
    assert_eq!(resp.status, 200);
    let body = json_of(&resp);
    assert_eq!(body["status"], "ok");
    assert!(body["time"].is_string());
    assert!(body.get("store_id").is_none());
    assert!(body.get("secrets").is_none());
}

#[test]
fn system_health_reports_real_state_without_secret_values() {
    let h = Harness::new();
    let cookie = h.login();
    let resp = h.get_auth("/api/system/health", &cookie);
    assert_eq!(resp.status, 200);
    let body = json_of(&resp);
    assert_eq!(body["secrets"]["session_signing_key"], "configured");
    assert_eq!(body["storage"]["read_probe"], "ok");
    let s = body.to_string();
    assert!(!s.contains(SESSION_KEY));
    assert!(!s.contains(APP_KEY));
    assert!(!s.contains(GCORE_API_KEY));
}

#[test]
fn system_limits_proxy_requires_api_key_and_reports_unavailability() {
    let h = Harness::new();
    let cookie = h.login();
    // No canned HTTP response → unreachable → explicit 502.
    let resp = h.get_auth("/api/system/limits", &cookie);
    assert_eq!(resp.status, 502);
    assert_eq!(error_code(&resp), "CONTROL_PLANE_UNAVAILABLE");

    // With a canned 200 response the proxy returns the real payload.
    h.http
        .push_ok(200, r#"{"limits": {"apps": 10}, "plan": "Free"}"#);
    let ok = h.get_auth("/api/system/limits", &cookie);
    assert_eq!(ok.status, 200);
    let body = json_of(&ok);
    assert_eq!(body["account"]["plan"], "Free");
    assert!(body["fetched_at"].is_string());
    // Both upstream attempts were recorded (the first was unreachable);
    // the successful one targets /fastedge/v1/me.
    let reqs = h.http.requests.lock().unwrap();
    assert_eq!(reqs.len(), 2);
    assert!(reqs.last().unwrap().1.contains("/fastedge/v1/me"));
}

#[test]
fn metrics_endpoint_labels_approximation_and_reports_unavailable() {
    let h = Harness::new();
    let cookie = h.login();
    let _ = h.get("/healthz"); // generate some traffic
    let resp = h.get_auth("/api/metrics?days=7", &cookie);
    assert_eq!(resp.status, 200);
    let body = json_of(&resp);
    assert_eq!(body["days"].as_array().unwrap().len(), 7);
    assert_eq!(body["counters"]["scope"], "per-POP approximations");
    assert!(body["counters"]["series"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s["metric"] == "req"));
    // Platform stats explicitly report unavailability, never fabricated.
    assert_eq!(body["platform_stats"]["available"], false);
    // Invalid range.
    let bad = h.get_auth("/api/metrics?days=99", &cookie);
    assert_eq!(bad.status, 422);
}

#[test]
fn overview_endpoint_reports_real_numbers() {
    let h = Harness::new();
    let cookie = h.step_up(&h.login());
    for email in ["o1@example.io", "o2@example.io"] {
        h.create_user(&cookie, email, Some("2100-01-01T00:00:00Z"));
    }
    let resp = h.get_auth("/api/overview", &cookie);
    assert_eq!(resp.status, 200);
    let body = json_of(&resp);
    assert_eq!(body["users"]["total"], 2);
    assert_eq!(body["users"]["active"], 2);
    assert_eq!(body["users"]["expiring_within_7d"], 0);
    assert_eq!(body["service"]["storage"], "ok");
    assert_eq!(body["service"]["config"], "ok");
}

#[test]
fn assets_are_served_and_unknown_paths_404() {
    let h = Harness::new();
    assert_eq!(h.get("/").status, 200);
    assert_eq!(h.get("/assets/styles.css").status, 200);
    assert_eq!(h.get("/favicon.svg").status, 200);
    assert_eq!(h.get("/assets/js/main.js").status, 200);
    assert_eq!(h.get("/nope.js").status, 404);
    assert_eq!(h.get("/assets/../../Cargo.toml").status, 404);
}

#[test]
fn logout_requires_session_and_csrf_header() {
    let h = Harness::new();
    let cookie = h.login();
    let no_csrf = h.request(
        Req::post("/api/auth/logout")
            .with_header("Cookie", &format!("fes_session={cookie}"))
            .with_body(b"{}".to_vec()),
    );
    assert_eq!(no_csrf.status, 403);
    let ok = h.post_json("/api/auth/logout", Some(&cookie), &serde_json::json!({}));
    assert_eq!(ok.status, 200);
}

#[test]
fn cookie_value_must_be_complete_garbage_resistant() {
    let h = Harness::new();
    for probe in ["", "a", "abc.def.ghi", "eyJhbGciOiJub25lIn0.x.y"] {
        let resp = h.request(
            Req::get("/api/overview").with_header("Cookie", &format!("fes_session={probe}")),
        );
        assert_eq!(resp.status, 401, "probe {probe:?} must be rejected");
    }
}

#[test]
fn login_without_session_key_configured_fails_closed() {
    let hash = "unused";
    let _ = hash;
    let h = Harness {
        secrets: StaticSecrets::new(&[]), // NO keys configured at all
        ..Default::default()
    };
    let resp = h.post_json(
        "/api/auth/login",
        None,
        &serde_json::json!({"username": ADMIN_USER, "password": ADMIN_PASS}),
    );
    assert_eq!(
        resp.status, 403,
        "login must be impossible without a signing key"
    );
}

#[test]
fn responses_never_leak_internal_paths_or_stack_info() {
    let h = Harness::new();
    let cookie = h.login();
    let probes = [
        h.get("/api/unknown-route"),
        h.get_auth("/api/users/uAAAAABBBBBBBBBBBBBBBBBBBBBB", &cookie),
        h.post_json(
            "/api/users",
            Some(&cookie),
            &serde_json::json!({"email": "bad"}),
        ),
        h.request(Req::new("PUT", "/api/users")),
    ];
    for resp in probes {
        let body = String::from_utf8_lossy(&resp.body).to_lowercase();
        assert!(!body.contains("panic"), "leaked: {body}");
        assert!(!body.contains("src/"), "leaked: {body}");
        assert!(!body.contains("traceback"), "leaked: {body}");
        assert!(!body.contains(".rs"), "leaked: {body}");
    }
}

// Local extension trait for small request tweaks.
trait GetWith {
    fn get_with(&self, f: impl FnOnce(Req) -> Req) -> Resp;
}

impl GetWith for Harness {
    fn get_with(&self, f: impl FnOnce(Req) -> Req) -> Resp {
        self.request(f(Req::get("/healthz")))
    }
}
