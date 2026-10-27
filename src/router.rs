//! The request pipeline: every request passes through the same stages in
//! the same order.
//!
//! ```text
//! request-id → metrics → size caps → CSRF/origin → route+method →
//! (public? | session → permission → step-up) → handler → audit/metrics →
//! security headers → response
//! ```
//!
//! Fail-closed everywhere: a route that cannot establish its required
//! security state returns 401/403/503 — never "continues with defaults".

use crate::app::App;
use crate::audit::redact;
use crate::auth::{self, Permission, Session};
use crate::errors::ApiError;
use crate::http::{Req, Resp};
use crate::metrics::{MetricKind, Metrics};
use serde::de::DeserializeOwned;

/// The single HTTP entrypoint used by both the wasm runtime and tests.
pub fn handle(app: &App, req: Req) -> Resp {
    let request_id = resolve_request_id(&req);
    let mut resp = route(app, &req, &request_id);
    resp.append_header("X-Request-ID", &request_id);
    resp
}

fn resolve_request_id(req: &Req) -> String {
    match req.header("x-request-id") {
        Some(id) if is_safe_request_id(id) => id.to_string(),
        _ => crate::ids::new_request_id().unwrap_or_else(|_| "req-unknown".into()),
    }
}

fn is_safe_request_id(s: &str) -> bool {
    (8..=64).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

fn route(app: &App, req: &Req, request_id: &str) -> Resp {
    let m = Metrics {
        cache: app.cache,
        clock: app.clock,
    };
    m.incr(MetricKind::Requests);

    let outcome = route_inner(app, req, request_id);

    match outcome {
        Ok(r) => r,
        Err(e) => {
            match e.status() {
                400..=499 => m.incr(MetricKind::ClientErrors),
                500..=599 => m.incr(MetricKind::ServerErrors),
                _ => {}
            }
            Resp::from_error(&e, request_id)
        }
    }
}

fn route_inner(app: &App, req: &Req, request_id: &str) -> Result<Resp, ApiError> {
    // --- Global request-size cap -------------------------------------------
    if req.body.len() > crate::validation::MAX_BODY_BYTES {
        return Err(ApiError::TooLarge);
    }
    if let Some(cl) = req.header("content-length") {
        if let Ok(n) = cl.trim().parse::<usize>() {
            if n > crate::validation::MAX_BODY_BYTES {
                return Err(ApiError::TooLarge);
            }
        }
    }

    let path = req.path.trim_end_matches('/');
    let path = if path.is_empty() { "/" } else { path };
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let method = req.method.as_str();

    // --- Public surface ----------------------------------------------------
    if path == "/healthz" {
        return match method {
            "GET" | "HEAD" => {
                let ctx = crate::handlers::system::Ctx {
                    app,
                    req,
                    request_id,
                };
                crate::handlers::system::healthz(&ctx)
            }
            _ => Err(ApiError::MethodNotAllowed(vec!["GET", "HEAD"])),
        };
    }

    // Static admin panel assets (embedded, CSP-protected, ETag-revalidated).
    if method == "GET" || method == "HEAD" {
        if let Some(resp) = crate::assets::serve(&req.path, req.header("if-none-match")) {
            return Ok(resp);
        }
    }

    // --- Application API ---------------------------------------------------
    if segments.first() == Some(&"api") {
        if segments.get(1) == Some(&"v1") {
            return route_app_api(app, req, request_id, segments, method);
        }
        return route_admin_api(app, req, request_id, segments, method);
    }

    Err(ApiError::NotFound("Resource not found."))
}

// ---------------------------------------------------------------------------
// CSRF / origin defenses
// ---------------------------------------------------------------------------

/// Cross-site defense for state-changing requests:
/// 1. `Origin` header, when present, must match the request `Host`
///    (same-origin policy enforced server-side). A deployment served behind a
///    proxy that rewrites `Host` can declare its own public origin in
///    `FE_PUBLIC_ORIGIN`; that one exact origin is then accepted as well.
/// 2. A custom header `X-Requested-With: fastedge-admin` is required on
///    every `/api/*` mutation — browsers cannot add custom headers to a
///    cross-site request without a CORS preflight, which this API never
///    grants.
fn csrf_guard(configured_origin: &str, req: &Req) -> Result<(), ApiError> {
    if !matches!(req.method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE") {
        return Ok(());
    }
    let xrw = req.header("x-requested-with").unwrap_or("");
    if xrw != "fastedge-admin" {
        return Err(ApiError::Forbidden("Cross-site requests are not accepted."));
    }
    if let (Some(origin), Some(host)) = (req.header("origin"), req.header("host")) {
        let origin_host = origin
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or("");
        let configured = configured_origin.trim_end_matches('/');
        let origin_matches_config =
            !configured.is_empty() && origin.trim_end_matches('/') == configured;
        if origin_host != host && !origin_matches_config {
            return Err(ApiError::Forbidden("Cross-site requests are not accepted."));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Admin API
// ---------------------------------------------------------------------------

fn route_admin_api(
    app: &App,
    req: &Req,
    request_id: &str,
    segments: Vec<&str>,
    method: &str,
) -> Result<Resp, ApiError> {
    let admin_ctx = crate::handlers::admin::Ctx {
        app,
        req,
        request_id,
    };
    let system_ctx = crate::handlers::system::Ctx {
        app,
        req,
        request_id,
    };
    // All admin API responses are dynamic and private.
    let no_store = |r: Resp| {
        r.header("Cache-Control", "no-store")
            .with_security_headers()
    };

    // OPTIONS is rejected globally without touching auth state: method
    // support is public information, and answering it pre-auth avoids an
    // unnecessary session oracle.
    if method == "OPTIONS" {
        return Err(ApiError::MethodNotAllowed(vec!["GET", "POST"]));
    }

    // ---- Public admin routes ----
    if let ("POST", ["api", "auth", "login"]) = (method, segments.as_slice()) {
        csrf_guard(&app.env.public_origin, req)?;
        let body = parse_json::<crate::handlers::admin::LoginRequest>(req)?;
        return Ok(no_store(crate::handlers::admin::login(&admin_ctx, &body)?));
    }

    // ---- Everything else requires a valid session ----
    let session = verify_session(app, req)?;

    match (method, segments.as_slice()) {
        ("GET", ["api", "auth", "session"]) => {
            return Ok(no_store(crate::handlers::admin::session_info(
                &admin_ctx, &session,
            )?))
        }
        ("POST", ["api", "auth", "logout"]) => {
            csrf_guard(&app.env.public_origin, req)?;
            return Ok(no_store(crate::handlers::admin::logout(
                &admin_ctx, &session,
            )?));
        }
        ("POST", ["api", "auth", "stepup"]) => {
            csrf_guard(&app.env.public_origin, req)?;
            let body = parse_json::<crate::handlers::admin::StepUpRequest>(req)?;
            return Ok(no_store(crate::handlers::admin::step_up(
                &admin_ctx, &session, &body,
            )?));
        }
        ("POST", ["api", "auth", "revoke-all"]) => {
            csrf_guard(&app.env.public_origin, req)?;
            require(app, &session, Permission::ConfigManage)?;
            require_step_up(app, req, &session)?;
            return Ok(no_store(crate::handlers::admin::revoke_all_sessions(
                &admin_ctx, &session,
            )?));
        }
        ("GET", ["api", "overview"]) => {
            require(app, &session, Permission::OverviewRead)?;
            return Ok(no_store(crate::handlers::admin::overview(
                &admin_ctx, &session,
            )?));
        }
        ("GET", ["api", "roles"]) => {
            return Ok(no_store(crate::handlers::admin::roles(
                &admin_ctx, &session,
            )?));
        }
        _ => {}
    }

    // ---- Users & subscriptions ----
    if segments.get(1) == Some(&"users")
        || segments.get(1) == Some(&"bulk")
        || segments.get(1) == Some(&"subscriptions")
    {
        return route_users(app, req, request_id, &segments, method, &session);
    }

    // ---- Audit ----
    if let ("GET", ["api", "audit"]) = (method, segments.as_slice()) {
        require(app, &session, Permission::AuditRead)?;
        return Ok(no_store(crate::handlers::admin::list_audit(
            &admin_ctx, &session,
        )?));
    }

    // ---- Admin accounts ----
    if segments.get(1) == Some(&"admins") {
        return route_admins(app, req, request_id, &segments, method, &session);
    }

    // ---- Config / import / export / metrics / system ----
    match (method, segments.as_slice()) {
        ("GET", ["api", "config"]) => {
            require(app, &session, Permission::ConfigRead)?;
            return Ok(no_store(crate::handlers::admin::get_config(
                &admin_ctx, &session,
            )?));
        }
        ("PUT", ["api", "config"]) => {
            csrf_guard(&app.env.public_origin, req)?;
            require(app, &session, Permission::ConfigManage)?;
            require_step_up(app, req, &session)?;
            let body = parse_json::<crate::handlers::admin::ConfigPutRequest>(req)?;
            return Ok(no_store(crate::handlers::admin::put_config(
                &admin_ctx, &session, &body,
            )?));
        }
        ("POST", ["api", "export"]) => {
            csrf_guard(&app.env.public_origin, req)?;
            require(app, &session, Permission::ExportRun)?;
            let body = parse_json::<crate::handlers::admin::ExportRequest>(req)?;
            if body.include_credentials {
                require_role_super(&session)?;
                require_step_up(app, req, &session)?;
            }
            return Ok(no_store(crate::handlers::admin::export(
                &admin_ctx, &session, &body,
            )?));
        }
        ("POST", ["api", "import"]) => {
            csrf_guard(&app.env.public_origin, req)?;
            require(app, &session, Permission::ImportRun)?;
            let raw: serde_json::Value = parse_json(req)?;
            let body = parse_value_as::<crate::handlers::admin::ImportRequest>(
                raw.get("options").unwrap_or(&serde_json::json!({})),
            )?;
            let payload = raw.get("payload").ok_or(ApiError::Unprocessable(vec![
                crate::errors::FieldError::new("payload", "payload object is required"),
            ]))?;
            if body.apply {
                require_step_up(app, req, &session)?;
            }
            return Ok(no_store(crate::handlers::admin::import(
                &admin_ctx, &session, &body, payload,
            )?));
        }
        ("GET", ["api", "metrics"]) => {
            require(app, &session, Permission::MetricsRead)?;
            return Ok(no_store(crate::handlers::system::metrics(
                &system_ctx,
                &session,
            )?));
        }
        ("GET", ["api", "system", "health"]) => {
            require(app, &session, Permission::SystemRead)?;
            return Ok(no_store(crate::handlers::system::health(
                &system_ctx,
                &session,
            )?));
        }
        ("GET", ["api", "system", "limits"]) => {
            require(app, &session, Permission::SystemRead)?;
            return Ok(no_store(crate::handlers::system::limits(
                &system_ctx,
                &session,
            )?));
        }
        ("POST", ["api", "system", "prune-audit"]) => {
            csrf_guard(&app.env.public_origin, req)?;
            require(app, &session, Permission::SystemRead)?;
            require_step_up(app, req, &session)?;
            return Ok(no_store(crate::handlers::system::prune_audit(
                &system_ctx,
                &session,
            )?));
        }
        _ => {}
    }

    Err(ApiError::NotFound("Resource not found."))
}

fn route_users(
    app: &App,
    req: &Req,
    request_id: &str,
    segments: &[&str],
    method: &str,
    session: &Session,
) -> Result<Resp, ApiError> {
    let ctx = crate::handlers::admin::Ctx {
        app,
        req,
        request_id,
    };
    let no_store = |r: Resp| {
        r.header("Cache-Control", "no-store")
            .with_security_headers()
    };

    if segments.len() == 2 && segments[1] == "bulk" {
        csrf_guard(&app.env.public_origin, req)?;
        let body = parse_json::<crate::handlers::admin::BulkRequest>(req)?;
        match body.action.as_str() {
            "suspend" | "reactivate" | "revoke" => {
                require(app, session, Permission::UsersManage)?;
                require_step_up(app, req, session)?;
            }
            "renew" => {
                require(app, session, Permission::SubsManage)?;
                require_step_up(app, req, session)?;
            }
            _ => {
                return Err(ApiError::Unprocessable(vec![
                    crate::errors::FieldError::new(
                        "action",
                        "must be suspend, reactivate, revoke, or renew",
                    ),
                ]))
            }
        }
        return Ok(no_store(crate::handlers::admin::bulk(
            &ctx, session, &body,
        )?));
    }

    if segments[1] == "users" && segments.len() == 2 {
        return match method {
            "GET" => {
                require(app, session, Permission::UsersRead)?;
                Ok(no_store(crate::handlers::admin::list_users(&ctx, session)?))
            }
            "POST" => {
                csrf_guard(&app.env.public_origin, req)?;
                require(app, session, Permission::UsersManage)?;
                require_step_up(app, req, session)?;
                let body = parse_json::<crate::handlers::admin::UserCreateRequest>(req)?;
                Ok(no_store(crate::handlers::admin::create_user(
                    &ctx, session, &body,
                )?))
            }
            _ => Err(ApiError::MethodNotAllowed(vec!["GET", "POST"])),
        };
    }

    if segments[1] == "users" && segments.len() >= 3 {
        let uid = segments[2];
        crate::validation::is_record_id(uid, 'u')
            .then_some(())
            .ok_or(ApiError::NotFound("Resource not found."))?;
        match segments.len() {
            3 => match method {
                "GET" => {
                    require(app, session, Permission::UsersRead)?;
                    return Ok(no_store(crate::handlers::admin::get_user(
                        &ctx, session, uid,
                    )?));
                }
                "PATCH" => {
                    csrf_guard(&app.env.public_origin, req)?;
                    require(app, session, Permission::UsersManage)?;
                    require_step_up(app, req, session)?;
                    let body = parse_json::<crate::handlers::admin::UserPatchRequest>(req)?;
                    return Ok(no_store(crate::handlers::admin::patch_user(
                        &ctx, session, uid, &body,
                    )?));
                }
                _ => return Err(ApiError::MethodNotAllowed(vec!["GET", "PATCH"])),
            },
            4 => match (method, segments[3]) {
                ("POST", "status") => {
                    csrf_guard(&app.env.public_origin, req)?;
                    require(app, session, Permission::UsersManage)?;
                    require_step_up(app, req, session)?;
                    let body = parse_json::<crate::handlers::admin::StatusActionRequest>(req)?;
                    return Ok(no_store(crate::handlers::admin::set_user_status(
                        &ctx, session, uid, &body,
                    )?));
                }
                ("POST", "credentials") => {
                    csrf_guard(&app.env.public_origin, req)?;
                    require(app, session, Permission::CredsManage)?;
                    require_step_up(app, req, session)?;
                    let body = parse_json::<crate::handlers::admin::CredentialIssueRequest>(req)?;
                    return Ok(no_store(crate::handlers::admin::issue_credential(
                        &ctx, session, uid, &body,
                    )?));
                }
                ("GET", "subscription") => {
                    require(app, session, Permission::SubsRead)?;
                    return Ok(no_store(crate::handlers::admin::get_subscription(
                        &ctx, session, uid,
                    )?));
                }
                ("PUT", "subscription") => {
                    csrf_guard(&app.env.public_origin, req)?;
                    require(app, session, Permission::SubsManage)?;
                    require_step_up(app, req, session)?;
                    let body = parse_json::<crate::handlers::admin::SubscriptionPutRequest>(req)?;
                    return Ok(no_store(crate::handlers::admin::put_subscription(
                        &ctx, session, uid, &body,
                    )?));
                }
                _ => return Err(ApiError::NotFound("Resource not found.")),
            },
            5 => match (method, segments[3], segments[4]) {
                ("DELETE", "credentials", cred_id) => {
                    csrf_guard(&app.env.public_origin, req)?;
                    require(app, session, Permission::CredsManage)?;
                    require_step_up(app, req, session)?;
                    return Ok(no_store(crate::handlers::admin::revoke_credential(
                        &ctx, session, uid, cred_id,
                    )?));
                }
                ("POST", "subscription", "renew") => {
                    csrf_guard(&app.env.public_origin, req)?;
                    require(app, session, Permission::SubsManage)?;
                    require_step_up(app, req, session)?;
                    let body = parse_json::<crate::handlers::admin::RenewRequest>(req)?;
                    return Ok(no_store(crate::handlers::admin::renew_subscription(
                        &ctx, session, uid, &body,
                    )?));
                }
                _ => return Err(ApiError::NotFound("Resource not found.")),
            },
            _ => return Err(ApiError::NotFound("Resource not found.")),
        }
    }

    Err(ApiError::NotFound("Resource not found."))
}

fn route_admins(
    app: &App,
    req: &Req,
    request_id: &str,
    segments: &[&str],
    method: &str,
    session: &Session,
) -> Result<Resp, ApiError> {
    let ctx = crate::handlers::admin::Ctx {
        app,
        req,
        request_id,
    };
    let no_store = |r: Resp| {
        r.header("Cache-Control", "no-store")
            .with_security_headers()
    };

    match (method, segments) {
        ("GET", ["api", "admins"]) => {
            require(app, session, Permission::SystemRead)?;
            return Ok(no_store(crate::handlers::admin::list_admins(
                &ctx, session,
            )?));
        }
        ("POST", ["api", "admins"]) => {
            csrf_guard(&app.env.public_origin, req)?;
            require(app, session, Permission::ConfigManage)?;
            require_step_up(app, req, session)?;
            let body = parse_json::<crate::handlers::admin::AdminCreateRequest>(req)?;
            return Ok(no_store(crate::handlers::admin::create_admin(
                &ctx, session, &body,
            )?));
        }
        (m, ["api", "admins", username]) => {
            require(app, session, Permission::ConfigManage)?;
            match m {
                "PATCH" => {
                    csrf_guard(&app.env.public_origin, req)?;
                    require_step_up(app, req, session)?;
                    let body = parse_json::<crate::handlers::admin::AdminPatchRequest>(req)?;
                    return Ok(no_store(crate::handlers::admin::patch_admin(
                        &ctx, session, username, &body,
                    )?));
                }
                "DELETE" => {
                    csrf_guard(&app.env.public_origin, req)?;
                    require_step_up(app, req, session)?;
                    return Ok(no_store(crate::handlers::admin::delete_admin(
                        &ctx, session, username,
                    )?));
                }
                _ => return Err(ApiError::MethodNotAllowed(vec!["PATCH", "DELETE"])),
            }
        }
        (m, ["api", "admins", username, "password"]) => {
            require(app, session, Permission::ConfigManage)?;
            match m {
                "POST" => {
                    csrf_guard(&app.env.public_origin, req)?;
                    require_step_up(app, req, session)?;
                    let body = parse_json::<crate::handlers::admin::AdminPasswordRequest>(req)?;
                    return Ok(no_store(crate::handlers::admin::reset_admin_password(
                        &ctx, session, username, &body,
                    )?));
                }
                _ => return Err(ApiError::MethodNotAllowed(vec!["POST"])),
            }
        }
        _ => {}
    }
    Err(ApiError::NotFound("Resource not found."))
}

// ---------------------------------------------------------------------------
// Application API (/api/v1/*)
// ---------------------------------------------------------------------------

fn route_app_api(
    app: &App,
    req: &Req,
    request_id: &str,
    segments: Vec<&str>,
    method: &str,
) -> Result<Resp, ApiError> {
    let ctx = crate::handlers::app::Ctx {
        app,
        req,
        request_id,
    };
    match (method, segments.as_slice()) {
        ("POST", ["api", "v1", "token"]) => {
            csrf_guard(&app.env.public_origin, req)?;
            let body = parse_json::<crate::handlers::app::TokenExchangeRequest>(req)?;
            crate::handlers::app::exchange(&ctx, &body)
        }
        ("GET", ["api", "v1", "me"]) => crate::handlers::app::me(&ctx),
        ("GET", ["api", "v1", "entitlements"]) => crate::handlers::app::entitlements(&ctx),
        _ => Err(ApiError::NotFound("Resource not found.")),
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn verify_session(app: &App, req: &Req) -> Result<Session, ApiError> {
    let svc = auth::AuthService {
        store: app.store,
        cache: app.cache,
        secrets: app.secrets,
        clock: app.clock,
    };
    let token = req
        .cookie(app.env.effective_cookie_name())
        .or_else(|| req.bearer().map(|t| t.to_string()));
    let token = token.ok_or(ApiError::Unauthorized("Authentication required."))?;
    svc.verify_session(&token)
}

fn require(app: &App, session: &Session, permission: Permission) -> Result<(), ApiError> {
    if session.can(permission) {
        return Ok(());
    }
    // Record the denial (best effort) — admin authz failures are auditable.
    let audit = crate::audit::Audit {
        store: app.store,
        clock: app.clock,
    };
    if let Ok(ev) = audit.new_event(
        crate::models::AuditCategory::Security,
        "admin_permission_denied",
        &format!("admin:{}", session.username),
        permission.as_str(),
        crate::models::AuditOutcome::Denied,
        "n/a",
        None,
    ) {
        audit.record_best_effort(&ev);
    }
    let _ = redact("", 0);
    Err(ApiError::Forbidden(
        "You do not have permission to perform this operation.",
    ))
}

fn require_role_super(session: &Session) -> Result<(), ApiError> {
    if session.role == crate::models::AdminRole::SuperAdmin {
        Ok(())
    } else {
        Err(ApiError::Forbidden(
            "This operation requires the super_admin role.",
        ))
    }
}

fn require_step_up(app: &App, req: &Req, session: &Session) -> Result<(), ApiError> {
    // Step-up state lives inside the session token; nothing else to read.
    let _ = (app, req);
    if session.has_step_up(app.clock.now_unix()) {
        Ok(())
    } else {
        Err(ApiError::StepUpRequired)
    }
}

fn parse_json<T: DeserializeOwned>(req: &Req) -> Result<T, ApiError> {
    req.json::<T>()
}

fn parse_value_as<T: DeserializeOwned>(v: &serde_json::Value) -> Result<T, ApiError> {
    serde_json::from_value(v.clone()).map_err(|_| {
        ApiError::Unprocessable(vec![crate::errors::FieldError::new(
            "options",
            "request fields are invalid",
        )])
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::Req;

    #[test]
    fn request_id_validation() {
        assert!(is_safe_request_id("abc123XYZ_01"));
        assert!(!is_safe_request_id("short"));
        assert!(!is_safe_request_id("has spaces"));
        assert!(!is_safe_request_id("bad\r\ninjection"));
        assert!(!is_safe_request_id(&"x".repeat(65)));
        let r = Req::get("/").with_header("X-Request-Id", "abcdefgh1234");
        assert_eq!(resolve_request_id(&r), "abcdefgh1234");
        let r2 = Req::get("/");
        let rid = resolve_request_id(&r2);
        assert_eq!(rid.len(), 18);
    }

    #[test]
    fn csrf_requires_custom_header_on_mutations() {
        // Missing X-Requested-With on POST → rejected.
        assert!(csrf_guard("", &Req::post("/api/users")).is_err());
        let ok = Req::post("/api/users").with_header("X-Requested-With", "fastedge-admin");
        assert!(csrf_guard("", &ok).is_ok());
        // GET needs nothing.
        assert!(csrf_guard("", &Req::get("/api/users")).is_ok());
    }

    #[test]
    fn csrf_rejects_cross_origin() {
        let req = Req::post("/api/users")
            .with_header("X-Requested-With", "fastedge-admin")
            .with_header("Origin", "https://evil.example")
            .with_header("Host", "myapp.fastedge.app");
        assert!(csrf_guard("", &req).is_err());
        let same = Req::post("/api/users")
            .with_header("X-Requested-With", "fastedge-admin")
            .with_header("Origin", "https://myapp.fastedge.app")
            .with_header("Host", "myapp.fastedge.app");
        assert!(csrf_guard("", &same).is_ok());
    }

    #[test]
    fn csrf_admits_only_the_configured_public_origin_behind_a_proxy() {
        // A proxy that rewrites `Host` (preview sandbox, CDN): the app's own
        // declared public origin is accepted although it differs from `Host`…
        let behind_proxy = Req::post("/api/users")
            .with_header("X-Requested-With", "fastedge-admin")
            .with_header("Origin", "https://3000-preview.example.com")
            .with_header("Host", "3000-abc123.internal.example");
        assert!(csrf_guard("https://3000-preview.example.com", &behind_proxy).is_ok());
        // …while every other origin stays rejected, configured or not.
        assert!(csrf_guard("", &behind_proxy).is_err());
        let cross = Req::post("/api/users")
            .with_header("X-Requested-With", "fastedge-admin")
            .with_header("Origin", "https://evil.example")
            .with_header("Host", "3000-abc123.internal.example");
        assert!(csrf_guard("https://3000-preview.example.com", &cross).is_err());
    }
}
