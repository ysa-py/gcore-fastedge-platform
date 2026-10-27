//! Request handlers: administrative surface.

use crate::app::App;
use crate::audit::{actor_admin, Audit};
use crate::auth::{self, Session};
use crate::errors::{ApiError, FieldError};
use crate::http::{Req, Resp};
use crate::metrics::MetricKind;
use crate::models::{
    keys, AdminRecord, AdminRole, AppConfig, AuditCategory, AuditOutcome, SubscriptionStatus,
    ADMIN_SCHEMA_VERSION,
};
use crate::timeutil;
use crate::users::{subscription_view, UsersService};
use serde::Deserialize;

/// Deserialize tri-state helper: missing → `None`, JSON null → `Some(None)`.
mod double_option {
    use serde::{Deserialize, Deserializer};
    pub fn deserialize<'de, T, D>(d: D) -> Result<Option<Option<T>>, D::Error>
    where
        T: Deserialize<'de>,
        D: Deserializer<'de>,
    {
        Ok(Some(Option::<T>::deserialize(d)?))
    }
}

pub struct Ctx<'a> {
    pub app: &'a App<'a>,
    pub req: &'a Req,
    pub request_id: &'a str,
}

impl Ctx<'_> {
    fn audit(&self) -> Audit<'_> {
        Audit {
            store: self.app.store,
            clock: self.app.clock,
        }
    }
    fn users(&self) -> UsersService<'_> {
        UsersService {
            store: self.app.store,
            clock: self.app.clock,
        }
    }
    fn now(&self) -> u64 {
        self.app.clock.now_unix()
    }
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginRequest {
    username: String,
    password: String,
}

pub fn login(ctx: &Ctx, body: &LoginRequest) -> Result<Resp, ApiError> {
    let cfg = ctx.app.load_config()?;
    let svc = auth::AuthService {
        store: ctx.app.store,
        cache: ctx.app.cache,
        secrets: ctx.app.secrets,
        clock: ctx.app.clock,
    };
    let ip = ctx.req.client_ip().map(str::to_string);
    let result = svc.login(&body.username, &body.password, ip.as_deref(), &cfg);

    let audit = ctx.audit();
    match result {
        Ok((token, role)) => {
            // Bootstrap: if no admin record exists but bootstrap env secrets
            // are set and matched, persist the first super_admin record.
            ensure_bootstrap_admin(ctx, &body.username)?;
            // Best-effort last-login update.
            let mut rec: Option<AdminRecord> = ctx
                .app
                .store
                .get(&keys::admin(&body.username))
                .ok()
                .flatten()
                .and_then(|b| serde_json::from_slice(&b).ok());
            if let Some(r) = rec.as_mut() {
                r.last_login_at = Some(ctx.now());
                let _ = ctx.app.store.put(
                    &keys::admin(&r.username),
                    serde_json::to_vec(r).unwrap_or_default(),
                );
            }
            let ev = audit
                .new_event(
                    AuditCategory::Auth,
                    "login",
                    &actor_admin(&body.username),
                    "session",
                    AuditOutcome::Ok,
                    ctx.request_id,
                    Some(format!("role={}", role.as_str())),
                )
                .map_err(|_| ApiError::Internal)?;
            audit.record_best_effort(&ev);
            ctx_app_metrics(ctx, MetricKind::AuthSuccesses);
            let cookie = build_session_cookie(ctx, &token, cfg.session_ttl_s);
            let mut resp = Resp::json(
                200,
                &serde_json::json!({
                    "username": body.username,
                    "role": role.as_str(),
                    "permissions": auth::permissions_for(role).iter().map(|p| p.as_str()).collect::<Vec<_>>(),
                    "session_ttl_s": cfg.session_ttl_s,
                    "step_up_ttl_s": cfg.step_up_ttl_s,
                }),
            );
            resp.append_header("Set-Cookie", &cookie);
            Ok(resp
                .with_security_headers()
                .header("Cache-Control", "no-store"))
        }
        Err(e) => {
            let outcome = match &e {
                ApiError::TooManyRequests { .. } => AuditOutcome::Denied,
                _ => AuditOutcome::Denied,
            };
            let details = match &e {
                ApiError::TooManyRequests { .. } => Some("reason=rate_limited".to_string()),
                _ => None,
            };
            let ev = audit
                .new_event(
                    AuditCategory::Auth,
                    "login",
                    &actor_admin(&body.username),
                    "session",
                    outcome,
                    ctx.request_id,
                    details,
                )
                .map_err(|_| ApiError::Internal)?;
            audit.record_best_effort(&ev);
            ctx_app_metrics(ctx, MetricKind::AuthFailures);
            Err(e)
        }
    }
}

/// Seed the first admin record from bootstrap secrets, if applicable.
fn ensure_bootstrap_admin(ctx: &Ctx, username: &str) -> Result<(), ApiError> {
    let existing = ctx
        .app
        .store
        .scan("admins/*")
        .map_err(|_| ApiError::StorageUnavailable)?;
    if !existing.is_empty() {
        return Ok(());
    }
    let boot_user = ctx
        .app
        .secrets
        .get("ADMIN_USERNAME")
        .ok()
        .flatten()
        .and_then(|v| String::from_utf8(v).ok());
    let boot_hash = ctx
        .app
        .secrets
        .get("ADMIN_PASSWORD_HASH")
        .ok()
        .flatten()
        .and_then(|v| String::from_utf8(v).ok());
    if boot_user.as_deref() == Some(username) {
        if let Some(hash) = boot_hash {
            let rec = AdminRecord {
                schema_version: ADMIN_SCHEMA_VERSION,
                username: username.into(),
                role: AdminRole::SuperAdmin,
                password_hash: hash,
                created_at: ctx.now(),
                created_by: "bootstrap".into(),
                updated_at: ctx.now(),
                last_login_at: None,
            };
            ctx.app
                .store
                .put(
                    &keys::admin(username),
                    serde_json::to_vec(&rec).map_err(|_| ApiError::Internal)?,
                )
                .map_err(|_| ApiError::ControlPlane("The change could not be persisted."))?;
        }
    }
    Ok(())
}

fn build_session_cookie(ctx: &Ctx, token: &str, max_age_s: u64) -> String {
    let name = ctx.app.env.effective_cookie_name();
    let secure = if ctx.app.env.insecure_cookie {
        ""
    } else {
        "; Secure"
    };
    format!("{name}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age_s}{secure}")
}

pub fn logout(ctx: &Ctx, session: &Session) -> Result<Resp, ApiError> {
    let svc = auth::AuthService {
        store: ctx.app.store,
        cache: ctx.app.cache,
        secrets: ctx.app.secrets,
        clock: ctx.app.clock,
    };
    svc.logout(session)?;
    let ev = ctx
        .audit()
        .new_event(
            AuditCategory::Auth,
            "logout",
            &actor_admin(&session.username),
            &format!("session:{}", crate::audit::fingerprint_prefix(&session.jti)),
            AuditOutcome::Ok,
            ctx.request_id,
            None,
        )
        .map_err(|_| ApiError::Internal)?;
    ctx.audit().record_best_effort(&ev);
    let mut resp = Resp::json(200, &serde_json::json!({"ok": true}));
    resp.append_header(
        "Set-Cookie",
        &format!(
            "{}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0",
            ctx.app.env.effective_cookie_name()
        ),
    );
    Ok(resp
        .with_security_headers()
        .header("Cache-Control", "no-store"))
}

pub fn session_info(ctx: &Ctx, session: &Session) -> Result<Resp, ApiError> {
    let cfg = ctx.app.config_or_default();
    Ok(Resp::json(
        200,
        &serde_json::json!({
            "username": session.username,
            "role": session.role.as_str(),
            "permissions": auth::permissions_for(session.role).iter().map(|p| p.as_str()).collect::<Vec<_>>(),
            "step_up_active": session.has_step_up(ctx.now()),
            "session_expires_at": timeutil::format_rfc3339_utc(session.exp),
            "session_ttl_s": cfg.session_ttl_s,
        }),
    )
    .with_security_headers()
    .header("Cache-Control", "no-store"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepUpRequest {
    password: String,
}

pub fn step_up(ctx: &Ctx, session: &Session, body: &StepUpRequest) -> Result<Resp, ApiError> {
    let cfg = ctx.app.load_config()?;
    let svc = auth::AuthService {
        store: ctx.app.store,
        cache: ctx.app.cache,
        secrets: ctx.app.secrets,
        clock: ctx.app.clock,
    };
    match svc.step_up(session, &body.password, &cfg) {
        Ok(token) => {
            let ev = ctx
                .audit()
                .new_event(
                    AuditCategory::Auth,
                    "step_up",
                    &actor_admin(&session.username),
                    "session",
                    AuditOutcome::Ok,
                    ctx.request_id,
                    None,
                )
                .map_err(|_| ApiError::Internal)?;
            ctx.audit().record_best_effort(&ev);
            let cookie = build_session_cookie(ctx, &token, cfg.session_ttl_s);
            let mut resp = Resp::json(
                200,
                &serde_json::json!({"ok": true, "step_up_ttl_s": cfg.step_up_ttl_s}),
            );
            resp.append_header("Set-Cookie", &cookie);
            Ok(resp
                .with_security_headers()
                .header("Cache-Control", "no-store"))
        }
        Err(e) => {
            let ev = ctx
                .audit()
                .new_event(
                    AuditCategory::Auth,
                    "step_up",
                    &actor_admin(&session.username),
                    "session",
                    AuditOutcome::Denied,
                    ctx.request_id,
                    None,
                )
                .map_err(|_| ApiError::Internal)?;
            ctx.audit().record_best_effort(&ev);
            Err(e)
        }
    }
}

/// Revoke ALL sessions (emergency logout everywhere) by bumping the epoch.
pub fn revoke_all_sessions(ctx: &Ctx, session: &Session) -> Result<Resp, ApiError> {
    let next = epoch_now(ctx)? + 1;
    ctx.app
        .store
        .put(keys::session_epoch(), next.to_string().into_bytes())
        .map_err(|_| ApiError::ControlPlane("The change could not be persisted."))?;
    record_admin_op(
        ctx,
        session,
        AuditCategory::Security,
        "revoke_all_sessions",
        "system:sessions",
        Some(format!("epoch={next}")),
    )?;
    Ok(
        Resp::json(200, &serde_json::json!({"ok": true, "epoch": next}))
            .with_security_headers()
            .header("Cache-Control", "no-store"),
    )
}

fn epoch_now(ctx: &Ctx) -> Result<u64, ApiError> {
    Ok(ctx
        .app
        .store
        .get(keys::session_epoch())
        .map_err(|_| ApiError::StorageUnavailable)?
        .and_then(|b| String::from_utf8(b).ok())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0))
}

fn ctx_app_metrics(ctx: &Ctx, kind: MetricKind) {
    crate::metrics::Metrics {
        cache: ctx.app.cache,
        clock: ctx.app.clock,
    }
    .incr(kind);
}

/// Write a critical audit event for a successful admin mutation, plus the
/// admin-operations metric.
fn record_admin_op(
    ctx: &Ctx,
    session: &Session,
    category: AuditCategory,
    action: &str,
    target: &str,
    details: Option<String>,
) -> Result<(), ApiError> {
    let ev = ctx
        .audit()
        .new_event(
            category,
            action,
            &actor_admin(&session.username),
            target,
            AuditOutcome::Ok,
            ctx.request_id,
            details,
        )
        .map_err(|_| ApiError::Internal)?;
    ctx.audit().record_critical(&ev)?;
    ctx_app_metrics(ctx, MetricKind::AdminOperations);
    Ok(())
}

// ---------------------------------------------------------------------------
// Overview / users / subscriptions
// ---------------------------------------------------------------------------

pub fn overview(ctx: &Ctx, _session: &Session) -> Result<Resp, ApiError> {
    let users = ctx.users();
    let counts = users.overview_counts()?;
    let (recent_security, _) = ctx.audit().list(
        &crate::audit::AuditQuery {
            category: Some(AuditCategory::Auth),
            actor: None,
            target: None,
            outcome: Some(AuditOutcome::Denied),
        },
        10,
        0,
    )?;
    let (recent_admin, _) = ctx.audit().list(
        &crate::audit::AuditQuery {
            category: None,
            actor: None,
            target: None,
            outcome: None,
        },
        10,
        0,
    )?;
    let cfg_status = match ctx.app.load_config() {
        Ok(_) => "ok",
        Err(_) => "invalid",
    };
    let store_ok = ctx.app.store.get(keys::CONFIG).is_ok(); // reads must work
    Ok(Resp::json(
        200,
        &serde_json::json!({
            "generated_at": timeutil::format_rfc3339_utc(ctx.now()),
            "users": {
                "total": counts.total,
                "active": counts.active,
                "suspended": counts.suspended,
                "revoked": counts.revoked,
                "expiring_within_7d": counts.expiring_within_7d,
                "scan_truncated": counts.truncated,
            },
            "recent_auth_failures": recent_security.iter().map(audit_view).collect::<Vec<_>>(),
            "recent_events": recent_admin.iter().map(audit_view).collect::<Vec<_>>(),
            "service": {
                "storage": if store_ok { "ok" } else { "unavailable" },
                "config": cfg_status,
                "cache": {
                    "available": crate::metrics::Metrics { cache: ctx.app.cache, clock: ctx.app.clock }.cache_available(),
                    "note": "per-POP counters; approximate aggregates"
                },
                "version": ctx.app.env.app_version,
                "store_id_configured": !ctx.app.env.store_id.is_empty(),
            },
        }),
    )
    .with_security_headers()
    .header("Cache-Control", "no-store"))
}

pub fn audit_view(ev: &crate::models::AuditEvent) -> serde_json::Value {
    serde_json::json!({
        "id": ev.id,
        "at": timeutil::format_rfc3339_utc_ms(ev.at),
        "category": ev.category.as_str(),
        "action": ev.action,
        "actor": ev.actor,
        "target": ev.target,
        "outcome": match ev.outcome { crate::models::AuditOutcome::Ok => "ok", crate::models::AuditOutcome::Denied => "denied", crate::models::AuditOutcome::Error => "error" },
        "request_id": ev.request_id,
        "details": ev.details,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserCreateRequest {
    email: String,
    display_name: String,
    #[serde(default = "default_role")]
    app_role: String,
    #[serde(default = "default_entitlement")]
    entitlement_id: String,
    #[serde(default)]
    expires_at: Option<String>,
    #[serde(default)]
    metadata: serde_json::Map<String, serde_json::Value>,
}

fn default_role() -> String {
    "member".into()
}
fn default_entitlement() -> String {
    "default".into()
}

pub fn create_user(
    ctx: &Ctx,
    session: &Session,
    body: &UserCreateRequest,
) -> Result<Resp, ApiError> {
    // The service owns timestamp parsing/validation so that ALL field
    // errors (email, display_name, expires_at, ...) return together.
    let input = crate::users::CreateUserInput {
        email: body.email.clone(),
        display_name: body.display_name.clone(),
        app_role: body.app_role.clone(),
        metadata: body.metadata.clone(),
        entitlement_id: body.entitlement_id.clone(),
        expires_at: body.expires_at.clone(),
    };
    let user = ctx
        .users()
        .create_user(&input, &actor_admin(&session.username))?;
    record_admin_op(
        ctx,
        session,
        AuditCategory::User,
        "create_user",
        &format!("user:{}", user.uid),
        Some(format!("email={};role={}", user.email, user.app_role)),
    )?;
    Ok(Resp::json(201, &ctx.users().user_view(&user)?)
        .with_security_headers()
        .header("Cache-Control", "no-store"))
}

pub fn list_users(ctx: &Ctx, _session: &Session) -> Result<Resp, ApiError> {
    let status = match ctx.req.query("status").as_deref() {
        None | Some("") | Some("all") => None,
        Some("active") => Some(crate::models::UserStatus::Active),
        Some("suspended") => Some(crate::models::UserStatus::Suspended),
        Some("revoked") => Some(crate::models::UserStatus::Revoked),
        _ => {
            return Err(ApiError::BadRequest(
                "status must be active, suspended, revoked, or all.",
            ));
        }
    };
    let limit = crate::validation::parse_bounded_u64(ctx.req.query("limit").as_deref(), 1, 100, 25)
        .map_err(|m| ApiError::Unprocessable(vec![FieldError::new("limit", m)]))?
        as usize;
    let offset =
        crate::validation::parse_bounded_u64(ctx.req.query("offset").as_deref(), 0, 100_000, 0)
            .map_err(|m| ApiError::Unprocessable(vec![FieldError::new("offset", m)]))?
            as usize;
    let newest_first = matches!(ctx.req.query("sort").as_deref(), Some("newest") | None);
    let query = crate::users::UserQuery {
        text: ctx.req.query("q").filter(|t| !t.is_empty()),
        status,
        newest_first,
        limit,
        offset,
    };
    let (views, total, truncated) = ctx.users().list_users(&query)?;
    Ok(Resp::json(
        200,
        &serde_json::json!({
            "users": views,
            "total": total,
            "limit": limit,
            "offset": offset,
            "truncated": truncated,
        }),
    )
    .with_security_headers()
    .header("Cache-Control", "no-store"))
}

pub fn get_user(ctx: &Ctx, _session: &Session, uid: &str) -> Result<Resp, ApiError> {
    let view = ctx.users().get_user(uid)?;
    Ok(Resp::json(200, &view)
        .with_security_headers()
        .header("Cache-Control", "no-store"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserPatchRequest {
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    app_role: Option<String>,
    #[serde(default)]
    metadata: Option<serde_json::Map<String, serde_json::Value>>,
}

pub fn patch_user(
    ctx: &Ctx,
    session: &Session,
    uid: &str,
    body: &UserPatchRequest,
) -> Result<Resp, ApiError> {
    let user = ctx.users().update_user(
        uid,
        body.display_name.clone(),
        body.app_role.clone(),
        body.metadata.clone(),
        &actor_admin(&session.username),
    )?;
    record_admin_op(
        ctx,
        session,
        AuditCategory::User,
        "update_user",
        &format!("user:{uid}"),
        None,
    )?;
    Ok(Resp::json(200, &ctx.users().user_view(&user)?)
        .with_security_headers()
        .header("Cache-Control", "no-store"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusActionRequest {
    action: String,
}

pub fn set_user_status(
    ctx: &Ctx,
    session: &Session,
    uid: &str,
    body: &StatusActionRequest,
) -> Result<Resp, ApiError> {
    let user = ctx
        .users()
        .set_user_status(uid, &body.action, &actor_admin(&session.username))?;
    record_admin_op(
        ctx,
        session,
        AuditCategory::User,
        &format!("user_{}", body.action),
        &format!("user:{uid}"),
        None,
    )?;
    Ok(Resp::json(200, &ctx.users().user_view(&user)?)
        .with_security_headers()
        .header("Cache-Control", "no-store"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialIssueRequest {
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    ttl_s: Option<u64>,
}

pub fn issue_credential(
    ctx: &Ctx,
    session: &Session,
    uid: &str,
    body: &CredentialIssueRequest,
) -> Result<Resp, ApiError> {
    if let Some(ttl) = body.ttl_s {
        if !(60..=31_536_000).contains(&ttl) {
            return Err(ApiError::Unprocessable(vec![FieldError::new(
                "ttl_s",
                "must be between 60 and 31536000 seconds",
            )]));
        }
    }
    let (raw, cred) = ctx.users().issue_credential(
        uid,
        body.label.clone(),
        body.ttl_s,
        &actor_admin(&session.username),
    )?;
    record_admin_op(
        ctx,
        session,
        AuditCategory::Credential,
        "issue_credential",
        &format!("user:{uid}/cred:{}", cred.cred_id),
        Some(format!(
            "fingerprint={}",
            crate::audit::fingerprint_prefix(&cred.token_hash)
        )),
    )?;
    ctx_app_metrics(ctx, MetricKind::TokensIssued);
    // The raw token appears exactly once, in this response, and nowhere else.
    Ok(Resp::json(
        201,
        &serde_json::json!({
            "credential": {
                "cred_id": cred.cred_id,
                "token": raw,
                "display_once": true,
                "issued_at": timeutil::format_rfc3339_utc(cred.issued_at),
                "expires_at": cred.expires_at.map(timeutil::format_rfc3339_utc),
                "label": cred.label,
                "fingerprint": crate::audit::fingerprint_prefix(&cred.token_hash),
            },
            "usage": "POST /api/v1/token with {\"token\": \"...\"} to obtain a short-lived access token",
        }),
    )
    .with_security_headers()
    .header("Cache-Control", "no-store"))
}

pub fn revoke_credential(
    ctx: &Ctx,
    session: &Session,
    uid: &str,
    cred_id: &str,
) -> Result<Resp, ApiError> {
    let user = ctx
        .users()
        .revoke_credential(uid, cred_id, &actor_admin(&session.username))?;
    record_admin_op(
        ctx,
        session,
        AuditCategory::Credential,
        "revoke_credential",
        &format!("user:{uid}/cred:{cred_id}"),
        Some(format!("cred_version={}", user.cred_version)),
    )?;
    Ok(Resp::json(200, &ctx.users().user_view(&user)?)
        .with_security_headers()
        .header("Cache-Control", "no-store"))
}

pub fn get_subscription(ctx: &Ctx, _session: &Session, uid: &str) -> Result<Resp, ApiError> {
    // Validate the user exists (404 otherwise) before reading the record.
    let _ = ctx.users().get_user(uid)?;
    let sub = load_sub_or_404(ctx, uid)?;
    Ok(Resp::json(200, &subscription_view(&sub, ctx.now()))
        .with_security_headers()
        .header("Cache-Control", "no-store"))
}

fn load_sub_or_404(ctx: &Ctx, uid: &str) -> Result<crate::models::SubscriptionRecord, ApiError> {
    let raw = ctx
        .app
        .store
        .get(&keys::subscription(uid))
        .map_err(|_| ApiError::StorageUnavailable)?
        .ok_or(ApiError::NotFound("Resource not found."))?;
    let sub: crate::models::SubscriptionRecord = serde_json::from_slice(&raw).map_err(|_| {
        ApiError::Unprocessable(vec![FieldError::new(
            "subscription",
            "stored record is malformed",
        )])
    })?;
    Ok(sub)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionPutRequest {
    #[serde(default)]
    status: Option<String>,
    #[serde(default, deserialize_with = "double_option::deserialize")]
    expires_at: Option<Option<String>>,
    #[serde(default)]
    entitlement_id: Option<String>,
}

pub fn put_subscription(
    ctx: &Ctx,
    session: &Session,
    uid: &str,
    body: &SubscriptionPutRequest,
) -> Result<Resp, ApiError> {
    let mut errs = vec![];
    let status = match body.status.as_deref() {
        None => None,
        Some("active") => Some(SubscriptionStatus::Active),
        Some("suspended") => Some(SubscriptionStatus::Suspended),
        Some("revoked") => Some(SubscriptionStatus::Revoked),
        _ => {
            errs.push(FieldError::new(
                "status",
                "must be active, suspended, or revoked",
            ));
            None
        }
    };
    let expires_at: Option<Option<u64>> = match &body.expires_at {
        None => None,
        Some(None) => Some(None),
        Some(Some(raw)) => Some(crate::validation::validate_future_timestamp(
            raw,
            ctx.now(),
            60,
            "expires_at",
            &mut errs,
        )),
    };
    if !errs.is_empty() {
        return Err(ApiError::Unprocessable(errs));
    }
    let sub = ctx.users().set_subscription(
        uid,
        status,
        expires_at,
        body.entitlement_id.clone(),
        &actor_admin(&session.username),
    )?;
    record_admin_op(
        ctx,
        session,
        AuditCategory::Subscription,
        "update_subscription",
        &format!("user:{uid}/subscription"),
        Some(crate::users::subscription_summary(&sub)),
    )?;
    Ok(Resp::json(200, &subscription_view(&sub, ctx.now()))
        .with_security_headers()
        .header("Cache-Control", "no-store"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenewRequest {
    #[serde(default)]
    extend_days: Option<u64>,
    #[serde(default)]
    until: Option<String>,
}

pub fn renew_subscription(
    ctx: &Ctx,
    session: &Session,
    uid: &str,
    body: &RenewRequest,
) -> Result<Resp, ApiError> {
    let mut errs = vec![];
    if let Some(d) = body.extend_days {
        if !(1..=3_650).contains(&d) {
            errs.push(FieldError::new(
                "extend_days",
                "must be between 1 and 3650 days",
            ));
        }
    }
    let until = match &body.until {
        None => None,
        Some(raw) => {
            crate::validation::validate_future_timestamp(raw, ctx.now(), 60, "until", &mut errs)
        }
    };
    if !errs.is_empty() {
        return Err(ApiError::Unprocessable(errs));
    }
    let sub = ctx.users().renew_subscription(
        uid,
        body.extend_days,
        until,
        &actor_admin(&session.username),
    )?;
    record_admin_op(
        ctx,
        session,
        AuditCategory::Subscription,
        "renew_subscription",
        &format!("user:{uid}/subscription"),
        Some(crate::users::subscription_summary(&sub)),
    )?;
    Ok(Resp::json(200, &subscription_view(&sub, ctx.now()))
        .with_security_headers()
        .header("Cache-Control", "no-store"))
}

// ---------------------------------------------------------------------------
// Bulk operations — one batched control-plane write, per-record outcomes
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BulkRequest {
    pub uids: Vec<String>,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub extend_days: Option<u64>,
    #[serde(default)]
    pub until: Option<String>,
}

pub fn bulk(ctx: &Ctx, session: &Session, body: &BulkRequest) -> Result<Resp, ApiError> {
    if body.uids.is_empty() || body.uids.len() > 100 {
        return Err(ApiError::Unprocessable(vec![FieldError::new(
            "uids",
            "provide between 1 and 100 ids",
        )]));
    }
    let actor = actor_admin(&session.username);
    let now = ctx.now();

    let until_ts = match &body.until {
        Some(raw) => match timeutil::parse_rfc3339_utc(raw) {
            Some(t) if t > now => Some(t),
            _ => {
                return Err(ApiError::Unprocessable(vec![FieldError::new(
                    "until",
                    "must be a future RFC3339 UTC timestamp",
                )]))
            }
        },
        None => None,
    };

    let outcome = match body.action.as_str() {
        "suspend" | "reactivate" | "revoke" => {
            let action = body.action.clone();
            ctx.users().bulk_set_status(&body.uids, &action, &actor)
        }
        "renew" => ctx
            .users()
            .bulk_renew(&body.uids, body.extend_days, until_ts, &actor),
        _ => {
            return Err(ApiError::Unprocessable(vec![FieldError::new(
                "action",
                "must be suspend, reactivate, revoke, or renew",
            )]))
        }
    }?;

    let rows: Vec<serde_json::Value> = outcome
        .rows
        .iter()
        .map(|(i, res, reason)| {
            if *res == "ok" {
                serde_json::json!({"uid": body.uids[*i], "outcome": "ok"})
            } else {
                serde_json::json!({"uid": body.uids[*i], "outcome": "error", "reason": reason})
            }
        })
        .collect();
    let total = body.uids.len();
    record_admin_op(
        ctx,
        session,
        AuditCategory::User,
        &format!("bulk_{}", body.action),
        &format!("users:{total}"),
        Some(format!("ok={}", outcome.ok)),
    )?;
    Ok(Resp::json(
        200,
        &serde_json::json!({"ok": outcome.ok, "total": total, "results": rows}),
    )
    .with_security_headers()
    .header("Cache-Control", "no-store"))
}

// ---------------------------------------------------------------------------
// Audit listing / config / roles / import / export
// ---------------------------------------------------------------------------

pub fn list_audit(ctx: &Ctx, _session: &Session) -> Result<Resp, ApiError> {
    let category = match ctx.req.query("category").as_deref() {
        None | Some("") => None,
        Some("auth") => Some(AuditCategory::Auth),
        Some("user") => Some(AuditCategory::User),
        Some("subscription") => Some(AuditCategory::Subscription),
        Some("credential") => Some(AuditCategory::Credential),
        Some("config") => Some(AuditCategory::Config),
        Some("security") => Some(AuditCategory::Security),
        Some("import") => Some(AuditCategory::Import),
        Some("export") => Some(AuditCategory::Export),
        Some("system") => Some(AuditCategory::System),
        _ => return Err(ApiError::BadRequest("unknown audit category.")),
    };
    let outcome = match ctx.req.query("outcome").as_deref() {
        None | Some("") => None,
        Some("ok") => Some(AuditOutcome::Ok),
        Some("denied") => Some(AuditOutcome::Denied),
        Some("error") => Some(AuditOutcome::Error),
        _ => {
            return Err(ApiError::BadRequest(
                "outcome must be ok, denied, or error.",
            ))
        }
    };
    let limit = crate::validation::parse_bounded_u64(ctx.req.query("limit").as_deref(), 1, 100, 25)
        .map_err(|m| ApiError::Unprocessable(vec![FieldError::new("limit", m)]))?
        as usize;
    let offset =
        crate::validation::parse_bounded_u64(ctx.req.query("offset").as_deref(), 0, 100_000, 0)
            .map_err(|m| ApiError::Unprocessable(vec![FieldError::new("offset", m)]))?
            as usize;
    let query = crate::audit::AuditQuery {
        category,
        actor: ctx.req.query("actor").filter(|a| !a.is_empty()),
        target: ctx.req.query("target").filter(|t| !t.is_empty()),
        outcome,
    };
    let (events, has_more) = ctx.audit().list(&query, limit, offset)?;
    Ok(Resp::json(
        200,
        &serde_json::json!({
            "events": events.iter().map(audit_view).collect::<Vec<_>>(),
            "limit": limit,
            "offset": offset,
            "has_more": has_more,
        }),
    )
    .with_security_headers()
    .header("Cache-Control", "no-store"))
}

pub fn get_config(ctx: &Ctx, _session: &Session) -> Result<Resp, ApiError> {
    let cfg = ctx.app.load_config()?;
    Ok(Resp::json(200, &config_view(&cfg))
        .with_security_headers()
        .header("Cache-Control", "no-store"))
}

fn config_view(cfg: &AppConfig) -> serde_json::Value {
    serde_json::json!({
        "schema_version": cfg.schema_version,
        "session_ttl_s": cfg.session_ttl_s,
        "step_up_ttl_s": cfg.step_up_ttl_s,
        "app_token_ttl_s": cfg.app_token_ttl_s,
        "login_max_attempts": cfg.login_max_attempts,
        "login_window_s": cfg.login_window_s,
        "import_batch_max": cfg.import_batch_max,
        "audit_retention_days": cfg.audit_retention_days,
        "pbkdf2_iterations": cfg.pbkdf2_iterations,
        "version": cfg.version,
        "updated_at": timeutil::format_rfc3339_utc(cfg.updated_at),
        "updated_by": cfg.updated_by,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigPutRequest {
    session_ttl_s: u64,
    step_up_ttl_s: u64,
    app_token_ttl_s: u64,
    login_max_attempts: u32,
    login_window_s: u64,
    import_batch_max: usize,
    audit_retention_days: u32,
    pbkdf2_iterations: u32,
}

pub fn put_config(ctx: &Ctx, session: &Session, body: &ConfigPutRequest) -> Result<Resp, ApiError> {
    let mut cfg = ctx.app.load_config()?;
    cfg.session_ttl_s = body.session_ttl_s;
    cfg.step_up_ttl_s = body.step_up_ttl_s;
    cfg.app_token_ttl_s = body.app_token_ttl_s;
    cfg.login_max_attempts = body.login_max_attempts;
    cfg.login_window_s = body.login_window_s;
    cfg.import_batch_max = body.import_batch_max;
    cfg.audit_retention_days = body.audit_retention_days;
    cfg.pbkdf2_iterations = body.pbkdf2_iterations;
    let mut errs = vec![];
    cfg.validate(&mut errs);
    if !errs.is_empty() {
        return Err(ApiError::Unprocessable(errs));
    }
    cfg.version += 1;
    cfg.updated_at = ctx.now();
    cfg.updated_by = actor_admin(&session.username);
    ctx.app
        .store
        .put(
            keys::CONFIG,
            serde_json::to_vec(&cfg).map_err(|_| ApiError::Internal)?,
        )
        .map_err(|_| ApiError::ControlPlane("The change could not be persisted."))?;
    record_admin_op(
        ctx,
        session,
        AuditCategory::Config,
        "update_config",
        "system:config",
        Some(format!("version={}", cfg.version)),
    )?;
    Ok(Resp::json(200, &config_view(&cfg))
        .with_security_headers()
        .header("Cache-Control", "no-store"))
}

pub fn roles(_ctx: &Ctx, session: &Session) -> Result<Resp, ApiError> {
    let matrix: Vec<serde_json::Value> = crate::auth::all_permissions()
        .iter()
        .map(|p| {
            let allowed: Vec<&str> = [
                AdminRole::SuperAdmin,
                AdminRole::Admin,
                AdminRole::SubscriptionManager,
                AdminRole::Operator,
                AdminRole::Auditor,
            ]
            .iter()
            .filter(|r| crate::auth::permissions_for(**r).contains(p))
            .map(|r| r.as_str())
            .collect();
            serde_json::json!({"permission": p.as_str(), "roles": allowed})
        })
        .collect();
    Ok(Resp::json(
        200,
        &serde_json::json!({
            "roles": [
                {"role": "super_admin", "description": "Full access to every capability."},
                {"role": "admin", "description": "Full operational access (same permissions as super_admin in this release)."},
                {"role": "subscription_manager", "description": "Manage subscriptions and credentials; read users."},
                {"role": "operator", "description": "Read-only operations plus sanitized export."},
                {"role": "auditor", "description": "Audit log, metrics, and user/subscription reads."},
            ],
            "permissions": matrix,
            "your_role": session.role.as_str(),
        }),
    )
    .with_security_headers()
    .header("Cache-Control", "no-store"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportRequest {
    #[serde(default)]
    pub include_credentials: bool,
}

pub fn export(ctx: &Ctx, session: &Session, body: &ExportRequest) -> Result<Resp, ApiError> {
    let include_creds = body.include_credentials
        && session.role == AdminRole::SuperAdmin
        && session.has_step_up(ctx.now());
    let data = ctx.users().export_all(include_creds)?;
    let ev = ctx
        .audit()
        .new_event(
            AuditCategory::Export,
            "export_data",
            &actor_admin(&session.username),
            "system:data",
            AuditOutcome::Ok,
            ctx.request_id,
            Some(format!("include_credentials={include_creds}")),
        )
        .map_err(|_| ApiError::Internal)?;
    ctx.audit().record_best_effort(&ev);
    ctx_app_metrics(ctx, MetricKind::AdminOperations);
    Ok(Resp::json(200, &data)
        .with_security_headers()
        .header("Cache-Control", "no-store"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportRequest {
    #[serde(default)]
    pub apply: bool,
}

pub fn import(
    ctx: &Ctx,
    session: &Session,
    body: &ImportRequest,
    payload: &serde_json::Value,
) -> Result<Resp, ApiError> {
    let cfg = ctx.app.load_config()?;
    let report =
        ctx.users()
            .import_users(payload, body.apply, &cfg, &actor_admin(&session.username))?;
    let ev = ctx
        .audit()
        .new_event(
            AuditCategory::Import,
            if body.apply {
                "import_apply"
            } else {
                "import_dry_run"
            },
            &actor_admin(&session.username),
            "system:data",
            AuditOutcome::Ok,
            ctx.request_id,
            Some(format!(
                "created={}",
                report["created"].as_u64().unwrap_or(0)
            )),
        )
        .map_err(|_| ApiError::Internal)?;
    if body.apply {
        ctx.audit().record_critical(&ev)?;
    } else {
        ctx.audit().record_best_effort(&ev);
    }
    if body.apply {
        ctx_app_metrics(ctx, MetricKind::AdminOperations);
    }
    Ok(Resp::json(200, &report)
        .with_security_headers()
        .header("Cache-Control", "no-store"))
}

// ---------------------------------------------------------------------------
// Admin account management (roles section)
// ---------------------------------------------------------------------------

pub fn list_admins(ctx: &Ctx, _session: &Session) -> Result<Resp, ApiError> {
    let keys_found = ctx
        .app
        .store
        .scan("admins/*")
        .map_err(|_| ApiError::StorageUnavailable)?;
    let mut admins = Vec::new();
    for k in keys_found {
        let raw = match ctx.app.store.get(&k) {
            Ok(Some(v)) => v,
            _ => continue,
        };
        let rec: AdminRecord = match serde_json::from_slice(&raw) {
            Ok(r) => r,
            Err(_) => continue,
        };
        admins.push(serde_json::json!({
            "username": rec.username,
            "role": rec.role.as_str(),
            "created_at": timeutil::format_rfc3339_utc(rec.created_at),
            "last_login_at": rec.last_login_at.map(timeutil::format_rfc3339_utc),
        }));
    }
    Ok(Resp::json(200, &serde_json::json!({"admins": admins}))
        .with_security_headers()
        .header("Cache-Control", "no-store"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminCreateRequest {
    username: String,
    password: String,
    role: String,
}

pub fn create_admin(
    ctx: &Ctx,
    session: &Session,
    body: &AdminCreateRequest,
) -> Result<Resp, ApiError> {
    let mut errs = vec![];
    if !crate::validation::is_username(&body.username) {
        errs.push(FieldError::new(
            "username",
            "must be 3-32 chars, lowercase letters/digits/._-",
        ));
    }
    if body.password.len() < 12 {
        errs.push(FieldError::new(
            "password",
            "must be at least 12 characters",
        ));
    }
    if body.password.len() > 256 {
        errs.push(FieldError::new(
            "password",
            "must be at most 256 characters",
        ));
    }
    let role = crate::auth::role_from_str(&body.role).ok_or_else(|| {
        errs.push(FieldError::new("role", "unknown role"));
        ApiError::Unprocessable(errs.clone())
    })?;
    if !errs.is_empty() {
        return Err(ApiError::Unprocessable(errs));
    }
    let existing = ctx
        .app
        .store
        .get(&keys::admin(&body.username))
        .map_err(|_| ApiError::StorageUnavailable)?;
    if existing.is_some() {
        return Err(ApiError::Conflict(
            "An administrator with this username already exists.",
        ));
    }
    let cfg = ctx.app.load_config()?;
    let rec = AdminRecord {
        schema_version: ADMIN_SCHEMA_VERSION,
        username: body.username.clone(),
        role,
        password_hash: crate::crypto::hash_password(&body.password, cfg.pbkdf2_iterations),
        created_at: ctx.now(),
        created_by: actor_admin(&session.username),
        updated_at: ctx.now(),
        last_login_at: None,
    };
    ctx.app
        .store
        .put(
            &keys::admin(&rec.username),
            serde_json::to_vec(&rec).map_err(|_| ApiError::Internal)?,
        )
        .map_err(|_| ApiError::ControlPlane("The change could not be persisted."))?;
    record_admin_op(
        ctx,
        session,
        AuditCategory::Security,
        "create_admin",
        &format!("admin:{}", body.username),
        Some(format!("role={}", role.as_str())),
    )?;
    Ok(Resp::json(
        201,
        &serde_json::json!({"username": body.username, "role": role.as_str()}),
    )
    .with_security_headers()
    .header("Cache-Control", "no-store"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminPatchRequest {
    role: String,
}

pub fn patch_admin(
    ctx: &Ctx,
    session: &Session,
    username: &str,
    body: &AdminPatchRequest,
) -> Result<Resp, ApiError> {
    if !crate::validation::is_username(username) {
        return Err(ApiError::NotFound("Resource not found."));
    }
    if username == session.username {
        return Err(ApiError::Conflict("You cannot change your own role."));
    }
    let new_role = crate::auth::role_from_str(&body.role).ok_or(ApiError::Unprocessable(vec![
        FieldError::new("role", "unknown role"),
    ]))?;
    let mut rec: AdminRecord = load_admin(ctx, username)?;
    let old_role = rec.role;
    rec.role = new_role;
    rec.updated_at = ctx.now();
    if old_role == AdminRole::SuperAdmin && new_role != AdminRole::SuperAdmin {
        ensure_last_super_admin(ctx, username)?;
    }
    ctx.app
        .store
        .put(
            &keys::admin(username),
            serde_json::to_vec(&rec).map_err(|_| ApiError::Internal)?,
        )
        .map_err(|_| ApiError::ControlPlane("The change could not be persisted."))?;
    record_admin_op(
        ctx,
        session,
        AuditCategory::Security,
        "update_admin",
        &format!("admin:{username}"),
        Some(format!("role={}->{}", old_role.as_str(), new_role.as_str())),
    )?;
    Ok(Resp::json(
        200,
        &serde_json::json!({"username": username, "role": new_role.as_str()}),
    )
    .with_security_headers()
    .header("Cache-Control", "no-store"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminPasswordRequest {
    password: String,
}

pub fn reset_admin_password(
    ctx: &Ctx,
    session: &Session,
    username: &str,
    body: &AdminPasswordRequest,
) -> Result<Resp, ApiError> {
    if !crate::validation::is_username(username) {
        return Err(ApiError::NotFound("Resource not found."));
    }
    if body.password.len() < 12 || body.password.len() > 256 {
        return Err(ApiError::Unprocessable(vec![FieldError::new(
            "password",
            "must be 12-256 characters",
        )]));
    }
    let mut rec = load_admin(ctx, username)?;
    let cfg = ctx.app.load_config()?;
    rec.password_hash = crate::crypto::hash_password(&body.password, cfg.pbkdf2_iterations);
    rec.updated_at = ctx.now();
    ctx.app
        .store
        .put(
            &keys::admin(username),
            serde_json::to_vec(&rec).map_err(|_| ApiError::Internal)?,
        )
        .map_err(|_| ApiError::ControlPlane("The change could not be persisted."))?;
    record_admin_op(
        ctx,
        session,
        AuditCategory::Security,
        "reset_admin_password",
        &format!("admin:{username}"),
        None,
    )?;
    Ok(Resp::json(200, &serde_json::json!({"ok": true}))
        .with_security_headers()
        .header("Cache-Control", "no-store"))
}

pub fn delete_admin(ctx: &Ctx, session: &Session, username: &str) -> Result<Resp, ApiError> {
    if !crate::validation::is_username(username) {
        return Err(ApiError::NotFound("Resource not found."));
    }
    if username == session.username {
        return Err(ApiError::Conflict("You cannot delete your own account."));
    }
    load_admin(ctx, username)?;
    ensure_last_super_admin(ctx, username)?;
    ctx.app
        .store
        .delete(&keys::admin(username))
        .map_err(|_| ApiError::ControlPlane("The change could not be persisted."))?;
    record_admin_op(
        ctx,
        session,
        AuditCategory::Security,
        "delete_admin",
        &format!("admin:{username}"),
        None,
    )?;
    Ok(Resp::json(200, &serde_json::json!({"ok": true}))
        .with_security_headers()
        .header("Cache-Control", "no-store"))
}

fn load_admin(ctx: &Ctx, username: &str) -> Result<AdminRecord, ApiError> {
    let raw = ctx
        .app
        .store
        .get(&keys::admin(username))
        .map_err(|_| ApiError::StorageUnavailable)?
        .ok_or(ApiError::NotFound("Resource not found."))?;
    serde_json::from_slice(&raw).map_err(|_| {
        ApiError::Unprocessable(vec![FieldError::new(
            "username",
            "stored record is malformed",
        )])
    })
}

/// Guard: the account must always retain at least one super_admin.
fn ensure_last_super_admin(ctx: &Ctx, removing: &str) -> Result<(), ApiError> {
    let keys_found = ctx
        .app
        .store
        .scan("admins/*")
        .map_err(|_| ApiError::StorageUnavailable)?;
    let mut supers = 0;
    for k in keys_found {
        let name = k.rsplit('/').next().unwrap_or("");
        if name == removing {
            continue;
        }
        if let Ok(Some(raw)) = ctx.app.store.get(&keys::admin(name)) {
            if let Ok(rec) = serde_json::from_slice::<AdminRecord>(&raw) {
                if rec.role == AdminRole::SuperAdmin {
                    supers += 1;
                }
            }
        }
    }
    if supers == 0 {
        return Err(ApiError::Conflict("At least one super_admin must remain."));
    }
    Ok(())
}
