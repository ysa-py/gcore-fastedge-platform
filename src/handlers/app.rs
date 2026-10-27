//! Request handlers: the application API (`/api/v1/*`) for end users.

use crate::app::App;
use crate::audit::{redact, Audit};
use crate::authorization::AuthorizationService;
use crate::errors::ApiError;
use crate::http::{Req, Resp};
use crate::metrics::MetricKind;
use crate::models::{AuditCategory, AuditOutcome};
use crate::timeutil;
use serde::Deserialize;

pub struct Ctx<'a> {
    pub app: &'a App<'a>,
    pub req: &'a Req,
    pub request_id: &'a str,
}

impl Ctx<'_> {
    fn now(&self) -> u64 {
        self.app.clock.now_unix()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenExchangeRequest {
    token: String,
}

/// `POST /api/v1/token` — exchange a long-lived API credential for a
/// short-lived signed access token. Rate-limited per fingerprint.
pub fn exchange(ctx: &Ctx, body: &TokenExchangeRequest) -> Result<Resp, ApiError> {
    let cfg = ctx.app.load_config()?;
    // Per-token-fingerprint rate limit (no usable username here).
    let fp = crate::ids::token_fingerprint(&body.token);
    let rl_key = format!("rl:exchange:{}", &fp[..16]);
    if let Ok(count) = ctx.app.cache.incr(&rl_key, 1) {
        if count == 1 {
            let _ = ctx.app.cache.expire(&rl_key, 60_000);
        }
        if count > 30 {
            return Err(ApiError::TooManyRequests { retry_after_s: 60 });
        }
    }

    let svc = AuthorizationService {
        store: ctx.app.store,
        clock: ctx.app.clock,
    };
    let key = ctx
        .app
        .secrets
        .get(crate::authorization::APP_TOKEN_KEY_SECRET)
        .ok()
        .flatten()
        .ok_or(ApiError::Forbidden(
            "The application is not configured for token issuance.",
        ))?;
    if key.len() < 32 {
        return Err(ApiError::Forbidden(
            "The application is not configured for token issuance.",
        ));
    }

    match svc.exchange(&body.token, cfg.app_token_ttl_s) {
        Ok((claims, user, _sub)) => {
            let signed = crate::crypto::jwt_encode(&claims, &key);
            let audit = Audit {
                store: ctx.app.store,
                clock: ctx.app.clock,
            };
            if let Ok(ev) = audit.new_event(
                AuditCategory::Auth,
                "app_token_exchange",
                &format!("user:{}", user.uid),
                &format!("user:{}/token", user.uid),
                AuditOutcome::Ok,
                ctx.request_id,
                Some(format!(
                    "fingerprint={}",
                    crate::audit::fingerprint_prefix(&fp)
                )),
            ) {
                audit.record_best_effort(&ev);
            }
            crate::metrics::Metrics {
                cache: ctx.app.cache,
                clock: ctx.app.clock,
            }
            .incr(MetricKind::TokensIssued);
            Ok(Resp::json(
                200,
                &serde_json::json!({
                    "access_token": signed,
                    "token_type": "Bearer",
                    "expires_at": timeutil::format_rfc3339_utc(claims.exp),
                    "expires_in": cfg.app_token_ttl_s,
                    "scope": user.app_role,
                }),
            )
            .with_security_headers()
            .header("Cache-Control", "no-store"))
        }
        Err((api_err, deny)) => {
            let audit = Audit {
                store: ctx.app.store,
                clock: ctx.app.clock,
            };
            if let Ok(ev) = audit.new_event(
                AuditCategory::Security,
                "app_token_denied",
                "user:unknown",
                "token-exchange",
                AuditOutcome::Denied,
                ctx.request_id,
                Some(format!("reason={}", deny.detail())),
            ) {
                audit.record_best_effort(&ev);
            }
            crate::metrics::Metrics {
                cache: ctx.app.cache,
                clock: ctx.app.clock,
            }
            .incr(MetricKind::AuthFailures);
            let _ = redact("", 0);
            Err(api_err)
        }
    }
}

/// Shared verification for `/api/v1/me` and `/api/v1/entitlements`.
fn require_access_token(
    ctx: &Ctx,
) -> Result<
    (
        crate::crypto::Claims,
        crate::models::UserRecord,
        crate::models::SubscriptionRecord,
    ),
    ApiError,
> {
    let token = ctx
        .req
        .bearer()
        .ok_or(ApiError::Unauthorized("A Bearer access token is required."))?;
    let key = ctx
        .app
        .secrets
        .get(crate::authorization::APP_TOKEN_KEY_SECRET)
        .ok()
        .flatten()
        .ok_or(ApiError::Forbidden("The application is not configured."))?;
    if key.len() < 32 {
        return Err(ApiError::Forbidden("The application is not configured."));
    }
    let svc = AuthorizationService {
        store: ctx.app.store,
        clock: ctx.app.clock,
    };
    svc.verify_access_token(&token, &key)
        .map_err(|(e, _deny)| e)
}

pub fn me(ctx: &Ctx) -> Result<Resp, ApiError> {
    let (_claims, user, sub) = require_access_token(ctx)?;
    Ok(Resp::json(
        200,
        &serde_json::json!({
            "uid": user.uid,
            "email": user.email,
            "display_name": user.display_name,
            "app_role": user.app_role,
            "status": user.status.as_str(),
            "subscription": {
                "status": sub.status.as_str(),
                "entitlement_id": sub.entitlement_id,
                "expires_at": sub.expires_at.map(timeutil::format_rfc3339_utc),
                "derived_status": crate::users::subscription_view(&sub, ctx.now())["derived_status"],
            },
            "server_time": timeutil::format_rfc3339_utc(ctx.now()),
        }),
    )
    .with_security_headers()
    .header("Cache-Control", "no-store"))
}

pub fn entitlements(ctx: &Ctx) -> Result<Resp, ApiError> {
    let (_claims, user, sub) = require_access_token(ctx)?;
    Ok(Resp::json(
        200,
        &serde_json::json!({
            "uid": user.uid,
            "entitlement": {
                "id": sub.entitlement_id,
                "status": sub.status.as_str(),
                "expires_at": sub.expires_at.map(timeutil::format_rfc3339_utc),
                "boundaries": {
                    "rule": "access allowed while now < expires_at (UTC)",
                    "checked": "every request",
                },
            },
            "app_role": user.app_role,
            "server_time": timeutil::format_rfc3339_utc(ctx.now()),
        }),
    )
    .with_security_headers()
    .header("Cache-Control", "no-store"))
}
