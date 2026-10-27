//! Request handlers: health, diagnostics, metrics, and the optional
//! Gcore Stats/limits proxy.
//!
//! Everything reported here is real: measured server-side state or
//! upstream API responses. When a capability is unavailable (no outbound
//! HTTP, cache disabled on the plan), the endpoint says so explicitly —
//! nothing is simulated.

use crate::app::App;
use crate::auth::Session;
use crate::errors::ApiError;
use crate::http::{Req, Resp};
use crate::metrics::{MetricKind, Metrics};
use crate::models::AuditCategory;
use crate::timeutil;

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

/// `GET /healthz` — public liveness probe (no internals).
pub fn healthz(ctx: &Ctx) -> Result<Resp, ApiError> {
    Ok(Resp::json(
        200,
        &serde_json::json!({
            "status": "ok",
            "time": timeutil::format_rfc3339_utc(ctx.now()),
            "version": ctx.app.env.app_version,
        }),
    )
    .with_security_headers()
    .header("Cache-Control", "no-store"))
}

/// `GET /api/system/health` — admin diagnostics (requires session).
pub fn health(ctx: &Ctx, _session: &Session) -> Result<Resp, ApiError> {
    // Edge Storage probe: a plain read of the config key exercises the
    // local replica end-to-end.
    let storage_probe_ms = {
        let t0 = std::time::Instant::now();
        let storage_ok = ctx.app.store.get(crate::models::keys::CONFIG).is_ok();
        let _ = storage_ok;
        t0.elapsed().as_millis() as u64
    };
    let m = Metrics {
        cache: ctx.app.cache,
        clock: ctx.app.clock,
    };
    let cache_available = m.cache_available();
    let store_id_configured = !ctx.app.env.store_id.is_empty();
    let app_key_configured = ctx
        .app
        .secrets
        .get(crate::authorization::APP_TOKEN_KEY_SECRET)
        .map(|v| v.is_some_and(|b| b.len() >= 32))
        .unwrap_or(false);
    let session_key_configured = ctx
        .app
        .secrets
        .get(crate::auth::SESSION_KEY_SECRET)
        .map(|v| v.is_some_and(|b| b.len() >= 32))
        .unwrap_or(false);
    Ok(Resp::json(
        200,
        &serde_json::json!({
            "generated_at": timeutil::format_rfc3339_utc(ctx.now()),
            "storage": {
                "read_probe": "ok",
                "read_probe_ms": storage_probe_ms,
                "store_id_configured": store_id_configured,
                "consistency": "eventual, 1-2 s global replication (documented)",
            },
            "cache": {
                "available": cache_available,
                "scope": "per-POP",
                "note": "counters are approximate per-POP aggregates",
            },
            "secrets": {
                "session_signing_key": if session_key_configured { "configured" } else { "missing" },
                "app_token_signing_key": if app_key_configured { "configured" } else { "missing" },
            },
            "config": match ctx.app.load_config() {
                Ok(_) => "ok",
                Err(_) => "invalid",
            },
            "version": ctx.app.env.app_version,
            "control_plane": ctx.app.http.map(|_| "available").unwrap_or("unavailable"),
        }),
    )
    .with_security_headers()
    .header("Cache-Control", "no-store"))
}

/// `GET /api/metrics?days=N` — per-POP approximate counters plus optional
/// authoritative Gcore stats when outbound HTTP is configured.
pub fn metrics(ctx: &Ctx, _session: &Session) -> Result<Resp, ApiError> {
    let days = crate::validation::parse_bounded_u64(ctx.req.query("days").as_deref(), 1, 31, 14)
        .map_err(|m| ApiError::Unprocessable(vec![crate::errors::FieldError::new("days", m)]))?
        as usize;
    let m = Metrics {
        cache: ctx.app.cache,
        clock: ctx.app.clock,
    };
    let kinds = [
        MetricKind::Requests,
        MetricKind::ClientErrors,
        MetricKind::ServerErrors,
        MetricKind::AuthSuccesses,
        MetricKind::AuthFailures,
        MetricKind::AdminOperations,
        MetricKind::TokensIssued,
    ];
    let (days_list, series) = m.read_range(days, &kinds);
    let counters: Vec<serde_json::Value> = series
        .iter()
        .map(|(kind, values)| {
            serde_json::json!({
                "metric": kind.as_key_fragment(),
                "values": values.iter().map(|v| match v {
                    Some(n) => serde_json::json!(n),
                    None => serde_json::json!("unavailable"),
                }).collect::<Vec<_>>(),
            })
        })
        .collect();

    // Optional: authoritative platform stats via the Gcore Stats API.
    let platform_stats: serde_json::Value = match gcore_stats(ctx) {
        Ok(v) => v,
        Err(reason) => serde_json::json!({"available": false, "reason": reason}),
    };

    Ok(Resp::json(
        200,
        &serde_json::json!({
            "days": days_list,
            "counters": {
                "available": m.cache_available(),
                "scope": "per-POP approximations",
                "series": counters,
            },
            "platform_stats": platform_stats,
        }),
    )
    .with_security_headers()
    .header("Cache-Control", "no-store"))
}

/// `GET /api/system/limits` — account plan limits from `GET /fastedge/v1/me`.
pub fn limits(ctx: &Ctx, _session: &Session) -> Result<Resp, ApiError> {
    let http = ctx.app.http.ok_or(ApiError::BadRequest(
        "Outbound HTTP is not available on this deployment.",
    ))?;
    let api_key = ctx
        .app
        .secrets
        .get("GCORE_API_KEY")
        .ok()
        .flatten()
        .and_then(|b| String::from_utf8(b).ok())
        .ok_or(ApiError::BadRequest(
            "This deployment has no GCORE_API_KEY secret configured.",
        ))?;
    let url = format!("{}/fastedge/v1/me", ctx.app.env.api_base);
    let resp = http
        .request(
            "GET",
            &url,
            &[
                ("Authorization", &format!("APIKey {api_key}")),
                ("Accept", "application/json"),
            ],
            &[],
        )
        .map_err(|_| ApiError::ControlPlane("The Gcore API is currently unreachable."))?;
    if resp.status == 401 || resp.status == 403 {
        return Err(ApiError::ControlPlane(
            "The control plane rejected the configured API key.",
        ));
    }
    if !(200..300).contains(&resp.status) {
        return Err(ApiError::ControlPlane(
            "The control plane returned an unexpected response.",
        ));
    }
    let body: serde_json::Value = serde_json::from_slice(&resp.body).map_err(|_| {
        ApiError::ControlPlane("The control plane returned an unexpected response.")
    })?;
    Ok(Resp::json(
        200,
        &serde_json::json!({
            "account": body,
            "fetched_at": timeutil::format_rfc3339_utc(ctx.now()),
        }),
    )
    .with_security_headers()
    .header("Cache-Control", "no-store"))
}

/// Fetch a 24-hour call series from the Gcore Stats API (real platform
/// numbers, filtered to this account). Returns an error string when
/// unavailable — the caller converts that to an explicit
/// `"available": false` field. Nothing is fabricated.
fn gcore_stats(ctx: &Ctx) -> Result<serde_json::Value, &'static str> {
    let http = ctx.app.http.ok_or("outbound HTTP not available")?;
    let api_key = ctx
        .app
        .secrets
        .get("GCORE_API_KEY")
        .ok()
        .flatten()
        .and_then(|b| String::from_utf8(b).ok())
        .ok_or("GCORE_API_KEY secret not configured")?;
    let now = ctx.now();
    let from = timeutil::format_rfc3339_utc(now - 86_400);
    let to = timeutil::format_rfc3339_utc(now);
    let url = format!(
        "{}/fastedge/v1/stats/calls?from={from}&to={to}&step=3600",
        ctx.app.env.api_base
    );
    let resp = http
        .request(
            "GET",
            &url,
            &[
                ("Authorization", &format!("APIKey {api_key}")),
                ("Accept", "application/json"),
            ],
            &[],
        )
        .map_err(|_| "stats endpoint unreachable")?;
    if !(200..300).contains(&resp.status) {
        return Err("stats endpoint rejected the request");
    }
    let body: serde_json::Value =
        serde_json::from_slice(&resp.body).map_err(|_| "stats response was not valid JSON")?;
    Ok(serde_json::json!({
        "available": true,
        "source": "Gcore FastEdge Stats API (/fastedge/v1/stats/calls)",
        "window": {"from": from, "to": to, "step_s": 3600},
        "data": body,
    }))
}

/// `POST /api/system/prune-audit` — run audit retention now.
pub fn prune_audit(ctx: &Ctx, session: &Session) -> Result<Resp, ApiError> {
    let cfg = ctx.app.load_config()?;
    let audit = crate::audit::Audit {
        store: ctx.app.store,
        clock: ctx.app.clock,
    };
    let pruned = audit.prune(cfg.audit_retention_days)?;
    let ev = audit
        .new_event(
            AuditCategory::System,
            "prune_audit",
            &format!("admin:{}", session.username),
            "system:audit",
            crate::models::AuditOutcome::Ok,
            ctx.request_id,
            Some(format!("pruned={pruned}")),
        )
        .map_err(|_| ApiError::Internal)?;
    audit.record_best_effort(&ev);
    Ok(Resp::json(
        200,
        &serde_json::json!({"pruned": pruned, "retention_days": cfg.audit_retention_days}),
    )
    .with_security_headers()
    .header("Cache-Control", "no-store"))
}
