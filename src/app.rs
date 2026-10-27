//! Application container and runtime configuration.

use crate::platform::{Cache, Clock, HttpOut, Secrets, Store};

/// Environment-derived, non-secret runtime configuration. Set as FastEdge
/// environment variables (or dictionary entries) at deployment time.
#[derive(Debug, Clone)]
pub struct EnvConfig {
    /// Edge Storage store numeric id — required by the REST write path.
    pub store_id: String,
    /// Gcore API base URL (overridable for tests/proxies).
    pub api_base: String,
    /// Session cookie name. `__Host-` prefix variant is used when
    /// [`EnvConfig::insecure_cookie`] is false (production HTTPS).
    pub cookie_name: String,
    /// When true, cookies omit the `Secure` attribute — LOCAL fastedge-run
    /// testing over plain HTTP only. Never enable in production.
    pub insecure_cookie: bool,
    /// The deployment's own public origin (`https://host[:port]`), for
    /// deployments served behind a proxy that rewrites the `Host` header
    /// (a CDN front end, or the Base44 preview sandbox). Empty by default:
    /// the cross-site check then relies on `Host` alone, exactly as before.
    pub public_origin: String,
    pub app_version: &'static str,
}

impl Default for EnvConfig {
    fn default() -> Self {
        Self {
            store_id: String::new(),
            api_base: "https://api.gcore.com".into(),
            cookie_name: "__Host-fes".into(),
            insecure_cookie: false,
            public_origin: String::new(),
            app_version: env!("CARGO_PKG_VERSION"),
        }
    }
}

impl EnvConfig {
    pub fn effective_cookie_name(&self) -> &str {
        if self.cookie_name.is_empty() {
            if self.insecure_cookie {
                "fes_session"
            } else {
                "__Host-fes"
            }
        } else {
            &self.cookie_name
        }
    }
}

/// The whole application, wired for one request context. On wasm32 this is
/// constructed per request (cheap: everything is borrowed + lazy).
pub struct App<'a> {
    pub store: &'a dyn Store,
    pub cache: &'a dyn Cache,
    pub secrets: &'a dyn Secrets,
    pub clock: &'a dyn Clock,
    /// Outbound HTTP, when available — used only for the optional Gcore
    /// Stats/`me` proxy endpoints. `None` disables those endpoints
    /// (reported as unavailable, never faked).
    pub http: Option<&'a dyn HttpOut>,
    pub env: EnvConfig,
}

impl App<'_> {
    /// Load operational config from Edge Storage. Missing → defaults
    /// (documented bootstrap behavior). Malformed → error for callers that
    /// must not proceed on unknown state.
    pub fn config_or_default(&self) -> crate::models::AppConfig {
        self.load_config().unwrap_or_default()
    }

    pub fn load_config(&self) -> Result<crate::models::AppConfig, crate::errors::ApiError> {
        match self.store.get(crate::models::keys::CONFIG) {
            Ok(Some(raw)) => {
                let cfg: crate::models::AppConfig = serde_json::from_slice(&raw)
                    .map_err(|_| crate::errors::ApiError::StorageUnavailable)?;
                let mut errs = vec![];
                cfg.validate(&mut errs);
                if !errs.is_empty() {
                    return Err(crate::errors::ApiError::StorageUnavailable);
                }
                Ok(cfg)
            }
            Ok(None) => Ok(crate::models::AppConfig::default()),
            Err(_) => Err(crate::errors::ApiError::StorageUnavailable),
        }
    }
}
