//! Administrative authentication and RBAC.
//!
//! Sessions are short-lived HS256 JWTs in `HttpOnly; SameSite=Strict`
//! cookies. Three independent revocation surfaces exist:
//! 1. `exp` — hard expiry (default 30 min).
//! 2. per-session deny-list `sys/srev/{jti}` — logout (eventual, 1–2 s).
//! 3. session epoch `sys/session_epoch` — bumping invalidates ALL sessions
//!    (eventual, 1–2 s). Emergency logout everywhere.
//!
//! Permission checks are explicit strings; roles merely map to permission
//! sets. The frontend mirrors this matrix, but the server never trusts it.

use crate::crypto::{self, Claims};
use crate::errors::ApiError;
use crate::models::{keys, AdminRecord, AdminRole};
use crate::platform::{Cache, Clock, Secrets, Store};
use crate::validation;

pub const ISSUER: &str = "fap";
pub const AUD_ADMIN: &str = "admin";
pub const AUD_APP: &str = "app";
pub const SESSION_COOKIE: &str = "fes_session";
pub const SESSION_KEY_SECRET: &str = "SESSION_SIGNING_KEY";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Permission {
    OverviewRead,
    UsersRead,
    UsersManage,
    SubsRead,
    SubsManage,
    CredsRead,
    CredsManage,
    ConfigRead,
    ConfigManage,
    AuditRead,
    MetricsRead,
    SystemRead,
    ExportRun,
    ImportRun,
}

impl Permission {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::OverviewRead => "overview:read",
            Self::UsersRead => "users:read",
            Self::UsersManage => "users:manage",
            Self::SubsRead => "subs:read",
            Self::SubsManage => "subs:manage",
            Self::CredsRead => "creds:read",
            Self::CredsManage => "creds:manage",
            Self::ConfigRead => "config:read",
            Self::ConfigManage => "config:manage",
            Self::AuditRead => "audit:read",
            Self::MetricsRead => "metrics:read",
            Self::SystemRead => "system:read",
            Self::ExportRun => "export:run",
            Self::ImportRun => "import:run",
        }
    }
}

/// Every permission, in stable order (used by the roles matrix endpoint).
pub fn all_permissions() -> [Permission; 14] {
    use Permission::*;
    [
        OverviewRead,
        UsersRead,
        UsersManage,
        SubsRead,
        SubsManage,
        CredsRead,
        CredsManage,
        ConfigRead,
        ConfigManage,
        AuditRead,
        MetricsRead,
        SystemRead,
        ExportRun,
        ImportRun,
    ]
}

pub fn permissions_for(role: AdminRole) -> Vec<Permission> {
    use AdminRole::*;
    use Permission::*;
    match role {
        SuperAdmin => vec![
            OverviewRead,
            UsersRead,
            UsersManage,
            SubsRead,
            SubsManage,
            CredsRead,
            CredsManage,
            ConfigRead,
            ConfigManage,
            AuditRead,
            MetricsRead,
            SystemRead,
            ExportRun,
            ImportRun,
        ],
        Admin => vec![
            OverviewRead,
            UsersRead,
            UsersManage,
            SubsRead,
            SubsManage,
            CredsRead,
            CredsManage,
            ConfigRead,
            ConfigManage,
            AuditRead,
            MetricsRead,
            SystemRead,
            ExportRun,
            ImportRun,
        ],
        SubscriptionManager => vec![
            OverviewRead,
            UsersRead,
            SubsRead,
            SubsManage,
            CredsRead,
            CredsManage,
            AuditRead,
            MetricsRead,
        ],
        Operator => vec![
            OverviewRead,
            UsersRead,
            SubsRead,
            CredsRead,
            ConfigRead,
            AuditRead,
            MetricsRead,
            SystemRead,
            ExportRun,
        ],
        Auditor => vec![OverviewRead, UsersRead, SubsRead, AuditRead, MetricsRead],
    }
}

pub fn role_from_str(s: &str) -> Option<AdminRole> {
    match s {
        "super_admin" => Some(AdminRole::SuperAdmin),
        "admin" => Some(AdminRole::Admin),
        "subscription_manager" => Some(AdminRole::SubscriptionManager),
        "operator" => Some(AdminRole::Operator),
        "auditor" => Some(AdminRole::Auditor),
        _ => None,
    }
}

/// An authenticated admin session.
#[derive(Debug, Clone)]
pub struct Session {
    pub username: String,
    pub role: AdminRole,
    pub jti: String,
    pub exp: u64,
    /// Step-up authenticated until this unix time (0 = not stepped up).
    pub step_up_until: u64,
}

impl Session {
    pub fn can(&self, p: Permission) -> bool {
        permissions_for(self.role).contains(&p)
    }
    pub fn has_step_up(&self, now: u64) -> bool {
        self.step_up_until > now
    }
}

pub struct AuthService<'a> {
    pub store: &'a dyn Store,
    pub cache: &'a dyn Cache,
    pub secrets: &'a dyn Secrets,
    pub clock: &'a dyn Clock,
}

impl<'a> AuthService<'a> {
    fn signing_key(&self) -> Result<Vec<u8>, ApiError> {
        let raw = self
            .secrets
            .get(SESSION_KEY_SECRET)
            .map_err(|_| ApiError::Internal)?
            .ok_or(ApiError::Forbidden(
                "Sign-in is not configured on this deployment.",
            ))?;
        if raw.len() < 32 {
            return Err(ApiError::Forbidden(
                "Sign-in is not configured on this deployment.",
            ));
        }
        Ok(raw)
    }

    /// Read the current global session epoch (0 if unset).
    pub fn session_epoch(&self) -> u64 {
        self.store
            .get(keys::session_epoch())
            .ok()
            .flatten()
            .and_then(|v| String::from_utf8(v).ok())
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    }

    /// Parse a raw admin JWT into a verified [`Session`].
    ///
    /// Fail-closed: signature, expiry, issuer/audience, revocation list,
    /// and session epoch are all checked. Storage failures are treated as
    /// "cannot establish a session" (401/403), never as "allow".
    pub fn verify_session(&self, token: &str) -> Result<Session, ApiError> {
        let now = self.clock.now_unix();
        let claims = crypto::jwt_verify(token, &self.signing_key()?, AUD_ADMIN, ISSUER, now)
            .map_err(|_| ApiError::Unauthorized("The session is invalid or expired."))?;
        if claims.purpose.as_deref() != Some("admin-session") {
            return Err(ApiError::Unauthorized("The session is invalid or expired."));
        }
        let role = claims
            .role
            .as_deref()
            .and_then(role_from_str)
            .ok_or(ApiError::Unauthorized("The session is invalid or expired."))?;
        // Revocation surfaces. A storage error here must deny.
        let jti_revoked = match self.store.get(&keys::session_revoke(&claims.jti)) {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(_) => return Err(ApiError::Forbidden("Unable to verify the session.")),
        };
        if jti_revoked {
            return Err(ApiError::Unauthorized("The session has been revoked."));
        }
        let token_epoch = claims.ep.unwrap_or(0);
        if token_epoch < self.session_epoch_or_deny()? {
            return Err(ApiError::Unauthorized("The session has been revoked."));
        }
        Ok(Session {
            username: claims.sub,
            role,
            jti: claims.jti,
            exp: claims.exp,
            step_up_until: claims.su.unwrap_or(0),
        })
    }

    fn session_epoch_or_deny(&self) -> Result<u64, ApiError> {
        match self.store.get(keys::session_epoch()) {
            Ok(v) => Ok(v
                .and_then(|b| String::from_utf8(b).ok())
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0)),
            Err(_) => Err(ApiError::Forbidden("Unable to verify the session.")),
        }
    }

    fn mint(
        &self,
        username: &str,
        role: AdminRole,
        now: u64,
        ttl_s: u64,
        step_up_until: u64,
    ) -> Result<(String, Claims), ApiError> {
        let claims = Claims {
            iss: ISSUER.into(),
            aud: AUD_ADMIN.into(),
            sub: username.to_string(),
            iat: now,
            exp: now + ttl_s,
            jti: crate::ids::new_jti().map_err(|_| ApiError::Internal)?,
            purpose: Some("admin-session".into()),
            role: Some(role.as_str().into()),
            cv: None,
            su: if step_up_until > 0 {
                Some(step_up_until)
            } else {
                None
            },
            ep: Some(self.session_epoch_or_deny()?),
            nbf: None,
        };
        let token = crypto::jwt_encode(&claims, &self.signing_key()?);
        Ok((token, claims))
    }

    /// Attempt an admin login. Returns (token, username, role, max_age) on
    /// success; the caller sets the cookie and records an audit event.
    pub fn login(
        &self,
        username: &str,
        password: &str,
        ip_hint: Option<&str>,
        cfg: &crate::models::AppConfig,
    ) -> Result<(String, AdminRole), ApiError> {
        if !validation::is_username(username) {
            return Err(ApiError::Unauthorized("Invalid username or password."));
        }
        // Anti-enumeration: the same generic error for unknown user and
        // wrong password.
        let denied = ApiError::Unauthorized("Invalid username or password.");

        // Rate limit by username fingerprint (primary) and IP (secondary).
        self.check_rate_limit(
            "login",
            username,
            1,
            cfg.login_max_attempts,
            cfg.login_window_s,
        )?;
        if let Some(ip) = ip_hint {
            let _ = self.check_rate_limit("login-ip", ip, 1, 200, cfg.login_window_s);
        }

        let record: Option<AdminRecord> = self
            .store
            .get(&keys::admin(username))
            .map_err(|_| ApiError::Forbidden("Sign-in is unavailable right now."))?
            .and_then(|b| serde_json::from_slice(&b).ok());
        let now = self.clock.now_unix();

        let record = match record {
            Some(r) => r,
            // Bootstrap path: with ZERO admin records, the deployment
            // secrets (ADMIN_USERNAME + ADMIN_PASSWORD_HASH) may seed the
            // very first super_admin. Disabled permanently once any admin
            // record exists.
            None => match self.try_bootstrap(username, password)? {
                Some(r) => r,
                None => {
                    return Err(denied);
                }
            },
        };
        match crypto::verify_password(password, &record.password_hash) {
            Ok(true) => {}
            Ok(false) => {
                return Err(denied);
            }
            Err(_) => {
                // Corrupt/unsupported stored hash → treat as failed login,
                // never as access.
                return Err(denied);
            }
        }
        // Clear failure counters on success (best effort).
        let user_key = format!("rl:login:{}", crate::ids::token_fingerprint(username));
        let _ = self.cache.delete(&user_key);
        let (token, _claims) =
            self.mint(&record.username, record.role, now, cfg.session_ttl_s, 0)?;
        // Best-effort last-login update via control plane happens in the
        // handler (audit + record patch).
        Ok((token, record.role))
    }

    /// First-run bootstrap: allow ADMIN_USERNAME/ADMIN_PASSWORD_HASH
    /// secrets to sign in as super_admin ONLY while the admin store is
    /// empty. The handler persists the record so the secret is used
    /// exactly once; later logins run against the stored record.
    fn try_bootstrap(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<AdminRecord>, ApiError> {
        let admins = self
            .store
            .scan("admins/*")
            .map_err(|_| ApiError::Forbidden("Sign-in is unavailable right now."))?;
        if !admins.is_empty() {
            return Ok(None);
        }
        let read_secret = |name: &str| -> Option<String> {
            self.secrets
                .get(name)
                .ok()
                .flatten()
                .and_then(|b| String::from_utf8(b).ok())
        };
        let boot_user = read_secret("ADMIN_USERNAME");
        let boot_hash = read_secret("ADMIN_PASSWORD_HASH");
        if boot_user.as_deref() != Some(username) {
            return Ok(None);
        }
        let Some(hash) = boot_hash else {
            return Ok(None);
        };
        match crate::crypto::verify_password(password, &hash) {
            Ok(true) => Ok(Some(AdminRecord {
                schema_version: crate::models::ADMIN_SCHEMA_VERSION,
                username: username.to_string(),
                role: AdminRole::SuperAdmin,
                password_hash: hash,
                created_at: self.clock.now_unix(),
                created_by: "bootstrap".into(),
                updated_at: self.clock.now_unix(),
                last_login_at: None,
            })),
            _ => Ok(None),
        }
    }

    /// Fixed-window rate limit using the atomic `incr` + `expire` pattern.
    /// `key_id` is fingerprinted — raw usernames/IPs are never used as keys.
    fn check_rate_limit(
        &self,
        kind: &str,
        id: &str,
        _dimension: u8,
        max: u32,
        window_s: u64,
    ) -> Result<(), ApiError> {
        let key = format!("rl:{}:{}", kind, crate::ids::token_fingerprint(id));
        let count = self
            .cache
            .incr(&key, 1)
            .map_err(|_| ApiError::TooManyRequests {
                retry_after_s: window_s,
            })?;
        if count == 1 {
            let _ = self.cache.expire(&key, window_s * 1000);
        }
        if count > max as i64 {
            return Err(ApiError::TooManyRequests {
                retry_after_s: window_s,
            });
        }
        Ok(())
    }

    /// Re-authenticate for step-up: only valid sessions can step up.
    pub fn step_up(
        &self,
        session: &Session,
        password: &str,
        cfg: &crate::models::AppConfig,
    ) -> Result<String, ApiError> {
        let record: Option<AdminRecord> = self
            .store
            .get(&keys::admin(&session.username))
            .map_err(|_| ApiError::Forbidden("Unable to verify credentials."))?
            .and_then(|b| serde_json::from_slice(&b).ok());
        let record = record.ok_or(ApiError::Unauthorized("Invalid username or password."))?;
        match crypto::verify_password(password, &record.password_hash) {
            Ok(true) => {}
            _ => return Err(ApiError::Unauthorized("Invalid username or password.")),
        }
        let now = self.clock.now_unix();
        let until = now + cfg.step_up_ttl_s;
        let (token, _) = self.mint(
            &session.username,
            session.role,
            now,
            cfg.session_ttl_s,
            until,
        )?;
        Ok(token)
    }

    /// Per-session logout: add this jti to the deny-list (eventual, 1–2 s).
    pub fn logout(&self, session: &Session) -> Result<(), ApiError> {
        // Write through the store (which routes through the control plane).
        self.store
            .put(&keys::session_revoke(&session.jti), b"1".to_vec())
            .map_err(|_| ApiError::StorageUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{keys, ADMIN_SCHEMA_VERSION};
    use crate::platform::{FixedClock, MemCache, MemStore, StaticSecrets};
    use std::sync::Arc;

    fn clock_arc(c: &FixedClock) -> Arc<dyn Fn() -> u64 + Send + Sync> {
        let inner = c.0.clone();
        Arc::new(move || *inner.read().unwrap())
    }

    struct Fixture {
        store: MemStore,
        cache: MemCache,
        clock: FixedClock,
        secrets: StaticSecrets,
    }

    impl Fixture {
        fn new() -> Self {
            let store = MemStore::new();
            let clock = FixedClock::new(1_800_000_000_000);
            let cache = MemCache::new(clock_arc(&clock));
            let secrets = StaticSecrets::new(&[(
                SESSION_KEY_SECRET,
                "0123456789abcdef0123456789abcdef0123456789abcdef",
            )]);
            let rec = AdminRecord {
                schema_version: ADMIN_SCHEMA_VERSION,
                username: "admin".into(),
                role: AdminRole::SuperAdmin,
                password_hash: crate::crypto::hash_password("pw-123456", 10_000),
                created_at: 1,
                created_by: "system".into(),
                updated_at: 1,
                last_login_at: None,
            };
            store
                .put(&keys::admin("admin"), serde_json::to_vec(&rec).unwrap())
                .unwrap();
            Self {
                store,
                cache,
                clock,
                secrets,
            }
        }

        fn auth(&self) -> AuthService<'_> {
            AuthService {
                store: &self.store,
                cache: &self.cache,
                clock: &self.clock,
                secrets: &self.secrets,
            }
        }
    }

    fn default_cfg() -> crate::models::AppConfig {
        crate::models::AppConfig::default()
    }

    #[test]
    fn login_success_and_failure() {
        let f = Fixture::new();
        let auth = f.auth();
        let (token, role) = auth
            .login("admin", "pw-123456", None, &default_cfg())
            .unwrap();
        assert_eq!(role, AdminRole::SuperAdmin);
        let sess = auth.verify_session(&token).unwrap();
        assert_eq!(sess.username, "admin");
        assert!(auth.login("admin", "wrong", None, &default_cfg()).is_err());
        assert!(auth
            .login("ghost", "whatever", None, &default_cfg())
            .is_err());
        // Anti-enumeration: same error variant for unknown user vs bad password.
        let a = auth
            .login("admin", "wrong", None, &default_cfg())
            .unwrap_err();
        let b = auth
            .login("ghost", "whatever", None, &default_cfg())
            .unwrap_err();
        assert_eq!(a.public_message(), b.public_message());
    }

    #[test]
    fn lockout_after_max_attempts() {
        let f = Fixture::new();
        let auth = f.auth();
        for _ in 0..10 {
            let _ = auth.login("admin", "wrong", None, &default_cfg());
        }
        assert!(matches!(
            auth.login("admin", "pw-123456", None, &default_cfg()),
            Err(ApiError::TooManyRequests { .. })
        ));
    }

    #[test]
    fn logout_denies_reuse() {
        let f = Fixture::new();
        let auth = f.auth();
        let (token, _) = auth
            .login("admin", "pw-123456", None, &default_cfg())
            .unwrap();
        let sess = auth.verify_session(&token).unwrap();
        auth.logout(&sess).unwrap();
        assert!(auth.verify_session(&token).is_err());
    }

    #[test]
    fn session_expiry_boundary() {
        let f = Fixture::new();
        let auth = f.auth();
        let (token, _) = auth
            .login("admin", "pw-123456", None, &default_cfg())
            .unwrap();
        let ttl = default_cfg().session_ttl_s;
        f.clock.set(1_800_000_000_000 + (ttl - 1) * 1000);
        assert!(auth.verify_session(&token).is_ok());
        f.clock.set(1_800_000_000_000 + ttl * 1000);
        assert!(auth.verify_session(&token).is_err());
    }

    #[test]
    fn step_up_flow() {
        let f = Fixture::new();
        let auth = f.auth();
        let (token, _) = auth
            .login("admin", "pw-123456", None, &default_cfg())
            .unwrap();
        let sess = auth.verify_session(&token).unwrap();
        assert!(!sess.has_step_up(auth.clock.now_unix()));
        let stepped = auth.step_up(&sess, "pw-123456", &default_cfg()).unwrap();
        let sess2 = auth.verify_session(&stepped).unwrap();
        assert!(sess2.has_step_up(auth.clock.now_unix()));
        assert!(auth.step_up(&sess, "bad", &default_cfg()).is_err());
    }

    #[test]
    fn epoch_bump_revokes_all_sessions() {
        let f = Fixture::new();
        let auth = f.auth();
        let (token, _) = auth
            .login("admin", "pw-123456", None, &default_cfg())
            .unwrap();
        assert!(auth.verify_session(&token).is_ok());
        // Simulate the global epoch bump (revoked-all).
        f.store.put(keys::session_epoch(), b"1".to_vec()).unwrap();
        assert!(auth.verify_session(&token).is_err());
    }

    #[test]
    fn permission_matrix_is_role_based_and_explicit() {
        use Permission::*;
        let check = |role, p| permissions_for(role).contains(&p);
        assert!(check(AdminRole::SuperAdmin, ConfigManage));
        assert!(check(AdminRole::Operator, UsersRead));
        assert!(!check(AdminRole::Operator, UsersManage));
        assert!(!check(AdminRole::Auditor, UsersManage));
        assert!(!check(AdminRole::Auditor, ConfigRead));
        assert!(check(AdminRole::SubscriptionManager, SubsManage));
        assert!(!check(AdminRole::SubscriptionManager, UsersManage));
        assert!(check(AdminRole::Admin, ImportRun));
    }
}
