//! Storage records and their schemas.
//!
//! Every record persisted to Edge Storage carries a `schema_version` so
//! that malformed or future/unknown data is rejected at load time
//! (fail-closed per the platform's storage rules) instead of being
//! interpreted incorrectly. Wire-facing inputs use
//! `deny_unknown_fields` wherever the caller is untrusted.

use serde::{Deserialize, Serialize};
use serde_json::Map;

pub const USER_SCHEMA_VERSION: u16 = 1;
pub const SUBSCRIPTION_SCHEMA_VERSION: u16 = 1;
pub const ADMIN_SCHEMA_VERSION: u16 = 1;
pub const AUDIT_SCHEMA_VERSION: u16 = 1;
pub const CONFIG_SCHEMA_VERSION: u16 = 1;

/// Key helpers — single place that knows the Edge Storage key layout.
pub mod keys {
    pub const CONFIG: &str = "config/app";

    pub fn user(uid: &str) -> String {
        format!("users/{uid}")
    }
    pub fn users_prefix() -> &'static str {
        "users/*"
    }
    pub fn email(email: &str) -> String {
        format!("email/{email}")
    }
    pub fn email_prefix() -> &'static str {
        "email/*"
    }
    pub fn subscription(uid: &str) -> String {
        format!("subs/{uid}")
    }
    pub fn subs_prefix() -> &'static str {
        "subs/*"
    }
    pub fn token(fingerprint_hex: &str) -> String {
        format!("tok/{fingerprint_hex}")
    }
    pub fn admin(username: &str) -> String {
        format!("admins/{username}")
    }
    pub fn audit_prefix() -> &'static str {
        "audit/e*"
    }
    pub fn audit(event_id: &str) -> String {
        format!("audit/{event_id}")
    }
    pub fn session_epoch() -> &'static str {
        "sys/session_epoch"
    }
    pub fn session_revoke(jti: &str) -> String {
        format!("sys/srev/{jti}")
    }
    pub fn session_revoke_prefix() -> &'static str {
        "sys/srev/*"
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserStatus {
    Active,
    Suspended,
    Revoked,
}

impl UserStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionStatus {
    Active,
    Suspended,
    Revoked,
}

impl SubscriptionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Revoked => "revoked",
        }
    }
}

/// A credential entry inside a user record. `token_hash` is a SHA-256 hex
/// fingerprint of the API token; the token itself is never stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredInfo {
    pub cred_id: String,
    pub token_hash: String,
    pub issued_at: u64,
    pub expires_at: Option<u64>,
    pub revoked_at: Option<u64>,
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRecord {
    pub schema_version: u16,
    pub uid: String,
    pub email: String,
    pub display_name: String,
    pub status: UserStatus,
    /// Application-facing role for entitlement decisions (never an admin role).
    pub app_role: String,
    #[serde(default)]
    pub metadata: Map<String, serde_json::Value>,
    pub cred_version: u32,
    #[serde(default)]
    pub credentials: Vec<CredInfo>,
    pub created_at: u64,
    pub created_by: String,
    pub updated_at: u64,
    pub updated_by: String,
}

impl UserRecord {
    /// Bounded: only the latest N credentials are retained per user.
    pub const MAX_CREDENTIALS: usize = 8;
    pub fn active_credential(&self, cred_id: &str) -> Option<&CredInfo> {
        self.credentials
            .iter()
            .find(|c| c.cred_id == cred_id && c.revoked_at.is_none())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubHistoryItem {
    pub at: u64,
    pub action: String,
    pub by: String,
    pub from: Option<String>,
    pub to: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionRecord {
    pub schema_version: u16,
    pub uid: String,
    pub sub_id: String,
    pub entitlement_id: String,
    pub status: SubscriptionStatus,
    /// Absolute UTC expiration (unix seconds). `None` = no expiry.
    pub expires_at: Option<u64>,
    pub created_at: u64,
    pub created_by: String,
    pub updated_at: u64,
    pub updated_by: String,
    #[serde(default)]
    pub history: Vec<SubHistoryItem>,
}

impl SubscriptionRecord {
    pub const MAX_HISTORY: usize = 50;
    pub fn push_history(&mut self, item: SubHistoryItem) {
        self.history.push(item);
        if self.history.len() > Self::MAX_HISTORY {
            let overflow = self.history.len() - Self::MAX_HISTORY;
            self.history.drain(0..overflow);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminRole {
    SuperAdmin,
    Admin,
    SubscriptionManager,
    Operator,
    Auditor,
}

impl AdminRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SuperAdmin => "super_admin",
            Self::Admin => "admin",
            Self::SubscriptionManager => "subscription_manager",
            Self::Operator => "operator",
            Self::Auditor => "auditor",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminRecord {
    pub schema_version: u16,
    pub username: String,
    pub role: AdminRole,
    pub password_hash: String,
    pub created_at: u64,
    pub created_by: String,
    pub updated_at: u64,
    pub last_login_at: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditCategory {
    Auth,
    User,
    Subscription,
    Credential,
    Config,
    Security,
    Import,
    Export,
    System,
}

impl AuditCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::User => "user",
            Self::Subscription => "subscription",
            Self::Credential => "credential",
            Self::Config => "config",
            Self::Security => "security",
            Self::Import => "import",
            Self::Export => "export",
            Self::System => "system",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Ok,
    Denied,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub schema_version: u16,
    pub id: String,
    /// Unix milliseconds.
    pub at: u64,
    pub category: AuditCategory,
    pub action: String,
    pub actor: String,
    pub target: String,
    pub outcome: AuditOutcome,
    pub request_id: String,
    /// Free-form, pre-redacted context. Never contains secrets.
    pub details: Option<String>,
}

/// Operational configuration. Secrets are NOT stored here — they live in
/// the Gcore Secrets Manager and are read per request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub schema_version: u16,
    /// Admin session TTL (seconds).
    pub session_ttl_s: u64,
    /// Step-up authentication window (seconds).
    pub step_up_ttl_s: u64,
    /// Application access-token TTL (seconds).
    pub app_token_ttl_s: u64,
    /// Failed logins per `login_window_s` before lockout.
    pub login_max_attempts: u32,
    pub login_window_s: u64,
    /// Maximum entries per import/control-plane batch.
    pub import_batch_max: usize,
    /// Audit retention before pruning (days).
    pub audit_retention_days: u32,
    /// PBKDF2 iterations for NEW admin password hashes. Verification always
    /// honors the parameters embedded in each stored hash (with the global
    /// security floor enforced separately).
    pub pbkdf2_iterations: u32,
    /// Monotonic config revision.
    pub version: u64,
    pub updated_at: u64,
    pub updated_by: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            schema_version: CONFIG_SCHEMA_VERSION,
            session_ttl_s: 1_800,
            step_up_ttl_s: 900,
            app_token_ttl_s: 300,
            login_max_attempts: 10,
            login_window_s: 900,
            import_batch_max: 100,
            audit_retention_days: 90,
            pbkdf2_iterations: crate::crypto::PBKDF2_DEFAULT_ITERATIONS,
            version: 1,
            updated_at: 0,
            updated_by: "system".into(),
        }
    }
}

impl AppConfig {
    pub fn validate(&self, errs: &mut Vec<crate::errors::FieldError>) {
        let mut field = |name: &str, ok: bool, msg: &str| {
            if !ok {
                errs.push(crate::errors::FieldError::new(name, msg));
            }
        };
        field(
            "session_ttl_s",
            (300..=86_400).contains(&self.session_ttl_s),
            "must be between 300 and 86400 seconds",
        );
        field(
            "step_up_ttl_s",
            (60..=3_600).contains(&self.step_up_ttl_s),
            "must be between 60 and 3600 seconds",
        );
        field(
            "app_token_ttl_s",
            (60..=3_600).contains(&self.app_token_ttl_s),
            "must be between 60 and 3600 seconds",
        );
        field(
            "login_max_attempts",
            (1..=100).contains(&self.login_max_attempts),
            "must be between 1 and 100",
        );
        field(
            "login_window_s",
            (60..=86_400).contains(&self.login_window_s),
            "must be between 60 and 86400 seconds",
        );
        field(
            "import_batch_max",
            (1..=100).contains(&self.import_batch_max),
            "must be between 1 and 100",
        );
        field(
            "audit_retention_days",
            (7..=3_650).contains(&self.audit_retention_days),
            "must be between 7 and 3650 days",
        );
        field(
            "pbkdf2_iterations",
            (crate::crypto::PBKDF2_MIN_ITERATIONS..=600_000).contains(&self.pbkdf2_iterations),
            "must be between 10000 and 600000",
        );
        field(
            "schema_version",
            self.schema_version == CONFIG_SCHEMA_VERSION,
            "unsupported config schema version",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_layout_is_stable() {
        assert_eq!(keys::user("uABC"), "users/uABC");
        assert_eq!(keys::subscription("uABC"), "subs/uABC");
        assert_eq!(keys::admin("alice"), "admins/alice");
        assert_eq!(keys::audit("e123"), "audit/e123");
        assert_eq!(keys::session_epoch(), "sys/session_epoch");
    }

    #[test]
    fn config_defaults_pass_validation() {
        let c = AppConfig::default();
        let mut errs = vec![];
        c.validate(&mut errs);
        assert!(errs.is_empty(), "defaults must be valid: {errs:?}");
    }

    #[test]
    fn config_rejects_out_of_range() {
        let c = AppConfig {
            session_ttl_s: 1,
            app_token_ttl_s: 999_999,
            ..AppConfig::default()
        };
        let mut errs = vec![];
        c.validate(&mut errs);
        assert_eq!(errs.len(), 2);
    }

    #[test]
    fn sub_history_is_bounded() {
        let mut s = SubscriptionRecord {
            schema_version: SUBSCRIPTION_SCHEMA_VERSION,
            uid: "uX".into(),
            sub_id: "sX".into(),
            entitlement_id: "ent-basic".into(),
            status: SubscriptionStatus::Active,
            expires_at: None,
            created_at: 1,
            created_by: "admin".into(),
            updated_at: 1,
            updated_by: "admin".into(),
            history: vec![],
        };
        for i in 0..(SubscriptionRecord::MAX_HISTORY + 10) {
            s.push_history(SubHistoryItem {
                at: i as u64,
                action: "renew".into(),
                by: "admin".into(),
                from: None,
                to: None,
            });
        }
        assert_eq!(s.history.len(), SubscriptionRecord::MAX_HISTORY);
    }
}
