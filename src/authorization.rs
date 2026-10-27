//! Application-side authorization engine: per-user entitlement checks and
//! the token exchange.
//!
//! THE boundary rule (documented, tested at the edge):
//!
//! ```text
//! allow  if and only if   now < expires_at          (UTC, unix seconds)
//! reject when             now >= expires_at
//! ```
//!
//! Authorization is evaluated **on every protected request** against the
//! *authoritative* Edge Storage records — the signed access token is never
//! sufficient by itself. If any part of the chain cannot be established
//! (missing record, malformed record, storage failure, unknown schema),
//! the decision is DENY (fail-closed). Deny reasons returned to end users
//! are deliberately coarse; precise causes go to the audit trail.

use crate::crypto::{self, Claims};
use crate::errors::ApiError;
use crate::models::{
    keys, CredInfo, SubscriptionRecord, SubscriptionStatus, UserRecord, UserStatus,
    SUBSCRIPTION_SCHEMA_VERSION, USER_SCHEMA_VERSION,
};
use crate::platform::{Clock, Store};

pub const APP_TOKEN_KEY_SECRET: &str = "APP_TOKEN_SIGNING_KEY";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    NoCredential,
    CredentialRevoked,
    CredentialVersionMismatch,
    UserMissing,
    UserMalformed,
    UserSuspended,
    UserRevoked,
    SubscriptionMissing,
    SubscriptionMalformed,
    SubscriptionSuspended,
    SubscriptionRevoked,
    SubscriptionExpired,
    StorageUnavailable,
}

impl DenyReason {
    /// Coarse, end-user-safe explanation. Never reveals storage internals.
    pub fn public_message(&self) -> &'static str {
        match self {
            Self::NoCredential
            | Self::CredentialRevoked
            | Self::CredentialVersionMismatch
            | Self::UserMissing
            | Self::UserMalformed
            | Self::StorageUnavailable => "Access denied.",
            Self::UserSuspended | Self::UserRevoked => "Access denied.",
            Self::SubscriptionMissing | Self::SubscriptionMalformed => "Access denied.",
            Self::SubscriptionSuspended | Self::SubscriptionRevoked => {
                "Access is currently not active."
            }
            Self::SubscriptionExpired => "Access expired.",
        }
    }

    /// Precise label for audit records and admin displays only.
    pub fn detail(&self) -> &'static str {
        match self {
            Self::NoCredential => "credential_not_found",
            Self::CredentialRevoked => "credential_revoked",
            Self::CredentialVersionMismatch => "credential_version_mismatch",
            Self::UserMissing => "user_record_missing",
            Self::UserMalformed => "user_record_malformed",
            Self::UserSuspended => "user_suspended",
            Self::UserRevoked => "user_revoked",
            Self::SubscriptionMissing => "subscription_missing",
            Self::SubscriptionMalformed => "subscription_malformed",
            Self::SubscriptionSuspended => "subscription_suspended",
            Self::SubscriptionRevoked => "subscription_revoked",
            Self::SubscriptionExpired => "subscription_expired_at_boundary",
            Self::StorageUnavailable => "storage_unavailable",
        }
    }
}

pub struct AuthorizationService<'a> {
    pub store: &'a dyn Store,
    pub clock: &'a dyn Clock,
}

impl AuthorizationService<'_> {
    fn load_user(&self, uid: &str) -> Result<UserRecord, DenyReason> {
        let raw = self
            .store
            .get(&keys::user(uid))
            .map_err(|_| DenyReason::StorageUnavailable)?
            .ok_or(DenyReason::UserMissing)?;
        let rec: UserRecord =
            serde_json::from_slice(&raw).map_err(|_| DenyReason::UserMalformed)?;
        if rec.schema_version != USER_SCHEMA_VERSION {
            return Err(DenyReason::UserMalformed);
        }
        if rec.uid != uid {
            return Err(DenyReason::UserMalformed);
        }
        Ok(rec)
    }

    fn load_subscription(&self, uid: &str) -> Result<SubscriptionRecord, DenyReason> {
        let raw = self
            .store
            .get(&keys::subscription(uid))
            .map_err(|_| DenyReason::StorageUnavailable)?
            .ok_or(DenyReason::SubscriptionMissing)?;
        let rec: SubscriptionRecord =
            serde_json::from_slice(&raw).map_err(|_| DenyReason::SubscriptionMalformed)?;
        if rec.schema_version != SUBSCRIPTION_SCHEMA_VERSION {
            return Err(DenyReason::SubscriptionMalformed);
        }
        Ok(rec)
    }

    /// The core entitlement decision. `now` is UTC unix seconds.
    pub fn decide(
        &self,
        user: &UserRecord,
        sub: &SubscriptionRecord,
        now: u64,
    ) -> Result<(), DenyReason> {
        match user.status {
            UserStatus::Active => {}
            UserStatus::Suspended => return Err(DenyReason::UserSuspended),
            UserStatus::Revoked => return Err(DenyReason::UserRevoked),
        }
        match sub.status {
            SubscriptionStatus::Active => {}
            SubscriptionStatus::Suspended => return Err(DenyReason::SubscriptionSuspended),
            SubscriptionStatus::Revoked => return Err(DenyReason::SubscriptionRevoked),
        }
        if let Some(exp) = sub.expires_at {
            if now >= exp {
                return Err(DenyReason::SubscriptionExpired);
            }
        }
        Ok(())
    }

    /// Exchange a raw API token for a short-lived access token.
    /// The raw token is hashed; only the SHA-256 fingerprint exists in
    /// storage, so a database read can never leak credentials.
    pub fn exchange(
        &self,
        token: &str,
        app_token_ttl_s: u64,
    ) -> Result<(Claims, UserRecord, SubscriptionRecord), (ApiError, DenyReason)> {
        if !crate::validation::is_route_id(token) || token.len() < 16 {
            return Err((
                ApiError::Unauthorized("Access denied."),
                DenyReason::NoCredential,
            ));
        }
        let fp = crate::ids::token_fingerprint(token);
        let tok_raw = match self.store.get(&keys::token(&fp)) {
            Ok(Some(v)) => v,
            Ok(None) => {
                return Err((
                    ApiError::Unauthorized("Access denied."),
                    DenyReason::NoCredential,
                ))
            }
            Err(_) => {
                return Err((
                    ApiError::Forbidden("Access denied."),
                    DenyReason::StorageUnavailable,
                ))
            }
        };
        let tok: TokenIndexEntry = serde_json::from_slice(&tok_raw).map_err(|_| {
            (
                ApiError::Unauthorized("Access denied."),
                DenyReason::NoCredential,
            )
        })?;
        if tok.revoked {
            return Err((
                ApiError::Unauthorized("Access denied."),
                DenyReason::CredentialRevoked,
            ));
        }
        let user = self.load_user(&tok.uid).map_err(|d| (map_deny(d), d))?;
        let _cred: &CredInfo = user.active_credential(&tok.cred_id).ok_or((
            ApiError::Unauthorized("Access denied."),
            DenyReason::CredentialRevoked,
        ))?;
        if user.cred_version != tok.cred_version {
            return Err((
                ApiError::Unauthorized("Access denied."),
                DenyReason::CredentialVersionMismatch,
            ));
        }
        let sub = self
            .load_subscription(&tok.uid)
            .map_err(|d| (map_deny(d), d))?;
        let now = self.clock.now_unix();
        self.decide(&user, &sub, now)
            .map_err(|d| (map_deny(d), d))?;

        let claims = Claims {
            iss: crate::auth::ISSUER.into(),
            aud: crate::auth::AUD_APP.into(),
            sub: user.uid.clone(),
            iat: now,
            exp: now + app_token_ttl_s,
            jti: crate::ids::new_jti()
                .map_err(|_| (ApiError::Internal, DenyReason::NoCredential))?,
            purpose: Some("app-access".into()),
            role: Some(user.app_role.clone()),
            cv: Some(user.cred_version),
            su: None,
            ep: None,
            nbf: None,
        };
        Ok((claims, user, sub))
    }

    /// Verify an access token AND re-evaluate the full entitlement chain
    /// against current storage. Called on every protected app request.
    pub fn verify_access_token(
        &self,
        token: &str,
        signing_key: &[u8],
    ) -> Result<(Claims, UserRecord, SubscriptionRecord), (ApiError, DenyReason)> {
        let now = self.clock.now_unix();
        let claims = crypto::jwt_verify(
            token,
            signing_key,
            crate::auth::AUD_APP,
            crate::auth::ISSUER,
            now,
        )
        .map_err(|_| {
            (
                ApiError::Unauthorized("Access denied."),
                DenyReason::NoCredential,
            )
        })?;
        if claims.purpose.as_deref() != Some("app-access") {
            return Err((
                ApiError::Unauthorized("Access denied."),
                DenyReason::NoCredential,
            ));
        }
        let user = self.load_user(&claims.sub).map_err(|d| (map_deny(d), d))?;
        if user.cred_version != claims.cv.unwrap_or(0) {
            return Err((
                ApiError::Unauthorized("Access denied."),
                DenyReason::CredentialVersionMismatch,
            ));
        }
        let sub = self
            .load_subscription(&claims.sub)
            .map_err(|d| (map_deny(d), d))?;
        self.decide(&user, &sub, now)
            .map_err(|d| (map_deny(d), d))?;
        Ok((claims, user, sub))
    }
}

fn map_deny(d: DenyReason) -> ApiError {
    // Status-based denials are authorization decisions (403) — the caller
    // authenticated fine but is not permitted. Credential/token problems
    // are authentication failures (401). Storage problems during
    // authorization fail closed as 403 without revealing the cause.
    use DenyReason::*;
    match d {
        SubscriptionExpired
        | SubscriptionSuspended
        | SubscriptionRevoked
        | UserSuspended
        | UserRevoked
        | StorageUnavailable => ApiError::Forbidden(d.public_message()),
        _ => ApiError::Unauthorized(d.public_message()),
    }
}

/// Edge Storage `tok/{sha256}` index entry.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct TokenIndexEntry {
    pub uid: String,
    pub cred_id: String,
    pub cred_version: u32,
    pub revoked: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{SubHistoryItem, UserRecord};
    use crate::platform::{FixedClock, MemStore};
    use serde_json::json;

    fn fixtures(clock: &FixedClock, store: &MemStore, expires_at: Option<u64>) {
        let user = UserRecord {
            schema_version: USER_SCHEMA_VERSION,
            uid: "uUSER0000000000000000000".into(),
            email: "a@b.io".into(),
            display_name: "A".into(),
            status: UserStatus::Active,
            app_role: "member".into(),
            metadata: Default::default(),
            cred_version: 1,
            credentials: vec![CredInfo {
                cred_id: "cCRED0000000000000000000".into(),
                token_hash: "deadbeef".repeat(8),
                issued_at: 1,
                expires_at: None,
                revoked_at: None,
                label: None,
            }],
            created_at: 1,
            created_by: "admin:root".into(),
            updated_at: 1,
            updated_by: "admin:root".into(),
        };
        let sub = SubscriptionRecord {
            schema_version: SUBSCRIPTION_SCHEMA_VERSION,
            uid: user.uid.clone(),
            sub_id: "sSUB0000000000000000000".into(),
            entitlement_id: "ent-basic".into(),
            status: SubscriptionStatus::Active,
            expires_at,
            created_at: 1,
            created_by: "admin:root".into(),
            updated_at: 1,
            updated_by: "admin:root".into(),
            history: vec![],
        };
        store
            .put(&keys::user(&user.uid), serde_json::to_vec(&user).unwrap())
            .unwrap();
        store
            .put(
                &keys::subscription(&sub.uid),
                serde_json::to_vec(&sub).unwrap(),
            )
            .unwrap();
        let _ = clock;
        let _ = SubHistoryItem {
            at: 0,
            action: String::new(),
            by: String::new(),
            from: None,
            to: None,
        };
    }

    fn svc<'a>(store: &'a MemStore, clock: &'a FixedClock) -> AuthorizationService<'a> {
        AuthorizationService { store, clock }
    }

    #[test]
    fn boundary_rule_exact() {
        let clock = FixedClock::new(1_000_000 * 1000);
        let store = MemStore::new();
        let exp = 1_000_000u64;
        fixtures(&clock, &store, Some(exp));

        let user: UserRecord = serde_json::from_slice(
            &store
                .get(&keys::user("uUSER0000000000000000000"))
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        let sub: SubscriptionRecord = serde_json::from_slice(
            &store
                .get(&keys::subscription("uUSER0000000000000000000"))
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        let s = svc(&store, &clock);

        // One second before expiration → allowed.
        clock.set((exp - 1) * 1000);
        assert!(s.decide(&user, &sub, exp - 1).is_ok());
        // Exactly at expiration → REJECTED (>= rule).
        clock.set(exp * 1000);
        assert_eq!(
            s.decide(&user, &sub, exp),
            Err(DenyReason::SubscriptionExpired)
        );
        // One second after → rejected.
        assert_eq!(
            s.decide(&user, &sub, exp + 1),
            Err(DenyReason::SubscriptionExpired)
        );
    }

    #[test]
    fn missing_subscription_fails_closed() {
        let clock = FixedClock::new(1_000_000 * 1000);
        let store = MemStore::new();
        fixtures(&clock, &store, None);
        // Delete the subscription record: decision must be DENY, not allow.
        store
            .delete(&keys::subscription("uUSER0000000000000000000"))
            .unwrap();
        let user: UserRecord = serde_json::from_slice(
            &store
                .get(&keys::user("uUSER0000000000000000000"))
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        let s = svc(&store, &clock);
        let sub_missing = s.load_subscription("uUSER0000000000000000000");
        assert_eq!(sub_missing.err(), Some(DenyReason::SubscriptionMissing));
        let _ = user;
    }

    #[test]
    fn malformed_and_future_schema_fail_closed() {
        let clock = FixedClock::new(1_000_000 * 1000);
        let store = MemStore::new();
        fixtures(&clock, &store, None);
        let mut raw: serde_json::Value = serde_json::from_slice(
            &store
                .get(&keys::user("uUSER0000000000000000000"))
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        raw["schema_version"] = json!(99);
        store
            .put(
                &keys::user("uUSER0000000000000000000"),
                serde_json::to_vec(&raw).unwrap(),
            )
            .unwrap();
        let s = svc(&store, &clock);
        assert_eq!(
            s.load_user("uUSER0000000000000000000").err(),
            Some(DenyReason::UserMalformed)
        );
        // Corrupt JSON also fails closed.
        store
            .put(
                &keys::subscription("uUSER0000000000000000000"),
                b"not json".to_vec(),
            )
            .unwrap();
        assert_eq!(
            s.load_subscription("uUSER0000000000000000000").err(),
            Some(DenyReason::SubscriptionMalformed)
        );
    }

    #[test]
    fn user_status_denies() {
        let clock = FixedClock::new(1_000_000 * 1000);
        let store = MemStore::new();
        fixtures(&clock, &store, None);
        let s = svc(&store, &clock);
        for status in [UserStatus::Suspended, UserStatus::Revoked] {
            let mut user: UserRecord = serde_json::from_slice(
                &store
                    .get(&keys::user("uUSER0000000000000000000"))
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
            user.status = status;
            let sub: SubscriptionRecord = serde_json::from_slice(
                &store
                    .get(&keys::subscription("uUSER0000000000000000000"))
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
            let expect = if status == UserStatus::Suspended {
                DenyReason::UserSuspended
            } else {
                DenyReason::UserRevoked
            };
            assert_eq!(s.decide(&user, &sub, 1_000_000).err(), Some(expect));
        }
    }
}
