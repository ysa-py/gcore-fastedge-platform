//! User, subscription, and credential business logic.
//!
//! Concurrency semantics (documented, deliberate):
//! * Writes are read-modify-write through the control plane. Edge Storage
//!   provides no CAS; two racing admins can last-write-win. Administrative
//!   concurrency is expected to be low, every record records `updated_by`,
//!   and all mutations are idempotent per-record (retry-safe).
//! * Destructive transitions are guarded by explicit status state
//!   machines — a second `revoke` is a no-op, not an error.

use crate::authorization::TokenIndexEntry;
use crate::errors::{ApiError, FieldError};
use crate::models::{
    keys, AppConfig, CredInfo, SubHistoryItem, SubscriptionRecord, SubscriptionStatus, UserRecord,
    UserStatus, SUBSCRIPTION_SCHEMA_VERSION, USER_SCHEMA_VERSION,
};
use crate::platform::{Clock, Store};
use crate::timeutil;
use crate::validation;

/// Hard cap for scan-driven reads so a pathological dataset can never
/// hang a request. Listings that hit the cap are marked truncated.
pub const MAX_SCAN_RECORDS: usize = 1000;

pub struct UsersService<'a> {
    pub store: &'a dyn Store,
    pub clock: &'a dyn Clock,
}

#[derive(Debug, Default)]
pub struct UserQuery {
    pub text: Option<String>,
    pub status: Option<UserStatus>,
    /// `true` → newest first.
    pub newest_first: bool,
    pub limit: usize,
    pub offset: usize,
}

#[derive(Debug, Clone)]
pub struct CreateUserInput {
    pub email: String,
    pub display_name: String,
    pub app_role: String,
    pub metadata: serde_json::Map<String, serde_json::Value>,
    pub entitlement_id: String,
    /// Raw RFC3339 UTC timestamp from the request; parsed and validated
    /// here so every field error surfaces together in one 422 response.
    pub expires_at: Option<String>,
}

/// Aggregate counts for the dashboard overview.
pub struct OverviewCounts {
    pub total: usize,
    pub active: usize,
    pub suspended: usize,
    pub revoked: usize,
    pub expiring_within_7d: usize,
    pub truncated: bool,
}

impl<'a> UsersService<'a> {
    fn now(&self) -> u64 {
        self.clock.now_unix()
    }

    fn load_user(&self, uid: &str) -> Result<UserRecord, ApiError> {
        if !validation::is_route_id(uid) {
            return Err(ApiError::NotFound("Resource not found."));
        }
        let raw = self
            .store
            .get(&keys::user(uid))
            .map_err(|_| ApiError::StorageUnavailable)?
            .ok_or(ApiError::NotFound("Resource not found."))?;
        let rec: UserRecord = serde_json::from_slice(&raw).map_err(|_| {
            ApiError::Unprocessable(vec![FieldError::new("uid", "stored record is malformed")])
        })?;
        if rec.schema_version != USER_SCHEMA_VERSION || rec.uid != uid {
            return Err(ApiError::Unprocessable(vec![FieldError::new(
                "uid",
                "stored record is malformed",
            )]));
        }
        Ok(rec)
    }

    fn load_sub(&self, uid: &str) -> Result<SubscriptionRecord, ApiError> {
        let raw = self
            .store
            .get(&keys::subscription(uid))
            .map_err(|_| ApiError::StorageUnavailable)?
            .ok_or(ApiError::NotFound("Resource not found."))?;
        let rec: SubscriptionRecord = serde_json::from_slice(&raw).map_err(|_| {
            ApiError::Unprocessable(vec![FieldError::new(
                "subscription",
                "stored record is malformed",
            )])
        })?;
        if rec.schema_version != SUBSCRIPTION_SCHEMA_VERSION {
            return Err(ApiError::Unprocessable(vec![FieldError::new(
                "subscription",
                "stored record is malformed",
            )]));
        }
        Ok(rec)
    }

    // ------------------------------------------------------------------
    // Users
    // ------------------------------------------------------------------

    pub fn create_user(
        &self,
        input: &CreateUserInput,
        actor: &str,
    ) -> Result<UserRecord, ApiError> {
        let mut errs: Vec<FieldError> = vec![];
        // Email problems are accumulated (not returned early) so forms can
        // show every invalid field in one round trip.
        let email = match validation::normalize_email(&input.email) {
            Ok(e) => e,
            Err(m) => {
                errs.push(FieldError::new("email", m));
                String::new()
            }
        };
        if !validation::is_display_name(&input.display_name) {
            errs.push(FieldError::new(
                "display_name",
                "must be 1-128 printable characters",
            ));
        }
        if !validation::is_app_role(&input.app_role) {
            errs.push(FieldError::new(
                "app_role",
                "must be 1-32 characters [a-z0-9_-]",
            ));
        }
        if input.entitlement_id.is_empty() || input.entitlement_id.len() > 64 {
            errs.push(FieldError::new("entitlement_id", "must be 1-64 characters"));
        }
        if input.metadata.len() > 16 {
            errs.push(FieldError::new("metadata", "at most 16 keys are allowed"));
        }
        let expires_at: Option<u64> = match &input.expires_at {
            None => None,
            Some(raw) => {
                let parsed = crate::timeutil::parse_rfc3339_utc(raw);
                let ts = match parsed {
                    None => {
                        errs.push(FieldError::new(
                            "expires_at",
                            "must be an RFC 3339 UTC timestamp ending in Z (e.g. 2026-12-31T23:59:59Z)",
                        ));
                        None
                    }
                    Some(ts) => Some(ts),
                };
                if let Some(ts) = ts {
                    // Expiration must be strictly in the future (>= rejects).
                    if self.now() >= ts {
                        errs.push(FieldError::new("expires_at", "must be in the future (UTC)"));
                        None
                    } else {
                        Some(ts)
                    }
                } else {
                    None
                }
            }
        };
        if !errs.is_empty() {
            return Err(ApiError::Unprocessable(errs));
        }

        // Uniqueness via the email index.
        if let Some(existing) = self
            .store
            .get(&keys::email(&email))
            .map_err(|_| ApiError::StorageUnavailable)?
        {
            let _ = existing;
            return Err(ApiError::Conflict("A user with this email already exists."));
        }

        let now_ms = self.clock.now_ms();
        let uid = crate::ids::new_user_id(now_ms).map_err(|_| ApiError::Internal)?;
        let sub_id = crate::ids::new_subscription_id(now_ms).map_err(|_| ApiError::Internal)?;
        let now = self.now();
        let user = UserRecord {
            schema_version: USER_SCHEMA_VERSION,
            uid: uid.clone(),
            email,
            display_name: crate::validation::sanitize_text(&input.display_name, 128),
            status: UserStatus::Active,
            app_role: input.app_role.clone(),
            metadata: input.metadata.clone(),
            cred_version: 0,
            credentials: vec![],
            created_at: now,
            created_by: actor.into(),
            updated_at: now,
            updated_by: actor.into(),
        };
        let mut sub = SubscriptionRecord {
            schema_version: SUBSCRIPTION_SCHEMA_VERSION,
            uid: uid.clone(),
            sub_id,
            entitlement_id: input.entitlement_id.clone(),
            status: SubscriptionStatus::Active,
            expires_at,
            created_at: now,
            created_by: actor.into(),
            updated_at: now,
            updated_by: actor.into(),
            history: vec![],
        };
        sub.push_history(SubHistoryItem {
            at: now,
            action: "create".into(),
            by: actor.into(),
            from: None,
            to: Some(subscription_summary(&sub)),
        });

        let batch = vec![
            (
                keys::user(&uid),
                serde_json::to_vec(&user).map_err(|_| ApiError::Internal)?,
            ),
            (
                keys::subscription(&uid),
                serde_json::to_vec(&sub).map_err(|_| ApiError::Internal)?,
            ),
            (keys::email(&user.email), uid.clone().into_bytes()),
        ];
        self.store
            .put_batch(&batch)
            .map_err(|_| ApiError::ControlPlane("The change could not be persisted."))?;
        Ok(user)
    }

    /// Paginated, filtered user listing. Returns (views, total_matched,
    /// truncated). `total_matched` is exact up to the scan cap.
    pub fn list_users(
        &self,
        query: &UserQuery,
    ) -> Result<(Vec<serde_json::Value>, usize, bool), ApiError> {
        let mut uids = self
            .store
            .scan(keys::users_prefix())
            .map_err(|_| ApiError::StorageUnavailable)?;
        uids.sort();
        if query.newest_first {
            uids.reverse();
        }
        let truncated = uids.len() > MAX_SCAN_RECORDS;
        uids.truncate(MAX_SCAN_RECORDS);

        let text = query.text.as_deref().map(|t| t.trim().to_lowercase());
        let mut views = Vec::new();
        let mut total = 0usize;
        for uid in uids {
            let key = match uid.rsplit('/').next() {
                Some(k) => keys::user(k),
                None => continue,
            };
            let raw = match self.store.get(&key) {
                Ok(Some(v)) => v,
                Ok(None) => continue,
                Err(_) => return Err(ApiError::StorageUnavailable),
            };
            let user: UserRecord = match serde_json::from_slice(&raw) {
                Ok(u) => u,
                Err(_) => continue,
            };
            if let Some(status) = query.status {
                if user.status != status {
                    continue;
                }
            }
            if let Some(t) = &text {
                let hay =
                    format!("{} {} {}", user.email, user.display_name, user.uid).to_lowercase();
                if !hay.contains(t.as_str()) {
                    continue;
                }
            }
            total += 1;
            if total > query.offset && views.len() < query.limit {
                views.push(self.user_view(&user)?);
            }
        }
        Ok((views, total, truncated))
    }

    pub fn get_user(&self, uid: &str) -> Result<serde_json::Value, ApiError> {
        let user = self.load_user(uid)?;
        self.user_view(&user)
    }

    /// Sanitized projection. Token hashes are never included; credential
    /// entries show only ids, timestamps, and labels.
    pub fn user_view(&self, user: &UserRecord) -> Result<serde_json::Value, ApiError> {
        let sub = self
            .store
            .get(&keys::subscription(&user.uid))
            .map_err(|_| ApiError::StorageUnavailable)?
            .and_then(|b| serde_json::from_slice::<SubscriptionRecord>(&b).ok());
        Ok(serde_json::json!({
            "uid": user.uid,
            "email": user.email,
            "display_name": user.display_name,
            "status": user.status.as_str(),
            "app_role": user.app_role,
            "metadata": user.metadata,
            "cred_version": user.cred_version,
            "credentials": user.credentials.iter().map(|c| serde_json::json!({
                "cred_id": c.cred_id,
                "issued_at": timeutil::format_rfc3339_utc(c.issued_at),
                "expires_at": c.expires_at.map(timeutil::format_rfc3339_utc),
                "revoked_at": c.revoked_at.map(timeutil::format_rfc3339_utc),
                "label": c.label,
                "fingerprint": crate::audit::fingerprint_prefix(&c.token_hash),
            })).collect::<Vec<_>>(),
            "created_at": timeutil::format_rfc3339_utc(user.created_at),
            "updated_at": timeutil::format_rfc3339_utc(user.updated_at),
            "subscription": sub.map(|s| subscription_view(&s, self.now())),
        }))
    }

    /// Editable metadata only: display_name, app_role, metadata.
    pub fn update_user(
        &self,
        uid: &str,
        display_name: Option<String>,
        app_role: Option<String>,
        metadata: Option<serde_json::Map<String, serde_json::Value>>,
        actor: &str,
    ) -> Result<UserRecord, ApiError> {
        let mut user = self.load_user(uid)?;
        let mut errs = vec![];
        if let Some(name) = &display_name {
            if !validation::is_display_name(name) {
                errs.push(FieldError::new(
                    "display_name",
                    "must be 1-128 printable characters",
                ));
            }
        }
        if let Some(role) = &app_role {
            if !validation::is_app_role(role) {
                errs.push(FieldError::new(
                    "app_role",
                    "must be 1-32 characters [a-z0-9_-]",
                ));
            }
        }
        if let Some(m) = &metadata {
            if m.len() > 16 {
                errs.push(FieldError::new("metadata", "at most 16 keys are allowed"));
            }
        }
        if !errs.is_empty() {
            return Err(ApiError::Unprocessable(errs));
        }
        if user.status == UserStatus::Revoked {
            return Err(ApiError::Conflict("A revoked user cannot be modified."));
        }
        if let Some(name) = display_name {
            user.display_name = crate::validation::sanitize_text(&name, 128);
        }
        if let Some(role) = app_role {
            user.app_role = role;
        }
        if let Some(m) = metadata {
            user.metadata = m;
        }
        user.updated_at = self.now();
        user.updated_by = actor.into();
        self.store
            .put(
                &keys::user(&user.uid),
                serde_json::to_vec(&user).map_err(|_| ApiError::Internal)?,
            )
            .map_err(|_| ApiError::ControlPlane("The change could not be persisted."))?;
        Ok(user)
    }

    /// Status transitions with explicit state machine.
    pub fn set_user_status(
        &self,
        uid: &str,
        action: &str,
        actor: &str,
    ) -> Result<UserRecord, ApiError> {
        let mut user = self.load_user(uid)?;
        apply_status_action(&mut user, action)?;
        user.updated_at = self.now();
        user.updated_by = actor.into();
        self.store
            .put(
                &keys::user(&user.uid),
                serde_json::to_vec(&user).map_err(|_| ApiError::Internal)?,
            )
            .map_err(|_| ApiError::ControlPlane("The change could not be persisted."))?;
        Ok(user)
    }

    /// Bulk status change: validates + mutates every record in memory, then
    /// persists ALL of them in ONE batched control-plane write.
    pub fn bulk_set_status(
        &self,
        uids: &[String],
        action: &str,
        actor: &str,
    ) -> Result<BulkOutcome, ApiError> {
        let mut rows: Vec<(usize, &str, String)> = Vec::new(); // (index, outcome, reason)
        let mut records: Vec<UserRecord> = Vec::new();
        for (i, uid) in uids.iter().enumerate() {
            if !validation::is_route_id(uid) {
                rows.push((i, "error", "invalid_id".into()));
                continue;
            }
            match self.load_user(uid) {
                Ok(mut user) => match apply_status_action(&mut user, action) {
                    Ok(()) => {
                        user.updated_at = self.now();
                        user.updated_by = actor.into();
                        rows.push((i, "ok", String::new()));
                        records.push(user);
                    }
                    Err(reason) => rows.push((i, "error", reason.to_static().to_string())),
                },
                Err(e) => rows.push((i, "error", e.code().to_string())),
            }
        }
        if !records.is_empty() {
            let mut batch: Vec<(String, Vec<u8>)> = Vec::with_capacity(records.len());
            for u in &records {
                batch.push((
                    keys::user(&u.uid),
                    serde_json::to_vec(u).map_err(|_| ApiError::Internal)?,
                ));
            }
            self.store
                .put_batch(&batch)
                .map_err(|_| ApiError::ControlPlane("The change could not be persisted."))?;
        }
        Ok(BulkOutcome {
            ok: records.len(),
            rows,
        })
    }

    /// Bulk renewal: one batched write for every successful record.
    pub fn bulk_renew(
        &self,
        uids: &[String],
        extend_days: Option<u64>,
        until: Option<u64>,
        actor: &str,
    ) -> Result<BulkOutcome, ApiError> {
        let now = self.now();
        if extend_days.is_none() && until.is_none() {
            return Err(ApiError::Unprocessable(vec![FieldError::new(
                "extend_days",
                "either extend_days or until is required",
            )]));
        }
        if let Some(d) = extend_days {
            if !(1..=3_650).contains(&d) {
                return Err(ApiError::Unprocessable(vec![FieldError::new(
                    "extend_days",
                    "must be between 1 and 3650 days",
                )]));
            }
        }
        if let Some(t) = until {
            if now >= t {
                return Err(ApiError::Unprocessable(vec![FieldError::new(
                    "until",
                    "must be in the future (UTC)",
                )]));
            }
        }
        let mut rows: Vec<(usize, &str, String)> = Vec::new();
        let mut records: Vec<SubscriptionRecord> = Vec::new();
        for (i, uid) in uids.iter().enumerate() {
            if !validation::is_route_id(uid) {
                rows.push((i, "error", "invalid_id".into()));
                continue;
            }
            match self.load_sub(uid) {
                Ok(mut sub) => {
                    if sub.status == SubscriptionStatus::Revoked {
                        rows.push((i, "error", "CONFLICT".into()));
                        continue;
                    }
                    let before = subscription_summary(&sub);
                    let new_exp = if let Some(t) = until {
                        Some(t)
                    } else {
                        let base = sub.expires_at.unwrap_or(now).max(now);
                        Some(base.saturating_add(extend_days.unwrap_or(0) * 86_400))
                    };
                    sub.expires_at = new_exp;
                    sub.status = SubscriptionStatus::Active;
                    sub.updated_at = now;
                    sub.updated_by = actor.into();
                    sub.push_history(SubHistoryItem {
                        at: now,
                        action: "bulk_renew".into(),
                        by: actor.into(),
                        from: Some(before),
                        to: Some(subscription_summary(&sub)),
                    });
                    rows.push((i, "ok", String::new()));
                    records.push(sub);
                }
                Err(e) => rows.push((i, "error", e.code().to_string())),
            }
        }
        if !records.is_empty() {
            let mut batch: Vec<(String, Vec<u8>)> = Vec::with_capacity(records.len());
            for s in &records {
                batch.push((
                    keys::subscription(&s.uid),
                    serde_json::to_vec(s).map_err(|_| ApiError::Internal)?,
                ));
            }
            self.store
                .put_batch(&batch)
                .map_err(|_| ApiError::ControlPlane("The change could not be persisted."))?;
        }
        Ok(BulkOutcome {
            ok: records.len(),
            rows,
        })
    }

    // ------------------------------------------------------------------
    // Credentials
    // ------------------------------------------------------------------

    /// Issue a new credential. Returns the raw token EXACTLY ONCE — it is
    /// never stored, logged, or echoed again.
    pub fn issue_credential(
        &self,
        uid: &str,
        label: Option<String>,
        ttl_s: Option<u64>,
        actor: &str,
    ) -> Result<(String, CredInfo), ApiError> {
        let mut user = self.load_user(uid)?;
        if user.status == UserStatus::Revoked {
            return Err(ApiError::Conflict(
                "A revoked user cannot receive credentials.",
            ));
        }
        let now = self.now();
        let now_ms = self.clock.now_ms();
        let raw = crate::ids::new_api_token().map_err(|_| ApiError::Internal)?;
        let cred = CredInfo {
            cred_id: crate::ids::new_credential_id(now_ms).map_err(|_| ApiError::Internal)?,
            token_hash: crate::ids::token_fingerprint(&raw),
            issued_at: now,
            expires_at: ttl_s.map(|t| now.saturating_add(t)),
            revoked_at: None,
            label: label.map(|l| crate::validation::sanitize_text(&l, 64)),
        };
        let index = TokenIndexEntry {
            uid: user.uid.clone(),
            cred_id: cred.cred_id.clone(),
            cred_version: user.cred_version + 1,
            revoked: false,
        };
        // Credential rotation: bumping cred_version invalidates every token
        // issued under the previous version (and their access tokens).
        user.cred_version += 1;
        user.credentials.push(cred.clone());
        // Bounded retention of old credential entries.
        if user.credentials.len() > UserRecord::MAX_CREDENTIALS {
            let overflow = user.credentials.len() - UserRecord::MAX_CREDENTIALS;
            user.credentials.drain(0..overflow);
        }
        user.updated_at = now;
        user.updated_by = actor.into();

        let batch = vec![
            (
                keys::user(&user.uid),
                serde_json::to_vec(&user).map_err(|_| ApiError::Internal)?,
            ),
            (
                keys::token(&cred.token_hash),
                serde_json::to_vec(&index).map_err(|_| ApiError::Internal)?,
            ),
        ];
        self.store
            .put_batch(&batch)
            .map_err(|_| ApiError::ControlPlane("The change could not be persisted."))?;
        Ok((raw, cred))
    }

    /// Revoke a credential and rotate the version.
    pub fn revoke_credential(
        &self,
        uid: &str,
        cred_id: &str,
        actor: &str,
    ) -> Result<UserRecord, ApiError> {
        if !validation::is_route_id(cred_id) {
            return Err(ApiError::NotFound("Resource not found."));
        }
        let mut user = self.load_user(uid)?;
        let now = self.now();
        let mut changed = false;
        let mut index_updates: Vec<(String, Vec<u8>)> = vec![];
        for c in user.credentials.iter_mut() {
            if c.cred_id == cred_id {
                if c.revoked_at.is_none() {
                    c.revoked_at = Some(now);
                    let mut idx = self
                        .store
                        .get(&keys::token(&c.token_hash))
                        .map_err(|_| ApiError::StorageUnavailable)?
                        .and_then(|b| serde_json::from_slice::<TokenIndexEntry>(&b).ok())
                        .unwrap_or(TokenIndexEntry {
                            uid: user.uid.clone(),
                            cred_id: c.cred_id.clone(),
                            cred_version: user.cred_version,
                            revoked: false,
                        });
                    idx.revoked = true;
                    index_updates.push((
                        keys::token(&c.token_hash),
                        serde_json::to_vec(&idx).map_err(|_| ApiError::Internal)?,
                    ));
                    changed = true;
                }
                break;
            }
        }
        if !changed {
            // Unknown credential id OR already revoked: unknown → 404,
            // already-revoked → idempotent success without a new write.
            let known = user.credentials.iter().any(|c| c.cred_id == cred_id);
            if !known {
                return Err(ApiError::NotFound("Resource not found."));
            }
            return Ok(user);
        }
        user.cred_version += 1; // rotate: invalidates prior version tokens
        user.updated_at = now;
        user.updated_by = actor.into();
        let mut batch = vec![(
            keys::user(&user.uid),
            serde_json::to_vec(&user).map_err(|_| ApiError::Internal)?,
        )];
        batch.extend(index_updates);
        self.store
            .put_batch(&batch)
            .map_err(|_| ApiError::ControlPlane("The change could not be persisted."))?;
        Ok(user)
    }

    // ------------------------------------------------------------------
    // Subscriptions
    // ------------------------------------------------------------------

    pub fn set_subscription(
        &self,
        uid: &str,
        status: Option<SubscriptionStatus>,
        expires_at: Option<Option<u64>>, // Some(None) = clear expiry; None = don't touch
        entitlement_id: Option<String>,
        actor: &str,
    ) -> Result<SubscriptionRecord, ApiError> {
        let mut sub = self.load_sub(uid)?;
        if sub.status == SubscriptionStatus::Revoked {
            return Err(ApiError::Conflict(
                "A revoked subscription cannot be changed.",
            ));
        }
        let mut errs = vec![];
        if let Some(e) = &entitlement_id {
            if e.is_empty() || e.len() > 64 {
                errs.push(FieldError::new("entitlement_id", "must be 1-64 characters"));
            }
        }
        if !errs.is_empty() {
            return Err(ApiError::Unprocessable(errs));
        }
        let now = self.now();
        let before = subscription_summary(&sub);
        if let Some(new_status) = status {
            if new_status == SubscriptionStatus::Revoked {
                sub.status = SubscriptionStatus::Revoked;
            } else {
                sub.status = new_status;
            }
        }
        if let Some(exp) = expires_at {
            if let Some(exp) = exp {
                if now >= exp {
                    return Err(ApiError::Unprocessable(vec![FieldError::new(
                        "expires_at",
                        "must be in the future (UTC)",
                    )]));
                }
            }
            sub.expires_at = exp;
        }
        if let Some(ent) = entitlement_id {
            sub.entitlement_id = ent;
        }
        sub.updated_at = now;
        sub.updated_by = actor.into();
        sub.push_history(SubHistoryItem {
            at: now,
            action: "update".into(),
            by: actor.into(),
            from: Some(before),
            to: Some(subscription_summary(&sub)),
        });
        self.store
            .put(
                &keys::subscription(&sub.uid),
                serde_json::to_vec(&sub).map_err(|_| ApiError::Internal)?,
            )
            .map_err(|_| ApiError::ControlPlane("The change could not be persisted."))?;
        Ok(sub)
    }

    /// Renew: extend by N days from max(now, current expiry), or set an
    /// absolute UTC timestamp. Reactivates Active/Suspended.
    pub fn renew_subscription(
        &self,
        uid: &str,
        extend_days: Option<u64>,
        until: Option<u64>,
        actor: &str,
    ) -> Result<SubscriptionRecord, ApiError> {
        let mut sub = self.load_sub(uid)?;
        if sub.status == SubscriptionStatus::Revoked {
            return Err(ApiError::Conflict(
                "A revoked subscription cannot be renewed.",
            ));
        }
        let now = self.now();
        let before = subscription_summary(&sub);
        let new_exp = if let Some(until) = until {
            if now >= until {
                return Err(ApiError::Unprocessable(vec![FieldError::new(
                    "until",
                    "must be in the future (UTC)",
                )]));
            }
            Some(until)
        } else if let Some(days) = extend_days {
            let base = sub.expires_at.unwrap_or(now).max(now);
            Some(base.saturating_add(days * 86_400))
        } else {
            return Err(ApiError::Unprocessable(vec![FieldError::new(
                "extend_days",
                "either extend_days or until is required",
            )]));
        };
        sub.expires_at = new_exp;
        sub.status = SubscriptionStatus::Active;
        sub.updated_at = now;
        sub.updated_by = actor.into();
        sub.push_history(SubHistoryItem {
            at: now,
            action: "renew".into(),
            by: actor.into(),
            from: Some(before),
            to: Some(subscription_summary(&sub)),
        });
        self.store
            .put(
                &keys::subscription(&sub.uid),
                serde_json::to_vec(&sub).map_err(|_| ApiError::Internal)?,
            )
            .map_err(|_| ApiError::ControlPlane("The change could not be persisted."))?;
        Ok(sub)
    }

    // ------------------------------------------------------------------
    // Aggregates for the dashboard
    // ------------------------------------------------------------------

    pub fn overview_counts(&self) -> Result<OverviewCounts, ApiError> {
        let mut uids = self
            .store
            .scan(keys::users_prefix())
            .map_err(|_| ApiError::StorageUnavailable)?;
        let truncated = uids.len() > MAX_SCAN_RECORDS;
        uids.truncate(MAX_SCAN_RECORDS);
        let mut c = OverviewCounts {
            total: 0,
            active: 0,
            suspended: 0,
            revoked: 0,
            expiring_within_7d: 0,
            truncated,
        };
        let now = self.now();
        for uid in &uids {
            let key = uid.rsplit('/').next().map(keys::user).unwrap_or_default();
            let raw = match self.store.get(&key) {
                Ok(Some(v)) => v,
                _ => continue,
            };
            let user: UserRecord = match serde_json::from_slice(&raw) {
                Ok(u) => u,
                Err(_) => continue,
            };
            c.total += 1;
            match user.status {
                UserStatus::Active => c.active += 1,
                UserStatus::Suspended => c.suspended += 1,
                UserStatus::Revoked => c.revoked += 1,
            }
            if user.status == UserStatus::Active {
                if let Some(sraw) = self
                    .store
                    .get(&keys::subscription(&user.uid))
                    .ok()
                    .flatten()
                {
                    if let Ok(s) = serde_json::from_slice::<SubscriptionRecord>(&sraw) {
                        if s.status == SubscriptionStatus::Active {
                            if let Some(exp) = s.expires_at {
                                // Expiring soon and not yet expired.
                                if now < exp && exp <= now + 7 * 86_400 {
                                    c.expiring_within_7d += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(c)
    }

    // ------------------------------------------------------------------
    // Import / Export
    // ------------------------------------------------------------------

    /// Export every user + subscription. `include_credentials` (super admin,
    /// step-up gated at the handler) additionally includes token
    /// fingerprints and token index entries for migration.
    pub fn export_all(&self, include_credentials: bool) -> Result<serde_json::Value, ApiError> {
        let uids = self
            .store
            .scan(keys::users_prefix())
            .map_err(|_| ApiError::StorageUnavailable)?;
        let mut users = Vec::new();
        let mut tokens = Vec::new();
        for uid in &uids {
            let key = uid.rsplit('/').next().map(keys::user).unwrap_or_default();
            let raw = match self.store.get(&key) {
                Ok(Some(v)) => v,
                _ => continue,
            };
            let user: UserRecord = match serde_json::from_slice(&raw) {
                Ok(u) => u,
                Err(_) => continue,
            };
            let sub = self
                .store
                .get(&keys::subscription(&user.uid))
                .ok()
                .flatten()
                .and_then(|b| serde_json::from_slice::<SubscriptionRecord>(&b).ok());
            if include_credentials {
                for c in &user.credentials {
                    if let Some(idx) = self
                        .store
                        .get(&keys::token(&c.token_hash))
                        .ok()
                        .flatten()
                        .and_then(|b| serde_json::from_slice::<TokenIndexEntry>(&b).ok())
                    {
                        tokens.push(serde_json::json!({
                            "fingerprint": c.token_hash,
                            "uid": idx.uid,
                            "cred_id": idx.cred_id,
                            "cred_version": idx.cred_version,
                            "revoked": idx.revoked,
                        }));
                    }
                }
            }
            users.push(serde_json::json!({
                "uid": user.uid,
                "email": user.email,
                "display_name": user.display_name,
                "status": user.status.as_str(),
                "app_role": user.app_role,
                "metadata": user.metadata,
                "cred_version": user.cred_version,
                "credentials": if include_credentials {
                    serde_json::Value::Array(user.credentials.iter().map(|c| serde_json::json!({
                        "cred_id": c.cred_id,
                        "token_hash": c.token_hash,
                        "issued_at": c.issued_at,
                        "expires_at": c.expires_at,
                        "revoked_at": c.revoked_at,
                        "label": c.label,
                    })).collect())
                } else { serde_json::json!([]) },
                "created_at": user.created_at,
                "created_by": user.created_by,
                "subscription": sub.map(|s| serde_json::json!({
                    "sub_id": s.sub_id,
                    "entitlement_id": s.entitlement_id,
                    "status": s.status.as_str(),
                    "expires_at": s.expires_at,
                    "history": s.history,
                })),
            }));
        }
        Ok(serde_json::json!({
            "format": "gcore-fastedge-admin/users-export",
            "schema_version": 1,
            "exported_at": timeutil::format_rfc3339_utc(self.now()),
            "include_credentials": include_credentials,
            "count": users.len(),
            "users": users,
            "tokens": tokens,
        }))
    }

    /// Import with full pre-validation. When `apply` is false, nothing is
    /// written; the same report shape is returned either way.
    pub fn import_users(
        &self,
        body: &serde_json::Value,
        apply: bool,
        cfg: &AppConfig,
        actor: &str,
    ) -> Result<serde_json::Value, ApiError> {
        let entries =
            body.get("users")
                .and_then(|u| u.as_array())
                .ok_or(ApiError::Unprocessable(vec![FieldError::new(
                    "users",
                    "must be an array",
                )]))?;
        if entries.len() > cfg.import_batch_max * 10 {
            return Err(ApiError::Unprocessable(vec![FieldError::new(
                "users",
                &format!(
                    "import payload exceeds {} entries",
                    cfg.import_batch_max * 10
                ),
            )]));
        }
        let now = self.now();
        let mut valid: Vec<(UserRecord, SubscriptionRecord, String)> = Vec::new();
        let mut results = Vec::new();
        for (i, e) in entries.iter().enumerate() {
            let email = e.get("email").and_then(|v| v.as_str()).unwrap_or("");
            let normalized = match validation::normalize_email(email) {
                Ok(n) => n,
                Err(m) => {
                    results.push(import_row(i, email, "error", vec![format!("email: {m}")]));
                    continue;
                }
            };
            let display_name = e.get("display_name").and_then(|v| v.as_str()).unwrap_or("");
            if !validation::is_display_name(display_name) {
                results.push(import_row(
                    i,
                    email,
                    "error",
                    vec!["display_name: invalid".into()],
                ));
                continue;
            }
            let app_role = e
                .get("app_role")
                .and_then(|v| v.as_str())
                .unwrap_or("member");
            if !validation::is_app_role(app_role) {
                results.push(import_row(
                    i,
                    email,
                    "error",
                    vec!["app_role: invalid".into()],
                ));
                continue;
            }
            let status_str = e.get("status").and_then(|v| v.as_str()).unwrap_or("active");
            let status = match status_str {
                "active" => UserStatus::Active,
                "suspended" => UserStatus::Suspended,
                _ => {
                    results.push(import_row(
                        i,
                        email,
                        "error",
                        vec!["status: must be active or suspended".into()],
                    ));
                    continue;
                }
            };
            let expires_at = match e.get("expires_at").and_then(|v| v.as_str()) {
                None | Some("") => None,
                Some(raw) => match timeutil::parse_rfc3339_utc(raw) {
                    Some(t) if t > now => Some(t),
                    _ => {
                        results.push(import_row(
                            i,
                            email,
                            "error",
                            vec!["expires_at: must be a future RFC3339 UTC timestamp".into()],
                        ));
                        continue;
                    }
                },
            };
            // Duplicate emails inside the payload are rejected in dry-run.
            if valid.iter().any(|(_, _, em)| *em == normalized) {
                results.push(import_row(
                    i,
                    email,
                    "error",
                    vec!["email: duplicated in payload".into()],
                ));
                continue;
            }
            // Duplicates against existing storage.
            if let Ok(Some(_)) = self.store.get(&keys::email(&normalized)) {
                results.push(import_row(
                    i,
                    email,
                    "skipped",
                    vec!["email: already exists".into()],
                ));
                continue;
            }
            let now_ms = self.clock.now_ms();
            let uid = crate::ids::new_user_id(now_ms).map_err(|_| ApiError::Internal)?;
            let sub_id = crate::ids::new_subscription_id(now_ms).map_err(|_| ApiError::Internal)?;
            let user = UserRecord {
                schema_version: USER_SCHEMA_VERSION,
                uid: uid.clone(),
                email: normalized.clone(),
                display_name: crate::validation::sanitize_text(display_name, 128),
                status,
                app_role: app_role.into(),
                metadata: e
                    .get("metadata")
                    .and_then(|m| m.as_object())
                    .cloned()
                    .unwrap_or_default(),
                cred_version: 0,
                credentials: vec![],
                created_at: now,
                created_by: actor.into(),
                updated_at: now,
                updated_by: actor.into(),
            };
            let mut sub = SubscriptionRecord {
                schema_version: SUBSCRIPTION_SCHEMA_VERSION,
                uid: uid.clone(),
                sub_id,
                entitlement_id: e
                    .get("entitlement_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("imported")
                    .chars()
                    .take(64)
                    .collect(),
                status: SubscriptionStatus::Active,
                expires_at,
                created_at: now,
                created_by: actor.into(),
                updated_at: now,
                updated_by: actor.into(),
                history: vec![],
            };
            sub.push_history(SubHistoryItem {
                at: now,
                action: "import".into(),
                by: actor.into(),
                from: None,
                to: Some(subscription_summary(&sub)),
            });
            results.push(import_row(i, email, "created", vec![]));
            valid.push((user, sub, normalized));
        }

        if apply {
            let mut chunk: Vec<(String, Vec<u8>)> = Vec::new();
            for (user, sub, email) in valid {
                chunk.push((
                    keys::user(&user.uid),
                    serde_json::to_vec(&user).map_err(|_| ApiError::Internal)?,
                ));
                chunk.push((
                    keys::subscription(&user.uid),
                    serde_json::to_vec(&sub).map_err(|_| ApiError::Internal)?,
                ));
                chunk.push((keys::email(&email), user.uid.clone().into_bytes()));
                if chunk.len() >= cfg.import_batch_max {
                    self.store.put_batch(&chunk).map_err(|_| {
                        ApiError::ControlPlane("The import could not be persisted.")
                    })?;
                    chunk = Vec::new();
                }
            }
            if !chunk.is_empty() {
                self.store
                    .put_batch(&chunk)
                    .map_err(|_| ApiError::ControlPlane("The import could not be persisted."))?;
            }
        }

        let created = results.iter().filter(|r| r["result"] == "created").count();
        Ok(serde_json::json!({
            "applied": apply,
            "created": if apply { created } else { 0 },
            "planned_creates": created,
            "skipped": results.iter().filter(|r| r["result"] == "skipped").count(),
            "errors": results.iter().filter(|r| r["result"] == "error").count(),
            "rows": results,
        }))
    }
}

fn import_row(index: usize, email: &str, result: &str, issues: Vec<String>) -> serde_json::Value {
    serde_json::json!({
        "index": index,
        "email": email,
        "result": result,
        "issues": issues,
    })
}

/// Human-readable snapshot of subscription state for history entries.
pub fn subscription_summary(s: &SubscriptionRecord) -> String {
    match s.expires_at {
        Some(exp) => format!(
            "status={};expires_at={}",
            s.status.as_str(),
            timeutil::format_rfc3339_utc(exp)
        ),
        None => format!("status={};expires_at=none", s.status.as_str()),
    }
}

/// Per-record outcome row for bulk operations.
pub struct BulkOutcome {
    pub ok: usize,
    /// (index, "ok"|"error", reason)
    pub rows: Vec<(usize, &'static str, String)>,
}

/// Shared status state machine used by both single and bulk operations.
fn apply_status_action(user: &mut UserRecord, action: &str) -> Result<(), Reason> {
    match action {
        "suspend" => match user.status {
            UserStatus::Active => {
                user.status = UserStatus::Suspended;
                Ok(())
            }
            UserStatus::Suspended => Ok(()), // idempotent
            UserStatus::Revoked => Err(Reason {
                code: "CONFLICT",
                msg: "A revoked user cannot be suspended.",
            }),
        },
        "reactivate" => match user.status {
            UserStatus::Suspended | UserStatus::Active => {
                user.status = UserStatus::Active;
                Ok(())
            }
            UserStatus::Revoked => Err(Reason {
                code: "CONFLICT",
                msg: "A revoked user cannot be reactivated.",
            }),
        },
        "revoke" => {
            user.status = UserStatus::Revoked; // idempotent
            Ok(())
        }
        _ => Err(Reason {
            code: "VALIDATION_FAILED",
            msg: "action must be suspend, reactivate, or revoke",
        }),
    }
}

pub struct Reason {
    pub code: &'static str,
    pub msg: &'static str,
}

impl Reason {
    fn to_static(&self) -> &str {
        self.code
    }
}

impl From<Reason> for ApiError {
    fn from(r: Reason) -> Self {
        match r.code {
            "CONFLICT" => ApiError::Conflict(r.msg),
            _ => ApiError::Unprocessable(vec![FieldError::new("action", r.msg)]),
        }
    }
}

/// UI-facing subscription projection with the DERIVED (computed) state.
pub fn subscription_view(s: &SubscriptionRecord, now: u64) -> serde_json::Value {
    let derived = if s.status == SubscriptionStatus::Revoked {
        "revoked"
    } else if s.status == SubscriptionStatus::Suspended {
        "suspended"
    } else {
        match s.expires_at {
            Some(exp) if now >= exp => "expired",
            _ => s.status.as_str(),
        }
    };
    serde_json::json!({
        "sub_id": s.sub_id,
        "entitlement_id": s.entitlement_id,
        "status": s.status.as_str(),
        "derived_status": derived,
        "expires_at": s.expires_at.map(timeutil::format_rfc3339_utc),
        "history_count": s.history.len(),
        "updated_at": timeutil::format_rfc3339_utc(s.updated_at),
        "updated_by": s.updated_by,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{FixedClock, MemStore};

    fn setup() -> (MemStore, FixedClock) {
        (MemStore::new(), FixedClock::new(1_800_000_000_000))
    }

    fn svc<'a>(store: &'a MemStore, clock: &'a FixedClock) -> UsersService<'a> {
        UsersService { store, clock }
    }

    fn sample_input(email: &str, expires_at: Option<u64>) -> CreateUserInput {
        let as_string = expires_at.map(crate::timeutil::format_rfc3339_utc);
        CreateUserInput {
            email: email.into(),
            display_name: "Sample User".into(),
            app_role: "member".into(),
            metadata: Default::default(),
            entitlement_id: "ent-basic".into(),
            expires_at: as_string,
        }
    }

    #[test]
    fn create_list_get_flow() {
        let (store, clock) = setup();
        let svc = svc(&store, &clock);
        let u = svc
            .create_user(
                &sample_input("alice@example.io", Some(clock.now_unix() + 86_400)),
                "admin:root",
            )
            .unwrap();
        assert!(u.uid.starts_with('u'));
        let (views, total, trunc) = svc
            .list_users(&UserQuery {
                text: None,
                status: None,
                newest_first: false,
                limit: 10,
                offset: 0,
            })
            .unwrap();
        assert_eq!(total, 1);
        assert!(!trunc);
        assert_eq!(views[0]["email"], "alice@example.io");

        let detail = svc.get_user(&u.uid).unwrap();
        assert_eq!(detail["subscription"]["derived_status"], "active");
        let _ = store;
    }

    #[test]
    fn duplicate_email_conflicts() {
        let (store, clock) = setup();
        let svc = svc(&store, &clock);
        svc.create_user(&sample_input("dupe@x.io", None), "admin:root")
            .unwrap();
        assert!(matches!(
            svc.create_user(&sample_input("dupe@x.io", None), "admin:root"),
            Err(ApiError::Conflict(_))
        ));
        // Case/whitespace normalization still conflicts.
        assert!(matches!(
            svc.create_user(&sample_input(" DUPE@X.IO ", None), "admin:root"),
            Err(ApiError::Conflict(_))
        ));
    }

    #[test]
    fn invalid_inputs_rejected_with_field_errors() {
        let (store, clock) = setup();
        let svc = svc(&store, &clock);
        // Bad email, bad name, past expiration.
        let past = clock.now_unix() - 10;
        let mut inp = sample_input("not-an-email", Some(past));
        inp.display_name = "bad\nname".into();
        match svc.create_user(&inp, "admin:root") {
            Err(ApiError::Unprocessable(fields)) => {
                let names: Vec<&str> = fields.iter().map(|f| f.field.as_str()).collect();
                assert!(names.contains(&"email"));
                assert!(names.contains(&"display_name"));
                assert!(names.contains(&"expires_at"));
            }
            other => panic!("expected validation errors, got {other:?}"),
        }
    }

    #[test]
    fn status_state_machine() {
        let (store, clock) = setup();
        let svc = svc(&store, &clock);
        let u = svc
            .create_user(&sample_input("sm@x.io", None), "admin:root")
            .unwrap();
        svc.set_user_status(&u.uid, "suspend", "admin:root")
            .unwrap();
        let v = svc.get_user(&u.uid).unwrap();
        assert_eq!(v["status"], "suspended");
        svc.set_user_status(&u.uid, "reactivate", "admin:root")
            .unwrap();
        let v = svc.get_user(&u.uid).unwrap();
        assert_eq!(v["status"], "active");
        svc.set_user_status(&u.uid, "revoke", "admin:root").unwrap();
        let v = svc.get_user(&u.uid).unwrap();
        assert_eq!(v["status"], "revoked");
        // Revoked is terminal.
        assert!(matches!(
            svc.set_user_status(&u.uid, "reactivate", "admin:root"),
            Err(ApiError::Conflict(_))
        ));
        assert!(matches!(
            svc.set_user_status(&u.uid, "suspend", "admin:root"),
            Err(ApiError::Conflict(_))
        ));
        // Idempotent revoke.
        svc.set_user_status(&u.uid, "revoke", "admin:root").unwrap();
    }

    #[test]
    fn credential_issue_once_and_revoke_rotates_version() {
        let (store, clock) = setup();
        let svc = svc(&store, &clock);
        let u = svc
            .create_user(&sample_input("cred@x.io", None), "admin:root")
            .unwrap();
        let (raw, cred) = svc
            .issue_credential(&u.uid, Some("ci".to_string()), None, "admin:root")
            .unwrap();
        assert!(raw.starts_with("sk_live_"));
        let view = svc.get_user(&u.uid).unwrap();
        assert_eq!(view["cred_version"], 1);
        assert_eq!(view["credentials"][0]["cred_id"], cred.cred_id);
        // The view never exposes the raw token or its full hash.
        let s = view.to_string();
        assert!(!s.contains(&raw));
        assert!(!s.contains(&cred.token_hash));

        svc.revoke_credential(&u.uid, &cred.cred_id, "admin:root")
            .unwrap();
        let view = svc.get_user(&u.uid).unwrap();
        assert_eq!(view["cred_version"], 2); // rotated
        assert!(view["credentials"][0]["revoked_at"].is_string());
        // Revoking an already-revoked credential is idempotent: no second
        // version bump, no extra write.
        let before = view["cred_version"].as_u64().unwrap();
        svc.revoke_credential(&u.uid, &cred.cred_id, "admin:root")
            .unwrap();
        let view2 = svc.get_user(&u.uid).unwrap();
        assert_eq!(view2["cred_version"].as_u64().unwrap(), before);
        // Unknown cred id → 404.
        assert!(matches!(
            svc.revoke_credential(&u.uid, "cUNKNOWN", "admin:root"),
            Err(ApiError::NotFound(_))
        ));
    }

    #[test]
    fn renewal_extends_from_latest_expiry() {
        let (store, clock) = setup();
        let svc = svc(&store, &clock);
        let exp0 = clock.now_unix() + 86_400;
        let u = svc
            .create_user(&sample_input("ren@x.io", Some(exp0)), "admin:root")
            .unwrap();
        svc.renew_subscription(&u.uid, Some(30), None, "admin:root")
            .unwrap();
        let v = svc.get_user(&u.uid).unwrap();
        let new_exp = v["subscription"]["expires_at"].as_str().unwrap();
        let new_exp_ts = crate::timeutil::parse_rfc3339_utc(new_exp).unwrap();
        assert_eq!(new_exp_ts, exp0 + 30 * 86_400);
        // Absolute `until` wins when provided.
        svc.renew_subscription(&u.uid, None, Some(exp0 + 10 * 86_400), "admin:root")
            .unwrap();
        let v = svc.get_user(&u.uid).unwrap();
        assert_eq!(
            crate::timeutil::parse_rfc3339_utc(v["subscription"]["expires_at"].as_str().unwrap())
                .unwrap(),
            exp0 + 10 * 86_400
        );
        // Neither field → validation error.
        assert!(matches!(
            svc.renew_subscription(&u.uid, None, None, "admin:root"),
            Err(ApiError::Unprocessable(_))
        ));
    }

    #[test]
    fn import_dry_run_then_apply() {
        let (store, clock) = setup();
        let svc = svc(&store, &clock);
        let cfg = AppConfig::default();
        let payload = serde_json::json!({
            "users": [
                {"email": "one@imp.io", "display_name": "One", "expires_at": "2100-01-01T00:00:00Z"},
                {"email": "TWO@IMP.io", "display_name": "Two"},
                {"email": "bad", "display_name": "Bad"},
                {"email": "one@imp.io", "display_name": "Dup"},
            ]
        });
        let report = svc
            .import_users(&payload, false, &cfg, "admin:root")
            .unwrap();
        assert_eq!(report["applied"], false);
        assert_eq!(report["planned_creates"], 2);
        assert_eq!(report["errors"], 2); // bad email + duplicate
                                         // Nothing written in dry-run.
        assert!(store.scan(keys::users_prefix()).unwrap().is_empty());

        let report = svc
            .import_users(&payload, true, &cfg, "admin:root")
            .unwrap();
        assert_eq!(report["applied"], true);
        assert_eq!(report["created"], 2);
        let uids = store.scan(keys::users_prefix()).unwrap();
        assert_eq!(uids.len(), 2);
        // Emails normalized on import.
        assert!(store.get(&keys::email("two@imp.io")).unwrap().is_some());
    }

    #[test]
    fn export_sanitizes_credentials_by_default() {
        let (store, clock) = setup();
        let svc = svc(&store, &clock);
        let u = svc
            .create_user(&sample_input("exp@x.io", None), "admin:root")
            .unwrap();
        let (raw, cred) = svc
            .issue_credential(&u.uid, None, None, "admin:root")
            .unwrap();
        let plain = serde_json::to_string(&svc.export_all(false).unwrap()).unwrap();
        assert!(!plain.contains(&raw));
        assert!(!plain.contains(&cred.token_hash));
        let full = serde_json::to_string(&svc.export_all(true).unwrap()).unwrap();
        assert!(full.contains(&cred.token_hash)); // explicit sensitive export
        assert!(!full.contains(&raw)); // raw token is NEVER exportable
    }
}
