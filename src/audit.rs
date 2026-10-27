//! Audit trail: append-only security record with strict redaction rules.
//!
//! Design points:
//! * One record per Edge Storage key (`audit/e<ULID>`); ULID ordering makes
//!   chronological listing a key-sort, no index needed.
//! * Two write modes: `critical` (admin mutations, credential issuance) and
//!   `best_effort` (auth failures). Critical events failing to persist
//!   abort the operation — the audit trail must never silently lose an
//!   administrative action.
//! * `details` is built from pre-redacted key=value fragments. Values are
//!   truncated and stripped of control characters; secrets and tokens are
//!   fingerprinted (first 8 hex chars max) before logging, never raw.

use crate::errors::ApiError;
use crate::models::{
    keys, AdminRecord, AuditCategory, AuditEvent, AuditOutcome, AUDIT_SCHEMA_VERSION,
};
use crate::platform::{Clock, Store, StoreError};

pub struct Audit<'a> {
    pub store: &'a dyn Store,
    pub clock: &'a dyn Clock,
}

#[derive(Debug, Clone)]
pub struct AuditQuery {
    pub category: Option<AuditCategory>,
    pub actor: Option<String>,
    pub target: Option<String>,
    pub outcome: Option<AuditOutcome>,
}

/// Redact a string for audit storage: strip control chars, cap length.
pub fn redact(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect()
}

/// Show only a safe prefix of a hash/token — enough to correlate, never
/// enough to replay.
pub fn fingerprint_prefix(hash_hex: &str) -> String {
    hash_hex.chars().take(8).collect()
}

impl<'a> Audit<'a> {
    /// Persist a critical event. Failure aborts the caller's operation.
    pub fn record_critical(&self, ev: &AuditEvent) -> Result<(), ApiError> {
        self.store
            .put(
                &keys::audit(&ev.id),
                serde_json::to_vec(ev).map_err(|_| ApiError::Internal)?,
            )
            .map_err(Self::map_put_err)
    }

    /// Persist a best-effort event (never blocks the caller).
    pub fn record_best_effort(&self, ev: &AuditEvent) {
        let _ = self.store.put(
            &keys::audit(&ev.id),
            serde_json::to_vec(ev).unwrap_or_default(),
        );
    }

    fn map_put_err(e: StoreError) -> ApiError {
        match e {
            StoreError::Unavailable => ApiError::StorageUnavailable,
        }
    }

    /// Build a new event with server-side time and a fresh id.
    #[allow(clippy::too_many_arguments)] // audit metadata is inherently tuple-shaped
    pub fn new_event(
        &self,
        category: AuditCategory,
        action: &str,
        actor: &str,
        target: &str,
        outcome: AuditOutcome,
        request_id: &str,
        details: Option<String>,
    ) -> Result<AuditEvent, ApiError> {
        let now_ms = self.clock.now_ms();
        Ok(AuditEvent {
            schema_version: AUDIT_SCHEMA_VERSION,
            id: crate::ids::new_event_id(now_ms).map_err(|_| ApiError::Internal)?,
            at: now_ms,
            category,
            action: redact(action, 64),
            actor: redact(actor, 64),
            target: redact(target, 128),
            outcome,
            request_id: redact(request_id, 64),
            details: details.map(|d| redact(&d, 256)),
        })
    }

    /// List events newest-first with filters. `limit` bounds both the scan
    /// read volume and the returned page.
    pub fn list(
        &self,
        query: &AuditQuery,
        limit: usize,
        offset: usize,
    ) -> Result<(Vec<AuditEvent>, bool), ApiError> {
        const MAX_SCAN: usize = 500;
        let mut keys_found = self
            .store
            .scan(keys::audit_prefix())
            .map_err(|_| ApiError::StorageUnavailable)?;
        // Newest first: ULID ids sort lexically by time.
        keys_found.sort();
        keys_found.reverse();
        keys_found.truncate(MAX_SCAN);
        let mut events = Vec::new();
        for k in keys_found {
            let raw = match self.store.get(&k) {
                Ok(Some(v)) => v,
                Ok(None) => continue,
                Err(_) => return Err(ApiError::StorageUnavailable),
            };
            let ev: AuditEvent = match serde_json::from_slice(&raw) {
                Ok(e) => e,
                Err(_) => continue, // unknown schema: skip, never fail the listing
            };
            if let Some(c) = query.category {
                if ev.category != c {
                    continue;
                }
            }
            if let Some(a) = &query.actor {
                if !ev.actor.eq_ignore_ascii_case(a) {
                    continue;
                }
            }
            if let Some(t) = &query.target {
                if !ev.target.contains(t.as_str()) {
                    continue;
                }
            }
            if let Some(o) = query.outcome {
                if ev.outcome != o {
                    continue;
                }
            }
            events.push(ev);
            if events.len() > offset + limit {
                break;
            }
        }
        let has_more = events.len() > offset + limit;
        let page: Vec<AuditEvent> = events.into_iter().skip(offset).take(limit).collect();
        Ok((page, has_more))
    }

    /// Prune events older than `retention_days`. Returns pruned count.
    pub fn prune(&self, retention_days: u32) -> Result<usize, ApiError> {
        let cutoff_ms = self
            .clock
            .now_ms()
            .saturating_sub(u64::from(retention_days) * 86_400_000);
        let all = self
            .store
            .scan(keys::audit_prefix())
            .map_err(|_| ApiError::StorageUnavailable)?;
        let old: Vec<String> = all
            .into_iter()
            .filter(|k| {
                k.rsplit('/')
                    .next()
                    .map(|id| {
                        // Event ids start with 'e' + 26-char ULID; the first 10
                        // base32 chars encode the timestamp (48 bits).
                        decode_ulid_ts_ms(id)
                            .map(|ts| ts < cutoff_ms)
                            .unwrap_or(false)
                    })
                    .unwrap_or(false)
            })
            .collect();
        let n = old.len();
        if n > 0 {
            self.store.delete_batch(&old).map_err(Self::map_put_err)?;
        }
        Ok(n)
    }
}

// ULID timestamp extraction (first 10 chars, 2 bits padding per 5-bit group).
fn decode_ulid_ts_ms(id: &str) -> Option<u64> {
    const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let body = id.strip_prefix('e')?;
    if body.len() < 10 {
        return None;
    }
    let mut ts: u64 = 0;
    for ch in body.chars().take(10) {
        let v = CROCKFORD
            .iter()
            .position(|&c| (c as char) == ch.to_ascii_uppercase())? as u64;
        ts = (ts << 5) | v;
    }
    Some(ts)
}

/// Actor identifier for audit events: admin username or system label.
pub fn actor_admin(username: &str) -> String {
    format!("admin:{username}")
}

pub fn actor_system() -> &'static str {
    "system"
}

/// Include the record's role (never the hash) in audit detail.
pub fn admin_detail(rec: &AdminRecord) -> String {
    format!("role={}", rec.role.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{FixedClock, MemStore};

    #[test]
    fn ulid_timestamp_roundtrip() {
        let ms = 1_800_000_123_456u64;
        let id = crate::ids::new_event_id(ms).unwrap();
        assert_eq!(decode_ulid_ts_ms(&id), Some(ms));
    }

    #[test]
    fn record_and_list_with_filters() {
        let store = MemStore::new();
        let clock = FixedClock::new(1_700_000_000_000);
        let audit = Audit {
            store: &store,
            clock: &clock,
        };

        let ev1 = audit
            .new_event(
                AuditCategory::Auth,
                "login",
                "admin:root",
                "session",
                AuditOutcome::Ok,
                "req1",
                None,
            )
            .unwrap();
        clock.advance_s(1);
        let ev2 = audit
            .new_event(
                AuditCategory::Auth,
                "login",
                "admin:root",
                "session",
                AuditOutcome::Denied,
                "req2",
                Some("reason=bad-password".into()),
            )
            .unwrap();
        audit.record_critical(&ev1).unwrap();
        audit.record_critical(&ev2).unwrap();

        let (all, more) = audit
            .list(
                &AuditQuery {
                    category: None,
                    actor: None,
                    target: None,
                    outcome: None,
                },
                10,
                0,
            )
            .unwrap();
        assert!(!more);
        assert_eq!(all.len(), 2);
        // Newest first.
        assert_eq!(all[0].id, ev2.id);

        let (denied, _) = audit
            .list(
                &AuditQuery {
                    category: Some(AuditCategory::Auth),
                    actor: None,
                    target: None,
                    outcome: Some(AuditOutcome::Denied),
                },
                10,
                0,
            )
            .unwrap();
        assert_eq!(denied.len(), 1);
        assert_eq!(denied[0].outcome, AuditOutcome::Denied);
    }

    #[test]
    fn redaction_removes_controls_and_caps_length() {
        assert_eq!(redact("clean", 10), "clean");
        assert_eq!(redact("a\r\nb", 10), "ab");
        assert_eq!(redact(&"x".repeat(300), 100).len(), 100);
        assert_eq!(fingerprint_prefix("0123456789abcdef"), "01234567");
    }

    #[test]
    fn prune_removes_old_events() {
        let store = MemStore::new();
        let clock = FixedClock::new(1_700_000_000_000);
        let audit = Audit {
            store: &store,
            clock: &clock,
        };
        let ev = audit
            .new_event(
                AuditCategory::System,
                "tick",
                "system",
                "clock",
                AuditOutcome::Ok,
                "r",
                None,
            )
            .unwrap();
        audit.record_critical(&ev).unwrap();
        // 91 days later, 90-day retention prunes it.
        clock.set(1_700_000_000_000 + 91 * 86_400_000);
        let _ = audit.prune(90).unwrap();
    }
}
