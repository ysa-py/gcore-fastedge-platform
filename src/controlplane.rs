//! Gcore control-plane client: the only path through which Edge Storage
//! records are written.
//!
//! Edge Storage is read-only from application code by design (verified
//! against the FastEdge WIT contract). Writes therefore go through the
//! account-level Gcore REST API:
//!
//! `PUT https://api.gcore.com/fastedge/v1/kv/{store_id}/data`
//! with entries of the documented `modify_store_data_entry` shape:
//! `{ "op": "add" | "del_key", "key": ..., "datatype": "kv",
//!    "payload": { "value": <base64>, "encoding": "base64" } }`
//!
//! The exact request envelope (bare array vs `{"data": [...]}`) is not
//! pinned by the published examples the way the entry schema is, so the
//! client probes once per instance: it tries the bare array first and, on
//! a 4xx, retries with the wrapper object, then sticks with whichever
//! form the account accepts. Upstream error bodies are never surfaced to
//! callers — only coarse categories are exposed.

use crate::platform::{HttpError, HttpOut, Store};
use base64::Engine;
use serde_json::{json, Value};
use std::sync::Mutex;

#[derive(Debug)]
pub enum CpError {
    /// Control plane unreachable / network failure.
    Unreachable,
    /// Control plane rejected our credentials or permission (config hint).
    Auth,
    /// Control plane rejected the request payload.
    Rejected,
    /// Any other upstream failure.
    Other,
}

#[derive(Debug, Clone)]
pub struct KvWriteOp {
    pub key: String,
    /// `None` deletes the key.
    pub value: Option<Vec<u8>>,
}

impl KvWriteOp {
    pub fn put(key: &str, value: Vec<u8>) -> Self {
        Self {
            key: key.into(),
            value: Some(value),
        }
    }
    pub fn delete(key: &str) -> Self {
        Self {
            key: key.into(),
            value: None,
        }
    }
}

pub trait ControlPlane: Send + Sync {
    fn apply(&self, ops: &[KvWriteOp]) -> Result<(), CpError>;
    /// Human-readable description for diagnostics (no secrets).
    fn describe(&self) -> String;
}

pub struct GcoreControlPlane<'a> {
    http: &'a dyn HttpOut,
    api_key: String,
    store_id: String,
    base_url: String,
    /// Some(true) → wrapper object; Some(false) → bare array; None → unprobed.
    body_form: Mutex<Option<bool>>,
}

impl<'a> GcoreControlPlane<'a> {
    pub fn new(http: &'a dyn HttpOut, api_key: &str, store_id: &str, base_url: &str) -> Self {
        Self {
            http,
            api_key: api_key.to_string(),
            store_id: store_id.to_string(),
            base_url: base_url.trim_end_matches('/').to_string(),
            body_form: Mutex::new(None),
        }
    }

    fn entries_json(ops: &[KvWriteOp]) -> Value {
        let mut entries = Vec::with_capacity(ops.len());
        for op in ops {
            let entry = match &op.value {
                Some(v) => json!({
                    "op": "add",
                    "key": op.key,
                    "datatype": "kv",
                    "payload": {
                        "value": base64::engine::general_purpose::STANDARD.encode(v),
                        "encoding": "base64",
                    },
                }),
                None => json!({
                    "op": "del_key",
                    "key": op.key,
                    "datatype": "kv",
                }),
            };
            entries.push(entry);
        }
        Value::Array(entries)
    }

    fn send(&self, body: Vec<u8>) -> Result<u16, CpError> {
        let url = format!("{}/fastedge/v1/kv/{}/data", self.base_url, self.store_id);
        let resp = self
            .http
            .request(
                "PUT",
                &url,
                &[
                    ("Authorization", &format!("APIKey {}", self.api_key)),
                    ("Content-Type", "application/json"),
                    ("Accept", "application/json"),
                ],
                &body,
            )
            .map_err(|e| match e {
                HttpError::Unreachable => CpError::Unreachable,
                HttpError::Status(_) => CpError::Other,
            })?;
        Ok(resp.status)
    }
}

impl ControlPlane for GcoreControlPlane<'_> {
    fn apply(&self, ops: &[KvWriteOp]) -> Result<(), CpError> {
        if ops.is_empty() {
            return Ok(());
        }
        let entries = Self::entries_json(ops);
        let probed = *self.body_form.lock().unwrap();
        // `true` → wrapper object {"data": [...]}, `false` → bare array.
        let initial_wrapper = probed.unwrap_or(false);

        let attempt = |wrapper: bool| -> Result<(), CpError> {
            let body = if wrapper {
                json!({ "data": entries }).to_string().into_bytes()
            } else {
                entries.to_string().into_bytes()
            };
            let status = self.send(body)?;
            match status {
                s if (200..300).contains(&s) => Ok(()),
                401 | 403 => Err(CpError::Auth),
                _ => Err(CpError::Rejected),
            }
        };

        match attempt(initial_wrapper) {
            Ok(()) => {
                *self.body_form.lock().unwrap() = Some(initial_wrapper);
                Ok(())
            }
            Err(e @ CpError::Auth) => Err(e),
            Err(e) => {
                if probed.is_some() {
                    // Envelope already established for this instance: the
                    // failure is not a shape problem.
                    return Err(e);
                }
                // Probe once with the alternate envelope.
                let alt = !initial_wrapper;
                attempt(alt)?;
                *self.body_form.lock().unwrap() = Some(alt);
                Ok(())
            }
        }
    }

    fn describe(&self) -> String {
        format!("Gcore REST control plane (store {})", self.store_id)
    }
}

/// Writes directly to a `Store` — used by host tests and any deployment
/// mode where the data plane itself is writable.
pub struct DirectControlPlane<'a> {
    pub store: &'a dyn Store,
}

impl ControlPlane for DirectControlPlane<'_> {
    fn apply(&self, ops: &[KvWriteOp]) -> Result<(), CpError> {
        for op in ops {
            match &op.value {
                Some(v) => self
                    .store
                    .put(&op.key, v.clone())
                    .map_err(|_| CpError::Rejected)?,
                None => {
                    // Deletes are idempotent: missing key is success.
                    self.store.delete(&op.key).map_err(|_| CpError::Rejected)?;
                }
            }
        }
        Ok(())
    }
    fn describe(&self) -> String {
        "direct data-plane writes (test mode)".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::FakeHttp;

    #[test]
    fn encodes_add_and_delete_entries() {
        let ops = vec![
            KvWriteOp::put("users/uX", b"{}".to_vec()),
            KvWriteOp::delete("email/a@b.c"),
        ];
        let v = GcoreControlPlane::entries_json(&ops);
        assert_eq!(v[0]["op"], "add");
        assert_eq!(v[0]["datatype"], "kv");
        assert_eq!(v[0]["payload"]["encoding"], "base64");
        assert_eq!(
            v[0]["payload"]["value"],
            base64::engine::general_purpose::STANDARD.encode(b"{}")
        );
        assert_eq!(v[1]["op"], "del_key");
        assert!(v[1].get("payload").is_none());
    }

    #[test]
    fn probes_envelope_and_rememberes_it() {
        let http = FakeHttp::default();
        let cp = GcoreControlPlane::new(&http, "key", "42", "https://api.example.com");
        // First attempt (bare array) rejected with 400; retry (wrapper) succeeds.
        http.push_ok(400, "");
        http.push_ok(200, "");
        cp.apply(&[KvWriteOp::put("k", b"v".to_vec())]).unwrap();
        {
            let reqs = http.requests.lock().unwrap();
            assert_eq!(reqs.len(), 2);
            assert_eq!(reqs[0].2[0], b'['); // bare array first
            assert_eq!(reqs[1].2[0], b'{'); // wrapper retry
        }
        // Subsequent writes use the remembered form only.
        http.push_ok(200, "");
        cp.apply(&[KvWriteOp::put("k2", b"v".to_vec())]).unwrap();
        assert_eq!(http.requests.lock().unwrap().len(), 3);
    }

    #[test]
    fn auth_failure_is_classified() {
        let http = FakeHttp::default();
        let cp = GcoreControlPlane::new(&http, "bad-key", "42", "https://api.example.com");
        http.push_ok(401, "");
        http.push_ok(401, "");
        assert!(matches!(
            cp.apply(&[KvWriteOp::delete("k")]),
            Err(CpError::Auth)
        ));
    }

    #[test]
    fn unreachable_is_classified() {
        let http = FakeHttp::default();
        let cp = GcoreControlPlane::new(&http, "key", "42", "https://api.example.com");
        assert!(matches!(
            cp.apply(&[KvWriteOp::delete("k")]),
            Err(CpError::Unreachable)
        ));
    }
}
