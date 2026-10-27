//! Shared integration-test harness: wires the full `App` with in-memory
//! providers, a controllable clock, and optional fault injection.
//!
//! Semantics note: a fresh composed store is built for every request.
//! That is strictly more conservative than production (where one
//! instance reuses its read-your-writes buffer across requests) — any
//! behavior that passes here also holds with a warmer buffer.

#![allow(dead_code)]

use fastedge_admin_platform::app::{App, EnvConfig};
use fastedge_admin_platform::controlplane::{ControlPlane, CpError, KvWriteOp};
use fastedge_admin_platform::datastore::ReadYourWritesStore;
use fastedge_admin_platform::http::{Req, Resp};
use fastedge_admin_platform::models::{keys, AdminRecord, AdminRole, ADMIN_SCHEMA_VERSION};
use fastedge_admin_platform::platform::{
    FakeHttp, FixedClock, MemCache, MemStore, StaticSecrets, Store, StoreError,
};
use fastedge_admin_platform::router;
use serde_json::Value;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

pub const ADMIN_USER: &str = "admin";
pub const ADMIN_PASS: &str = "correct-horse-battery-staple-42";
pub const SESSION_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef";
pub const APP_KEY: &str = "9876543210abcdef9876543210abcdef9876543210abcdef";
pub const GCORE_API_KEY: &str = "test-gcore-api-key";
pub const XRW: &str = "fastedge-admin";

/// Cloneable control plane writing straight to the memory store, with
/// optional fault injection after N calls.
#[derive(Clone)]
pub struct MemControlPlane {
    pub mem: MemStore,
    pub fail_calls: Arc<AtomicUsize>,
    pub fail_after: Option<usize>,
}

impl MemControlPlane {
    pub fn new(mem: MemStore) -> Self {
        Self {
            mem,
            fail_calls: Arc::new(AtomicUsize::new(0)),
            fail_after: None,
        }
    }
    pub fn fail_after(&mut self, n: usize) {
        self.fail_after = Some(n);
        self.fail_calls.store(0, Ordering::SeqCst);
    }
}

impl ControlPlane for MemControlPlane {
    fn apply(&self, ops: &[KvWriteOp]) -> Result<(), CpError> {
        let n = 1 + self.fail_calls.fetch_add(1, Ordering::SeqCst);
        if let Some(limit) = self.fail_after {
            if n > limit {
                return Err(CpError::Rejected);
            }
        }
        for op in ops {
            match &op.value {
                Some(v) => self
                    .mem
                    .put(&op.key, v.clone())
                    .map_err(|_| CpError::Rejected)?,
                None => {
                    self.mem.delete(&op.key).map_err(|_| CpError::Rejected)?;
                }
            }
        }
        Ok(())
    }
    fn describe(&self) -> String {
        "mem control plane (tests)".into()
    }
}

/// Store wrapper that can fail reads after N calls (fail-closed testing).
pub struct FailingReads {
    pub mem: MemStore,
    pub fail_get_after: RwLockUsize,
    pub get_calls: AtomicUsize,
}

pub struct RwLockUsize(std::sync::RwLock<Option<usize>>);

impl RwLockUsize {
    pub fn none() -> Self {
        Self(std::sync::RwLock::new(None))
    }
    pub fn set(&self, v: Option<usize>) {
        *self.0.write().unwrap() = v;
    }
    pub fn get(&self) -> Option<usize> {
        *self.0.read().unwrap()
    }
}

impl FailingReads {
    pub fn wrap(mem: MemStore) -> Self {
        Self {
            mem,
            fail_get_after: RwLockUsize::none(),
            get_calls: AtomicUsize::new(0),
        }
    }
    pub fn fail_get_after(&self, n: usize) {
        self.fail_get_after.set(Some(n));
        self.get_calls.store(0, Ordering::SeqCst);
    }
}

impl Store for FailingReads {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let n = 1 + self.get_calls.fetch_add(1, Ordering::SeqCst);
        if let Some(limit) = self.fail_get_after.get() {
            if n > limit {
                return Err(StoreError::Unavailable);
            }
        }
        self.mem.get(key)
    }
    fn put(&self, key: &str, value: Vec<u8>) -> Result<(), StoreError> {
        self.mem.put(key, value)
    }
    fn delete(&self, key: &str) -> Result<(), StoreError> {
        self.mem.delete(key)
    }
    fn scan(&self, pattern: &str) -> Result<Vec<String>, StoreError> {
        self.mem.scan(pattern)
    }
}

pub struct Harness {
    pub mem: MemStore,
    pub clock: FixedClock,
    pub cache: MemCache,
    pub secrets: StaticSecrets,
    pub http: FakeHttp,
    pub cp: MemControlPlane,
    pub failing_reads: Option<FailingReads>,
}

impl Harness {
    pub fn new() -> Self {
        let mem = MemStore::new();
        let clock = FixedClock::new(1_800_000_000_000);
        let now_fn = {
            let inner = clock.0.clone();
            Arc::new(move || *inner.read().unwrap()) as Arc<dyn Fn() -> u64 + Send + Sync>
        };
        let cache = MemCache::new(now_fn);
        let secrets = StaticSecrets::new(&[
            ("SESSION_SIGNING_KEY", SESSION_KEY),
            ("APP_TOKEN_SIGNING_KEY", APP_KEY),
            ("GCORE_API_KEY", GCORE_API_KEY),
        ]);
        let rec = AdminRecord {
            schema_version: ADMIN_SCHEMA_VERSION,
            username: ADMIN_USER.into(),
            role: AdminRole::SuperAdmin,
            password_hash: fastedge_admin_platform::crypto::hash_password(ADMIN_PASS, 10_000),
            created_at: 1,
            created_by: "test".into(),
            updated_at: 1,
            last_login_at: None,
        };
        mem.put(&keys::admin(ADMIN_USER), serde_json::to_vec(&rec).unwrap())
            .unwrap();
        let cp = MemControlPlane::new(mem.clone());
        Self {
            mem,
            clock,
            cache,
            secrets,
            http: FakeHttp::default(),
            cp,
            failing_reads: None,
        }
    }

    /// Route one request through the FULL production pipeline.
    pub fn request(&self, req: Req) -> Resp {
        let ryw = ReadYourWritesStore::new(self.read_side(), &self.cp, &self.clock);
        let app = App {
            store: &ryw,
            cache: &self.cache,
            secrets: &self.secrets,
            clock: &self.clock,
            http: Some(&self.http),
            env: EnvConfig {
                store_id: "42".into(),
                api_base: "https://api.test.example".into(),
                cookie_name: "fes_session".into(),
                insecure_cookie: true,
                app_version: "test",
            },
        };
        router::handle(&app, req)
    }

    fn read_side(&self) -> &dyn Store {
        match &self.failing_reads {
            Some(f) => f,
            None => &self.mem,
        }
    }

    // ------------------------------------------------------------------
    // Convenience helpers
    // ------------------------------------------------------------------

    pub fn get(&self, path: &str) -> Resp {
        self.request(Req::get(path))
    }

    pub fn get_auth(&self, path: &str, cookie: &str) -> Resp {
        self.request(Req::get(path).with_header("Cookie", &format!("fes_session={cookie}")))
    }

    pub fn post_json(&self, path: &str, cookie: Option<&str>, body: &Value) -> Resp {
        let mut req = Req::post(path)
            .with_header("Content-Type", "application/json")
            .with_header("X-Requested-With", XRW)
            .with_body(serde_json::to_vec(body).unwrap());
        if let Some(c) = cookie {
            req = req.with_header("Cookie", &format!("fes_session={c}"));
        }
        self.request(req)
    }

    pub fn put_json(&self, path: &str, cookie: &str, body: &Value) -> Resp {
        self.request(
            Req::new("PUT", path)
                .with_header("Content-Type", "application/json")
                .with_header("X-Requested-With", XRW)
                .with_header("Cookie", &format!("fes_session={cookie}"))
                .with_body(serde_json::to_vec(body).unwrap()),
        )
    }

    pub fn patch_json(&self, path: &str, cookie: &str, body: &Value) -> Resp {
        self.request(
            Req::new("PATCH", path)
                .with_header("Content-Type", "application/json")
                .with_header("X-Requested-With", XRW)
                .with_header("Cookie", &format!("fes_session={cookie}"))
                .with_body(serde_json::to_vec(body).unwrap()),
        )
    }

    pub fn delete(&self, path: &str, cookie: &str) -> Resp {
        self.request(
            Req::new("DELETE", path)
                .with_header("X-Requested-With", XRW)
                .with_header("Cookie", &format!("fes_session={cookie}")),
        )
    }

    /// Login as the default admin; panics on failure.
    pub fn login(&self) -> String {
        self.login_as(ADMIN_USER, ADMIN_PASS)
            .unwrap_or_else(|r| panic!("bootstrap login failed: {}", r.status))
    }

    pub fn login_as(&self, user: &str, pass: &str) -> Result<String, Resp> {
        let resp = self.post_json(
            "/api/auth/login",
            None,
            &serde_json::json!({
                "username": user, "password": pass,
            }),
        );
        if resp.status != 200 {
            return Err(resp);
        }
        Ok(cookie_of(&resp).expect("login must set a session cookie"))
    }

    /// Perform step-up for a session cookie; panics on failure.
    pub fn step_up(&self, cookie: &str) -> String {
        let resp = self.post_json(
            "/api/auth/stepup",
            Some(cookie),
            &serde_json::json!({
                "password": ADMIN_PASS,
            }),
        );
        assert_eq!(resp.status, 200, "step-up failed");
        cookie_of(&resp).unwrap_or_else(|| cookie.to_string())
    }

    /// Create a user through the API; returns (uid, stepped cookie).
    pub fn create_user(&self, cookie: &str, email: &str, expires_at: Option<&str>) -> Value {
        let mut body = serde_json::json!({
            "email": email,
            "display_name": "Test User",
            "app_role": "member",
            "entitlement_id": "ent-basic",
        });
        if let Some(exp) = expires_at {
            body["expires_at"] = serde_json::json!(exp);
        }
        let resp = self.post_json("/api/users", Some(cookie), &body);
        assert_eq!(
            resp.status,
            201,
            "user creation failed: {}",
            String::from_utf8_lossy(&resp.body)
        );
        json_of(&resp)
    }

    /// Issue a credential through the API; returns the raw token.
    pub fn issue_credential(&self, cookie: &str, uid: &str) -> String {
        let resp = self.post_json(
            &format!("/api/users/{uid}/credentials"),
            Some(cookie),
            &serde_json::json!({}),
        );
        assert_eq!(resp.status, 201, "credential issuance failed");
        json_of(&resp)["credential"]["token"]
            .as_str()
            .unwrap()
            .to_string()
    }

    /// Exchange an app token for an access token; returns the JWT.
    pub fn exchange(&self, token: &str) -> Resp {
        self.post_json(
            "/api/v1/token",
            None,
            &serde_json::json!({ "token": token }),
        )
    }

    pub fn me(&self, access_token: &str) -> Resp {
        self.request(
            Req::get("/api/v1/me").with_header("Authorization", &format!("Bearer {access_token}")),
        )
    }

    pub fn advance(&self, secs: u64) {
        self.clock.advance_s(secs);
    }
}

impl Default for Harness {
    fn default() -> Self {
        Self::new()
    }
}

// ----------------------------------------------------------------------
// Response helpers
// ----------------------------------------------------------------------

pub fn json_of(resp: &Resp) -> Value {
    serde_json::from_slice(&resp.body).unwrap_or_else(|_| {
        panic!(
            "response is not JSON: {}",
            String::from_utf8_lossy(&resp.body)
        )
    })
}

pub fn cookie_of(resp: &Resp) -> Option<String> {
    for (k, v) in &resp.headers {
        if k.eq_ignore_ascii_case("set-cookie") && v.starts_with("fes_session=") {
            let value = v.trim_start_matches("fes_session=");
            let value = value.split(';').next().unwrap_or("");
            return Some(value.to_string());
        }
    }
    None
}

pub fn header_of(resp: &Resp, name: &str) -> Option<String> {
    resp.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

pub fn error_code(resp: &Resp) -> String {
    json_of(resp)["error"]["code"]
        .as_str()
        .unwrap_or("")
        .to_string()
}
