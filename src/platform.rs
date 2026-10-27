//! Platform provider traits and in-memory implementations.
//!
//! All business logic is written against these traits, never against a
//! concrete backend. Two real implementations exist:
//!
//! * `wasm32-wasip1` (production): `Store` reads from the FastEdge Edge
//!   Storage local replica and writes through the Gcore REST control
//!   plane; `Cache` maps to the FastEdge per-POP cache; `Secrets` maps to
//!   the encrypted Secrets Manager; `HttpOut` wraps `send_request`.
//! * host (tests): the in-memory providers in this module plus injectable
//!   failure modes, giving full control over failure/boundary testing.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// The backend is unreachable, not linked, or refused access.
    /// Deliberately coarse: callers must not branch on internals.
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheError {
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretError {
    Unavailable,
}

#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

#[derive(Debug)]
pub enum HttpError {
    Unreachable,
    Status(u16),
}

pub trait Clock: Send + Sync {
    fn now_unix(&self) -> u64 {
        self.now_ms() / 1000
    }
    fn now_ms(&self) -> u64;
}

pub struct SystemClock;
impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

/// Deterministic clock for tests; settable per test scenario.
#[derive(Clone)]
pub struct FixedClock(pub Arc<RwLock<u64>>);
impl FixedClock {
    pub fn new(ms: u64) -> Self {
        Self(Arc::new(RwLock::new(ms)))
    }
    pub fn set(&self, ms: u64) {
        *self.0.write().unwrap() = ms;
    }
    pub fn advance_s(&self, s: u64) {
        *self.0.write().unwrap() += s * 1000;
    }
}
impl Clock for FixedClock {
    fn now_ms(&self) -> u64 {
        *self.0.read().unwrap()
    }
}

pub trait Store: Send + Sync {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError>;
    fn put(&self, key: &str, value: Vec<u8>) -> Result<(), StoreError>;
    fn delete(&self, key: &str) -> Result<(), StoreError>;
    fn scan(&self, pattern: &str) -> Result<Vec<String>, StoreError>;
    /// Batched put — default loops `put`; smart implementations translate
    /// this into a single control-plane call.
    fn put_batch(&self, pairs: &[(String, Vec<u8>)]) -> Result<(), StoreError> {
        for (k, v) in pairs {
            self.put(k, v.clone())?;
        }
        Ok(())
    }
    /// Batched delete — default loops `delete`.
    fn delete_batch(&self, keys: &[String]) -> Result<(), StoreError> {
        for k in keys {
            self.delete(k)?;
        }
        Ok(())
    }
}

pub trait Cache: Send + Sync {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, CacheError>;
    fn set(&self, key: &str, value: Vec<u8>, ttl_ms: Option<u64>) -> Result<(), CacheError>;
    fn delete(&self, key: &str) -> Result<(), CacheError>;
    /// Atomic increment. Returns the new value.
    fn incr(&self, key: &str, delta: i64) -> Result<i64, CacheError>;
    /// Set/extend the TTL of an existing key. Returns false if missing.
    fn expire(&self, key: &str, ttl_ms: u64) -> Result<bool, CacheError>;
}

pub trait Secrets: Send + Sync {
    fn get(&self, name: &str) -> Result<Option<Vec<u8>>, SecretError>;
}

pub trait HttpOut: Send + Sync {
    fn request(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<HttpResponse, HttpError>;
}

/// Glob matcher mirroring the documented Edge Storage semantics:
/// `*` matches within one key segment (no `/`), `?` one character,
/// `[abc]` a character set. No wildcards → exact match.
pub fn glob_match(pattern: &str, key: &str) -> bool {
    let (p, k): (&[u8], &[u8]) = (pattern.as_bytes(), key.as_bytes());
    fn rec(p: &[u8], k: &[u8]) -> bool {
        match p.first() {
            None => k.is_empty(),
            Some(b'*') => {
                // `*` must not cross a segment boundary.
                for i in 0..=k.len() {
                    if i > 0 && k[i - 1] == b'/' {
                        break;
                    }
                    if rec(&p[1..], &k[i..]) {
                        return true;
                    }
                }
                false
            }
            Some(b'?') => {
                if k.is_empty() || k[0] == b'/' {
                    false
                } else {
                    rec(&p[1..], &k[1..])
                }
            }
            Some(b'[') => {
                let close = match p.iter().position(|&c| c == b']') {
                    Some(i) if i >= 2 => i,
                    _ => return false,
                };
                match k.first() {
                    Some(&c) if p[1..close].contains(&c) => rec(&p[close + 1..], &k[1..]),
                    _ => false,
                }
            }
            Some(&c) => {
                if k.first() == Some(&c) {
                    rec(&p[1..], &k[1..])
                } else {
                    false
                }
            }
        }
    }
    rec(p, k)
}

#[derive(Clone, Default)]
pub struct MemStore(pub Arc<Mutex<BTreeMap<String, Vec<u8>>>>);

impl MemStore {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(BTreeMap::new())))
    }
}

impl Store for MemStore {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.0.lock().unwrap().get(key).cloned())
    }
    fn put(&self, key: &str, value: Vec<u8>) -> Result<(), StoreError> {
        self.0.lock().unwrap().insert(key.into(), value);
        Ok(())
    }
    fn delete(&self, key: &str) -> Result<(), StoreError> {
        self.0.lock().unwrap().remove(key);
        Ok(())
    }
    fn scan(&self, pattern: &str) -> Result<Vec<String>, StoreError> {
        let m = self.0.lock().unwrap();
        Ok(m.keys()
            .filter(|k| glob_match(pattern, k))
            .cloned()
            .collect())
    }
}

struct CacheEntry {
    value: Vec<u8>,
    expires_at_ms: Option<u64>,
}

#[derive(Clone)]
pub struct MemCache {
    map: Arc<Mutex<BTreeMap<String, CacheEntry>>>,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl MemCache {
    pub fn new(clock: Arc<dyn Fn() -> u64 + Send + Sync>) -> Self {
        Self {
            map: Arc::new(Mutex::new(BTreeMap::new())),
            clock,
        }
    }
    fn now(&self) -> u64 {
        (self.clock)()
    }
    fn live(&self, e: &CacheEntry) -> bool {
        e.expires_at_ms.map(|t| self.now() < t).unwrap_or(true)
    }
}

impl Cache for MemCache {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, CacheError> {
        let m = self.map.lock().unwrap();
        Ok(m.get(key).filter(|e| self.live(e)).map(|e| e.value.clone()))
    }
    fn set(&self, key: &str, value: Vec<u8>, ttl_ms: Option<u64>) -> Result<(), CacheError> {
        let expires = ttl_ms.map(|t| self.now() + t);
        self.map.lock().unwrap().insert(
            key.into(),
            CacheEntry {
                value,
                expires_at_ms: expires,
            },
        );
        Ok(())
    }
    fn delete(&self, key: &str) -> Result<(), CacheError> {
        self.map.lock().unwrap().remove(key);
        Ok(())
    }
    fn incr(&self, key: &str, delta: i64) -> Result<i64, CacheError> {
        let mut m = self.map.lock().unwrap();
        let entry = m.entry(key.into()).or_insert(CacheEntry {
            value: b"0".to_vec(),
            expires_at_ms: None,
        });
        if !self.live(entry) {
            entry.value = b"0".to_vec();
            entry.expires_at_ms = None;
        }
        let cur: i64 = String::from_utf8_lossy(&entry.value)
            .trim()
            .parse()
            .unwrap_or(0);
        let next = cur + delta;
        entry.value = next.to_string().into_bytes();
        Ok(next)
    }
    fn expire(&self, key: &str, ttl_ms: u64) -> Result<bool, CacheError> {
        let mut m = self.map.lock().unwrap();
        match m.get_mut(key) {
            Some(e) if self.live(e) => {
                e.expires_at_ms = Some(self.now() + ttl_ms);
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

#[derive(Clone, Default)]
pub struct StaticSecrets(pub Arc<BTreeMap<String, Vec<u8>>>);

impl StaticSecrets {
    pub fn new(pairs: &[(&str, &str)]) -> Self {
        let mut m = BTreeMap::new();
        for (k, v) in pairs {
            m.insert((*k).to_string(), v.as_bytes().to_vec());
        }
        Self(Arc::new(m))
    }
}

impl Secrets for StaticSecrets {
    fn get(&self, name: &str) -> Result<Option<Vec<u8>>, SecretError> {
        Ok(self.0.get(name).cloned())
    }
}

/// HTTP stub for control-plane tests: records requests and replays
/// programmable responses in FIFO order.
#[derive(Default)]
pub struct FakeHttp {
    pub requests: Mutex<Vec<(String, String, Vec<u8>)>>, // method, url, body
    pub responses: Mutex<Vec<Result<HttpResponse, HttpError>>>,
}

impl FakeHttp {
    pub fn push_ok(&self, status: u16, body: &str) {
        self.responses.lock().unwrap().push(Ok(HttpResponse {
            status,
            body: body.as_bytes().to_vec(),
        }));
    }
    pub fn push_err(&self, e: HttpError) {
        self.responses.lock().unwrap().push(Err(e));
    }
}

impl HttpOut for FakeHttp {
    fn request(
        &self,
        method: &str,
        url: &str,
        _headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<HttpResponse, HttpError> {
        self.requests
            .lock()
            .unwrap()
            .push((method.into(), url.into(), body.to_vec()));
        let mut r = self.responses.lock().unwrap();
        if r.is_empty() {
            return Err(HttpError::Unreachable);
        }
        r.remove(0)
    }
}

/// Store wrapper that fails after N calls of the given kind — used to test
/// fail-closed behavior under storage outages.
pub struct FailingStore {
    pub inner: MemStore,
    pub fail_get_after: RwLock<Option<usize>>,
    pub fail_put_after: RwLock<Option<usize>>,
    pub get_calls: AtomicCounter,
    pub put_calls: AtomicCounter,
}

#[derive(Default)]
pub struct AtomicCounter(Mutex<usize>);
impl AtomicCounter {
    pub fn inc(&self) -> usize {
        let mut v = self.0.lock().unwrap();
        *v += 1;
        *v
    }
    pub fn get(&self) -> usize {
        *self.0.lock().unwrap()
    }
}

impl FailingStore {
    pub fn wrap(inner: MemStore) -> Self {
        Self {
            inner,
            fail_get_after: RwLock::new(None),
            fail_put_after: RwLock::new(None),
            get_calls: AtomicCounter::default(),
            put_calls: AtomicCounter::default(),
        }
    }
}

impl Store for FailingStore {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let n = self.get_calls.inc();
        if let Some(limit) = *self.fail_get_after.read().unwrap() {
            if n > limit {
                return Err(StoreError::Unavailable);
            }
        }
        self.inner.get(key)
    }
    fn put(&self, key: &str, value: Vec<u8>) -> Result<(), StoreError> {
        let n = self.put_calls.inc();
        if let Some(limit) = *self.fail_put_after.read().unwrap() {
            if n > limit {
                return Err(StoreError::Unavailable);
            }
        }
        self.inner.put(key, value)
    }
    fn delete(&self, key: &str) -> Result<(), StoreError> {
        self.inner.delete(key)
    }
    fn scan(&self, pattern: &str) -> Result<Vec<String>, StoreError> {
        self.inner.scan(pattern)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_matches_like_edge_storage() {
        assert!(glob_match("users/*", "users/uABC"));
        assert!(glob_match("audit/e*", "audit/e123"));
        assert!(!glob_match("users/*", "users/a/b")); // * stays in segment
        assert!(glob_match("users/*/*", "users/a/b"));
        assert!(glob_match("a?c", "abc"));
        assert!(glob_match("a[bc]d", "abd"));
        assert!(!glob_match("a[bc]d", "aad"));
        assert!(glob_match("exact/key", "exact/key"));
        assert!(!glob_match("exact/key", "exact/other"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*/*", "a/b"));
    }

    #[test]
    fn mem_cache_ttl_and_incr() {
        let t = Arc::new(RwLock::new(1000u64));
        let now = {
            let t = t.clone();
            Arc::new(move || *t.read().unwrap()) as Arc<dyn Fn() -> u64 + Send + Sync>
        };
        let c = MemCache::new(now);
        c.set("k", b"v".to_vec(), Some(500)).unwrap();
        assert_eq!(c.get("k").unwrap(), Some(b"v".to_vec()));
        *t.write().unwrap() = 1600;
        assert_eq!(c.get("k").unwrap(), None); // expired
        assert_eq!(c.incr("counter", 1).unwrap(), 1);
        assert_eq!(c.incr("counter", 5).unwrap(), 6);
        assert_eq!(c.incr("counter", -2).unwrap(), 4);
        assert!(c.expire("counter", 100).unwrap());
        assert!(!c.expire("missing", 100).unwrap());
    }
}
