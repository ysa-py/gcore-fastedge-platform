//! Data-store composition: the write path, the read path, and the bridge
//! over Edge Storage's replication gap.
//!
//! Production wiring (wasm32-wasip1):
//! ```text
//!   admin write → ControlPlane (Gcore REST) → central DB → 1–2 s global
//!   replication → local Edge Storage replica → fast reads
//!                    ▲
//!   read-your-writes buffer (15 s, per instance) ────┘
//! ```
//!
//! Edge Storage replication is eventual (verified: 1–2 s globally). To keep
//! administrative workflows coherent, every successful write is also
//! remembered in a short-lived in-instance buffer that `get`/`scan`
//! consult first. This is a *best-effort, per-instance* optimization with
//! a documented bound: another PoP may serve stale data for at most the
//! replication window, while this instance serves fresh data immediately.
//!
//! Both behaviors are unit-tested on the host with a `LaggingReplica`
//! that mimics the replication delay deterministically.

use crate::controlplane::{ControlPlane, KvWriteOp};
use crate::platform::{glob_match, Clock, Store, StoreError};
use std::collections::HashMap;
use std::sync::Mutex;

/// Buffer lifetime: comfortably above the documented 1–2 s replication
/// window, short enough to self-heal if a write never replicates.
const BUFFER_TTL_MS: u64 = 15_000;

#[derive(Default)]
struct Buffer {
    /// key → (value, stored_at_ms)
    puts: HashMap<String, (Vec<u8>, u64)>,
    /// key → deleted_at_ms
    tombstones: HashMap<String, u64>,
}

impl Buffer {
    fn fresh(now: u64, at: u64) -> bool {
        now.saturating_sub(at) < BUFFER_TTL_MS
    }
}

pub struct ReadYourWritesStore<'a> {
    read: &'a dyn Store,
    cp: &'a dyn ControlPlane,
    clock: &'a dyn Clock,
    buffer: Mutex<Buffer>,
}

impl<'a> ReadYourWritesStore<'a> {
    pub fn new(read: &'a dyn Store, cp: &'a dyn ControlPlane, clock: &'a dyn Clock) -> Self {
        Self {
            read,
            cp,
            clock,
            buffer: Mutex::new(Buffer::default()),
        }
    }

    fn prune_if_large(&self, buf: &mut Buffer) {
        if buf.puts.len() + buf.tombstones.len() > 256 {
            let now = self.clock.now_ms();
            buf.puts.retain(|_, (_, at)| Buffer::fresh(now, *at));
            buf.tombstones.retain(|_, at| Buffer::fresh(now, *at));
        }
    }
}

impl Store for ReadYourWritesStore<'_> {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let now = self.clock.now_ms();
        {
            let buf = self.buffer.lock().unwrap();
            if let Some(at) = buf.tombstones.get(key) {
                if Buffer::fresh(now, *at) {
                    return Ok(None);
                }
            }
            if let Some((value, at)) = buf.puts.get(key) {
                if Buffer::fresh(now, *at) {
                    return Ok(Some(value.clone()));
                }
            }
        }
        self.read.get(key)
    }

    fn put(&self, key: &str, value: Vec<u8>) -> Result<(), StoreError> {
        self.cp
            .apply(&[KvWriteOp::put(key, value.clone())])
            .map_err(|_| StoreError::Unavailable)?;
        let now = self.clock.now_ms();
        let mut buf = self.buffer.lock().unwrap();
        buf.puts.insert(key.to_string(), (value, now));
        buf.tombstones.remove(key);
        self.prune_if_large(&mut buf);
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<(), StoreError> {
        self.cp
            .apply(&[KvWriteOp::delete(key)])
            .map_err(|_| StoreError::Unavailable)?;
        let now = self.clock.now_ms();
        let mut buf = self.buffer.lock().unwrap();
        buf.tombstones.insert(key.to_string(), now);
        buf.puts.remove(key);
        self.prune_if_large(&mut buf);
        Ok(())
    }

    fn put_batch(&self, pairs: &[(String, Vec<u8>)]) -> Result<(), StoreError> {
        if pairs.is_empty() {
            return Ok(());
        }
        let ops: Vec<KvWriteOp> = pairs
            .iter()
            .map(|(k, v)| KvWriteOp::put(k, v.clone()))
            .collect();
        self.cp.apply(&ops).map_err(|_| StoreError::Unavailable)?;
        let now = self.clock.now_ms();
        let mut buf = self.buffer.lock().unwrap();
        for (k, v) in pairs {
            buf.puts.insert(k.clone(), (v.clone(), now));
            buf.tombstones.remove(k);
        }
        self.prune_if_large(&mut buf);
        Ok(())
    }

    fn delete_batch(&self, keys: &[String]) -> Result<(), StoreError> {
        if keys.is_empty() {
            return Ok(());
        }
        let ops: Vec<KvWriteOp> = keys.iter().map(|k| KvWriteOp::delete(k)).collect();
        self.cp.apply(&ops).map_err(|_| StoreError::Unavailable)?;
        let now = self.clock.now_ms();
        let mut buf = self.buffer.lock().unwrap();
        for k in keys {
            buf.tombstones.insert(k.clone(), now);
            buf.puts.remove(k);
        }
        self.prune_if_large(&mut buf);
        Ok(())
    }

    fn scan(&self, pattern: &str) -> Result<Vec<String>, StoreError> {
        let now = self.clock.now_ms();
        let mut keys = self.read.scan(pattern)?;
        {
            let buf = self.buffer.lock().unwrap();
            keys.retain(|k| match buf.tombstones.get(k) {
                Some(at) => !Buffer::fresh(now, *at),
                None => true,
            });
            for (k, (_, at)) in buf.puts.iter() {
                if Buffer::fresh(now, *at) && glob_match(pattern, k) && !keys.contains(k) {
                    keys.push(k.clone());
                }
            }
        }
        keys.sort();
        keys.dedup();
        Ok(keys)
    }
}

/// Deterministic simulation of Edge Storage replication lag for tests:
/// writes land in `origin` (as the REST API would), reads are served from
/// `replica`, which only receives data when [`LaggingReplica::sync`] is
/// invoked (simulating the 1–2 s replication tick).
#[derive(Clone, Default)]
pub struct LaggingReplica {
    pub origin: crate::platform::MemStore,
    pub replica: crate::platform::MemStore,
}

impl LaggingReplica {
    pub fn new() -> Self {
        Self {
            origin: crate::platform::MemStore::new(),
            replica: crate::platform::MemStore::new(),
        }
    }
    /// Simulate the replication tick: copy all origin data to the replica.
    /// Note: `scan("*")` cannot be used here because `*` matches within a
    /// single key segment (Edge Storage semantics) — multi-segment keys
    /// like `users/uA` would be invisible. The backing map is read
    /// directly instead, which is exactly what replication does.
    pub fn sync(&self) {
        let snapshot: Vec<(String, Vec<u8>)> = self
            .origin
            .0
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (k, v) in snapshot {
            self.replica.put(&k, v).unwrap();
        }
    }
}

impl Store for LaggingReplica {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        self.replica.get(key)
    }
    fn put(&self, key: &str, value: Vec<u8>) -> Result<(), StoreError> {
        self.origin.put(key, value)
    }
    fn delete(&self, key: &str) -> Result<(), StoreError> {
        self.origin.delete(key)
    }
    fn scan(&self, pattern: &str) -> Result<Vec<String>, StoreError> {
        self.replica.scan(pattern)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controlplane::DirectControlPlane;
    use crate::platform::{FixedClock, MemStore};

    fn setup() -> (MemStore, FixedClock) {
        (MemStore::new(), FixedClock::new(1_000))
    }

    #[test]
    fn read_your_writes_across_replication_lag() {
        let (origin, clock) = setup();
        let cp = DirectControlPlane { store: &origin };
        let lag = LaggingReplica {
            origin: origin.clone(),
            replica: MemStore::new(),
        };
        let s = ReadYourWritesStore::new(&lag, &cp, &clock);

        s.put("users/uA", br#"{"a":1}"#.to_vec()).unwrap();

        // Replica has NOT received the write yet, but the composed store
        // must still serve it (read-your-writes).
        assert_eq!(s.get("users/uA").unwrap(), Some(br#"{"a":1}"#.to_vec()));
        assert_eq!(s.scan("users/*").unwrap(), vec!["users/uA".to_string()]);

        // Fresh instance WITHOUT a buffer (another PoP) sees stale data...
        let lag2 = LaggingReplica {
            origin: origin.clone(),
            replica: MemStore::new(),
        };
        assert_eq!(lag2.get("users/uA").unwrap(), None);

        // ...until the replication tick.
        lag.sync();
        assert_eq!(lag.get("users/uA").unwrap(), Some(br#"{"a":1}"#.to_vec()));
    }

    #[test]
    fn buffer_expires_after_ttl() {
        let (origin, clock) = setup();
        let cp = DirectControlPlane { store: &origin };
        let lag = LaggingReplica {
            origin: origin.clone(),
            replica: MemStore::new(),
        };
        let s = ReadYourWritesStore::new(&lag, &cp, &clock);

        s.put("k", b"v1".to_vec()).unwrap();
        assert_eq!(s.get("k").unwrap(), Some(b"v1".to_vec()));

        // After the buffer TTL (and no replication tick), the store falls
        // back to the replica — the documented worst case.
        clock.set(1_000 + 16_000);
        assert_eq!(s.get("k").unwrap(), None);
    }

    #[test]
    fn deletes_are_visible_immediately_then_replicate() {
        let (origin, clock) = setup();
        let cp = DirectControlPlane { store: &origin };
        let lag = LaggingReplica {
            origin: origin.clone(),
            replica: MemStore::new(),
        };
        let s = ReadYourWritesStore::new(&lag, &cp, &clock);

        s.put("email/x@y.z", b"uA".to_vec()).unwrap();
        lag.sync();
        assert_eq!(lag.get("email/x@y.z").unwrap(), Some(b"uA".to_vec()));

        s.delete("email/x@y.z").unwrap();
        // Read-your-writes: tombstone hides the still-replicated value.
        assert_eq!(s.get("email/x@y.z").unwrap(), None);
        assert!(s.scan("email/*").unwrap().is_empty());
    }

    #[test]
    fn overwrite_replaces_buffered_value() {
        let (origin, clock) = setup();
        let cp = DirectControlPlane { store: &origin };
        let s_plain = origin.clone();
        let s = ReadYourWritesStore::new(&s_plain, &cp, &clock);
        s.put("k", b"1".to_vec()).unwrap();
        s.put("k", b"2".to_vec()).unwrap();
        assert_eq!(s.get("k").unwrap(), Some(b"2".to_vec()));
    }
}
