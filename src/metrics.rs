//! Operational metrics.
//!
//! Counters live in the FastEdge per-POP cache using its atomic `incr`.
//! They are *approximate by construction*: the cache is per-POP, so the
//! same logical counter exists independently at every point of presence.
//! Every surface that displays these numbers labels them as approximate
//! per-POP aggregates — no precise global claim is ever made from them.
//!
//! For authoritative request statistics, the admin panel additionally
//! exposes the Gcore Stats API (`/fastedge/v1/stats/calls`) through
//! [`crate::handlers::system`], which measures at the platform level.

use crate::platform::{Cache, CacheError, Clock};

/// (UTC day list, per-metric aligned series). `None` = unavailable, not zero.
pub type DaySeries = (Vec<String>, Vec<(MetricKind, Vec<Option<i64>>)>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricKind {
    Requests,
    ClientErrors,
    ServerErrors,
    AuthFailures,
    AuthSuccesses,
    AdminOperations,
    TokensIssued,
}

impl MetricKind {
    pub fn as_key_fragment(&self) -> &'static str {
        match self {
            Self::Requests => "req",
            Self::ClientErrors => "err4xx",
            Self::ServerErrors => "err5xx",
            Self::AuthFailures => "authfail",
            Self::AuthSuccesses => "authok",
            Self::AdminOperations => "adminops",
            Self::TokensIssued => "tokissue",
        }
    }
}

pub struct Metrics<'a> {
    pub cache: &'a dyn Cache,
    pub clock: &'a dyn Clock,
}

/// How long per-day counters are kept (45 days).
const METRIC_TTL_MS: u64 = 45 * 86_400_000;

impl Metrics<'_> {
    fn day_key(&self, kind: MetricKind) -> String {
        let day = crate::timeutil::format_date_utc(self.clock.now_unix());
        format!("m:{}:{}", kind.as_key_fragment(), day)
    }

    /// Increment a counter (best effort — metrics never fail a request).
    pub fn incr(&self, kind: MetricKind) {
        let key = self.day_key(kind);
        if let Ok(count) = self.cache.incr(&key, 1) {
            if count == 1 {
                let _ = self.cache.expire(&key, METRIC_TTL_MS);
            }
        }
    }

    /// Read the counter for a specific UTC day (may be missing → 0).
    pub fn read_day(&self, kind: MetricKind, day: &str) -> Option<i64> {
        let key = format!("m:{}:{}", kind.as_key_fragment(), day);
        match self.cache.get(&key) {
            Ok(Some(v)) => Some(String::from_utf8_lossy(&v).trim().parse().unwrap_or(0)),
            Ok(None) => Some(0),
            Err(_) => None, // cache unavailable → explicitly unknown
        }
    }

    /// Read the last `days` UTC days for a set of kinds.
    /// Returns (days, map kind → values aligned with days). A `None` value
    /// means "unavailable", not zero.
    pub fn read_range(&self, days: usize, kinds: &[MetricKind]) -> DaySeries {
        let today = self.clock.now_unix();
        let mut day_list = Vec::with_capacity(days);
        for i in (0..days as u64).rev() {
            day_list.push(crate::timeutil::format_date_utc(
                today.saturating_sub(i * 86_400),
            ));
        }
        let series = kinds
            .iter()
            .map(|k| {
                let vals = day_list.iter().map(|d| self.read_day(*k, d)).collect();
                (*k, vals)
            })
            .collect();
        (day_list, series)
    }

    pub fn cache_available(&self) -> bool {
        !matches!(self.cache.get("m:probe"), Err(CacheError::Unavailable))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{FixedClock, MemCache};
    use std::sync::Arc;

    #[test]
    fn counters_increment_per_day() {
        let clock = FixedClock::new(1_800_000_000_000); // fixed instant
        let now = {
            let inner = clock.0.clone();
            Arc::new(move || *inner.read().unwrap()) as Arc<dyn Fn() -> u64 + Send + Sync>
        };
        let cache = MemCache::new(now);
        let m = Metrics {
            cache: &cache,
            clock: &clock,
        };

        m.incr(MetricKind::Requests);
        m.incr(MetricKind::Requests);
        m.incr(MetricKind::AuthFailures);

        let (days, series) = m.read_range(
            1,
            &[
                MetricKind::Requests,
                MetricKind::AuthFailures,
                MetricKind::TokensIssued,
            ],
        );
        assert_eq!(days.len(), 1);
        let req = series
            .iter()
            .find(|(k, _)| *k == MetricKind::Requests)
            .unwrap();
        assert_eq!(req.1[0], Some(2));
        let af = series
            .iter()
            .find(|(k, _)| *k == MetricKind::AuthFailures)
            .unwrap();
        assert_eq!(af.1[0], Some(1));
        let ti = series
            .iter()
            .find(|(k, _)| *k == MetricKind::TokensIssued)
            .unwrap();
        assert_eq!(ti.1[0], Some(0));
    }
}
