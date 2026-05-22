//! DNS cache: positive (RFC 2181), negative (RFC 2308), serve-stale (RFC 8767),
//! reverse-map (IpAddr → {qname, geo, asn}).

use crate::types::{AnswerRecord, QType};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const TTL_MAX_POSITIVE: Duration = Duration::from_secs(300);
const TTL_DEFAULT_NEGATIVE: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct CacheKey {
    pub qname: String,
    pub qtype: QType,
}

#[derive(Debug, Clone)]
struct PositiveEntry {
    records: Vec<AnswerRecord>,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
struct NegativeEntry {
    expires_at: Instant,
}

#[derive(Debug, Clone)]
pub struct ReverseEntry {
    pub qname: String,
    pub geo: Option<String>,
    pub asn: Option<u32>,
    pub expires_at: Instant,
}

#[derive(Debug, Default)]
struct Inner {
    positive: HashMap<CacheKey, PositiveEntry>,
    negative: HashMap<CacheKey, NegativeEntry>,
    reverse: HashMap<IpAddr, ReverseEntry>,
}

#[derive(Debug)]
pub struct DnsCache {
    inner: Mutex<Inner>,
    stale_window: Duration,
}

impl Default for DnsCache {
    fn default() -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            stale_window: Duration::from_secs(60),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Lookup {
    Positive {
        records: Vec<AnswerRecord>,
        expires_at: Instant,
    },
    Negative {
        expires_at: Instant,
    },
}

impl Lookup {
    pub fn is_fresh(&self) -> bool {
        let exp = match self {
            Lookup::Positive { expires_at, .. } => *expires_at,
            Lookup::Negative { expires_at } => *expires_at,
        };
        Instant::now() < exp
    }

    pub fn records(&self) -> &[AnswerRecord] {
        match self {
            Lookup::Positive { records, .. } => records.as_slice(),
            Lookup::Negative { .. } => &[],
        }
    }

    pub fn remaining(&self) -> Duration {
        let exp = match self {
            Lookup::Positive { expires_at, .. } => *expires_at,
            Lookup::Negative { expires_at } => *expires_at,
        };
        exp.saturating_duration_since(Instant::now())
    }
}

impl DnsCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_stale_window(window: Duration) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            stale_window: window,
        }
    }

    pub fn put_positive(&self, key: CacheKey, records: Vec<AnswerRecord>, ttl: Duration) {
        let clamped = ttl.min(TTL_MAX_POSITIVE);
        let expires_at = Instant::now() + clamped;
        self.inner
            .lock()
            .expect("dns cache mutex poisoned")
            .positive
            .insert(
                key,
                PositiveEntry {
                    records,
                    expires_at,
                },
            );
    }

    pub fn put_negative(&self, key: CacheKey, ttl: Option<Duration>) {
        let ttl = ttl.unwrap_or(TTL_DEFAULT_NEGATIVE);
        let expires_at = Instant::now() + ttl;
        self.inner
            .lock()
            .expect("dns cache mutex poisoned")
            .negative
            .insert(key, NegativeEntry { expires_at });
    }

    pub fn lookup(&self, key: &CacheKey) -> Option<Lookup> {
        let inner = self.inner.lock().expect("dns cache mutex poisoned");
        if let Some(p) = inner.positive.get(key) {
            return Some(Lookup::Positive {
                records: p.records.clone(),
                expires_at: p.expires_at,
            });
        }
        if let Some(n) = inner.negative.get(key) {
            return Some(Lookup::Negative {
                expires_at: n.expires_at,
            });
        }
        None
    }

    /// RFC 8767: return an expired positive entry within `stale_window` past TTL.
    /// Returns None if no entry exists, if entry is fresh (use `lookup`), or if
    /// entry expired more than `stale_window` ago.
    pub fn lookup_stale(&self, key: &CacheKey) -> Option<Lookup> {
        let inner = self.inner.lock().expect("dns cache mutex poisoned");
        let p = inner.positive.get(key)?;
        let now = Instant::now();
        if now < p.expires_at {
            return None;
        }
        if now.duration_since(p.expires_at) > self.stale_window {
            return None;
        }
        Some(Lookup::Positive {
            records: p.records.clone(),
            expires_at: p.expires_at,
        })
    }

    pub fn put_reverse(&self, ip: IpAddr, entry: ReverseEntry) {
        self.inner
            .lock()
            .expect("dns cache mutex poisoned")
            .reverse
            .insert(ip, entry);
    }

    pub fn lookup_reverse(&self, ip: IpAddr) -> Option<ReverseEntry> {
        let mut inner = self.inner.lock().expect("dns cache mutex poisoned");
        if let Some(entry) = inner.reverse.get(&ip) {
            if Instant::now() < entry.expires_at {
                return Some(entry.clone());
            }
        }
        inner.reverse.remove(&ip);
        None
    }
}
