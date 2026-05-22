use crate::types::UpstreamServer;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Round-robin server selection using a shared counter.
/// Caller invariant: `servers` must be non-empty.
/// Returns a reference into the slice, wrapping mod len.
pub fn select_round_robin<'a>(
    servers: &'a [UpstreamServer],
    counter: &AtomicUsize,
) -> &'a UpstreamServer {
    let idx = counter.fetch_add(1, Ordering::Relaxed) % servers.len();
    &servers[idx]
}

/// Consistent-hash server selection keyed by `qname_lower`.
/// Caller invariant: `servers` must be non-empty.
/// Uses `DefaultHasher` (deterministic within a single process run);
/// stability across process restarts is not required (docs §4.4 says
/// "stable hash" means same qname → same server within a session).
pub fn select_consistent_hash<'a>(
    servers: &'a [UpstreamServer],
    qname_lower: &str,
) -> &'a UpstreamServer {
    let mut h = DefaultHasher::new();
    qname_lower.hash(&mut h);
    let idx = (h.finish() as usize) % servers.len();
    &servers[idx]
}

/// FanOut server selection: returns first `min(k, len)` servers.
/// Deterministic order (preserves original server list order).
/// k=0 returns empty slice.
pub fn select_fanout(servers: &[UpstreamServer], k: u32) -> Vec<&UpstreamServer> {
    let take = (k as usize).min(servers.len());
    servers[..take].iter().collect()
}
