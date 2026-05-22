//! L4 scheduler evidence projected from `PathStats`.
//!
//! `LinkEvidence` mirrors schema `link_evidence_v1` (owner L4). It is a pure
//! projection of locally observed `PathStats` into the scheduler-facing shape;
//! it is observation evidence, never route or registry truth.
//!
//! `LinkEvidenceSnapshot` keeps the durable configured-peer identity separate
//! from soft, TTL-expirable per-neighbor evidence. Live evidence is held behind
//! an `arc_swap::ArcSwap` so control-path tasks rebuild-and-swap an immutable
//! map while hot-path delivery reads it lock-free, without awaiting a mutex.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::transport::path_stats::PathStats;

/// Scheduling-cost penalty per unit of `(1 - delivery_ratio)`, in the
/// microsecond domain of `srtt`. Documented heuristic; tunable later.
const LOSS_COST_PENALTY_US: f64 = 50_000.0;

/// L4 scheduler evidence for one sender-to-mouth relation. The field set and
/// owner layer mirror schema `link_evidence_v1`. Observation, not route truth.
#[derive(Clone, Debug, PartialEq)]
pub struct LinkEvidence {
    pub srtt: f64,
    pub rttvar: f64,
    pub delivery_ratio: f64,
    pub loss_burst: u32,
    pub reorder_score: f64,
    pub pmtu: u16,
    pub queue_delay: f64,
    pub cost_weight: f64,
}

impl LinkEvidence {
    /// Project locally observed `PathStats` into scheduler evidence. Pure: no
    /// I/O, no clock, no payload inspection. Heuristics are documented and
    /// stay inside the schema ranges (delivery_ratio in `(0, 1]`, all `>= 0`).
    pub fn from_path_stats(stats: &PathStats) -> Self {
        let srtt = stats.rtt_us.unwrap_or(0) as f64;
        let rttvar = stats.rttvar_us.unwrap_or(0) as f64;
        let failures =
            stats.send_errors as f64 + stats.drops as f64 + stats.queue_full_drops as f64;
        // PathStats carries no total-sent counter, so delivery_ratio is a
        // bounded monotone-decreasing proxy: 1.0 with no failures, asymptotic
        // toward 0 as failures grow. Best-effort evidence, not a metric.
        let delivery_ratio = if failures == 0.0 {
            1.0
        } else {
            1.0 / (1.0 + failures)
        };
        let queue_delay = stats.pacing_delay_us.unwrap_or(0) as f64;
        // RTO-shaped base cost (srtt + 4·rttvar) plus a loss penalty so a lossy
        // mouth ranks worse than a clean one at equal RTT.
        let cost_weight = srtt + 4.0 * rttvar + LOSS_COST_PENALTY_US * (1.0 - delivery_ratio);
        LinkEvidence {
            srtt,
            rttvar,
            delivery_ratio,
            loss_burst: stats.drops,
            // PathStats has no send-side reorder measure; receiver-side
            // LinkSample evidence fills this later. No evidence -> 0.0.
            reorder_score: 0.0,
            pmtu: stats.pmtu.unwrap_or(0),
            queue_delay,
            cost_weight,
        }
    }
}

#[derive(Clone)]
struct EvidenceEntry {
    evidence: LinkEvidence,
    observed_at_ms: u64,
}

/// Per-neighbor link evidence with a lock-free hot-path read.
///
/// The configured-peer identity is durable and is **never** removed by
/// evidence expiry: a mouth dropping out of the candidate set because its
/// evidence went stale must not erase the operator-configured peer. Live
/// evidence is held behind `ArcSwap`; control-path tasks publish a fresh
/// immutable map, hot-path reads load it without blocking.
pub struct LinkEvidenceSnapshot {
    configured: Arc<Vec<String>>,
    evidence: ArcSwap<HashMap<String, EvidenceEntry>>,
    ttl_ms: u64,
}

impl LinkEvidenceSnapshot {
    pub fn new(configured_peers: impl IntoIterator<Item = String>, ttl_ms: u64) -> Self {
        LinkEvidenceSnapshot {
            configured: Arc::new(configured_peers.into_iter().collect()),
            evidence: ArcSwap::from_pointee(HashMap::new()),
            ttl_ms,
        }
    }

    /// Durable operator-configured peer identity. Independent of evidence
    /// freshness — evidence expiry never mutates this.
    pub fn configured_peers(&self) -> &[String] {
        &self.configured
    }

    /// Control-path update: publish (or refresh) one neighbor's evidence by
    /// rebuilding an immutable map and swapping it in. Copy-on-write keeps the
    /// hot-path read wait-free.
    pub fn observe(&self, neighbor: &str, evidence: LinkEvidence, now_ms: u64) {
        let current = self.evidence.load();
        let mut next: HashMap<String, EvidenceEntry> = HashMap::with_capacity(current.len() + 1);
        for (k, v) in current.iter() {
            next.insert(k.clone(), v.clone());
        }
        next.insert(
            neighbor.to_string(),
            EvidenceEntry {
                evidence,
                observed_at_ms: now_ms,
            },
        );
        self.evidence.store(Arc::new(next));
    }

    fn is_fresh(&self, observed_at_ms: u64, now_ms: u64) -> bool {
        now_ms.saturating_sub(observed_at_ms) <= self.ttl_ms
    }

    /// Hot-path read: neighbors whose evidence is still fresh. A stale entry is
    /// excluded from the candidate set but is **not** deleted, and configured
    /// identity is untouched. Lock-free; returns a sorted, stable order.
    pub fn candidate_mouths(&self, now_ms: u64) -> Vec<String> {
        let snap = self.evidence.load();
        let mut out: Vec<String> = snap
            .iter()
            .filter(|(_, e)| self.is_fresh(e.observed_at_ms, now_ms))
            .map(|(k, _)| k.clone())
            .collect();
        out.sort();
        out
    }

    /// Hot-path read: fresh evidence for one neighbor, or `None` when missing
    /// or expired. Lock-free.
    pub fn evidence_for(&self, neighbor: &str, now_ms: u64) -> Option<LinkEvidence> {
        let snap = self.evidence.load();
        snap.get(neighbor)
            .filter(|e| self.is_fresh(e.observed_at_ms, now_ms))
            .map(|e| e.evidence.clone())
    }
}
