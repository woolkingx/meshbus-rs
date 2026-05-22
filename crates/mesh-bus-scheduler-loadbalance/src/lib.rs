//! Load-balance scheduler for multi-WAN egress distribution.

use mb_loadbalance::{Candidate, ConsistentHash, StickyTable, Wrr};
use mesh_bus_core::{ExitId, ExitResult, RankContext, ScheduleDecision, SchedulerPlugin};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadBalanceMode {
    RoundRobin,
    StickySessions,
    ConsistentHashing,
}

pub struct LoadBalanceScheduler {
    mode: LoadBalanceMode,
    state: Mutex<LoadBalanceState>,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    weights: Arc<HashMap<String, u32>>,
}

struct LoadBalanceState {
    ids: Vec<String>,
    rr: Wrr,
    sticky: StickyTable,
}

impl LoadBalanceScheduler {
    pub fn new(mode: LoadBalanceMode) -> Self {
        Self::with_sticky_ttl_ms(mode, 600_000)
    }

    pub fn with_sticky_ttl_ms(mode: LoadBalanceMode, sticky_ttl_ms: u64) -> Self {
        Self {
            mode,
            state: Mutex::new(LoadBalanceState {
                ids: Vec::new(),
                rr: Wrr::new(Vec::new()),
                sticky: StickyTable::new(sticky_ttl_ms),
            }),
            clock: Arc::new(now_ms),
            weights: Arc::new(HashMap::new()),
        }
    }

    pub fn with_clock(mut self, clock: Arc<dyn Fn() -> u64 + Send + Sync>) -> Self {
        self.clock = clock;
        self
    }

    pub fn with_weights(mut self, weights: impl IntoIterator<Item = (String, u32)>) -> Self {
        self.weights = Arc::new(weights.into_iter().collect());
        self
    }
}

fn target_key_or_flow(ctx: &RankContext) -> &str {
    ctx.target_key.as_deref().unwrap_or(ctx.flow_id.0.as_str())
}

fn hash_pair(src: Option<&str>, tgt: Option<&str>) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    match src {
        Some(s) => {
            1u8.hash(&mut h);
            s.len().hash(&mut h);
            s.hash(&mut h);
        }
        None => 0u8.hash(&mut h),
    }
    match tgt {
        Some(t) => {
            1u8.hash(&mut h);
            t.len().hash(&mut h);
            t.hash(&mut h);
        }
        None => 0u8.hash(&mut h),
    }
    format!("h:{:016x}", h.finish())
}

fn sticky_key(ctx: &RankContext) -> String {
    match (ctx.source_key.as_deref(), ctx.target_key.as_deref()) {
        (None, None) => ctx.flow_id.0.clone(),
        (src, tgt) => hash_pair(src, tgt),
    }
}

#[doc(hidden)]
pub fn sticky_key_for_test(src: Option<&str>, tgt: Option<&str>) -> String {
    hash_pair(src, tgt)
}

impl SchedulerPlugin for LoadBalanceScheduler {
    fn schedule(&self, candidates: &[ExitId], ctx: &RankContext) -> ScheduleDecision {
        let picked = match self.mode {
            LoadBalanceMode::ConsistentHashing => {
                let lb = ConsistentHash::new(to_candidates(candidates, &self.weights));
                lb.pick(target_key_or_flow(ctx))
            }
            LoadBalanceMode::StickySessions => {
                let mut state = self.state.lock().expect("load-balance state");
                state.sticky.pick(
                    &sticky_key(ctx),
                    &to_candidates(candidates, &self.weights),
                    (self.clock)(),
                )
            }
            LoadBalanceMode::RoundRobin => {
                let mut state = self.state.lock().expect("load-balance state");
                state.refresh(candidates, &self.weights);
                state.rr.pick()
            }
        };
        ScheduleDecision::ordered(order_with_first(candidates, picked.as_deref()))
    }

    fn feedback(&self, _result: &ExitResult, _payload_bytes: u64, _at_ms: u64) {}
}

impl LoadBalanceState {
    fn refresh(&mut self, candidates: &[ExitId], weights: &HashMap<String, u32>) {
        let ids: Vec<String> = candidates.iter().map(|id| id.0.clone()).collect();
        if ids == self.ids {
            return;
        }
        let lb_candidates = to_candidates(candidates, weights);
        self.ids = ids;
        self.rr = Wrr::new(lb_candidates);
    }
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn to_candidates(candidates: &[ExitId], weights: &HashMap<String, u32>) -> Vec<Candidate> {
    candidates
        .iter()
        .map(|id| Candidate {
            id: id.0.clone(),
            weight: weights.get(&id.0).copied().unwrap_or(1).max(1),
        })
        .collect()
}

fn order_with_first(candidates: &[ExitId], picked: Option<&str>) -> Vec<usize> {
    let mut order: Vec<usize> = (0..candidates.len()).collect();
    if let Some(picked) = picked {
        if let Some(pos) = candidates.iter().position(|id| id.0 == picked) {
            order.remove(pos);
            order.insert(0, pos);
        }
    }
    order
}
