//! Pure load-balancing algorithms. Stable hashing (FxHash, not DefaultHasher).

use std::collections::{HashMap, HashSet};
use std::hash::Hasher;

#[derive(Debug, Clone)]
pub struct Candidate {
    pub id: String,
    pub weight: u32,
}

pub struct Wrr {
    cands: Vec<Candidate>,
    cursor: usize,
    counter: u32,
}

impl Wrr {
    pub fn new(cands: Vec<Candidate>) -> Self {
        Self {
            cands,
            cursor: 0,
            counter: 0,
        }
    }
    pub fn pick(&mut self) -> Option<String> {
        if self.cands.is_empty() {
            return None;
        }
        loop {
            let c = &self.cands[self.cursor];
            if self.counter < c.weight {
                self.counter += 1;
                return Some(c.id.clone());
            }
            self.cursor = (self.cursor + 1) % self.cands.len();
            self.counter = 0;
        }
    }
}

pub struct Swrr {
    cands: Vec<Candidate>,
    current: Vec<i64>,
}

impl Swrr {
    pub fn new(cands: Vec<Candidate>) -> Self {
        let len = cands.len();
        Self {
            cands,
            current: vec![0; len],
        }
    }
    pub fn pick(&mut self) -> Option<String> {
        if self.cands.is_empty() {
            return None;
        }
        let total: i64 = self.cands.iter().map(|c| c.weight as i64).sum();
        let mut best = 0;
        for i in 0..self.cands.len() {
            self.current[i] += self.cands[i].weight as i64;
            if self.current[i] > self.current[best] {
                best = i;
            }
        }
        self.current[best] -= total;
        Some(self.cands[best].id.clone())
    }
}

pub struct ConsistentHash {
    cands: Vec<Candidate>,
}

impl ConsistentHash {
    pub fn new(cands: Vec<Candidate>) -> Self {
        Self { cands }
    }
    pub fn pick(&self, key: &str) -> Option<String> {
        if self.cands.is_empty() {
            return None;
        }
        let mut hasher = fxhash::FxHasher::default();
        hasher.write(key.as_bytes());
        let h = hasher.finish();
        let total_weight: u64 = self.cands.iter().map(|c| c.weight as u64).sum();
        if total_weight == 0 {
            return None;
        }
        let mut bucket = h % total_weight;
        for c in &self.cands {
            let w = c.weight as u64;
            if bucket < w {
                return Some(c.id.clone());
            }
            bucket -= w;
        }
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StickyEntry {
    candidate_id: String,
    expires_at_ms: u64,
}

pub struct StickyTable {
    ttl_ms: u64,
    entries: HashMap<String, StickyEntry>,
    picker: Wrr,
    picker_ids: Vec<String>,
}

impl StickyTable {
    pub fn new(ttl_ms: u64) -> Self {
        Self {
            ttl_ms: ttl_ms.max(1),
            entries: HashMap::new(),
            picker: Wrr::new(Vec::new()),
            picker_ids: Vec::new(),
        }
    }

    pub fn pick(&mut self, key: &str, candidates: &[Candidate], now_ms: u64) -> Option<String> {
        if candidates.is_empty() {
            self.entries.clear();
            self.refresh_picker(candidates);
            return None;
        }

        let active_ids: HashSet<&str> = candidates.iter().map(|c| c.id.as_str()).collect();
        if let Some(entry) = self.entries.get(key) {
            if now_ms < entry.expires_at_ms && active_ids.contains(entry.candidate_id.as_str()) {
                return Some(entry.candidate_id.clone());
            }
        }

        self.refresh_picker(candidates);
        let picked = self.picker.pick()?;
        self.entries.insert(
            key.to_string(),
            StickyEntry {
                candidate_id: picked.clone(),
                expires_at_ms: now_ms.saturating_add(self.ttl_ms),
            },
        );
        Some(picked)
    }

    fn refresh_picker(&mut self, candidates: &[Candidate]) {
        let ids: Vec<String> = candidates.iter().map(|c| c.id.clone()).collect();
        if ids == self.picker_ids {
            return;
        }
        self.picker_ids = ids;
        self.picker = Wrr::new(candidates.to_vec());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaxAgePolicy {
    Off,
    Soft,
    Hard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceLeaseRotateConfig {
    pub idle_timeout_ms: u64,
    pub max_age_ms: u64,
    pub max_age_policy: MaxAgePolicy,
    pub switch_cooldown_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceLeaseActivity {
    pub active_flows: u32,
    pub idle_since_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceLeaseReason {
    New,
    Hit,
    IdleExpired,
    MaxAgeSoft,
    MaxAgeHard,
    Unhealthy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceLeaseDecision {
    pub candidate_id: String,
    pub reason: SourceLeaseReason,
    pub generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SourceLeaseEntry {
    candidate_id: String,
    created_at_ms: u64,
    last_seen_at_ms: u64,
    generation: u64,
    cooldown_until_ms: u64,
}

pub struct SourceLeaseRotate {
    config: SourceLeaseRotateConfig,
    entries: HashMap<String, SourceLeaseEntry>,
}

impl SourceLeaseRotate {
    pub fn new(config: SourceLeaseRotateConfig) -> Self {
        Self {
            config: SourceLeaseRotateConfig {
                idle_timeout_ms: config.idle_timeout_ms.max(1),
                max_age_ms: config.max_age_ms.max(1),
                switch_cooldown_ms: config.switch_cooldown_ms,
                max_age_policy: config.max_age_policy,
            },
            entries: HashMap::new(),
        }
    }

    pub fn pick(
        &mut self,
        source_key: &str,
        candidates: &[Candidate],
        now_ms: u64,
    ) -> Option<SourceLeaseDecision> {
        self.pick_inner(source_key, candidates, now_ms, None)
    }

    pub fn pick_with_activity(
        &mut self,
        source_key: &str,
        candidates: &[Candidate],
        now_ms: u64,
        activity: Option<SourceLeaseActivity>,
    ) -> Option<SourceLeaseDecision> {
        self.pick_inner(source_key, candidates, now_ms, activity)
    }

    fn pick_inner(
        &mut self,
        source_key: &str,
        candidates: &[Candidate],
        now_ms: u64,
        activity: Option<SourceLeaseActivity>,
    ) -> Option<SourceLeaseDecision> {
        if candidates.is_empty() {
            self.entries.clear();
            return None;
        }

        let active_ids: HashSet<&str> = candidates.iter().map(|c| c.id.as_str()).collect();
        let existing = self.entries.get(source_key).cloned();
        let (reason, generation, exclude_id) = match existing.as_ref() {
            None => (SourceLeaseReason::New, 0, None),
            Some(entry) if !active_ids.contains(entry.candidate_id.as_str()) => {
                (SourceLeaseReason::Unhealthy, entry.generation + 1, None)
            }
            Some(entry) if self.idle_expired(entry, now_ms, activity) => {
                (SourceLeaseReason::IdleExpired, entry.generation + 1, None)
            }
            Some(entry)
                if self.config.max_age_policy != MaxAgePolicy::Off
                    && now_ms.saturating_sub(entry.created_at_ms) >= self.config.max_age_ms
                    && now_ms >= entry.cooldown_until_ms =>
            {
                let reason = match self.config.max_age_policy {
                    MaxAgePolicy::Off => SourceLeaseReason::Hit,
                    MaxAgePolicy::Soft => SourceLeaseReason::MaxAgeSoft,
                    MaxAgePolicy::Hard => SourceLeaseReason::MaxAgeHard,
                };
                let exclude_id =
                    if self.config.max_age_policy == MaxAgePolicy::Hard && candidates.len() > 1 {
                        Some(entry.candidate_id.as_str())
                    } else {
                        None
                    };
                (reason, entry.generation + 1, exclude_id)
            }
            Some(entry) => {
                let mut updated = entry.clone();
                updated.last_seen_at_ms = now_ms;
                self.entries.insert(source_key.to_string(), updated);
                return Some(SourceLeaseDecision {
                    candidate_id: entry.candidate_id.clone(),
                    reason: SourceLeaseReason::Hit,
                    generation: entry.generation,
                });
            }
        };

        let picked = pick_weighted_rendezvous(source_key, generation, candidates, exclude_id)?;
        self.entries.insert(
            source_key.to_string(),
            SourceLeaseEntry {
                candidate_id: picked.clone(),
                created_at_ms: now_ms,
                last_seen_at_ms: now_ms,
                generation,
                cooldown_until_ms: now_ms.saturating_add(self.config.switch_cooldown_ms),
            },
        );
        Some(SourceLeaseDecision {
            candidate_id: picked,
            reason,
            generation,
        })
    }

    fn idle_expired(
        &self,
        entry: &SourceLeaseEntry,
        now_ms: u64,
        activity: Option<SourceLeaseActivity>,
    ) -> bool {
        match activity {
            Some(activity) if activity.active_flows > 0 => false,
            Some(SourceLeaseActivity {
                idle_since_ms: Some(idle_since),
                ..
            }) => now_ms.saturating_sub(idle_since) >= self.config.idle_timeout_ms,
            None => now_ms.saturating_sub(entry.last_seen_at_ms) >= self.config.idle_timeout_ms,
            Some(_) => now_ms.saturating_sub(entry.last_seen_at_ms) >= self.config.idle_timeout_ms,
        }
    }
}

fn pick_weighted_rendezvous(
    source_key: &str,
    generation: u64,
    candidates: &[Candidate],
    exclude_id: Option<&str>,
) -> Option<String> {
    let mut best: Option<(&str, f64)> = None;
    for candidate in candidates {
        if Some(candidate.id.as_str()) == exclude_id {
            continue;
        }
        let mut hasher = fxhash::FxHasher::default();
        hasher.write(source_key.as_bytes());
        hasher.write_u8(0xff);
        hasher.write_u64(generation);
        hasher.write_u8(0xfe);
        hasher.write(candidate.id.as_bytes());
        let hash = hasher.finish();
        let unit = (((hash >> 11) as f64) + 1.0) / (((1u64 << 53) as f64) + 1.0);
        let score = (candidate.weight.max(1) as f64) / -unit.ln();
        if best.is_none_or(|(_, best_score)| score > best_score) {
            best = Some((candidate.id.as_str(), score));
        }
    }
    best.map(|(id, _)| id.to_string())
}
