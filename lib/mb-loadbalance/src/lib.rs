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
