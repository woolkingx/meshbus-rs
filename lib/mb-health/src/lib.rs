//! Sliding-window health stats and per-exit health policy.

use std::collections::{HashMap, VecDeque};

pub struct HealthWindow {
    capacity: usize,
    rtts: VecDeque<u64>,
    outcomes: VecDeque<bool>,
    rtt_ewma: Option<u64>,
    jitter_ewma: Option<u64>,
    bytes: VecDeque<(u64, u64)>, // (at_ms, payload_bytes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthPolicy {
    pub failure_threshold: u8,
    pub recovery_window_ms: u64,
    pub probe_after_ms: u64,
}

impl Default for HealthPolicy {
    fn default() -> Self {
        Self {
            failure_threshold: 2,
            recovery_window_ms: 60_000,
            probe_after_ms: 1_000,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExitHealthTable {
    policy: HealthPolicy,
    exits: HashMap<String, ExitHealth>,
}

#[derive(Debug, Clone)]
struct ExitHealth {
    failures: u8,
    last_failure_ms: u64,
    last_success_ms: u64,
}

impl ExitHealthTable {
    pub fn new(policy: HealthPolicy) -> Self {
        Self {
            policy,
            exits: HashMap::new(),
        }
    }

    pub fn can_dispatch(&self, exit_id: &str, now_ms: u64) -> bool {
        let Some(health) = self.exits.get(exit_id) else {
            return true;
        };
        if health.failures < self.policy.failure_threshold {
            return true;
        }
        now_ms.saturating_sub(health.last_failure_ms) >= self.policy.probe_after_ms
    }

    pub fn record(&mut self, exit_id: impl Into<String>, success: bool, now_ms: u64) {
        let exit_id = exit_id.into();
        let health = self.exits.entry(exit_id.clone()).or_insert(ExitHealth {
            failures: 0,
            last_failure_ms: 0,
            last_success_ms: 0,
        });
        if success {
            health.failures = 0;
            health.last_success_ms = now_ms;
            return;
        }
        if now_ms.saturating_sub(health.last_failure_ms) > self.policy.recovery_window_ms {
            health.failures = 0;
        }
        health.failures = health.failures.saturating_add(1);
        health.last_failure_ms = now_ms;
    }
}

impl HealthWindow {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            rtts: VecDeque::new(),
            outcomes: VecDeque::new(),
            rtt_ewma: None,
            jitter_ewma: None,
            bytes: VecDeque::new(),
        }
    }
    pub fn record_rtt(&mut self, rtt_ms: u64) {
        if self.rtts.len() == self.capacity {
            self.rtts.pop_front();
        }
        self.rtts.push_back(rtt_ms);
        self.rtt_ewma = Some(match self.rtt_ewma {
            None => rtt_ms,
            Some(prev) => {
                let prev_i = prev as i64;
                let new_i = rtt_ms as i64;
                let updated = prev_i + (new_i - prev_i) / 8;
                updated.max(0) as u64
            }
        });
        let new_dev = (rtt_ms as i64 - self.rtt_ewma.unwrap() as i64).unsigned_abs();
        self.jitter_ewma = Some(match self.jitter_ewma {
            None => new_dev,
            Some(prev) => {
                let prev_i = prev as i64;
                let dev_i = new_dev as i64;
                let updated = prev_i + (dev_i - prev_i) / 8;
                updated.max(0) as u64
            }
        });
    }
    pub fn record_outcome(&mut self, success: bool) {
        if self.outcomes.len() == self.capacity {
            self.outcomes.pop_front();
        }
        self.outcomes.push_back(success);
    }
    pub fn sample_count(&self) -> usize {
        self.rtts.len()
    }
    pub fn mean_rtt_ms(&self) -> u64 {
        self.rtt_ewma.unwrap_or(0)
    }
    pub fn jitter_ms(&self) -> u64 {
        self.jitter_ewma.unwrap_or(0)
    }
    pub fn record_payload(&mut self, payload_bytes: u64, at_ms: u64) {
        if self.bytes.len() == self.capacity {
            self.bytes.pop_front();
        }
        self.bytes.push_back((at_ms, payload_bytes));
    }

    pub fn goodput_bps(&self) -> u64 {
        if self.bytes.len() < 2 {
            return 0;
        }
        let (first_t, _) = self.bytes.front().copied().unwrap();
        let (last_t, _) = self.bytes.back().copied().unwrap();
        if last_t <= first_t {
            return 0;
        }
        let span_ms = last_t - first_t;
        let sum_bytes: u64 = self.bytes.iter().map(|(_, b)| *b).sum();
        sum_bytes.saturating_mul(1000) / span_ms
    }

    pub fn success_rate(&self) -> f64 {
        if self.outcomes.is_empty() {
            return 1.0;
        }
        let ok = self.outcomes.iter().filter(|x| **x).count() as f64;
        ok / self.outcomes.len() as f64
    }
}

#[cfg(test)]
mod ewma_tests;
#[cfg(test)]
mod goodput_tests;
#[cfg(test)]
mod jitter_tests;
