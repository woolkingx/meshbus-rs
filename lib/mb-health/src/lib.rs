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
mod goodput_tests {
    use super::*;

    #[test]
    fn empty_goodput_is_zero() {
        assert_eq!(HealthWindow::new(64).goodput_bps(), 0);
    }

    #[test]
    fn single_sample_goodput_is_zero() {
        let mut w = HealthWindow::new(64);
        w.record_payload(1_000_000, 1000);
        assert_eq!(w.goodput_bps(), 0);
    }

    #[test]
    fn two_samples_compute_byte_rate() {
        // 1 MB at t=1000ms, 1 MB at t=2000ms -> 2 MB over 1s -> 2_000_000 B/s
        let mut w = HealthWindow::new(64);
        w.record_payload(1_000_000, 1000);
        w.record_payload(1_000_000, 2000);
        assert_eq!(w.goodput_bps(), 2_000_000);
    }

    #[test]
    fn ringbuffer_evicts_oldest() {
        let mut w = HealthWindow::new(4);
        for i in 0..10u64 {
            w.record_payload(100, 1000 + i * 100);
        }
        // Last 4 samples at t=(1700,1800,1900,2000), span 300ms, 400 bytes -> 1333 B/s
        assert_eq!(w.goodput_bps(), 1333);
    }
}

#[cfg(test)]
mod jitter_tests {
    use super::*;

    #[test]
    fn empty_jitter_is_zero() {
        assert_eq!(HealthWindow::new(64).jitter_ms(), 0);
    }

    #[test]
    fn stable_samples_have_low_jitter() {
        let mut w = HealthWindow::new(64);
        for _ in 0..10 {
            w.record_rtt(100);
        }
        assert_eq!(w.jitter_ms(), 0);
    }

    #[test]
    fn outlier_raises_jitter_but_decays() {
        let mut w = HealthWindow::new(64);
        for _ in 0..5 {
            w.record_rtt(100);
        }
        w.record_rtt(500);
        let j_after_spike = w.jitter_ms();
        assert!(
            j_after_spike > 10,
            "jitter should respond to outlier, got {}",
            j_after_spike
        );
        for _ in 0..20 {
            w.record_rtt(100);
        }
        let j_decayed = w.jitter_ms();
        assert!(
            j_decayed < j_after_spike,
            "jitter should decay, was {} now {}",
            j_after_spike,
            j_decayed
        );
    }
}

#[cfg(test)]
mod ewma_tests {
    use super::*;

    #[test]
    fn empty_window_returns_zero() {
        let w = HealthWindow::new(64);
        assert_eq!(w.mean_rtt_ms(), 0);
    }

    #[test]
    fn single_sample_is_returned_as_is() {
        let mut w = HealthWindow::new(64);
        w.record_rtt(100);
        assert_eq!(w.mean_rtt_ms(), 100);
    }

    #[test]
    fn ewma_converges_with_alpha_one_eighth() {
        // 100, 200 -> 100 + (200-100)/8 = 112
        let mut w = HealthWindow::new(64);
        w.record_rtt(100);
        w.record_rtt(200);
        assert_eq!(w.mean_rtt_ms(), 112);
    }

    #[test]
    fn ewma_resists_single_spike() {
        let mut w = HealthWindow::new(64);
        for _ in 0..5 {
            w.record_rtt(100);
        }
        w.record_rtt(1000);
        let m = w.mean_rtt_ms();
        assert!(m < 250, "EWMA should resist single spike, got {}", m);
        assert!(m > 100, "EWMA should still move toward spike, got {}", m);
    }
}
