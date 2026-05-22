//! CAKE ranking: compose Score over candidates, return ordered IDs.

use mb_cost::{Score, ScoreInputs};
use std::hash::Hasher;

#[derive(Debug, Clone)]
pub struct ExitMetric {
    pub id: String,
    pub rtt_ms: u64,
    pub jitter_ms: u64,
    pub success_rate: f64,
    pub weight: u32,
    pub goodput_bps: Option<u64>,
    pub capacity_bps: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct RankConfig {
    pub price_weight: u32,
}

pub fn rank(metrics: &[ExitMetric], session_id: &str, cfg: RankConfig) -> Vec<String> {
    let mut scored: Vec<(Score, u64, &ExitMetric)> = metrics
        .iter()
        .map(|m| {
            let inputs = ScoreInputs {
                rtt_ms: m.rtt_ms,
                jitter_ms: m.jitter_ms,
                success_rate: m.success_rate,
                price_weight: cfg.price_weight.max(1),
                goodput_bps: m.goodput_bps,
                capacity_bps: m.capacity_bps,
            };
            (Score::compute(&inputs), tiebreaker(session_id, &m.id), m)
        })
        .collect();
    scored.sort_by(|(sa, ta, _), (sb, tb, _)| sa.cmp(sb).then(ta.cmp(tb)));
    scored.into_iter().map(|(_, _, m)| m.id.clone()).collect()
}

fn tiebreaker(session_id: &str, exit_id: &str) -> u64 {
    let mut h = fxhash::FxHasher::default();
    h.write(session_id.as_bytes());
    h.write(b"|");
    h.write(exit_id.as_bytes());
    h.finish()
}

#[cfg(test)]
mod passthrough_tests {
    use super::*;

    #[test]
    fn saturated_exit_ranks_lower_than_idle() {
        let metrics = vec![
            ExitMetric {
                id: "a".into(),
                rtt_ms: 50,
                jitter_ms: 5,
                success_rate: 1.0,
                weight: 1,
                goodput_bps: Some(950_000_000),
                capacity_bps: Some(1_000_000_000),
            },
            ExitMetric {
                id: "b".into(),
                rtt_ms: 50,
                jitter_ms: 5,
                success_rate: 1.0,
                weight: 1,
                goodput_bps: Some(100_000_000),
                capacity_bps: Some(1_000_000_000),
            },
        ];
        let order = rank(&metrics, "flow-1", RankConfig::default());
        assert_eq!(order, vec!["b".to_string(), "a".to_string()]);
    }
}
