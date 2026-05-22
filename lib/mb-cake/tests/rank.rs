use mb_cake::{ExitMetric, RankConfig, rank};

#[test]
fn ranks_lower_score_first() {
    let metrics = vec![
        ExitMetric {
            id: "slow".into(),
            rtt_ms: 200,
            jitter_ms: 10,
            success_rate: 1.0,
            weight: 1,
            goodput_bps: None,
            capacity_bps: None,
        },
        ExitMetric {
            id: "fast".into(),
            rtt_ms: 20,
            jitter_ms: 1,
            success_rate: 1.0,
            weight: 1,
            goodput_bps: None,
            capacity_bps: None,
        },
        ExitMetric {
            id: "med".into(),
            rtt_ms: 80,
            jitter_ms: 5,
            success_rate: 1.0,
            weight: 1,
            goodput_bps: None,
            capacity_bps: None,
        },
    ];
    let order = rank(&metrics, "session-1", RankConfig::default());
    assert_eq!(order, vec!["fast", "med", "slow"]);
}

#[test]
fn dead_exit_ranked_last() {
    let metrics = vec![
        ExitMetric {
            id: "dead".into(),
            rtt_ms: 0,
            jitter_ms: 0,
            success_rate: 0.0,
            weight: 1,
            goodput_bps: None,
            capacity_bps: None,
        },
        ExitMetric {
            id: "alive".into(),
            rtt_ms: 100,
            jitter_ms: 0,
            success_rate: 1.0,
            weight: 1,
            goodput_bps: None,
            capacity_bps: None,
        },
    ];
    let order = rank(&metrics, "x", RankConfig::default());
    assert_eq!(order.last(), Some(&"dead".to_string()));
}

#[test]
fn empty_metrics_returns_empty() {
    let order = rank(&[], "x", RankConfig::default());
    assert!(order.is_empty());
}
