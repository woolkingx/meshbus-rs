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
