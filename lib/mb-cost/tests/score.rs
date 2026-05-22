use mb_cost::{Score, ScoreInputs};

#[test]
fn lower_rtt_yields_lower_score() {
    let fast = Score::compute(&ScoreInputs {
        rtt_ms: 10,
        jitter_ms: 0,
        success_rate: 1.0,
        price_weight: 1,
        goodput_bps: None,
        capacity_bps: None,
    });
    let slow = Score::compute(&ScoreInputs {
        rtt_ms: 200,
        jitter_ms: 0,
        success_rate: 1.0,
        price_weight: 1,
        goodput_bps: None,
        capacity_bps: None,
    });
    assert!(fast.value() < slow.value());
}

#[test]
fn lower_success_rate_yields_higher_score() {
    let good = Score::compute(&ScoreInputs {
        rtt_ms: 50,
        jitter_ms: 0,
        success_rate: 1.0,
        price_weight: 1,
        goodput_bps: None,
        capacity_bps: None,
    });
    let bad = Score::compute(&ScoreInputs {
        rtt_ms: 50,
        jitter_ms: 0,
        success_rate: 0.5,
        price_weight: 1,
        goodput_bps: None,
        capacity_bps: None,
    });
    assert!(bad.value() > good.value());
}

#[test]
fn higher_jitter_increases_score() {
    let calm = Score::compute(&ScoreInputs {
        rtt_ms: 50,
        jitter_ms: 0,
        success_rate: 1.0,
        price_weight: 1,
        goodput_bps: None,
        capacity_bps: None,
    });
    let jittery = Score::compute(&ScoreInputs {
        rtt_ms: 50,
        jitter_ms: 100,
        success_rate: 1.0,
        price_weight: 1,
        goodput_bps: None,
        capacity_bps: None,
    });
    assert!(jittery.value() > calm.value());
}

#[test]
fn zero_success_rate_saturates() {
    let dead = Score::compute(&ScoreInputs {
        rtt_ms: 0,
        jitter_ms: 0,
        success_rate: 0.0,
        price_weight: 1,
        goodput_bps: None,
        capacity_bps: None,
    });
    assert_eq!(dead.value(), u64::MAX);
}
