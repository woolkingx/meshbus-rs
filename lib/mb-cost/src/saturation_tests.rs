use super::*;

fn base() -> ScoreInputs {
    ScoreInputs {
        rtt_ms: 50,
        jitter_ms: 5,
        success_rate: 1.0,
        price_weight: 1,
        goodput_bps: None,
        capacity_bps: None,
    }
}

#[test]
fn capacity_none_means_no_penalty() {
    let base_score = Score::compute(&base()).value();
    let with_goodput = Score::compute(&ScoreInputs {
        goodput_bps: Some(900_000_000),
        ..base()
    })
    .value();
    assert_eq!(base_score, with_goodput);
}

#[test]
fn under_threshold_no_penalty() {
    let unsaturated = Score::compute(&ScoreInputs {
        goodput_bps: Some(500_000_000),
        capacity_bps: Some(1_000_000_000),
        ..base()
    })
    .value();
    let dry = Score::compute(&base()).value();
    assert_eq!(unsaturated, dry);
}

#[test]
fn near_capacity_adds_penalty() {
    let saturated = Score::compute(&ScoreInputs {
        goodput_bps: Some(950_000_000),
        capacity_bps: Some(1_000_000_000),
        ..base()
    })
    .value();
    let dry = Score::compute(&base()).value();
    assert!(
        saturated > dry,
        "saturated must score worse, dry={} sat={}",
        dry,
        saturated
    );
}
