//! Pure score computation. No state, no I/O.

#[derive(Debug, Clone, Copy)]
pub struct ScoreInputs {
    pub rtt_ms: u64,
    pub jitter_ms: u64,
    pub success_rate: f64,
    pub price_weight: u32,
    pub goodput_bps: Option<u64>,
    pub capacity_bps: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Score(u64);

impl Score {
    pub fn compute(inputs: &ScoreInputs) -> Self {
        if inputs.success_rate <= 0.0 {
            return Self(u64::MAX);
        }
        let rtt = inputs
            .rtt_ms
            .saturating_mul(inputs.price_weight.max(1) as u64);
        let jitter = inputs.jitter_ms;
        let penalty = ((1.0 - inputs.success_rate) * 10_000.0) as u64;
        let saturation = saturation_penalty(inputs.goodput_bps, inputs.capacity_bps);
        Self(
            rtt.saturating_add(jitter)
                .saturating_add(penalty)
                .saturating_add(saturation),
        )
    }

    pub fn value(self) -> u64 {
        self.0
    }
}

fn saturation_penalty(goodput_bps: Option<u64>, capacity_bps: Option<u64>) -> u64 {
    let (Some(g), Some(c)) = (goodput_bps, capacity_bps) else {
        return 0;
    };
    if c == 0 {
        return 0;
    }
    let util = g as f64 / c as f64;
    if util < 0.70 {
        0
    } else {
        (((util - 0.70) / 0.30).min(1.0) * 10_000.0) as u64
    }
}

#[cfg(test)]
mod saturation_tests {
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
}
