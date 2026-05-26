use super::helpers::DevNullEgress;
use crate::kernel::dispatch_forwarder::apply_pin_with_hysteresis;
use crate::{
    Capabilities, EgressPlugin, ExitId, ExitResult, RankContext, ScheduleDecision, SchedulerPlugin,
    SessionId,
};

// ── apply_pin_with_hysteresis pure-function tests ─────────────────────────────

const HYSTERESIS_TAU: f64 = 0.20;

/// Scheduler that returns per-exit scores injected at construction.
struct ScoredScheduler {
    scores: std::collections::HashMap<String, u64>,
}

impl SchedulerPlugin for ScoredScheduler {
    fn schedule(&self, candidates: &[ExitId], _ctx: &RankContext) -> ScheduleDecision {
        ScheduleDecision::ordered((0..candidates.len()).collect())
    }
    fn feedback(&self, _r: &ExitResult, _payload_bytes: u64, _at_ms: u64) {}
    fn score_for(&self, exit_id: &ExitId, _candidates: &[ExitId], _ctx: &RankContext) -> u64 {
        self.scores.get(&exit_id.0).copied().unwrap_or(0)
    }
}

fn mk_egress(id: &str) -> Box<dyn EgressPlugin> {
    Box::new(DevNullEgress {
        id: ExitId(id.into()),
        caps: Capabilities {
            protocol: "test".into(),
            supports_stream: true,
            supports_datagram: false,
            max_payload_bytes: None,
            groups: vec![],
        },
    })
}

fn mk_ctx() -> RankContext {
    use crate::{FlowSemantics, PacketId, ReturnSemantics, ScheduleHint, TrafficClass};
    RankContext {
        packet_id: PacketId(0),
        flow_id: crate::FlowId("f".into()),
        session_id: SessionId("s".into()),
        target: mb_endpoint::Endpoint::new("127.0.0.1", 1).unwrap(),
        traffic_class: TrafficClass::Bulk,
        policy_ref: None,
        deadline_ms: None,
        schedule_hint: ScheduleHint::Auto,
        flow_semantics: FlowSemantics::ByteStream,
        return_semantics: ReturnSemantics::Direct,
        source_key: None,
        target_key: None,
        source_activity: None,
    }
}

#[test]
fn pinned_exit_retained_under_marginal_alternative() {
    // A=100, B=110.  threshold = 100*(1+0.20)=120.  110 < 120 -> retained.
    let egresses: Vec<Box<dyn EgressPlugin>> = vec![mk_egress("a"), mk_egress("b")];
    let mut scores = std::collections::HashMap::new();
    scores.insert("a".into(), 100u64);
    scores.insert("b".into(), 110u64);
    let sched = ScoredScheduler { scores };
    let candidates = vec![ExitId("a".into()), ExitId("b".into())];
    let ctx = mk_ctx();
    // order from scheduler: [1 (b), 0 (a)]; pinned=0 (a)
    let mut order = vec![1usize, 0usize];
    apply_pin_with_hysteresis(
        &mut order,
        0,
        &egresses,
        &sched,
        &candidates,
        &ctx,
        HYSTERESIS_TAU,
    );
    assert_eq!(order[0], 0, "pin A should be promoted to front");
}

#[test]
fn pinned_exit_migrates_under_persistent_degradation() {
    // A=200, B=100.  threshold = 200*(1+0.20)=240.  100 < 240? yes, but check formula:
    // retain = pin_score < (1+tau)*alt_score => 200 < 1.20*100=120 => false -> not retained.
    let egresses: Vec<Box<dyn EgressPlugin>> = vec![mk_egress("a"), mk_egress("b")];
    let mut scores = std::collections::HashMap::new();
    scores.insert("a".into(), 200u64);
    scores.insert("b".into(), 100u64);
    let sched = ScoredScheduler { scores };
    let candidates = vec![ExitId("a".into()), ExitId("b".into())];
    let ctx = mk_ctx();
    // order from scheduler: [1 (b), 0 (a)]; pinned=0 (a)
    let mut order = vec![1usize, 0usize];
    apply_pin_with_hysteresis(
        &mut order,
        0,
        &egresses,
        &sched,
        &candidates,
        &ctx,
        HYSTERESIS_TAU,
    );
    assert_eq!(order[0], 1, "pin A should NOT be promoted; B should lead");
}

#[test]
fn hysteresis_single_candidate_always_promotes() {
    // With only one exit, pin is always retained (no alt to compare against).
    let egresses: Vec<Box<dyn EgressPlugin>> = vec![mk_egress("a")];
    let sched = ScoredScheduler {
        scores: Default::default(),
    };
    let candidates = vec![ExitId("a".into())];
    let ctx = mk_ctx();
    let mut order = vec![0usize];
    apply_pin_with_hysteresis(
        &mut order,
        0,
        &egresses,
        &sched,
        &candidates,
        &ctx,
        HYSTERESIS_TAU,
    );
    assert_eq!(order[0], 0);
}
