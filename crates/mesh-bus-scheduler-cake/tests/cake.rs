use mb_endpoint::Endpoint;
use mesh_bus_core::{
    ExitId, ExitResult, FlowId, FlowSemantics, PacketId, RankContext, ReturnEvent, ReturnSemantics,
    ScheduleHint, SchedulerPlugin, SessionId, TrafficClass,
};
use mesh_bus_scheduler_cake::CakeScheduler;

fn rr(exit_id: &str, rtt: u64, success: bool) -> ExitResult {
    ExitResult {
        exit_id: ExitId(exit_id.into()),
        success,
        rtt_ms: rtt,
        local_endpoint: None,
        return_event: ReturnEvent::Idle,
    }
}

fn ctx(flow: &str, traffic_class: TrafficClass) -> RankContext {
    RankContext {
        packet_id: PacketId(0),
        flow_id: FlowId(flow.into()),
        session_id: SessionId("s-1".into()),
        target: Endpoint::new("example.com", 443).expect("endpoint"),
        traffic_class,
        policy_ref: None,
        deadline_ms: None,
        schedule_hint: ScheduleHint::Auto,
        flow_semantics: FlowSemantics::ByteStream,
        return_semantics: ReturnSemantics::Direct,
        source_key: None,
        target_key: None,
    }
}

#[test]
fn ranks_low_rtt_first_after_feedback() {
    let s = CakeScheduler::new();
    s.feedback(&rr("a", 200, true), 0, 0);
    s.feedback(&rr("b", 20, true), 0, 0);
    let cands = vec![ExitId("a".into()), ExitId("b".into())];
    let decision = s.schedule(&cands, &ctx("flow-a", TrafficClass::Interactive));
    assert_eq!(decision.indices(), &[1, 0]); // b (low RTT) first
}

#[test]
fn unknown_exits_default_to_input_order() {
    let s = CakeScheduler::new();
    let cands = vec![ExitId("a".into()), ExitId("b".into())];
    let decision = s.schedule(&cands, &ctx("flow-a", TrafficClass::Bulk));
    assert_eq!(decision.indices().len(), 2);
}

#[test]
fn sampled_slow_exit_does_not_pin_against_unknown_candidate() {
    let s = CakeScheduler::new();
    s.feedback(&rr("slow", 50, true), 0, 0);
    let cands = vec![ExitId("fast".into()), ExitId("slow".into())];
    let decision = s.schedule(&cands, &ctx("flow-a", TrafficClass::Interactive));
    assert_eq!(
        decision.indices()[0],
        0,
        "unknown candidate must get one optimistic probe before sampled 50ms slow path"
    );
}

#[test]
fn equal_score_exits_split_by_flow_id_tiebreaker() {
    let s = CakeScheduler::new();
    for _ in 0..8 {
        s.feedback(&rr("a", 50, true), 0, 0);
        s.feedback(&rr("b", 50, true), 0, 0);
        s.feedback(&rr("c", 50, true), 0, 0);
    }
    let cands = vec![ExitId("a".into()), ExitId("b".into()), ExitId("c".into())];
    let mut seen = std::collections::HashSet::new();
    for i in 0..30 {
        let flow = format!("flow-{}", i);
        let first = s
            .schedule(&cands, &ctx(&flow, TrafficClass::Bulk))
            .indices()[0];
        seen.insert(first);
    }
    assert!(
        seen.len() >= 2,
        "equal-score exits should not all collapse onto one"
    );
}

#[test]
fn jitter_penalty_demotes_unstable_exit() {
    let s = CakeScheduler::new();
    for r in [50, 50, 50, 50, 50, 50, 50, 50] {
        s.feedback(&rr("steady", r, true), 0, 0);
    }
    for r in [10, 200, 10, 200, 10, 200, 10, 200] {
        s.feedback(&rr("jittery", r, true), 0, 0);
    }
    let cands = vec![ExitId("steady".into()), ExitId("jittery".into())];
    let order = s
        .schedule(&cands, &ctx("flow", TrafficClass::Interactive))
        .indices()
        .to_vec();
    assert_eq!(
        order[0], 0,
        "steady exit must beat jittery exit with same mean"
    );
}
