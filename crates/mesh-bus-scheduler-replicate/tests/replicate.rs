use mb_endpoint::Endpoint;
use mesh_bus_core::{
    ExitId, ExitResult, FlowId, FlowSemantics, PacketId, RankContext, ReturnEvent, ReturnSemantics,
    ScheduleDecision, ScheduleHint, SchedulerPlugin, SessionId, TrafficClass,
};
use mesh_bus_scheduler_replicate::ReplicateScheduler;

fn ctx() -> RankContext {
    RankContext {
        packet_id: PacketId(0),
        flow_id: FlowId("flow".into()),
        session_id: SessionId("session".into()),
        target: Endpoint::new("127.0.0.1", 53).expect("endpoint"),
        traffic_class: TrafficClass::Interactive,
        policy_ref: None,
        deadline_ms: None,
        schedule_hint: ScheduleHint::Auto,
        flow_semantics: FlowSemantics::Datagram,
        return_semantics: ReturnSemantics::PacketDedup,
        source_key: None,
        target_key: None,
    }
}

#[test]
fn returns_replicate_decision_for_all_candidates() {
    let scheduler = ReplicateScheduler::new();
    let candidates = vec![ExitId("a".into()), ExitId("b".into())];

    let decision = scheduler.schedule(&candidates, &ctx());

    assert_eq!(decision, ScheduleDecision::replicate(vec![0, 1]));
}

#[test]
fn feedback_is_accepted_without_state() {
    let scheduler = ReplicateScheduler::new();
    scheduler.feedback(
        &ExitResult {
            exit_id: ExitId("a".into()),
            success: true,
            rtt_ms: 1,
            local_endpoint: None,
            return_event: ReturnEvent::Idle,
        },
        0,
        0,
    );
}
