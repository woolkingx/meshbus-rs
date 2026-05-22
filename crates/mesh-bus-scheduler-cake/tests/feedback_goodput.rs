use mb_endpoint::Endpoint;
use mesh_bus_core::{
    ExitId, ExitResult, FlowId, FlowSemantics, PacketId, RankContext, ReturnEvent, ReturnSemantics,
    ScheduleHint, SchedulerPlugin, SessionId, TrafficClass,
};
use mesh_bus_scheduler_cake::CakeScheduler;

fn result(exit: &str, rtt_ms: u64) -> ExitResult {
    ExitResult {
        exit_id: ExitId(exit.into()),
        success: true,
        rtt_ms,
        local_endpoint: None,
        return_event: ReturnEvent::Idle,
    }
}

fn rank_context(flow_id_str: &str) -> RankContext {
    RankContext {
        packet_id: PacketId(0),
        flow_id: FlowId(flow_id_str.into()),
        session_id: SessionId("s-1".into()),
        target: Endpoint::new("example.com", 443).expect("endpoint"),
        traffic_class: TrafficClass::Interactive,
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
fn feedback_records_goodput_window() {
    let s = CakeScheduler::new();
    s.feedback(&result("a", 10), 1_000_000, 1000);
    s.feedback(&result("a", 10), 1_000_000, 2000);
    let g = s.goodput_bps_for(&ExitId("a".into())).unwrap();
    assert_eq!(g, 2_000_000);
}

#[test]
fn score_for_returns_nonzero_after_feedback() {
    let s = CakeScheduler::new();
    s.feedback(&result("a", 10), 500, 1000);
    s.feedback(&result("b", 100), 500, 1000);
    let cand = vec![ExitId("a".into()), ExitId("b".into())];
    let ctx = rank_context("flow-x");
    let sa = s.score_for(&ExitId("a".into()), &cand, &ctx);
    let sb = s.score_for(&ExitId("b".into()), &cand, &ctx);
    assert!(
        sa < sb,
        "low-RTT exit must score lower, sa={} sb={}",
        sa,
        sb
    );
}
