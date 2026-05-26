use super::*;
use mb_endpoint::Endpoint;
use mesh_bus_core::ScheduleHint;

fn base_request() -> BusSessionRequest {
    BusSessionRequest::stream(Endpoint::new("example.com", 443).expect("endpoint"))
}

#[test]
fn continue_verdict_fails_closed() {
    let outcome = apply_verdict(&Verdict::Continue, &Event::default(), base_request());

    match outcome {
        PipelineOutcome::Deny { reason } => {
            assert_eq!(reason, "pipeline_did_not_terminate");
        }
        PipelineOutcome::Allow { .. } => panic!("unterminated pipeline must not fail open"),
        PipelineOutcome::Drop => panic!("unterminated pipeline must deny with reason"),
    }
}

#[test]
fn drop_verdict_stays_silent_drop() {
    let outcome = apply_verdict(&Verdict::Drop, &Event::default(), base_request());

    match outcome {
        PipelineOutcome::Drop => {}
        PipelineOutcome::Allow { .. } | PipelineOutcome::Deny { .. } => {
            panic!("drop verdict must not be projected as allow or deny")
        }
    }
}

#[test]
fn absent_schedule_hint_preserves_core_auto_default() {
    let outcome = apply_verdict(
        &Verdict::Accept(mesh_bus_core::kernel::SinkId::new("direct")),
        &Event::default(),
        base_request(),
    );

    match outcome {
        PipelineOutcome::Allow { request } => {
            assert_eq!(request.schedule_hint, ScheduleHint::Auto);
        }
        PipelineOutcome::Deny { .. } | PipelineOutcome::Drop => panic!("expected allow"),
    }
}

#[test]
fn fanout_schedule_hint_preserves_k() {
    let mut event = Event::default();
    event.meta.transport.schedule_hint = Some(ScheduleHintLabel::FanOut);
    event.meta.transport.schedule_fanout_k = Some(3);
    let outcome = apply_verdict(
        &Verdict::Accept(mesh_bus_core::kernel::SinkId::new("direct")),
        &event,
        base_request(),
    );

    match outcome {
        PipelineOutcome::Allow { request } => {
            assert_eq!(request.schedule_hint, ScheduleHint::FanOut { k: 3 });
        }
        PipelineOutcome::Deny { .. } | PipelineOutcome::Drop => panic!("expected allow"),
    }
}

#[test]
fn fanout_schedule_hint_without_k_fails_closed() {
    let mut event = Event::default();
    event.meta.transport.schedule_hint = Some(ScheduleHintLabel::FanOut);
    let outcome = apply_verdict(
        &Verdict::Accept(mesh_bus_core::kernel::SinkId::new("direct")),
        &event,
        base_request(),
    );

    match outcome {
        PipelineOutcome::Deny { reason } => {
            assert_eq!(reason, "missing_schedule_fanout_k");
        }
        PipelineOutcome::Allow { .. } | PipelineOutcome::Drop => {
            panic!("FanOut without k must fail closed")
        }
    }
}
