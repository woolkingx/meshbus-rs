use super::*;
use mb_endpoint::Endpoint;

fn base_request() -> BusSessionRequest {
    BusSessionRequest::datagram(Endpoint::new("example.com", 53).expect("endpoint"))
}

#[test]
fn continue_verdict_fails_closed() {
    let outcome = apply_verdict(&Verdict::Continue, &Event::default(), base_request());
    match outcome {
        PipelineOutcome::Deny { reason } => {
            assert_eq!(reason, "pipeline_did_not_terminate");
        }
        PipelineOutcome::Allow { .. } | PipelineOutcome::Drop => {
            panic!("unterminated pipeline must deny with reason")
        }
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
