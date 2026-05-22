//! Projects a pipeline `Verdict` + post-run `Event` metadata onto a
//! `BusSessionRequest`. Counterpart to `action_apply.rs` for the
//! event-pipeline path: rule_chain has already written
//! `policy.route_group` / `transport.schedule_hint` onto the event;
//! this module reads them back and stamps them on the session request.
//! `Verdict::Accept(SinkId)` projects onto `BusSessionRequest.target_sink`
//! so the runtime dispatcher pins the session to that exit exactly.

use mesh_bus_core::kernel::{Event, ScheduleHintLabel, Verdict};
use mesh_bus_core::{BusSessionRequest, ScheduleHint};

#[derive(Debug, Clone)]
pub enum PipelineOutcome {
    Allow { request: BusSessionRequest },
    Deny { reason: String },
    Drop,
}

pub fn apply_verdict(verdict: &Verdict, event: &Event, base: BusSessionRequest) -> PipelineOutcome {
    match verdict {
        Verdict::Accept(sink) => match project(base, event) {
            Ok(request) => PipelineOutcome::Allow {
                request: request.with_target_sink(sink.as_str()),
            },
            Err(reason) => PipelineOutcome::Deny { reason },
        },
        Verdict::Reject(reason) => PipelineOutcome::Deny {
            reason: reason.code.clone(),
        },
        Verdict::Drop => PipelineOutcome::Drop,
        Verdict::Continue | Verdict::Jump(_) => PipelineOutcome::Deny {
            reason: "pipeline_did_not_terminate".into(),
        },
    }
}

fn project(base: BusSessionRequest, event: &Event) -> Result<BusSessionRequest, String> {
    let mut req = base;
    if let Some(g) = &event.meta.policy.route_group {
        req = req.with_route_group(g.clone());
    }
    if let Some(label) = &event.meta.transport.schedule_hint {
        req = req.with_schedule_hint(match label {
            ScheduleHintLabel::Ordered => ScheduleHint::SinglePath,
            ScheduleHintLabel::FanOut => ScheduleHint::FanOut {
                k: event
                    .meta
                    .transport
                    .schedule_fanout_k
                    .ok_or_else(|| "missing_schedule_fanout_k".to_string())?
                    as usize,
            },
            ScheduleHintLabel::Stripe => {
                tracing::warn!(
                    target: "mesh_bus.ingress.socks5",
                    "schedule_hint_stripe_unsupported: downgrading to Auto"
                );
                ScheduleHint::Auto
            }
        });
    }
    Ok(req)
}

#[cfg(test)]
mod tests {
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
}
