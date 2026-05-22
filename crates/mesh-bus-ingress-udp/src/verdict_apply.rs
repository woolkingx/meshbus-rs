//! Projects a pipeline `Verdict` + post-run `Event` metadata onto a
//! `BusSessionRequest` for the direct UDP datagram path.
//! `Verdict::Accept(SinkId)` projects onto `BusSessionRequest.target_sink`;
//! `policy.route_group` and `transport.schedule_hint` are read back and
//! stamped on the request. Direct UDP has no protocol reply, so `Deny` and
//! `Drop` both skip opening the datagram session; the distinction is log-only.

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
                    target: "mesh_bus.ingress.udp",
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
}
