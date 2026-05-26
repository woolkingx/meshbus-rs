use crate::{
    BusEvent, Capabilities, EgressPlugin, ExitId, ExitResult, Frame, Measurement, ObserverPlugin,
    RankContext, ReturnEvent, ScheduleDecision, SchedulerPlugin, SessionId,
};
use async_trait::async_trait;
use mb_endpoint::Endpoint;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

pub(super) struct NoopScheduler;
impl SchedulerPlugin for NoopScheduler {
    fn schedule(&self, candidates: &[ExitId], _ctx: &RankContext) -> ScheduleDecision {
        ScheduleDecision::ordered((0..candidates.len()).collect())
    }
    fn feedback(&self, _r: &ExitResult, _payload_bytes: u64, _at_ms: u64) {}
}

pub(super) struct RecordingScheduler {
    pub(super) contexts: Arc<Mutex<Vec<RankContext>>>,
}

impl SchedulerPlugin for RecordingScheduler {
    fn schedule(&self, candidates: &[ExitId], ctx: &RankContext) -> ScheduleDecision {
        self.contexts
            .lock()
            .expect("recording scheduler contexts")
            .push(ctx.clone());
        ScheduleDecision::ordered((0..candidates.len()).collect())
    }

    fn feedback(&self, _r: &ExitResult, _payload_bytes: u64, _at_ms: u64) {}
}

pub(super) struct DevNullEgress {
    pub(super) id: ExitId,
    pub(super) caps: Capabilities,
}

#[async_trait]
impl EgressPlugin for DevNullEgress {
    fn id(&self) -> &ExitId {
        &self.id
    }
    fn capabilities(&self) -> &Capabilities {
        &self.caps
    }
    async fn send(&self, _frame: Frame) -> ExitResult {
        ExitResult {
            exit_id: self.id.clone(),
            success: false,
            rtt_ms: 0,
            local_endpoint: None,
            return_event: ReturnEvent::Idle,
        }
    }
    async fn poll(&self, _s: &SessionId) -> ReturnEvent {
        ReturnEvent::Idle
    }
    async fn probe(&self, _t: &Endpoint) -> Measurement {
        Measurement {
            exit_id: self.id.clone(),
            at_ms: 0,
            rtt_ms: 0,
            payload_bytes: 0,
            jitter_ms: None,
            throughput_bps: None,
            success: true,
        }
    }
    async fn close(&self, _s: &SessionId) {}
}

pub(super) struct RecordingObserver {
    pub(super) events: Arc<std::sync::Mutex<Vec<BusEvent>>>,
}

impl ObserverPlugin for RecordingObserver {
    fn on_event(&self, event: &BusEvent) {
        self.events
            .lock()
            .expect("recorder mutex")
            .push(event.clone());
    }
}

pub(super) struct FlappingEgress {
    pub(super) id: ExitId,
    pub(super) caps: Capabilities,
    pub(super) fail_first: AtomicBool,
}

#[async_trait]
impl EgressPlugin for FlappingEgress {
    fn id(&self) -> &ExitId {
        &self.id
    }
    fn capabilities(&self) -> &Capabilities {
        &self.caps
    }
    async fn send(&self, frame: Frame) -> ExitResult {
        let fail = self.fail_first.swap(false, Ordering::SeqCst);
        if fail {
            ExitResult {
                exit_id: self.id.clone(),
                success: false,
                rtt_ms: 0,
                local_endpoint: None,
                return_event: ReturnEvent::Closed {
                    reason: crate::CloseReason::Other("upstream".into()),
                },
            }
        } else {
            ExitResult {
                exit_id: self.id.clone(),
                success: true,
                rtt_ms: 1,
                local_endpoint: None,
                return_event: ReturnEvent::Data {
                    seq: frame.seq,
                    payload: frame.payload,
                },
            }
        }
    }
    async fn poll(&self, _s: &SessionId) -> ReturnEvent {
        ReturnEvent::Idle
    }
    async fn probe(&self, _t: &Endpoint) -> Measurement {
        Measurement {
            exit_id: self.id.clone(),
            at_ms: 0,
            rtt_ms: 0,
            payload_bytes: 0,
            jitter_ms: None,
            throughput_bps: None,
            success: true,
        }
    }
    async fn close(&self, _s: &SessionId) {}
}

pub(super) struct NarrowObserver {
    pub(super) which: &'static [crate::kernel::observation::CoreEventId],
    pub(super) events: Arc<std::sync::Mutex<Vec<BusEvent>>>,
}

impl ObserverPlugin for NarrowObserver {
    fn on_event(&self, event: &BusEvent) {
        self.events
            .lock()
            .expect("recorder mutex")
            .push(event.clone());
    }
    fn subscribed_core_events(&self) -> &'static [crate::kernel::observation::CoreEventId] {
        self.which
    }
}
