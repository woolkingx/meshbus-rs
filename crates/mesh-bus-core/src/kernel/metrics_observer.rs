use crate::kernel::observation::{
    CoreEventId, EventEnvelope, EventTypeId, OBS_MESHSEC_DROP, OBS_NATIVE_DROP,
};
use crate::{BusEvent, ObserverPlugin};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct MetricsObserver {
    dispatch_success: AtomicU64,
    dispatch_failure: AtomicU64,
    bytes_sent: AtomicU64,
    meshsec_drop_total: AtomicU64,
    meshsec_auth_drop_total: AtomicU64,
    meshsec_replay_drop_total: AtomicU64,
    native_drop_total: AtomicU64,
    native_queue_overflow_drop_total: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct MetricsSnapshot {
    pub dispatch_success: u64,
    pub dispatch_failure: u64,
    pub bytes_sent: u64,
    pub meshsec_drop_total: u64,
    pub meshsec_auth_drop_total: u64,
    pub meshsec_replay_drop_total: u64,
    pub native_drop_total: u64,
    pub native_queue_overflow_drop_total: u64,
}

impl MetricsObserver {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            dispatch_success: self.dispatch_success.load(Ordering::Relaxed),
            dispatch_failure: self.dispatch_failure.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            meshsec_drop_total: self.meshsec_drop_total.load(Ordering::Relaxed),
            meshsec_auth_drop_total: self.meshsec_auth_drop_total.load(Ordering::Relaxed),
            meshsec_replay_drop_total: self.meshsec_replay_drop_total.load(Ordering::Relaxed),
            native_drop_total: self.native_drop_total.load(Ordering::Relaxed),
            native_queue_overflow_drop_total: self
                .native_queue_overflow_drop_total
                .load(Ordering::Relaxed),
        }
    }

    pub fn on_event_inline(&self, event: &BusEvent) {
        match event {
            BusEvent::Core(env) => self.on_core_event(env),
            BusEvent::Observation(env) => self.on_observation_event(env),
            _ => {}
        }
    }

    pub fn on_core_event(&self, env: &EventEnvelope) {
        match env.type_id {
            EventTypeId::Core(CoreEventId::FlowOpened) => {
                let payload = &env.payload.0;
                self.dispatch_success.fetch_add(1, Ordering::Relaxed);
                self.bytes_sent.fetch_add(
                    payload.bytes_out.max(payload.payload_bytes),
                    Ordering::Relaxed,
                );
            }
            EventTypeId::Core(CoreEventId::FlowClosed) => {
                let payload = &env.payload.0;
                if !payload.success.unwrap_or(true) {
                    self.dispatch_failure.fetch_add(1, Ordering::Relaxed);
                }
                self.bytes_sent.fetch_add(
                    payload.bytes_out.max(payload.payload_bytes),
                    Ordering::Relaxed,
                );
            }
            EventTypeId::Core(CoreEventId::PathIoError) => {
                self.dispatch_failure.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    pub fn on_observation_event(&self, env: &EventEnvelope) {
        match env.type_id {
            OBS_MESHSEC_DROP => {
                self.meshsec_drop_total.fetch_add(1, Ordering::Relaxed);
                match env.payload.0.reason.as_deref() {
                    Some("auth") => {
                        self.meshsec_auth_drop_total.fetch_add(1, Ordering::Relaxed);
                    }
                    Some("replay") | Some("replay_too_old") => {
                        self.meshsec_replay_drop_total
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {}
                }
            }
            OBS_NATIVE_DROP => {
                self.native_drop_total.fetch_add(1, Ordering::Relaxed);
                if env.payload.0.reason.as_deref() == Some("queue_overflow") {
                    self.native_queue_overflow_drop_total
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
            _ => {}
        }
    }
}

impl ObserverPlugin for MetricsObserver {
    fn on_event(&self, event: &BusEvent) {
        self.on_event_inline(event);
    }
}

#[cfg(test)]
#[path = "metrics_observer_tests.rs"]
mod metrics_observer_tests;
