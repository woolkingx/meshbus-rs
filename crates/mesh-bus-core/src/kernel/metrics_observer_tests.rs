use super::*;
use crate::kernel::observation::{EventPayload, EventPayloadInner};

#[test]
fn metrics_observer_counts_success_and_failure() {
    let m = MetricsObserver::new();
    m.on_core_event(&EventEnvelope {
        type_id: EventTypeId::Core(CoreEventId::FlowOpened),
        payload: EventPayload(Arc::new(EventPayloadInner {
            payload_bytes: 1000,
            success: Some(true),
            ..Default::default()
        })),
        at_ns: 1,
    });
    m.on_core_event(&EventEnvelope {
        type_id: EventTypeId::Core(CoreEventId::PathIoError),
        payload: EventPayload::empty(),
        at_ns: 2,
    });
    let s = m.snapshot();
    assert_eq!(s.dispatch_success, 1);
    assert_eq!(s.dispatch_failure, 1);
    assert_eq!(s.bytes_sent, 1000);
}

#[test]
fn metrics_observer_counts_observation_drops_by_reason() {
    let m = MetricsObserver::new();
    m.on_observation_event(&EventEnvelope {
        type_id: OBS_MESHSEC_DROP,
        payload: EventPayload(Arc::new(EventPayloadInner {
            reason: Some("auth".into()),
            ..Default::default()
        })),
        at_ns: 1,
    });
    m.on_observation_event(&EventEnvelope {
        type_id: OBS_MESHSEC_DROP,
        payload: EventPayload(Arc::new(EventPayloadInner {
            reason: Some("replay".into()),
            ..Default::default()
        })),
        at_ns: 2,
    });
    m.on_observation_event(&EventEnvelope {
        type_id: OBS_NATIVE_DROP,
        payload: EventPayload(Arc::new(EventPayloadInner {
            reason: Some("queue_overflow".into()),
            ..Default::default()
        })),
        at_ns: 3,
    });
    let s = m.snapshot();
    assert_eq!(s.meshsec_drop_total, 2);
    assert_eq!(s.meshsec_auth_drop_total, 1);
    assert_eq!(s.meshsec_replay_drop_total, 1);
    assert_eq!(s.native_drop_total, 1);
    assert_eq!(s.native_queue_overflow_drop_total, 1);
}
