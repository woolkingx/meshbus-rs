use mesh_bus_core::kernel::observation::{
    CoreEventId, EventEnvelope, EventPayload, EventPayloadInner, EventTypeId, OBS_MESHSEC_DROP,
    OBS_NATIVE_DROP,
};
use mesh_bus_core::{BusEvent, ObserverPlugin};
use mesh_bus_observer_metrics::CounterObserver;
use std::sync::Arc;

fn flow_opened(exit_id: &str) -> BusEvent {
    BusEvent::Core(EventEnvelope {
        type_id: EventTypeId::Core(CoreEventId::FlowOpened),
        payload: EventPayload(Arc::new(EventPayloadInner {
            selected_exit: Some(exit_id.into()),
            success: Some(true),
            ..Default::default()
        })),
        at_ns: 0,
    })
}

fn obs_drop(type_id: EventTypeId, reason: &str) -> BusEvent {
    BusEvent::Observation(EventEnvelope {
        type_id,
        payload: EventPayload(Arc::new(EventPayloadInner {
            reason: Some(reason.into()),
            ..Default::default()
        })),
        at_ns: 0,
    })
}

#[test]
fn counts_flow_opened_events() {
    let obs = CounterObserver::new();
    obs.on_event(&flow_opened("a"));
    obs.on_event(&flow_opened("a"));
    let snapshot = obs.snapshot();
    assert_eq!(snapshot.get("a"), Some(&2u64));
}

#[test]
fn counts_observation_drops_by_reason() {
    let obs = CounterObserver::new();
    obs.on_event(&obs_drop(OBS_MESHSEC_DROP, "auth"));
    obs.on_event(&obs_drop(OBS_MESHSEC_DROP, "replay"));
    obs.on_event(&obs_drop(OBS_NATIVE_DROP, "queue_overflow"));
    let snapshot = obs.drop_snapshot();
    assert_eq!(snapshot.meshsec_drop_total, 2);
    assert_eq!(snapshot.meshsec_auth_drop_total, 1);
    assert_eq!(snapshot.meshsec_replay_drop_total, 1);
    assert_eq!(snapshot.native_drop_total, 1);
    assert_eq!(snapshot.native_queue_overflow_drop_total, 1);
}
