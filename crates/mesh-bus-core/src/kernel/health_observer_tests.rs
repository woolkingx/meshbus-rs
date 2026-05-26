use super::*;
use crate::kernel::observation::{EventPayload, EventPayloadInner};
use mb_health::HealthPolicy;

fn strict_policy() -> HealthPolicy {
    HealthPolicy {
        failure_threshold: 2,
        recovery_window_ms: 60_000,
        probe_after_ms: 30_000,
    }
}

#[tokio::test]
async fn three_failures_mark_exit_unhealthy() {
    let publisher = Arc::new(HealthPublisher::new());
    let obs = ExitHealthObserver::new(publisher.clone(), strict_policy(), vec!["e1".to_string()]);
    for i in 0..5 {
        obs.on_core_event(&EventEnvelope {
            type_id: EventTypeId::Core(CoreEventId::PathIoError),
            payload: EventPayload(Arc::new(EventPayloadInner {
                selected_exit: Some("e1".into()),
                at_ms: i * 100,
                success: Some(false),
                ..Default::default()
            })),
            at_ns: 0,
        });
    }
    obs.flush_for_test().await;
    let snap = publisher.load();
    assert!(
        snap.unhealthy.contains("e1"),
        "e1 should be unhealthy after consecutive failures"
    );
}

#[tokio::test]
async fn success_recovers_exit() {
    let publisher = Arc::new(HealthPublisher::new());
    let obs = ExitHealthObserver::new(publisher.clone(), strict_policy(), vec!["e1".to_string()]);
    for i in 0..5 {
        obs.on_core_event(&EventEnvelope {
            type_id: EventTypeId::Core(CoreEventId::PathIoError),
            payload: EventPayload(Arc::new(EventPayloadInner {
                selected_exit: Some("e1".into()),
                at_ms: i * 100,
                success: Some(false),
                ..Default::default()
            })),
            at_ns: 0,
        });
    }
    obs.flush_for_test().await;
    assert!(publisher.load().unhealthy.contains("e1"));

    // hammer success; use at_ms far enough past probe_after_ms so can_dispatch returns true
    for i in 0..10 {
        obs.on_core_event(&EventEnvelope {
            type_id: EventTypeId::Core(CoreEventId::FlowClosed),
            payload: EventPayload(Arc::new(EventPayloadInner {
                selected_exit: Some("e1".into()),
                at_ms: 100_000 + i * 100,
                success: Some(true),
                ..Default::default()
            })),
            at_ns: 0,
        });
    }
    obs.flush_for_test().await;
    assert!(
        !publisher.load().unhealthy.contains("e1"),
        "e1 should recover after success"
    );
}
