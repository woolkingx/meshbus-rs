use std::sync::Arc;
use std::time::Duration;

use mesh_bus_core::kernel::observation::*;
use tokio::sync::mpsc;

fn make_wedged(
    bus: &ObservationBus,
    t: EventTypeId,
    n: usize,
) -> Vec<mpsc::Receiver<EventEnvelope>> {
    (0..n)
        .map(|_| {
            let (tx, rx) = mpsc::channel(1);
            bus.wire_subscriber(t, tx.clone());
            // Wedge by filling the single slot before publish.
            let _ = tx.try_send(EventEnvelope {
                type_id: t,
                payload: EventPayload::empty(),
                at_ns: 0,
            });
            rx
        })
        .collect()
}

#[tokio::test]
async fn reliable_publish_returns_under_total_deadline_with_wedged_subscribers() {
    let bus = Arc::new(ObservationBus::new());
    let t = EventTypeId::Core(CoreEventId::FlowOpened);
    let _wedged = make_wedged(&bus, t, 8);
    let start = std::time::Instant::now();
    let report = bus
        .publish_reliable(t, EventPayload::empty(), Duration::from_millis(50))
        .await;
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_millis(150),
        "exceeded total deadline: {elapsed:?}"
    );
    assert_eq!(report.timed_out, 8);
}

#[tokio::test]
async fn auto_unwire_after_threshold_consecutive_timeouts() {
    let bus = Arc::new(ObservationBus::new());
    let t = EventTypeId::Core(CoreEventId::FlowOpened);
    let _wedged = make_wedged(&bus, t, 1);
    for _ in 0..MAX_LIFECYCLE_TIMEOUTS_BEFORE_UNWIRE {
        let _ = bus
            .publish_reliable(t, EventPayload::empty(), Duration::from_millis(20))
            .await;
    }
    let snap = bus.subscriber_status_snapshot();
    assert!(snap.values().any(|s| matches!(
        s,
        SubscriberStatus::Unwired {
            reason: UnwireReason::LifecycleTimeoutThresholdExceeded,
            ..
        }
    )));
}
