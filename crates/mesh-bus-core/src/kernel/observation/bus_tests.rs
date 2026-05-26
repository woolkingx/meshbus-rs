use super::*;
use crate::kernel::observation::{CoreEventId, EventTypeId};
use tokio::sync::mpsc;

#[tokio::test]
async fn publish_lossy_fans_out_to_registered_subscribers() {
    let bus = ObservationBus::new();
    let (tx_a, mut rx_a) = mpsc::channel(8);
    let (tx_b, mut rx_b) = mpsc::channel(8);
    let t = EventTypeId::Core(CoreEventId::PathIoError);
    bus.wire_subscriber(t, tx_a);
    bus.wire_subscriber(t, tx_b);
    bus.publish(t, EventPayload::empty());
    assert!(rx_a.recv().await.is_some());
    assert!(rx_b.recv().await.is_some());
}

#[tokio::test]
async fn publish_lossy_drops_on_full_queue_no_panic() {
    let bus = ObservationBus::new();
    let (tx, _rx) = mpsc::channel(1);
    let t = EventTypeId::Core(CoreEventId::PathIoError);
    bus.wire_subscriber(t, tx);
    for _ in 0..10 {
        bus.publish(t, EventPayload::empty());
    }
}
