use std::sync::Arc;

use mesh_bus_core::kernel::observation::*;
use tokio::sync::mpsc;

#[tokio::test]
async fn unwire_scope_removes_all_observers_subscriptions_and_publish_slots() {
    let mut reg = ObservationRegistry::new();
    let bus = Arc::new(ObservationBus::new());
    let plugin_scope = ScopeId(7);

    let mut subs = Vec::new();
    for i in 0..5u32 {
        let t = EventTypeId::Obs(ObsEventId(100 + i));
        reg.register_event_type(EventTypeSpec {
            id: t,
            schema_hash: 0,
            multi_writer: false,
            delivery: DeliveryPolicy::Lossy,
        })
        .unwrap();
        reg.register_observer(ObserverSpec {
            id: ObserverId(100 + i),
            owner: PluginId(1),
            scope: plugin_scope,
            reads: vec![t],
            writes: vec![],
            pulls: vec![],
        })
        .unwrap();
        let (tx, rx) = mpsc::channel(4);
        bus.wire_subscriber_scoped(t, tx, plugin_scope);
        subs.push((t, rx));
    }
    reg.verify().unwrap();

    for (t, _) in &subs {
        bus.publish(*t, EventPayload::empty());
    }
    for (_t, rx) in &mut subs {
        assert!(rx.try_recv().is_ok());
    }

    reg.unwire_scope(plugin_scope);
    bus.unwire_scope(plugin_scope);

    assert!(
        reg.observers_in_scope(plugin_scope).is_empty(),
        "registry must drop observers in unwired scope"
    );
    for (t, rx) in &mut subs {
        bus.publish(*t, EventPayload::empty());
        assert!(
            rx.try_recv().is_err(),
            "bus routing must remove subscribers of unwired scope for {:?}",
            t
        );
    }
}
