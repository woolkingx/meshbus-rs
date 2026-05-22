use mesh_bus_core::kernel::observation::{
    CoreEventId, EventEnvelope, EventPayload, EventPayloadInner, EventTypeId,
};
use mesh_bus_core::{BusEvent, ExitId, ObserverPlugin, SchedulerPlugin};
use mesh_bus_scheduler_cake::{CakeFeedbackObserver, CakeScheduler};
use std::sync::Arc;

#[tokio::test]
async fn cake_observer_forwards_core_flow_closed_to_scheduler_feedback() {
    let scheduler = Arc::new(CakeScheduler::new());
    let obs = CakeFeedbackObserver::new(scheduler.clone());
    // hammer enough events so HealthWindow has goodput data
    for i in 0..32 {
        obs.on_event(&BusEvent::Core(EventEnvelope {
            type_id: EventTypeId::Core(CoreEventId::FlowClosed),
            payload: EventPayload(Arc::new(EventPayloadInner {
                selected_exit: Some("e1".into()),
                at_ms: 1_000 + i * 10,
                rtt_ms: 5,
                payload_bytes: 1500,
                success: Some(true),
                ..Default::default()
            })),
            at_ns: 0,
        }));
    }
    obs.flush_for_test().await;
    assert!(
        scheduler.goodput_bps_for(&ExitId("e1".into())).is_some(),
        "feedback should have produced a goodput sample"
    );
}
