use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use mesh_bus_core::kernel::observation::{
    EventEnvelope, EventPayload, EventPayloadInner, EventTypeId, OBS_MESHSEC_DROP,
};
use mesh_bus_core::{
    BusBuilder, BusError, BusEvent, Capabilities, EgressPlugin, ExitId, ExitResult, Frame,
    Measurement, ObserverPlugin, RankContext, ReturnEvent, ScheduleDecision, SchedulerPlugin,
    SessionId,
};

struct NoopScheduler;

impl SchedulerPlugin for NoopScheduler {
    fn schedule(&self, candidates: &[ExitId], _ctx: &RankContext) -> ScheduleDecision {
        ScheduleDecision::ordered((0..candidates.len()).collect())
    }

    fn feedback(&self, _result: &ExitResult, _payload_bytes: u64, _at_ms: u64) {}
}

struct NoopEgress {
    id: ExitId,
    caps: Capabilities,
}

#[async_trait]
impl EgressPlugin for NoopEgress {
    fn id(&self) -> &ExitId {
        &self.id
    }

    fn capabilities(&self) -> &Capabilities {
        &self.caps
    }

    async fn send(&self, _frame: Frame) -> ExitResult {
        ExitResult {
            exit_id: self.id.clone(),
            success: true,
            rtt_ms: 0,
            local_endpoint: None,
            return_event: ReturnEvent::Idle,
        }
    }

    async fn poll(&self, _session_id: &SessionId) -> ReturnEvent {
        ReturnEvent::Idle
    }

    async fn probe(&self, _target: &mb_endpoint::Endpoint) -> Measurement {
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

    async fn close(&self, _session_id: &SessionId) {}
}

struct ObsRecorder {
    events: Arc<Mutex<Vec<EventEnvelope>>>,
}

impl ObserverPlugin for ObsRecorder {
    fn subscribed_core_events(&self) -> &'static [mesh_bus_core::kernel::observation::CoreEventId] {
        &[]
    }

    fn subscribed_events(&self) -> &'static [EventTypeId] {
        &[OBS_MESHSEC_DROP]
    }

    fn on_event(&self, event: &BusEvent) {
        if let BusEvent::Core(env) | BusEvent::Observation(env) = event {
            self.events.lock().expect("events").push(env.clone());
        }
    }
}

struct UnknownObs;

impl ObserverPlugin for UnknownObs {
    fn subscribed_core_events(&self) -> &'static [mesh_bus_core::kernel::observation::CoreEventId] {
        &[]
    }

    fn subscribed_events(&self) -> &'static [EventTypeId] {
        &[EventTypeId::Obs(
            mesh_bus_core::kernel::observation::ObsEventId(999),
        )]
    }

    fn on_event(&self, _event: &BusEvent) {}
}

struct CoreWriter;

impl ObserverPlugin for CoreWriter {
    fn observation_writes(&self) -> &'static [EventTypeId] {
        &[EventTypeId::Core(
            mesh_bus_core::kernel::observation::CoreEventId::FlowOpened,
        )]
    }

    fn on_event(&self, _event: &BusEvent) {}
}

fn builder_with(observer: Box<dyn ObserverPlugin>) -> BusBuilder {
    BusBuilder::new()
        .scheduler(Box::new(NoopScheduler))
        .add_egress(Box::new(NoopEgress {
            id: ExitId("noop".into()),
            caps: Capabilities {
                protocol: "test".into(),
                supports_stream: true,
                supports_datagram: true,
                max_payload_bytes: Some(65_507),
                groups: vec![],
            },
        }))
        .add_observer(observer)
}

#[tokio::test]
async fn bus_port_publishes_obs_events_to_subscribed_observer() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let bus = builder_with(Box::new(ObsRecorder {
        events: events.clone(),
    }))
    .build()
    .await;
    let port = bus.port();

    port.publish_observation(
        OBS_MESHSEC_DROP,
        EventPayload(Arc::new(EventPayloadInner {
            reason: Some("auth".into()),
            source_addr: Some("127.0.0.1:10000".into()),
            secure: Some(true),
            ..EventPayloadInner::default()
        })),
    );

    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let got = events.lock().expect("events");
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].type_id, OBS_MESHSEC_DROP);
    assert_eq!(got[0].payload.0.reason.as_deref(), Some("auth"));
}

#[tokio::test]
async fn build_rejects_undeclared_obs_subscription() {
    let err = match builder_with(Box::new(UnknownObs)).try_build().await {
        Ok(_) => panic!("undeclared obs subscription must fail"),
        Err(err) => err,
    };
    assert!(matches!(err, BusError::InvalidObservationRegistry(_)));
}

#[tokio::test]
async fn build_rejects_core_event_writes() {
    let err = match builder_with(Box::new(CoreWriter)).try_build().await {
        Ok(_) => panic!("core event write declaration must fail"),
        Err(err) => err,
    };
    assert!(matches!(err, BusError::InvalidObservationRegistry(_)));
}
