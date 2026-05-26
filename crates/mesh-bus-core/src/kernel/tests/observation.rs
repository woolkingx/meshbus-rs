use super::helpers::{
    DevNullEgress, FlappingEgress, NarrowObserver, NoopScheduler, RecordingObserver,
    RecordingScheduler,
};
use crate::{BusBuilder, BusEvent, Capabilities, ExitId, Frame, RankContext};
use bytes::Bytes;
use mb_endpoint::Endpoint;
use std::sync::{Arc, Mutex};

#[tokio::test]
async fn shutdown_with_timeout_clean_drain_returns_ok() {
    let bus = BusBuilder::new()
        .scheduler(Box::new(NoopScheduler))
        .add_egress(Box::new(DevNullEgress {
            id: ExitId("dev-null".into()),
            caps: Capabilities {
                protocol: "tcp".into(),
                supports_stream: true,
                supports_datagram: false,
                max_payload_bytes: None,
                groups: vec![],
            },
        }))
        .build()
        .await;
    let handle = bus.spawn();
    // No frames in flight — drain should complete immediately within the timeout.
    let result = handle
        .shutdown_with_timeout(std::time::Duration::from_secs(2))
        .await;
    assert!(result.is_ok(), "clean drain must return Ok; got {result:?}");
}

// ── observer routed fan-out: core events emitted ───────────────────────────────

#[tokio::test]
async fn dispatch_emits_core_events_via_observation_bus() {
    let events = Arc::new(std::sync::Mutex::new(Vec::<BusEvent>::new()));
    let spy = RecordingObserver {
        events: events.clone(),
    };

    let bus = BusBuilder::new()
        .scheduler(Box::new(NoopScheduler))
        .add_egress(Box::new(FlappingEgress {
            id: ExitId("flap".into()),
            caps: Capabilities {
                protocol: "test".into(),
                supports_stream: true,
                supports_datagram: false,
                max_payload_bytes: None,
                groups: vec![],
            },
            fail_first: std::sync::atomic::AtomicBool::new(true),
        }))
        .add_observer(Box::new(spy))
        .build()
        .await;

    let port = bus.port();
    let handle = bus.spawn();
    let target = Endpoint::new("x", 1).expect("valid endpoint");

    // Frame 1: fail_first=true -> send fails -> core.path.io_error emitted.
    // dispatch_ordered sends ReturnEvent::Closed back.
    let mut s1 = port.open_session(target.clone()).await;
    s1.submit
        .send(Frame::data(
            s1.id.clone(),
            0,
            target.clone(),
            Bytes::from_static(b"fail"),
        ))
        .await
        .expect("send frame 1");
    let _ = s1.returns.recv().await; // Closed(Other("upstream"))

    // Frame 2: fail_first now false -> open succeeds -> core.flow.opened emitted.
    let mut s2 = port.open_session(target.clone()).await;
    s2.submit
        .send(Frame::open(s2.id.clone(), target.clone()))
        .await
        .expect("send frame 2");
    let _ = s2.returns.recv().await; // Connected { .. }

    // Let observer drainers process.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    handle.shutdown().await;

    let evs = events.lock().expect("recorder mutex");
    assert!(
        evs.iter().any(|e| matches!(
            e,
            BusEvent::Core(env)
                if env.type_id
                    == crate::kernel::observation::EventTypeId::Core(
                        crate::kernel::observation::CoreEventId::PathIoError
                    )
        )),
        "expected at least one core.path.io_error, got: {evs:?}"
    );
    assert!(
        evs.iter().any(|e| matches!(
            e,
            BusEvent::Core(env)
                if env.type_id
                    == crate::kernel::observation::EventTypeId::Core(
                        crate::kernel::observation::CoreEventId::FlowOpened
                    )
        )),
        "expected at least one core.flow.opened, got: {evs:?}"
    );
}

#[tokio::test]
async fn path_io_error_increments_metrics_failure_snapshot() {
    // A failing first send emits ONLY core.path.io_error: the flow never opens,
    // so close_flow_if_open is a no-op and no FlowClosed is published. The runtime
    // MetricsObserver must be wired to PathIoError, otherwise dispatch_failure
    // stays 0 even though a dispatch attempt failed.
    let bus = BusBuilder::new()
        .scheduler(Box::new(NoopScheduler))
        .add_egress(Box::new(FlappingEgress {
            id: ExitId("flap".into()),
            caps: Capabilities {
                protocol: "test".into(),
                supports_stream: true,
                supports_datagram: false,
                max_payload_bytes: None,
                groups: vec![],
            },
            fail_first: std::sync::atomic::AtomicBool::new(true),
        }))
        .build()
        .await;

    let port = bus.port();
    let handle = bus.spawn();
    let target = Endpoint::new("x", 1).expect("valid endpoint");

    let mut s1 = port.open_session(target.clone()).await;
    s1.submit
        .send(Frame::data(
            s1.id.clone(),
            0,
            target.clone(),
            Bytes::from_static(b"fail"),
        ))
        .await
        .expect("send failing frame");
    let _ = s1.returns.recv().await; // Closed(Other("upstream"))

    // Let the core observer drainer process the PathIoError envelope.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let snap = handle.snapshot().await;
    handle.shutdown().await;

    assert!(
        snap.dispatch_failure >= 1,
        "PathIoError must increment dispatch_failure via runtime wiring, got {snap:?}"
    );
}

#[tokio::test]
async fn scheduler_rank_context_includes_source_activity_projection() {
    let contexts = Arc::new(Mutex::new(Vec::<RankContext>::new()));
    let scheduler = RecordingScheduler {
        contexts: contexts.clone(),
    };
    let bus = BusBuilder::new()
        .scheduler(Box::new(scheduler))
        .add_egress(Box::new(FlappingEgress {
            id: ExitId("ok".into()),
            caps: Capabilities {
                protocol: "test".into(),
                supports_stream: true,
                supports_datagram: false,
                max_payload_bytes: None,
                groups: vec![],
            },
            fail_first: std::sync::atomic::AtomicBool::new(false),
        }))
        .build()
        .await;
    let port = bus.port();
    let handle = bus.spawn();
    let source = Some("203.0.113.7".to_string());

    let first_target = Endpoint::new("first.example", 443).expect("valid endpoint");
    let mut s1 = port.open_session(first_target.clone()).await;
    let mut first = Frame::open(s1.id.clone(), first_target);
    first.source_key.clone_from(&source);
    s1.submit.send(first).await.expect("send first open");
    let _ = s1.returns.recv().await;

    let second_target = Endpoint::new("second.example", 443).expect("valid endpoint");
    let mut s2 = port.open_session(second_target.clone()).await;
    let mut second = Frame::open(s2.id.clone(), second_target);
    second.source_key.clone_from(&source);
    s2.submit.send(second).await.expect("send second open");
    let _ = s2.returns.recv().await;

    handle.shutdown().await;

    let recorded = contexts.lock().expect("recorded contexts");
    assert_eq!(recorded.len(), 2, "expected two scheduler contexts");
    assert_eq!(
        recorded[0].source_activity, None,
        "first open has no prior core lifecycle evidence for the source"
    );
    assert_eq!(
        recorded[1].source_activity.as_ref().map(|a| a.active_flows),
        Some(1),
        "second open from same source must see the first active flow"
    );
    assert_eq!(
        recorded[1].source_activity.as_ref().unwrap().idle_since_ms,
        None
    );
}

#[tokio::test]
async fn user_observer_receives_only_declared_core_event_types() {
    use crate::kernel::observation::{CoreEventId, EventTypeId};
    let events = Arc::new(std::sync::Mutex::new(Vec::<BusEvent>::new()));
    let spy = RecordingObserver {
        events: events.clone(),
    };

    let bus = BusBuilder::new()
        .scheduler(Box::new(NoopScheduler))
        .add_egress(Box::new(FlappingEgress {
            id: ExitId("flap".into()),
            caps: Capabilities {
                protocol: "test".into(),
                supports_stream: true,
                supports_datagram: false,
                max_payload_bytes: None,
                groups: vec![],
            },
            fail_first: std::sync::atomic::AtomicBool::new(true),
        }))
        .add_observer(Box::new(spy))
        .build()
        .await;

    let port = bus.port();
    let handle = bus.spawn();
    let target = Endpoint::new("x", 1).expect("valid endpoint");

    let mut s1 = port.open_session(target.clone()).await;
    s1.submit
        .send(Frame::data(
            s1.id.clone(),
            0,
            target.clone(),
            Bytes::from_static(b"fail"),
        ))
        .await
        .expect("send failing frame");
    let _ = s1.returns.recv().await;

    let mut s2 = port.open_session(target.clone()).await;
    s2.submit
        .send(Frame::open(s2.id.clone(), target.clone()))
        .await
        .expect("send open frame");
    let _ = s2.returns.recv().await;

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    handle.shutdown().await;

    let evs = events.lock().expect("recorder mutex");
    assert!(!evs.is_empty(), "expected at least one routed core event");
    for e in evs.iter() {
        let BusEvent::Core(env) = e else {
            panic!("user observer received a non-core event: {e:?}");
        };
        assert!(
            matches!(
                env.type_id,
                EventTypeId::Core(CoreEventId::FlowOpened)
                    | EventTypeId::Core(CoreEventId::FlowClosed)
                    | EventTypeId::Core(CoreEventId::PathIoError)
            ),
            "user observer received an undeclared event type: {:?}",
            env.type_id
        );
    }
}

#[tokio::test]
async fn observer_receives_only_declared_event_types() {
    use crate::kernel::observation::{CoreEventId, EventTypeId};
    let opened_evs = Arc::new(std::sync::Mutex::new(Vec::<BusEvent>::new()));
    let ioerr_evs = Arc::new(std::sync::Mutex::new(Vec::<BusEvent>::new()));

    let bus = BusBuilder::new()
        .scheduler(Box::new(NoopScheduler))
        .add_egress(Box::new(FlappingEgress {
            id: ExitId("flap".into()),
            caps: Capabilities {
                protocol: "test".into(),
                supports_stream: true,
                supports_datagram: false,
                max_payload_bytes: None,
                groups: vec![],
            },
            fail_first: std::sync::atomic::AtomicBool::new(true),
        }))
        .add_observer(Box::new(NarrowObserver {
            which: &[CoreEventId::FlowOpened],
            events: opened_evs.clone(),
        }))
        .add_observer(Box::new(NarrowObserver {
            which: &[CoreEventId::PathIoError],
            events: ioerr_evs.clone(),
        }))
        .build()
        .await;

    let port = bus.port();
    let handle = bus.spawn();
    let target = Endpoint::new("x", 1).expect("valid endpoint");

    // Frame 1: send fails -> core.path.io_error.
    let mut s1 = port.open_session(target.clone()).await;
    s1.submit
        .send(Frame::data(
            s1.id.clone(),
            0,
            target.clone(),
            Bytes::from_static(b"fail"),
        ))
        .await
        .expect("send failing frame");
    let _ = s1.returns.recv().await;

    // Frame 2: open succeeds -> core.flow.opened.
    let mut s2 = port.open_session(target.clone()).await;
    s2.submit
        .send(Frame::open(s2.id.clone(), target.clone()))
        .await
        .expect("send open frame");
    let _ = s2.returns.recv().await;

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    handle.shutdown().await;

    let opened = opened_evs.lock().expect("recorder mutex");
    assert!(
        !opened.is_empty(),
        "FlowOpened-only observer expected at least one event"
    );
    for e in opened.iter() {
        let BusEvent::Core(env) = e else {
            panic!("unexpected non-core event: {e:?}");
        };
        assert_eq!(
            env.type_id,
            EventTypeId::Core(CoreEventId::FlowOpened),
            "FlowOpened-only observer received undeclared type: {:?}",
            env.type_id
        );
    }

    let ioerr = ioerr_evs.lock().expect("recorder mutex");
    assert!(
        !ioerr.is_empty(),
        "PathIoError-only observer expected at least one event"
    );
    for e in ioerr.iter() {
        let BusEvent::Core(env) = e else {
            panic!("unexpected non-core event: {e:?}");
        };
        assert_eq!(
            env.type_id,
            EventTypeId::Core(CoreEventId::PathIoError),
            "PathIoError-only observer received undeclared type: {:?}",
            env.type_id
        );
    }
}

#[test]
fn observer_registry_rejects_undeclared_publish() {
    use crate::kernel::observation::{
        EventTypeId, ObsEventId, ObservationRegistry, ObserverId, ObserverSpec, PluginId, ScopeId,
    };
    let mut reg = ObservationRegistry::new();
    // Observer declares a write to an obs.* event type that was never
    // registered. verify() must fail closed before any runtime build.
    reg.register_observer(ObserverSpec {
        id: ObserverId(1),
        owner: PluginId(1),
        scope: ScopeId(1),
        reads: vec![],
        writes: vec![EventTypeId::Obs(ObsEventId(0))],
        pulls: vec![],
    })
    .expect("register observer");
    assert!(
        reg.verify().is_err(),
        "registry must reject an undeclared obs.* publish before runtime build"
    );
}

#[test]
fn bus_event_core_carries_typed_observation_envelope() {
    use crate::BusEvent;
    use crate::kernel::observation::{
        CoreEventId, EventEnvelope, EventPayload, EventPayloadInner, EventTypeId,
    };
    let ev = BusEvent::Core(EventEnvelope {
        type_id: EventTypeId::Core(CoreEventId::PathIoError),
        payload: EventPayload(Arc::new(EventPayloadInner {
            selected_exit: Some("e1".into()),
            close_reason: Some("upstream EOF".into()),
            payload_bytes: 1500,
            ..Default::default()
        })),
        at_ns: 1234,
    });
    match ev {
        BusEvent::Core(env) => {
            assert_eq!(env.type_id, EventTypeId::Core(CoreEventId::PathIoError));
            assert_eq!(env.payload.0.selected_exit.as_deref(), Some("e1"));
        }
        _ => panic!("variant mismatch"),
    }
}
