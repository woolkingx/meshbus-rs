use mesh_bus_core::kernel::observation::*;

fn dummy_event(id: EventTypeId) -> EventTypeSpec {
    EventTypeSpec {
        id,
        schema_hash: 0,
        multi_writer: false,
        delivery: DeliveryPolicy::Lossy,
    }
}

fn obs(reads: Vec<EventTypeId>, writes: Vec<EventTypeId>, scope: ScopeId) -> ObserverSpec {
    ObserverSpec {
        id: ObserverId(1),
        owner: PluginId(1),
        scope,
        reads,
        writes,
        pulls: vec![],
    }
}

#[test]
fn v01_unknown_event_type_in_reads() {
    let mut reg = ObservationRegistry::new();
    let spec = obs(vec![EventTypeId::Obs(ObsEventId(99))], vec![], ScopeId(1));
    reg.register_observer(spec).unwrap();
    let err = reg.verify().unwrap_err();
    assert!(matches!(
        err.first().unwrap(),
        RegError::UnknownEventType(_, _)
    ));
}

#[test]
fn v02_core_write_violation() {
    let mut reg = ObservationRegistry::new();
    reg.register_event_type(dummy_event(EventTypeId::Core(CoreEventId::FlowOpened)))
        .unwrap();
    let spec = obs(
        vec![],
        vec![EventTypeId::Core(CoreEventId::FlowOpened)],
        ScopeId(1),
    );
    reg.register_observer(spec).unwrap();
    let err = reg.verify().unwrap_err();
    assert!(
        err.iter()
            .any(|e| matches!(e, RegError::CoreWriteViolation(_, _)))
    );
}

#[test]
fn v07_scope_missing() {
    let mut reg = ObservationRegistry::new();
    let spec = obs(vec![], vec![], ScopeId(0));
    let err = reg.register_observer(spec).unwrap_err();
    assert!(matches!(err, RegError::ScopeMissing(_)));
}

#[test]
fn v03_duplicate_exclusive_writer() {
    let mut reg = ObservationRegistry::new();
    let t = EventTypeId::Obs(ObsEventId(1));
    reg.register_event_type(EventTypeSpec {
        id: t,
        schema_hash: 0,
        multi_writer: false,
        delivery: DeliveryPolicy::Lossy,
    })
    .unwrap();
    reg.register_observer(ObserverSpec {
        id: ObserverId(1),
        owner: PluginId(1),
        scope: ScopeId(1),
        reads: vec![],
        writes: vec![t],
        pulls: vec![],
    })
    .unwrap();
    reg.register_observer(ObserverSpec {
        id: ObserverId(2),
        owner: PluginId(1),
        scope: ScopeId(1),
        reads: vec![],
        writes: vec![t],
        pulls: vec![],
    })
    .unwrap();
    let err = reg.verify().unwrap_err();
    assert!(
        err.iter()
            .any(|e| matches!(e, RegError::DuplicateExclusiveWriter(_)))
    );
}

#[test]
fn v04_cycle_in_observation_graph() {
    let mut reg = ObservationRegistry::new();
    let a = EventTypeId::Obs(ObsEventId(1));
    let b = EventTypeId::Obs(ObsEventId(2));
    for t in [a, b] {
        reg.register_event_type(EventTypeSpec {
            id: t,
            schema_hash: 0,
            multi_writer: false,
            delivery: DeliveryPolicy::Lossy,
        })
        .unwrap();
    }
    reg.register_observer(ObserverSpec {
        id: ObserverId(1),
        owner: PluginId(1),
        scope: ScopeId(1),
        reads: vec![a],
        writes: vec![b],
        pulls: vec![],
    })
    .unwrap();
    reg.register_observer(ObserverSpec {
        id: ObserverId(2),
        owner: PluginId(1),
        scope: ScopeId(1),
        reads: vec![b],
        writes: vec![a],
        pulls: vec![],
    })
    .unwrap();
    let err = reg.verify().unwrap_err();
    assert!(
        err.iter()
            .any(|e| matches!(e, RegError::CycleInObservationGraph(_)))
    );
}

#[test]
fn v08_unknown_pull_source() {
    let mut reg = ObservationRegistry::new();
    reg.register_observer(ObserverSpec {
        id: ObserverId(1),
        owner: PluginId(1),
        scope: ScopeId(1),
        reads: vec![],
        writes: vec![],
        pulls: vec![PullSourceId(99)],
    })
    .unwrap();
    let err = reg.verify().unwrap_err();
    assert!(
        err.iter()
            .any(|e| matches!(e, RegError::UnknownPullSource(_)))
    );
}

#[test]
fn declared_obs_event_types_are_accepted() {
    let mut reg = ObservationRegistry::new();
    for spec in default_event_type_specs() {
        reg.register_event_type(spec).unwrap();
    }
    reg.register_observer(obs(vec![OBS_MESHSEC_DROP], vec![], ScopeId(1)))
        .unwrap();
    reg.register_observer(ObserverSpec {
        id: ObserverId(2),
        owner: PluginId(1),
        scope: ScopeId(1),
        reads: vec![OBS_NATIVE_DROP],
        writes: vec![OBS_MESHSEC_DROP],
        pulls: vec![],
    })
    .unwrap();
    reg.verify().unwrap();
}

#[test]
fn undeclared_obs_event_types_are_rejected() {
    let mut reg = ObservationRegistry::new();
    for spec in default_event_type_specs() {
        reg.register_event_type(spec).unwrap();
    }
    reg.register_observer(obs(
        vec![EventTypeId::Obs(ObsEventId(77))],
        vec![],
        ScopeId(1),
    ))
    .unwrap();
    let err = reg.verify().unwrap_err();
    assert!(err.iter().any(|e| matches!(
        e,
        RegError::UnknownEventType(EventTypeId::Obs(ObsEventId(77)), _)
    )));
}
