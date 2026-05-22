use super::types::BusError;
use crate::kernel::observation::{
    CoreEventId, EventTypeId, ObservationBus, ObservationRegistry, ObserverId, ObserverSpec,
    PluginId, ScopeId, default_event_type_specs,
};
use crate::{BusEvent, ObserverPlugin, SchedulerPlugin};
use std::sync::Arc;
use tokio::sync::mpsc;

pub(crate) fn wire_core_observers(
    observation_bus: &Arc<ObservationBus>,
    metrics: Arc<crate::kernel::metrics_observer::MetricsObserver>,
    health: Arc<crate::kernel::health_observer::ExitHealthObserver>,
) {
    let (metrics_tx, mut metrics_rx) = mpsc::channel(1024);
    for type_id in [
        EventTypeId::Core(CoreEventId::FlowOpened),
        EventTypeId::Core(CoreEventId::FlowClosed),
        EventTypeId::Core(CoreEventId::PathIoError),
        crate::kernel::observation::OBS_MESHSEC_DROP,
        crate::kernel::observation::OBS_NATIVE_DROP,
    ] {
        observation_bus.wire_subscriber(type_id, metrics_tx.clone());
    }
    tokio::spawn(async move {
        while let Some(env) = metrics_rx.recv().await {
            match env.type_id {
                EventTypeId::Core(_) => metrics.on_core_event(&env),
                EventTypeId::Obs(_) => metrics.on_observation_event(&env),
            }
        }
    });

    let (health_tx, mut health_rx) = mpsc::channel(1024);
    for type_id in [
        EventTypeId::Core(CoreEventId::FlowOpened),
        EventTypeId::Core(CoreEventId::FlowClosed),
        EventTypeId::Core(CoreEventId::PathIoError),
    ] {
        observation_bus.wire_subscriber(type_id, health_tx.clone());
    }
    tokio::spawn(async move {
        while let Some(env) = health_rx.recv().await {
            health.on_core_event(&env);
        }
    });
}

pub(crate) fn wire_user_observers(
    observation_bus: &Arc<ObservationBus>,
    observers: Vec<Box<dyn ObserverPlugin>>,
) {
    for boxed in observers {
        let observer: Arc<dyn ObserverPlugin> = Arc::from(boxed);
        let (tx, mut rx) = mpsc::channel(1024);
        for core_id in observer.subscribed_core_events() {
            observation_bus.wire_subscriber(EventTypeId::Core(*core_id), tx.clone());
        }
        for type_id in observer.subscribed_events() {
            observation_bus.wire_subscriber(*type_id, tx.clone());
        }
        tokio::spawn(async move {
            while let Some(env) = rx.recv().await {
                match env.type_id {
                    EventTypeId::Core(_) => observer.on_event(&BusEvent::Core(env)),
                    EventTypeId::Obs(_) => observer.on_event(&BusEvent::Observation(env)),
                }
            }
        });
    }
}

pub(crate) fn verify_observer_declarations(
    observers: &[Box<dyn ObserverPlugin>],
) -> Result<(), BusError> {
    let mut registry = ObservationRegistry::new();
    for spec in default_event_type_specs() {
        registry.register_event_type(spec).map_err(registry_error)?;
    }
    for (idx, observer) in observers.iter().enumerate() {
        let reads = observer
            .subscribed_core_events()
            .iter()
            .copied()
            .map(EventTypeId::Core)
            .chain(observer.subscribed_events().iter().copied())
            .collect();
        let spec = ObserverSpec {
            id: ObserverId((idx + 1) as u32),
            owner: PluginId(1),
            scope: ScopeId((idx + 1) as u32),
            reads,
            writes: observer.observation_writes().to_vec(),
            pulls: observer.observation_pulls().to_vec(),
        };
        registry.register_observer(spec).map_err(registry_error)?;
    }
    registry.verify().map_err(|errs| {
        BusError::InvalidObservationRegistry(errs.into_iter().map(|e| e.to_string()).collect())
    })
}

pub(crate) fn wire_scheduler_observer(
    observation_bus: &Arc<ObservationBus>,
    scheduler: Arc<dyn SchedulerPlugin>,
) {
    let (tx, mut rx) = mpsc::channel(1024);
    for type_id in [
        EventTypeId::Core(CoreEventId::FlowOpened),
        EventTypeId::Core(CoreEventId::FlowClosed),
        EventTypeId::Core(CoreEventId::PathIoError),
    ] {
        observation_bus.wire_subscriber(type_id, tx.clone());
    }
    tokio::spawn(async move {
        while let Some(env) = rx.recv().await {
            scheduler.on_observation(&env);
        }
    });
}

fn registry_error(err: crate::kernel::observation::RegError) -> BusError {
    BusError::InvalidObservationRegistry(vec![err.to_string()])
}
