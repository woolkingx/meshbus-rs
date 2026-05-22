//! Flow counter observer. Counts closed core-flow observations per exit ID.

use mesh_bus_core::kernel::observation::{
    CoreEventId, EventTypeId, OBS_MESHSEC_DROP, OBS_NATIVE_DROP,
};
use mesh_bus_core::{BusEvent, ObserverPlugin};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub struct CounterObserver {
    inner: Arc<Mutex<HashMap<String, u64>>>,
    drops: Arc<Mutex<DropCounterSnapshot>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DropCounterSnapshot {
    pub meshsec_drop_total: u64,
    pub meshsec_auth_drop_total: u64,
    pub meshsec_replay_drop_total: u64,
    pub native_drop_total: u64,
    pub native_queue_overflow_drop_total: u64,
}

impl CounterObserver {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            drops: Arc::new(Mutex::new(DropCounterSnapshot::default())),
        }
    }

    pub fn snapshot(&self) -> HashMap<String, u64> {
        self.inner.lock().expect("counter mutex").clone()
    }

    pub fn drop_snapshot(&self) -> DropCounterSnapshot {
        self.drops.lock().expect("drop counter mutex").clone()
    }
}

impl Default for CounterObserver {
    fn default() -> Self {
        Self::new()
    }
}

impl ObserverPlugin for CounterObserver {
    fn on_event(&self, event: &BusEvent) {
        match event {
            BusEvent::Core(env) => {
                if env.type_id != EventTypeId::Core(CoreEventId::FlowOpened) {
                    return;
                }
                let Some(exit_id) = env.payload.0.selected_exit.as_ref().or(env
                    .payload
                    .0
                    .exit_id
                    .as_ref())
                else {
                    return;
                };
                let mut map = self.inner.lock().expect("counter mutex");
                *map.entry(exit_id.clone()).or_insert(0) += 1;
            }
            BusEvent::Observation(env) => {
                let mut drops = self.drops.lock().expect("drop counter mutex");
                match env.type_id {
                    OBS_MESHSEC_DROP => {
                        drops.meshsec_drop_total += 1;
                        match env.payload.0.reason.as_deref() {
                            Some("auth") => drops.meshsec_auth_drop_total += 1,
                            Some("replay") | Some("replay_too_old") => {
                                drops.meshsec_replay_drop_total += 1;
                            }
                            _ => {}
                        }
                    }
                    OBS_NATIVE_DROP => {
                        drops.native_drop_total += 1;
                        if env.payload.0.reason.as_deref() == Some("queue_overflow") {
                            drops.native_queue_overflow_drop_total += 1;
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    fn subscribed_events(&self) -> &'static [EventTypeId] {
        &[OBS_MESHSEC_DROP, OBS_NATIVE_DROP]
    }
}
