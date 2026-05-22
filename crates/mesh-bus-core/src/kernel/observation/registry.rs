use std::collections::{BTreeMap, BTreeSet};

use super::{
    event_type::{CoreEventId, EventTypeId, EventTypeSpec},
    ids::{ObserverId, PluginId, PullSourceId, ScopeId},
};

#[derive(Clone, Debug)]
pub struct ObserverSpec {
    pub id: ObserverId,
    pub owner: PluginId,
    pub scope: ScopeId,
    pub reads: Vec<EventTypeId>,
    pub writes: Vec<EventTypeId>,
    pub pulls: Vec<PullSourceId>,
}

#[derive(Debug, thiserror::Error)]
pub enum RegError {
    #[error("V01 unknown event type {0:?} referenced by observer {1:?}")]
    UnknownEventType(EventTypeId, ObserverId),
    #[error("V02 observer {0:?} declares writes to core event {1:?}")]
    CoreWriteViolation(ObserverId, EventTypeId),
    #[error("V03 duplicate exclusive writer for {0:?}")]
    DuplicateExclusiveWriter(EventTypeId),
    #[error("V04 cycle in observation graph at {0:?}")]
    CycleInObservationGraph(ObserverId),
    #[error("V05 undeclared publish to {0:?} from observer {1:?}")]
    UndeclaredPublish(EventTypeId, ObserverId),
    #[error("V06 undeclared subscribe to {0:?} from observer {1:?}")]
    UndeclaredSubscribe(EventTypeId, ObserverId),
    #[error("V07 observer {0:?} missing scope")]
    ScopeMissing(ObserverId),
    #[error("V08 unknown pull source {0:?}")]
    UnknownPullSource(PullSourceId),
    #[error("V09 schema_hash mismatch for {0:?}")]
    SchemaHashMismatch(EventTypeId),
}

#[derive(Default)]
pub struct ObservationRegistry {
    event_types: BTreeMap<u32, EventTypeSpec>,
    observers: BTreeMap<u32, ObserverSpec>,
    pull_sources: BTreeSet<u32>,
}

impl ObservationRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_event_type(&mut self, spec: EventTypeSpec) -> Result<(), RegError> {
        self.event_types.insert(spec.id.as_u32(), spec);
        Ok(())
    }

    pub fn register_observer(&mut self, spec: ObserverSpec) -> Result<(), RegError> {
        if spec.scope.0 == 0 {
            return Err(RegError::ScopeMissing(spec.id));
        }
        self.observers.insert(spec.id.0, spec);
        Ok(())
    }

    pub fn register_pull_source(&mut self, id: PullSourceId) {
        self.pull_sources.insert(id.0);
    }

    pub fn observers_in_scope(&self, scope: ScopeId) -> Vec<ObserverId> {
        self.observers
            .values()
            .filter(|s| s.scope == scope)
            .map(|s| s.id)
            .collect()
    }

    pub fn unwire_scope(&mut self, scope: ScopeId) {
        let to_drop: Vec<u32> = self
            .observers
            .iter()
            .filter(|(_, s)| s.scope == scope)
            .map(|(k, _)| *k)
            .collect();
        for k in to_drop {
            self.observers.remove(&k);
        }
    }

    pub fn event_type(&self, id: EventTypeId) -> Option<&EventTypeSpec> {
        self.event_types.get(&id.as_u32())
    }

    pub fn verify(&self) -> Result<(), Vec<RegError>> {
        let mut errs = Vec::new();

        for spec in self.observers.values() {
            for r in &spec.reads {
                if !self.event_types.contains_key(&r.as_u32()) {
                    errs.push(RegError::UnknownEventType(*r, spec.id));
                }
            }
            for w in &spec.writes {
                if matches!(w, EventTypeId::Core(_)) {
                    errs.push(RegError::CoreWriteViolation(spec.id, *w));
                }
                if !self.event_types.contains_key(&w.as_u32()) {
                    errs.push(RegError::UnknownEventType(*w, spec.id));
                }
            }
        }

        // V03: duplicate exclusive writers
        let mut writer_count: BTreeMap<u32, usize> = BTreeMap::new();
        for spec in self.observers.values() {
            for w in &spec.writes {
                if !matches!(w, EventTypeId::Core(_)) {
                    *writer_count.entry(w.as_u32()).or_default() += 1;
                }
            }
        }
        for (k, n) in &writer_count {
            if *n > 1 {
                if let Some(t) = self.event_types.get(k) {
                    if !t.multi_writer {
                        errs.push(RegError::DuplicateExclusiveWriter(t.id));
                    }
                }
            }
        }

        // V08: pull sources must be registered
        for spec in self.observers.values() {
            for p in &spec.pulls {
                if !self.pull_sources.contains(&p.0) {
                    errs.push(RegError::UnknownPullSource(*p));
                }
            }
        }

        // V04: cycle detection on observer -> observer edges through writes/reads
        let mut by_read: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
        for spec in self.observers.values() {
            for r in &spec.reads {
                by_read.entry(r.as_u32()).or_default().push(spec.id.0);
            }
        }
        let mut edges: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
        for spec in self.observers.values() {
            for w in &spec.writes {
                if let Some(consumers) = by_read.get(&w.as_u32()) {
                    edges
                        .entry(spec.id.0)
                        .or_default()
                        .extend(consumers.iter().copied());
                }
            }
        }
        let mut color: BTreeMap<u32, u8> = BTreeMap::new();
        for id in self.observers.keys().copied().collect::<Vec<_>>() {
            if color.get(&id).copied().unwrap_or(0) == 0 {
                if let Some(c) = dfs_cycle(id, &edges, &mut color) {
                    errs.push(RegError::CycleInObservationGraph(ObserverId(c)));
                    break;
                }
            }
        }

        if errs.is_empty() { Ok(()) } else { Err(errs) }
    }
}

fn dfs_cycle(
    node: u32,
    edges: &BTreeMap<u32, Vec<u32>>,
    color: &mut BTreeMap<u32, u8>,
) -> Option<u32> {
    color.insert(node, 1);
    if let Some(next) = edges.get(&node) {
        for n in next {
            match color.get(n).copied().unwrap_or(0) {
                0 => {
                    if let Some(c) = dfs_cycle(*n, edges, color) {
                        return Some(c);
                    }
                }
                1 => return Some(*n),
                _ => {}
            }
        }
    }
    color.insert(node, 2);
    None
}

// silence unused-variant warnings on RegError variants reserved for later wiring
const _: fn() = || {
    let _ = RegError::UndeclaredPublish(EventTypeId::Core(CoreEventId::FlowOpened), ObserverId(0));
    let _ =
        RegError::UndeclaredSubscribe(EventTypeId::Core(CoreEventId::FlowOpened), ObserverId(0));
    let _ = RegError::SchemaHashMismatch(EventTypeId::Core(CoreEventId::FlowOpened));
};
