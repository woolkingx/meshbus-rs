use arc_swap::ArcSwap;
use std::collections::HashSet;
use std::sync::Arc;

#[derive(Debug, Default, Clone)]
pub struct HealthSnapshot {
    pub unhealthy: HashSet<String>,
}

#[derive(Debug, Default)]
pub struct HealthPublisher {
    current: ArcSwap<HealthSnapshot>,
}

impl HealthPublisher {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn load(&self) -> Arc<HealthSnapshot> {
        self.current.load_full()
    }
    pub fn publish(&self, snap: HealthSnapshot) {
        self.current.store(Arc::new(snap));
    }
}

#[cfg(test)]
#[path = "health_snapshot_tests.rs"]
mod health_snapshot_tests;
