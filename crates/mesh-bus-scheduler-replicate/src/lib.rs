//! Replicate scheduler plugin.

use mesh_bus_core::{ExitId, ExitResult, RankContext, ScheduleDecision, SchedulerPlugin};

pub struct ReplicateScheduler;

impl ReplicateScheduler {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ReplicateScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl SchedulerPlugin for ReplicateScheduler {
    fn schedule(&self, candidates: &[ExitId], _ctx: &RankContext) -> ScheduleDecision {
        ScheduleDecision::replicate((0..candidates.len()).collect())
    }

    fn feedback(&self, _result: &ExitResult, _payload_bytes: u64, _at_ms: u64) {}
}
