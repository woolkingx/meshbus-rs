use crate::kernel::verdict::types::{HookId, PipelineId, SourceId};

#[derive(Debug, Clone)]
pub struct Pipeline {
    pub id: PipelineId,
    pub hooks: Vec<HookId>,
}

#[derive(Debug, Clone)]
pub struct Wiring {
    pub source: SourceId,
    pub pipeline: PipelineId,
}
