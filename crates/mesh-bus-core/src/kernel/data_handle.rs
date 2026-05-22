pub use super::builder::BusBuilder;
pub use super::port::BusPort;
pub use super::registry::Registry;
pub use super::runtime::{Bus, BusHandle, BusSnapshotClient};

// event-pipeline-kernel primitives — public surface for external hook crates
// and application source adapters to register hooks against the kernel registry
// and drive `run_pipeline` directly.

pub use super::compiled::CompiledPipelineSet;
pub use super::event::types::{Event, HookTrace};
pub use super::kernel_registry::data_handle::verify as kernel_registry_verify;
pub use super::kernel_registry::types::{
    HookFn, HookKind, HookSpec, KernelCtx, KernelRegistry, SinkSpec, SourceSpec,
};
pub use super::kernel_registry::verify_error::VerifyError;
pub use super::metadata::data_handle::is_valid_ext_key_tail;
pub use super::metadata::types::{
    AuthMeta, MetaValue, NetMeta, PolicyMeta, ScheduleHintLabel, SmallMap, TraceMeta,
    TransportMeta, TypedMap,
};
pub use super::pipeline::data_handle::{
    MAX_JUMP_DEPTH, PipelineRunError, run_pipeline, run_pipeline_with_registry,
};
pub use super::pipeline::types::{Pipeline, Wiring};
pub use super::verdict::types::{HookId, PipelineId, Reason, SinkId, SourceId, Verdict};
