mod builder;
pub(crate) mod compiled;
pub mod data_handle;
mod dispatch;
mod dispatch_forwarder;
mod dispatch_observation;
mod dispatch_return;
pub(crate) mod event;
pub mod forwarder;
pub(crate) mod health_observer;
pub(crate) mod health_snapshot;
#[path = "registry/mod.rs"]
pub(crate) mod kernel_registry;
pub(crate) mod metadata;
pub(crate) mod metrics_observer;
pub mod observation;
pub(crate) mod observation_wiring;
pub(crate) mod pipeline;
pub mod port;
#[path = "registry.rs"]
mod registry;
mod runtime;
pub mod session_handle;
pub mod types;
pub(crate) mod verdict;

#[cfg(test)]
mod tests;

pub use data_handle::{
    AuthMeta, Bus, BusBuilder, BusHandle, BusPort, BusSnapshotClient, CompiledPipelineSet, Event,
    HookFn, HookId, HookKind, HookSpec, HookTrace, KernelCtx, KernelRegistry, MAX_JUMP_DEPTH,
    MetaValue, NetMeta, Pipeline, PipelineId, PipelineRunError, PolicyMeta, Reason, Registry,
    ScheduleHintLabel, SinkId, SinkSpec, SmallMap, SourceId, SourceSpec, TraceMeta, TransportMeta,
    TypedMap, Verdict, VerifyError, Wiring, is_valid_ext_key_tail, kernel_registry_verify,
    run_pipeline, run_pipeline_with_registry,
};
pub use health_snapshot::{HealthPublisher, HealthSnapshot};
pub use types::*;
