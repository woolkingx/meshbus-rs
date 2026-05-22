//! Generic event-pipeline runtime bundle.
//!
//! Application source adapters own protocol parsing, but the pipeline execution
//! bundle is protocol-neutral: shared hook context + verified kernel registry +
//! source id resolved through KernelRegistry wiring.

use crate::context::{SharedHookCtx, install_scoped};
use mesh_bus_core::kernel::{
    CompiledPipelineSet, Event, HookTrace, KernelCtx, KernelRegistry, PipelineRunError, SourceId,
    Verdict, VerifyError,
};
use std::sync::Arc;
use thiserror::Error;

/// Verified pipeline runtime shared by application source adapters.
#[derive(Clone)]
pub struct PipelineRuntime {
    shared_ctx: SharedHookCtx,
    registry: Arc<KernelRegistry>,
    compiled: Arc<CompiledPipelineSet>,
    source_id: SourceId,
}

#[derive(Debug, Error)]
pub enum PipelineRuntimeError {
    #[error("kernel registry verify: {0:?}")]
    KernelRegistryVerify(VerifyError),
    #[error("source `{source_id}` has no runtime wiring")]
    MissingSourceWiring { source_id: String },
    #[error("pipeline run: {0}")]
    PipelineRun(PipelineRunError),
    #[error("pipeline worker join: {0}")]
    Join(#[from] tokio::task::JoinError),
}

impl PipelineRuntime {
    pub fn new(
        shared_ctx: SharedHookCtx,
        registry: Arc<KernelRegistry>,
        source_id: SourceId,
    ) -> Result<Self, PipelineRuntimeError> {
        let compiled = CompiledPipelineSet::compile(&registry)
            .map_err(PipelineRuntimeError::KernelRegistryVerify)?;
        if !registry
            .wirings
            .iter()
            .any(|wiring| wiring.source == source_id)
        {
            return Err(PipelineRuntimeError::MissingSourceWiring {
                source_id: source_id.as_str().into(),
            });
        }
        Ok(Self {
            shared_ctx,
            registry,
            compiled: Arc::new(compiled),
            source_id,
        })
    }

    pub fn shared_ctx(&self) -> &SharedHookCtx {
        &self.shared_ctx
    }

    pub fn registry(&self) -> &KernelRegistry {
        &self.registry
    }

    pub fn source_id(&self) -> &SourceId {
        &self.source_id
    }
}

/// Result of running one Event through the generic pipeline executor.
pub struct PipelineRun {
    pub verdict: Verdict,
    pub event: Event,
    pub hook_trace: Vec<HookTrace>,
}

pub async fn run_pipeline_event(
    runtime: Arc<PipelineRuntime>,
    event: Event,
) -> Result<PipelineRun, PipelineRuntimeError> {
    tokio::task::spawn_blocking(move || {
        let _ctx_guard = install_scoped(runtime.shared_ctx.clone());
        let mut ev = event;
        let mut kctx = KernelCtx::default();
        let pipeline_id = runtime
            .registry
            .wirings
            .iter()
            .find(|wiring| wiring.source == runtime.source_id)
            .map(|wiring| &wiring.pipeline)
            .ok_or_else(|| PipelineRuntimeError::MissingSourceWiring {
                source_id: runtime.source_id.as_str().into(),
            })?;
        let result = runtime
            .compiled
            .run_pipeline(pipeline_id, &mut ev, &mut kctx);
        result
            .map_err(PipelineRuntimeError::PipelineRun)
            .map(|verdict| PipelineRun {
                verdict,
                event: ev,
                hook_trace: kctx.hook_trace,
            })
    })
    .await?
}
