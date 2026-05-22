use crate::kernel::pipeline::types::{Pipeline, Wiring};
use crate::kernel::verdict::types::{HookId, PipelineId, SinkId, SourceId};
use std::collections::BTreeMap;

/// `HookFn` is a sync function pointer. The callable and its declarative
/// `HookSpec` are looked up separately via HookId. Async upstream is bridged
/// through `SharedHookCtx.tokio.block_on` per kernel spec §4.
pub type HookFn = fn(
    &mut crate::kernel::event::types::Event,
    &mut KernelCtx,
) -> crate::kernel::verdict::types::Verdict;

#[derive(Debug, Default)]
pub struct KernelCtx {
    pub hook_trace: Vec<crate::kernel::event::types::HookTrace>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookKind {
    Net,
    Transport,
    Policy,
    Auth,
    SideEffect,
}

/// Declarative specification for a hook — separate from the callable HookFn.
///
/// `allowed_namespaces` entries are glob patterns of the form `<head>.*` where
/// head is one of `net|transport|policy|auth|trace|ext`. A read/write key is
/// covered when some pattern's head matches the key's leading dotted segment.
///
/// `may_accept_to` lists every SinkId that `Verdict::Accept(...)` may name.
/// Empty is legal for hooks that may terminate only via Reject/Drop.
#[derive(Debug, Clone)]
pub struct HookSpec {
    pub id: HookId,
    pub kind: HookKind,
    pub allowed_namespaces: Vec<String>,
    pub reads: Vec<String>,
    pub writes: Vec<String>,
    pub may_terminate: bool,
    pub may_jump: bool,
    pub may_jump_to: Vec<PipelineId>,
    pub may_accept_to: Vec<SinkId>,
    pub side_effect_only: bool,
}

#[derive(Debug, Clone)]
pub struct SourceSpec {
    pub id: SourceId,
    pub kind: String,
    pub initial_writes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SinkSpec {
    pub id: SinkId,
    pub kind: String,
}

/// Unified registry.
/// Distinct from `kernel/registry.rs::Registry` (egress/scheduler/observer Frame runtime).
#[derive(Debug, Default)]
pub struct KernelRegistry {
    pub sources: BTreeMap<SourceId, SourceSpec>,
    pub sinks: BTreeMap<SinkId, SinkSpec>,
    pub hooks: BTreeMap<HookId, HookSpec>,
    pub pipelines: BTreeMap<PipelineId, Pipeline>,
    pub wirings: Vec<Wiring>,
    /// Callable table — parallel to `hooks`; populated by register_hook_fn.
    pub fns: BTreeMap<HookId, HookFn>,
}
