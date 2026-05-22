//! Schema-compiled kernel slots, id interning, and the compiled pipeline graph.
//!
//! Crate-internal (plan drift D3): `CompiledKernel` and its slot newtypes are
//! not re-exported on the public surface, so public-surface acceptance #1 is
//! unaffected. `CompiledKernel::from_registry` runs the existing `verify()`
//! first, so every one of the 26 registry error classes still fails closed
//! before any interning happens.
//!
//! `CompiledKernel::run_pipeline` mirrors `run_pipeline_with_registry`
//! byte-for-byte (control flow, `MAX_JUMP_DEPTH`, terminal handling, HookTrace
//! ordering, and every `PipelineRunError` string) on the verified-registry
//! domain, but resolves hooks through pre-interned slots and pre-copied
//! `HookFn` pointers instead of per-hook `BTreeMap` look-ups.
//!
//! Plan drift D5: external `mesh-bus-pipeline-hooks::PipelineRuntime` must
//! build and run the compiled graph, so exactly one minimal opaque handle
//! `CompiledPipelineSet` is re-exported from `kernel`. It exposes no slot
//! newtypes or data-plane internals and changes no schema/config/rule
//! contract, so acceptance #1 and the public-surface guards still hold.

use std::collections::HashMap;

use crate::kernel::event::data_handle::hook_trace_record;
use crate::kernel::event::types::Event;
use crate::kernel::kernel_registry::data_handle::verify;
use crate::kernel::kernel_registry::types::{HookFn, KernelCtx, KernelRegistry};
use crate::kernel::kernel_registry::verify_error::VerifyError;
use crate::kernel::pipeline::data_handle::{MAX_JUMP_DEPTH, PipelineRunError};
use crate::kernel::verdict::types::{HookId, PipelineId, SinkId, SourceId, Verdict};
use crate::transport::forwarding::data_handle::capability_matches_flow;
use crate::transport::forwarding::types::FlowSemantics;
use crate::{EgressPlugin, ExitId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SourceSlot(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SinkSlot(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HookSlot(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PipelineSlot(pub u32);

/// Interns an ordered, deduplicated id sequence into dense slots.
///
/// `KernelRegistry` keys come from `BTreeMap`, so the input is already unique
/// and deterministically ordered; slot indices follow that order.
fn intern<T, S>(ids: impl Iterator<Item = T>, mk: impl Fn(u32) -> S) -> (HashMap<T, S>, Box<[T]>)
where
    T: Clone + Eq + std::hash::Hash,
    S: Copy,
{
    let ids: Vec<T> = ids.collect();
    let map = ids
        .iter()
        .cloned()
        .enumerate()
        .map(|(i, id)| (id, mk(i as u32)))
        .collect();
    (map, ids.into_boxed_slice())
}

/// One hook resolved to its `HookFn` pointer and pre-cloned declared targets.
///
/// Built once per `from_registry` after `verify()`, so `f`, `may_accept_to`,
/// and `may_jump_to` are guaranteed present by the registry contract.
#[derive(Debug)]
struct CompiledHook {
    id: HookId,
    f: HookFn,
    may_accept_to: Box<[SinkId]>,
    may_jump_to: Box<[PipelineId]>,
}

/// One pipeline resolved to dense hook slots in declaration order.
#[derive(Debug)]
struct CompiledPipeline {
    #[allow(dead_code)]
    id: PipelineId,
    hooks: Box<[HookSlot]>,
}

/// Schema-compiled view of a verified `KernelRegistry`.
///
/// Holds id->slot maps for build-time resolution, slot->id arrays for
/// snapshots and logs, and the compiled pipeline graph (hooks resolved to
/// `HookFn` pointers, pipelines resolved to hook slots). Construction is
/// fail-closed: it returns the same `VerifyError` the registry path produces.
#[derive(Debug)]
pub struct CompiledKernel {
    // M4/M5 capability/candidate/snapshot scaffolding (plan D6): read only by
    // the slot/id accessor block until those milestones wire them.
    #[allow(dead_code)]
    source_slots: HashMap<SourceId, SourceSlot>,
    #[allow(dead_code)]
    sink_slots: HashMap<SinkId, SinkSlot>,
    hook_slots: HashMap<HookId, HookSlot>,
    pipeline_slots: HashMap<PipelineId, PipelineSlot>,
    #[allow(dead_code)]
    source_ids: Box<[SourceId]>,
    #[allow(dead_code)]
    sink_ids: Box<[SinkId]>,
    hook_ids: Box<[HookId]>,
    pipeline_ids: Box<[PipelineId]>,
    compiled_hooks: Box<[CompiledHook]>,
    compiled_pipelines: Box<[CompiledPipeline]>,
}

impl CompiledKernel {
    pub fn from_registry(reg: &KernelRegistry) -> Result<Self, VerifyError> {
        verify(reg)?;
        let (source_slots, source_ids) = intern(reg.sources.keys().cloned(), SourceSlot);
        let (sink_slots, sink_ids) = intern(reg.sinks.keys().cloned(), SinkSlot);
        let (hook_slots, hook_ids) = intern(reg.hooks.keys().cloned(), HookSlot);
        let (pipeline_slots, pipeline_ids) = intern(reg.pipelines.keys().cloned(), PipelineSlot);

        // verify() proved every pipeline hook has a HookSpec + HookFn and every
        // pipeline hook id resolves to a registered hook, so these look-ups are
        // infallible on the verified-registry domain.
        let compiled_hooks: Box<[CompiledHook]> = hook_ids
            .iter()
            .map(|hid| {
                let spec = reg.hooks.get(hid).expect("verify() guarantees hook spec");
                let f = *reg.fns.get(hid).expect("verify() guarantees hook fn");
                CompiledHook {
                    id: hid.clone(),
                    f,
                    may_accept_to: spec.may_accept_to.clone().into_boxed_slice(),
                    may_jump_to: spec.may_jump_to.clone().into_boxed_slice(),
                }
            })
            .collect();

        let compiled_pipelines: Box<[CompiledPipeline]> = pipeline_ids
            .iter()
            .map(|pid| {
                let p = reg
                    .pipelines
                    .get(pid)
                    .expect("verify() guarantees pipeline");
                let hooks: Box<[HookSlot]> = p
                    .hooks
                    .iter()
                    .map(|hid| {
                        *hook_slots
                            .get(hid)
                            .expect("verify() guarantees pipeline hook registered")
                    })
                    .collect();
                CompiledPipeline {
                    id: pid.clone(),
                    hooks,
                }
            })
            .collect();

        Ok(Self {
            source_slots,
            sink_slots,
            hook_slots,
            pipeline_slots,
            source_ids,
            sink_ids,
            hook_ids,
            pipeline_ids,
            compiled_hooks,
            compiled_pipelines,
        })
    }

    /// Compiled-graph equivalent of `run_pipeline_with_registry`.
    ///
    /// Behaviour is identical on a verified registry: same jump-depth guard
    /// order, same `UnknownPipeline`/`FellOffEnd`/`UndeclaredAcceptTarget`/
    /// `UndeclaredJumpTarget`/`JumpDepthExceeded` strings, and HookTrace pushed
    /// only after the declared-target checks pass and before jump resolution.
    pub fn run_pipeline(
        &self,
        entry: &PipelineId,
        event: &mut Event,
        ctx: &mut KernelCtx,
    ) -> Result<Verdict, PipelineRunError> {
        let mut current = entry.clone();
        let mut jumps = 0usize;

        loop {
            if jumps > MAX_JUMP_DEPTH {
                return Err(PipelineRunError::JumpDepthExceeded);
            }
            let pslot = self
                .pipeline_slots
                .get(&current)
                .ok_or_else(|| PipelineRunError::UnknownPipeline(current.as_str().into()))?;
            let pipeline = &self.compiled_pipelines[pslot.0 as usize];

            let mut next: Option<PipelineId> = None;
            for hslot in pipeline.hooks.iter() {
                let chook = &self.compiled_hooks[hslot.0 as usize];
                let verdict = (chook.f)(event, ctx);
                match &verdict {
                    Verdict::Accept(sink) if !chook.may_accept_to.iter().any(|s| s == sink) => {
                        return Err(PipelineRunError::UndeclaredAcceptTarget {
                            hook: chook.id.as_str().into(),
                            sink: sink.as_str().into(),
                        });
                    }
                    Verdict::Jump(target) if !chook.may_jump_to.iter().any(|p| p == target) => {
                        return Err(PipelineRunError::UndeclaredJumpTarget {
                            hook: chook.id.as_str().into(),
                            pipeline: target.as_str().into(),
                        });
                    }
                    _ => {}
                }
                ctx.hook_trace.push(hook_trace_record(&chook.id, &verdict));
                match verdict {
                    Verdict::Continue => continue,
                    Verdict::Jump(target) => {
                        next = Some(target);
                        break;
                    }
                    terminal @ (Verdict::Accept(_) | Verdict::Reject(_) | Verdict::Drop) => {
                        return Ok(terminal);
                    }
                }
            }
            match next {
                Some(target) => {
                    current = target;
                    jumps += 1;
                }
                None => return Err(PipelineRunError::FellOffEnd(current.as_str().into())),
            }
        }
    }
}

/// M4/M5 capability/candidate/snapshot scaffolding accessors (plan D6).
/// The narrow allow is removed by the milestone that wires each accessor.
#[allow(dead_code)]
impl CompiledKernel {
    pub fn source_slot(&self, id: &SourceId) -> Option<SourceSlot> {
        self.source_slots.get(id).copied()
    }

    pub fn sink_slot(&self, id: &SinkId) -> Option<SinkSlot> {
        self.sink_slots.get(id).copied()
    }

    pub fn hook_slot(&self, id: &HookId) -> Option<HookSlot> {
        self.hook_slots.get(id).copied()
    }

    pub fn pipeline_slot(&self, id: &PipelineId) -> Option<PipelineSlot> {
        self.pipeline_slots.get(id).copied()
    }

    pub fn source_id(&self, slot: SourceSlot) -> Option<&SourceId> {
        self.source_ids.get(slot.0 as usize)
    }

    pub fn sink_id(&self, slot: SinkSlot) -> Option<&SinkId> {
        self.sink_ids.get(slot.0 as usize)
    }

    pub fn hook_id(&self, slot: HookSlot) -> Option<&HookId> {
        self.hook_ids.get(slot.0 as usize)
    }

    pub fn pipeline_id(&self, slot: PipelineSlot) -> Option<&PipelineId> {
        self.pipeline_ids.get(slot.0 as usize)
    }
}

/// Minimal opaque public handle over a compiled registry (plan drift D5).
///
/// `compile` runs `verify()` + interning + graph compilation once; `run_pipeline`
/// executes the compiled graph. No slot newtypes or data-plane internals are
/// exposed, so the public-surface guards and acceptance #1 still hold.
#[derive(Debug)]
pub struct CompiledPipelineSet(CompiledKernel);

impl CompiledPipelineSet {
    pub fn compile(reg: &KernelRegistry) -> Result<Self, VerifyError> {
        Ok(Self(CompiledKernel::from_registry(reg)?))
    }

    pub fn run_pipeline(
        &self,
        pid: &PipelineId,
        event: &mut Event,
        ctx: &mut KernelCtx,
    ) -> Result<Verdict, PipelineRunError> {
        self.0.run_pipeline(pid, event, ctx)
    }
}

/// One egress pre-resolved for candidate lookup: original dispatch index,
/// cloned exit id, and cloned route-group labels.
///
/// `egress_idx` is the position in `runtime.egresses`, so candidate order and
/// `map_candidate_order` results stay byte-identical to the pre-compiled scan.
#[derive(Debug)]
pub(crate) struct CompiledCandidate {
    pub(crate) egress_idx: usize,
    pub(crate) exit_id: ExitId,
    pub(crate) groups: Box<[String]>,
}

/// Per-`FlowSemantics` candidate buckets compiled once at bus build.
///
/// Each bucket holds, in original egress order, only the egresses whose
/// capabilities satisfy that semantics under the canonical
/// `capability_matches_flow` predicate — so candidate lookup skips the
/// per-flow `dyn EgressPlugin::capabilities()` scan over capability-incompatible
/// exits (plan acceptance #4). Route-group and target-sink filtering and the
/// health filter stay runtime checks over the matching bucket, preserving the
/// exact `healthy_candidates` fallback and fail-closed behaviour.
#[derive(Debug)]
pub(crate) struct CompiledCandidates {
    by_semantics: [Box<[CompiledCandidate]>; 3],
}

fn semantics_index(semantics: FlowSemantics) -> usize {
    match semantics {
        FlowSemantics::ByteStream => 0,
        FlowSemantics::Datagram => 1,
        FlowSemantics::Message => 2,
    }
}

impl CompiledCandidates {
    pub(crate) fn from_egresses(egresses: &[Box<dyn EgressPlugin>]) -> Self {
        let bucket = |want: FlowSemantics| -> Box<[CompiledCandidate]> {
            egresses
                .iter()
                .enumerate()
                .filter_map(|(idx, e)| {
                    let caps = e.capabilities();
                    if !capability_matches_flow(caps, want) {
                        return None;
                    }
                    Some(CompiledCandidate {
                        egress_idx: idx,
                        exit_id: e.id().clone(),
                        groups: caps.groups.clone().into_boxed_slice(),
                    })
                })
                .collect()
        };
        Self {
            by_semantics: [
                bucket(FlowSemantics::ByteStream),
                bucket(FlowSemantics::Datagram),
                bucket(FlowSemantics::Message),
            ],
        }
    }

    pub(crate) fn bucket(&self, semantics: FlowSemantics) -> &[CompiledCandidate] {
        &self.by_semantics[semantics_index(semantics)]
    }
}
