use super::types::Pipeline;
use crate::kernel::event::data_handle::hook_trace_record;
use crate::kernel::event::types::Event;
use crate::kernel::kernel_registry::types::{KernelCtx, KernelRegistry};
use crate::kernel::verdict::types::{HookId, PipelineId, Verdict};
use thiserror::Error;

pub const MAX_JUMP_DEPTH: usize = 32;

#[derive(Debug, Error)]
pub enum PipelineRunError {
    #[error("hook `{0}` not registered")]
    UnknownHook(String),
    #[error("pipeline `{0}` not found")]
    UnknownPipeline(String),
    #[error("pipeline `{0}` fell off the end without a terminal verdict")]
    FellOffEnd(String),
    #[error("pipeline jump depth exceeded (max {})", MAX_JUMP_DEPTH)]
    JumpDepthExceeded,
    #[error("hook `{hook}` returned Accept `{sink}` not declared in may_accept_to")]
    UndeclaredAcceptTarget { hook: String, sink: String },
    #[error("hook `{hook}` returned Jump `{pipeline}` not declared in may_jump_to")]
    UndeclaredJumpTarget { hook: String, pipeline: String },
}

/// Execute a pipeline against an event.
///
/// `resolve` maps a HookId to its Verdict by running the corresponding HookFn.
/// Using a closure here lets callers inject KernelRegistry look-up (Task 5)
/// or a test-double without coupling this function to the registry type directly.
pub fn run_pipeline<E, C, R>(
    entry: &PipelineId,
    pipelines: &[Pipeline],
    event: &mut E,
    ctx: &mut C,
    resolve: &R,
) -> Result<Verdict, PipelineRunError>
where
    R: Fn(&HookId, &mut E, &mut C) -> Result<Verdict, PipelineRunError>,
{
    let mut current = entry.clone();
    let mut jumps = 0usize;

    loop {
        if jumps > MAX_JUMP_DEPTH {
            return Err(PipelineRunError::JumpDepthExceeded);
        }
        let pipeline = pipelines
            .iter()
            .find(|p| p.id == current)
            .ok_or_else(|| PipelineRunError::UnknownPipeline(current.as_str().into()))?;

        let mut next: Option<PipelineId> = None;
        for hook_id in &pipeline.hooks {
            let verdict = resolve(hook_id, event, ctx)?;
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

/// Registry-aware facade: dispatch `pid` against `reg.fns` until a terminal verdict.
/// Reuses [`run_pipeline`] under the hood; resolves HookId via `reg.fns`.
pub fn run_pipeline_with_registry(
    reg: &KernelRegistry,
    pid: &PipelineId,
    event: &mut Event,
    ctx: &mut KernelCtx,
) -> Result<Verdict, PipelineRunError> {
    let pipelines: Vec<Pipeline> = reg.pipelines.values().cloned().collect();
    run_pipeline(pid, &pipelines, event, ctx, &|hook_id, ev, c| {
        let spec = reg
            .hooks
            .get(hook_id)
            .ok_or_else(|| PipelineRunError::UnknownHook(hook_id.as_str().into()))?;
        let f = reg
            .fns
            .get(hook_id)
            .ok_or_else(|| PipelineRunError::UnknownHook(hook_id.as_str().into()))?;
        let verdict = f(ev, c);
        match &verdict {
            Verdict::Accept(sink) if !spec.may_accept_to.iter().any(|s| s == sink) => {
                return Err(PipelineRunError::UndeclaredAcceptTarget {
                    hook: hook_id.as_str().into(),
                    sink: sink.as_str().into(),
                });
            }
            Verdict::Jump(target) if !spec.may_jump_to.iter().any(|p| p == target) => {
                return Err(PipelineRunError::UndeclaredJumpTarget {
                    hook: hook_id.as_str().into(),
                    pipeline: target.as_str().into(),
                });
            }
            _ => {}
        }
        c.hook_trace.push(hook_trace_record(hook_id, &verdict));
        Ok(verdict)
    })
}
