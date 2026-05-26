use crate::kernel::compiled::CompiledKernel;
use crate::kernel::event::types::Event;
use crate::kernel::kernel_registry::types::{
    HookKind, HookSpec, KernelCtx, KernelRegistry, SinkSpec, SourceSpec,
};
use crate::kernel::kernel_registry::verify_error::VerifyError;
use crate::kernel::pipeline::types::{Pipeline, Wiring};
use crate::kernel::verdict::types::{HookId, PipelineId, SinkId, SourceId, Verdict};

fn terminal_spec(id: &str) -> HookSpec {
    HookSpec {
        id: HookId::new(id),
        kind: HookKind::Net,
        allowed_namespaces: vec![],
        reads: vec![],
        writes: vec![],
        may_terminate: true,
        may_jump: false,
        may_jump_to: vec![],
        may_accept_to: vec![],
        side_effect_only: false,
    }
}

fn continue_fn(_event: &mut Event, _ctx: &mut KernelCtx) -> Verdict {
    Verdict::Continue
}

fn valid_registry() -> KernelRegistry {
    let mut r = KernelRegistry::default();
    r.sources.insert(
        SourceId::new("src"),
        SourceSpec {
            id: SourceId::new("src"),
            kind: "application/source".into(),
            initial_writes: vec![],
        },
    );
    r.sinks.insert(
        SinkId::new("direct"),
        SinkSpec {
            id: SinkId::new("direct"),
            kind: "stream_egress".into(),
        },
    );
    r.hooks.insert(HookId::new("allow"), terminal_spec("allow"));
    r.fns.insert(HookId::new("allow"), continue_fn);
    r.pipelines.insert(
        PipelineId::new("main"),
        Pipeline {
            id: PipelineId::new("main"),
            hooks: vec![HookId::new("allow")],
        },
    );
    r.wirings.push(Wiring {
        source: SourceId::new("src"),
        pipeline: PipelineId::new("main"),
    });
    r
}

#[test]
fn compiles_valid_registry_and_round_trips_slots() {
    let reg = valid_registry();
    let ck = CompiledKernel::from_registry(&reg).expect("valid registry compiles");

    let src = ck.source_slot(&SourceId::new("src")).expect("source slot");
    assert_eq!(ck.source_id(src), Some(&SourceId::new("src")));
    let sink = ck.sink_slot(&SinkId::new("direct")).expect("sink slot");
    assert_eq!(ck.sink_id(sink), Some(&SinkId::new("direct")));
    let hook = ck.hook_slot(&HookId::new("allow")).expect("hook slot");
    assert_eq!(ck.hook_id(hook), Some(&HookId::new("allow")));
    let pipe = ck
        .pipeline_slot(&PipelineId::new("main"))
        .expect("pipeline slot");
    assert_eq!(ck.pipeline_id(pipe), Some(&PipelineId::new("main")));

    assert!(ck.source_slot(&SourceId::new("absent")).is_none());
}

#[test]
fn identity_mismatch_still_fails_closed() {
    let mut reg = valid_registry();
    // Key disagrees with embedded HookSpec.id.
    reg.hooks
        .insert(HookId::new("ghost"), terminal_spec("allow"));
    let err = CompiledKernel::from_registry(&reg)
        .expect_err("identity mismatch must fail before interning");
    assert!(
        matches!(err, VerifyError::RegistryIdentityMismatch { .. }),
        "expected RegistryIdentityMismatch, got {err:?}"
    );
}

#[test]
fn unknown_hook_still_fails_closed() {
    let mut reg = valid_registry();
    reg.pipelines.insert(
        PipelineId::new("main"),
        Pipeline {
            id: PipelineId::new("main"),
            hooks: vec![HookId::new("missing")],
        },
    );
    let err =
        CompiledKernel::from_registry(&reg).expect_err("unknown hook must fail before interning");
    assert!(
        matches!(err, VerifyError::UnknownHook(_, _)),
        "expected UnknownHook, got {err:?}"
    );
}

#[test]
fn invalid_wiring_still_fails_closed() {
    let mut reg = valid_registry();
    reg.wirings.clear();
    reg.wirings.push(Wiring {
        source: SourceId::new("src"),
        pipeline: PipelineId::new("nope"),
    });
    let err =
        CompiledKernel::from_registry(&reg).expect_err("invalid wiring must fail before interning");
    assert!(
        matches!(err, VerifyError::UnknownWiringPipeline { .. }),
        "expected UnknownWiringPipeline, got {err:?}"
    );
}
