use crate::kernel::compiled::CompiledPipelineSet;
use crate::kernel::event::types::Event;
use crate::kernel::kernel_registry::types::{
    HookKind, HookSpec, KernelCtx, KernelRegistry, SinkSpec, SourceSpec,
};
use crate::kernel::pipeline::data_handle::{PipelineRunError, run_pipeline_with_registry};
use crate::kernel::pipeline::types::{Pipeline, Wiring};
use crate::kernel::verdict::types::{HookId, PipelineId, SinkId, SourceId, Verdict};

fn spec(
    id: &str,
    may_terminate: bool,
    may_accept_to: &[&str],
    may_jump: bool,
    may_jump_to: &[&str],
) -> HookSpec {
    HookSpec {
        id: HookId::new(id),
        kind: HookKind::Net,
        allowed_namespaces: vec![],
        reads: vec![],
        writes: vec![],
        may_terminate,
        may_jump,
        may_jump_to: may_jump_to.iter().map(|p| PipelineId::new(*p)).collect(),
        may_accept_to: may_accept_to.iter().map(|s| SinkId::new(*s)).collect(),
        side_effect_only: false,
    }
}

fn continue_fn(_e: &mut Event, _c: &mut KernelCtx) -> Verdict {
    Verdict::Continue
}
fn accept_direct_fn(_e: &mut Event, _c: &mut KernelCtx) -> Verdict {
    Verdict::Accept(SinkId::new("direct"))
}
fn accept_ghost_fn(_e: &mut Event, _c: &mut KernelCtx) -> Verdict {
    Verdict::Accept(SinkId::new("ghost"))
}
fn jump_other_fn(_e: &mut Event, _c: &mut KernelCtx) -> Verdict {
    Verdict::Jump(PipelineId::new("other"))
}
fn jump_nowhere_fn(_e: &mut Event, _c: &mut KernelCtx) -> Verdict {
    Verdict::Jump(PipelineId::new("nowhere"))
}
/// Jumps to the next pipeline in a linear chain. `hook_trace.len()` equals
/// the count of hooks already executed (one per chain step), so step `i`
/// jumps to `p{i+1}`, matching that hook's single declared `may_jump_to`.
fn dyn_jump_fn(_e: &mut Event, c: &mut KernelCtx) -> Verdict {
    Verdict::Jump(PipelineId::new(format!("p{}", c.hook_trace.len() + 1)))
}

fn base() -> KernelRegistry {
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
    r
}

fn wire(r: &mut KernelRegistry, pipeline: &str) {
    r.wirings.push(Wiring {
        source: SourceId::new("src"),
        pipeline: PipelineId::new(pipeline),
    });
}

fn outcome(r: &Result<Verdict, PipelineRunError>) -> String {
    match r {
        Ok(v) => format!("OK {v:?}"),
        Err(e) => format!("ERR {e}"),
    }
}

/// Runs `entry` through the registry executor and the compiled graph over
/// the same verify-passing registry, asserting identical outcome string
/// and identical `HookTrace` sequence.
fn assert_equivalent(reg: &KernelRegistry, entry: &str) {
    let pid = PipelineId::new(entry);

    let mut ev_r = Event::default();
    let mut ctx_r = KernelCtx::default();
    let res_r = run_pipeline_with_registry(reg, &pid, &mut ev_r, &mut ctx_r);

    let compiled = CompiledPipelineSet::compile(reg).expect("registry compiles");
    let mut ev_c = Event::default();
    let mut ctx_c = KernelCtx::default();
    let res_c = compiled.run_pipeline(&pid, &mut ev_c, &mut ctx_c);

    assert_eq!(
        outcome(&res_r),
        outcome(&res_c),
        "verdict/error string diverged for entry `{entry}`"
    );
    assert_eq!(
        format!("{:?}", ctx_r.hook_trace),
        format!("{:?}", ctx_c.hook_trace),
        "HookTrace sequence diverged for entry `{entry}`"
    );
}

#[test]
fn accept_terminal_equivalence() {
    let mut r = base();
    for h in ["r1", "r2", "r3"] {
        r.hooks
            .insert(HookId::new(h), spec(h, false, &[], false, &[]));
        r.fns.insert(HookId::new(h), continue_fn);
    }
    r.hooks
        .insert(HookId::new("r4"), spec("r4", true, &["direct"], false, &[]));
    r.fns.insert(HookId::new("r4"), accept_direct_fn);
    r.pipelines.insert(
        PipelineId::new("main"),
        Pipeline {
            id: PipelineId::new("main"),
            hooks: ["r1", "r2", "r3", "r4"]
                .iter()
                .map(|h| HookId::new(*h))
                .collect(),
        },
    );
    wire(&mut r, "main");
    assert_equivalent(&r, "main");
}

#[test]
fn fell_off_end_equivalence() {
    let mut r = base();
    r.hooks
        .insert(HookId::new("t"), spec("t", true, &[], false, &[]));
    r.fns.insert(HookId::new("t"), continue_fn);
    r.pipelines.insert(
        PipelineId::new("main"),
        Pipeline {
            id: PipelineId::new("main"),
            hooks: vec![HookId::new("t")],
        },
    );
    wire(&mut r, "main");
    assert_equivalent(&r, "main");
}

#[test]
fn jump_across_pipelines_equivalence() {
    let mut r = base();
    r.hooks
        .insert(HookId::new("j"), spec("j", false, &[], true, &["other"]));
    r.fns.insert(HookId::new("j"), jump_other_fn);
    r.hooks
        .insert(HookId::new("a"), spec("a", true, &["direct"], false, &[]));
    r.fns.insert(HookId::new("a"), accept_direct_fn);
    r.pipelines.insert(
        PipelineId::new("main"),
        Pipeline {
            id: PipelineId::new("main"),
            hooks: vec![HookId::new("j")],
        },
    );
    r.pipelines.insert(
        PipelineId::new("other"),
        Pipeline {
            id: PipelineId::new("other"),
            hooks: vec![HookId::new("a")],
        },
    );
    wire(&mut r, "main");
    assert_equivalent(&r, "main");
}

#[test]
fn undeclared_accept_target_equivalence() {
    let mut r = base();
    r.hooks.insert(
        HookId::new("bad"),
        spec("bad", true, &["direct"], false, &[]),
    );
    r.fns.insert(HookId::new("bad"), accept_ghost_fn);
    r.pipelines.insert(
        PipelineId::new("main"),
        Pipeline {
            id: PipelineId::new("main"),
            hooks: vec![HookId::new("bad")],
        },
    );
    wire(&mut r, "main");
    assert_equivalent(&r, "main");
}

#[test]
fn undeclared_jump_target_equivalence() {
    let mut r = base();
    r.hooks.insert(
        HookId::new("bj"),
        spec("bj", false, &[], true, &["sink_pipe"]),
    );
    r.fns.insert(HookId::new("bj"), jump_nowhere_fn);
    r.hooks
        .insert(HookId::new("a"), spec("a", true, &["direct"], false, &[]));
    r.fns.insert(HookId::new("a"), accept_direct_fn);
    r.pipelines.insert(
        PipelineId::new("main"),
        Pipeline {
            id: PipelineId::new("main"),
            hooks: vec![HookId::new("bj")],
        },
    );
    r.pipelines.insert(
        PipelineId::new("sink_pipe"),
        Pipeline {
            id: PipelineId::new("sink_pipe"),
            hooks: vec![HookId::new("a")],
        },
    );
    wire(&mut r, "main");
    assert_equivalent(&r, "main");
}

#[test]
fn unknown_pipeline_equivalence() {
    let mut r = base();
    r.hooks
        .insert(HookId::new("a"), spec("a", true, &["direct"], false, &[]));
    r.fns.insert(HookId::new("a"), accept_direct_fn);
    r.pipelines.insert(
        PipelineId::new("main"),
        Pipeline {
            id: PipelineId::new("main"),
            hooks: vec![HookId::new("a")],
        },
    );
    wire(&mut r, "main");
    assert_equivalent(&r, "ghost-pipe");
}

#[test]
fn jump_depth_exceeded_equivalence() {
    // verify() rejects jump cycles, so the only verify-passing way to reach
    // the runtime depth guard is an acyclic chain longer than
    // MAX_JUMP_DEPTH (32). Chain p0→…→p33: hooks h0..h32 each jump to the
    // next; h33 is a terminal accept so p33 verifies as terminating (it is
    // never reached at runtime — jumps>32 errors at p33's lookup).
    let mut r = base();
    let chain = 34usize;
    for i in 0..chain {
        let h = format!("h{i}");
        let p = format!("p{i}");
        if i + 1 < chain {
            let next = format!("p{}", i + 1);
            r.hooks.insert(
                HookId::new(&h),
                spec(&h, false, &[], true, &[next.as_str()]),
            );
            r.fns.insert(HookId::new(&h), dyn_jump_fn);
        } else {
            r.hooks
                .insert(HookId::new(&h), spec(&h, true, &["direct"], false, &[]));
            r.fns.insert(HookId::new(&h), accept_direct_fn);
        }
        r.pipelines.insert(
            PipelineId::new(&p),
            Pipeline {
                id: PipelineId::new(&p),
                hooks: vec![HookId::new(&h)],
            },
        );
    }
    wire(&mut r, "p0");
    assert_equivalent(&r, "p0");
}
