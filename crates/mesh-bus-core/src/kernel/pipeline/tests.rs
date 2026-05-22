use super::data_handle::{PipelineRunError, run_pipeline, run_pipeline_with_registry};
use super::types::{Pipeline, Wiring};
use crate::kernel::event::data_handle::event_empty;
use crate::kernel::event::types::Event;
use crate::kernel::kernel_registry::types::{
    HookKind, HookSpec, KernelCtx, KernelRegistry, SinkSpec,
};
use crate::kernel::verdict::types::{HookId, PipelineId, Reason, SinkId, SourceId, Verdict};

/// Minimal Ctx for tests — just accumulates HookId strings executed.
struct TestCtx {
    pub executed: Vec<String>,
}

fn make_resolver<'a>(
    hooks: &'a [(&'static str, Verdict)],
) -> impl Fn(&HookId, &mut Event, &mut TestCtx) -> Result<Verdict, PipelineRunError> + 'a {
    move |id, _ev, ctx| {
        ctx.executed.push(id.as_str().to_string());
        hooks
            .iter()
            .find(|(name, _)| *name == id.as_str())
            .map(|(_, v)| v.clone())
            .ok_or_else(|| PipelineRunError::UnknownHook(id.as_str().into()))
    }
}

fn pipeline(id: &str, hook_ids: &[&str]) -> Pipeline {
    Pipeline {
        id: PipelineId::new(id),
        hooks: hook_ids.iter().map(|h| HookId::new(*h)).collect(),
    }
}

#[test]
fn run_pipeline_executes_hooks_in_order_and_stops_on_accept() {
    let pipelines = vec![pipeline("main", &["tag", "allow", "deny"])];
    let hook_table: &[(&str, Verdict)] = &[
        ("tag", Verdict::Continue),
        ("allow", Verdict::Accept(SinkId::new("direct"))),
        ("deny", Verdict::Reject(Reason::code("denied"))),
    ];
    let resolver = make_resolver(hook_table);
    let mut ev = event_empty();
    let mut ctx = TestCtx { executed: vec![] };

    let v = run_pipeline(
        &PipelineId::new("main"),
        &pipelines,
        &mut ev,
        &mut ctx,
        &resolver,
    )
    .expect("pipeline run failed");
    assert!(matches!(v, Verdict::Accept(_)));
    assert_eq!(
        ctx.executed,
        vec!["tag", "allow"],
        "deny must not run after Accept"
    );
}

#[test]
fn run_pipeline_jump_follows_to_target() {
    let pipelines = vec![
        pipeline("main", &["jump_to_cn"]),
        pipeline("cn", &["allow"]),
    ];
    let hook_table: &[(&str, Verdict)] = &[
        ("jump_to_cn", Verdict::Jump(PipelineId::new("cn"))),
        ("allow", Verdict::Accept(SinkId::new("direct"))),
    ];
    let resolver = make_resolver(hook_table);
    let mut ev = event_empty();
    let mut ctx = TestCtx { executed: vec![] };

    let v = run_pipeline(
        &PipelineId::new("main"),
        &pipelines,
        &mut ev,
        &mut ctx,
        &resolver,
    )
    .expect("pipeline run failed");
    assert!(matches!(v, Verdict::Accept(_)));
    assert_eq!(ctx.executed, vec!["jump_to_cn", "allow"]);
}

#[test]
fn run_pipeline_fell_off_end_is_error() {
    let pipelines = vec![pipeline("main", &["cont"])];
    let hook_table: &[(&str, Verdict)] = &[("cont", Verdict::Continue)];
    let resolver = make_resolver(hook_table);
    let mut ev = event_empty();
    let mut ctx = TestCtx { executed: vec![] };

    let err = run_pipeline(
        &PipelineId::new("main"),
        &pipelines,
        &mut ev,
        &mut ctx,
        &resolver,
    )
    .expect_err("expected FellOffEnd");
    assert!(matches!(err, PipelineRunError::FellOffEnd(_)));
}

#[test]
fn run_pipeline_jump_depth_exceeded_is_error() {
    // a jumps to b, b jumps to a — infinite cycle
    let pipelines = vec![pipeline("a", &["jump_b"]), pipeline("b", &["jump_a"])];
    let hook_table: &[(&str, Verdict)] = &[
        ("jump_b", Verdict::Jump(PipelineId::new("b"))),
        ("jump_a", Verdict::Jump(PipelineId::new("a"))),
    ];
    let resolver = make_resolver(hook_table);
    let mut ev = event_empty();
    let mut ctx = TestCtx { executed: vec![] };

    let err = run_pipeline(
        &PipelineId::new("a"),
        &pipelines,
        &mut ev,
        &mut ctx,
        &resolver,
    )
    .expect_err("expected JumpDepthExceeded");
    assert!(matches!(err, PipelineRunError::JumpDepthExceeded));
}

#[test]
fn wiring_links_source_to_pipeline() {
    let w = Wiring {
        source: SourceId::new("ingress:0"),
        pipeline: PipelineId::new("ingress"),
    };
    assert_eq!(w.source.as_str(), "ingress:0");
    assert_eq!(w.pipeline.as_str(), "ingress");
}

fn accept_direct(_event: &mut Event, _ctx: &mut KernelCtx) -> Verdict {
    Verdict::Accept(SinkId::new("direct"))
}

fn accept_ghost(_event: &mut Event, _ctx: &mut KernelCtx) -> Verdict {
    Verdict::Accept(SinkId::new("ghost"))
}

fn jump_undeclared(_event: &mut Event, _ctx: &mut KernelCtx) -> Verdict {
    Verdict::Jump(PipelineId::new("side"))
}

#[test]
fn run_pipeline_with_registry_records_hook_trace() {
    let mut reg = KernelRegistry::default();
    let hook = HookId::new("allow");
    let pid = PipelineId::new("main");
    reg.sinks.insert(
        SinkId::new("direct"),
        SinkSpec {
            id: SinkId::new("direct"),
            kind: "stream_egress".into(),
        },
    );
    reg.hooks.insert(
        hook.clone(),
        HookSpec {
            id: hook.clone(),
            kind: HookKind::Transport,
            allowed_namespaces: vec![],
            reads: vec![],
            writes: vec![],
            may_terminate: true,
            may_jump: false,
            may_jump_to: vec![],
            may_accept_to: vec![SinkId::new("direct")],
            side_effect_only: false,
        },
    );
    reg.fns.insert(hook.clone(), accept_direct);
    reg.pipelines.insert(
        pid.clone(),
        Pipeline {
            id: pid.clone(),
            hooks: vec![hook.clone()],
        },
    );

    let mut event = event_empty();
    let mut ctx = KernelCtx::default();
    let verdict =
        run_pipeline_with_registry(&reg, &pid, &mut event, &mut ctx).expect("pipeline run");

    assert!(matches!(verdict, Verdict::Accept(_)));
    assert_eq!(ctx.hook_trace.len(), 1);
    assert_eq!(ctx.hook_trace[0].hook_id, hook);
    assert_eq!(ctx.hook_trace[0].verdict, "Accept");
}

#[test]
fn run_pipeline_with_registry_rejects_undeclared_accept_sink() {
    let mut reg = KernelRegistry::default();
    let hook = HookId::new("allow");
    let pid = PipelineId::new("main");
    reg.sinks.insert(
        SinkId::new("direct"),
        SinkSpec {
            id: SinkId::new("direct"),
            kind: "stream_egress".into(),
        },
    );
    reg.hooks.insert(
        hook.clone(),
        HookSpec {
            id: hook.clone(),
            kind: HookKind::Transport,
            allowed_namespaces: vec![],
            reads: vec![],
            writes: vec![],
            may_terminate: true,
            may_jump: false,
            may_jump_to: vec![],
            may_accept_to: vec![SinkId::new("direct")],
            side_effect_only: false,
        },
    );
    reg.fns.insert(hook.clone(), accept_ghost);
    reg.pipelines.insert(
        pid.clone(),
        Pipeline {
            id: pid.clone(),
            hooks: vec![hook],
        },
    );

    let mut event = event_empty();
    let mut ctx = KernelCtx::default();
    let err = run_pipeline_with_registry(&reg, &pid, &mut event, &mut ctx)
        .expect_err("runtime must reject Accept sink not declared by HookSpec");

    assert!(
        matches!(err, PipelineRunError::UndeclaredAcceptTarget { .. }),
        "{err:?}"
    );
}

#[test]
fn run_pipeline_with_registry_rejects_undeclared_jump_target() {
    let mut reg = KernelRegistry::default();
    let hook = HookId::new("jump");
    let pid = PipelineId::new("main");
    reg.hooks.insert(
        hook.clone(),
        HookSpec {
            id: hook.clone(),
            kind: HookKind::Transport,
            allowed_namespaces: vec![],
            reads: vec![],
            writes: vec![],
            may_terminate: false,
            may_jump: true,
            may_jump_to: vec![PipelineId::new("declared")],
            may_accept_to: vec![],
            side_effect_only: false,
        },
    );
    reg.fns.insert(hook.clone(), jump_undeclared);
    reg.pipelines.insert(
        pid.clone(),
        Pipeline {
            id: pid.clone(),
            hooks: vec![hook],
        },
    );
    for name in ["declared", "side"] {
        reg.pipelines.insert(
            PipelineId::new(name),
            Pipeline {
                id: PipelineId::new(name),
                hooks: vec![],
            },
        );
    }

    let mut event = event_empty();
    let mut ctx = KernelCtx::default();
    let err = run_pipeline_with_registry(&reg, &pid, &mut event, &mut ctx)
        .expect_err("runtime must reject Jump target not declared by HookSpec");

    assert!(
        matches!(err, PipelineRunError::UndeclaredJumpTarget { .. }),
        "{err:?}"
    );
}
