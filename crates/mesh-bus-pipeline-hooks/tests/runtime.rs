use bytes::Bytes;
use mesh_bus_core::kernel::{
    Event, HookId, HookKind, HookSpec, KernelCtx, KernelRegistry, MetaValue, Pipeline, PipelineId,
    Reason, SinkId, SinkSpec, SourceId, SourceSpec, TypedMap, Verdict, Wiring,
};
use mesh_bus_pipeline_hooks::context::{ExitCandidate, SharedHookCtx, current, install_scoped};
use mesh_bus_pipeline_hooks::runtime::{PipelineRuntime, run_pipeline_event};
use std::sync::Arc;

fn accept_direct(_event: &mut Event, _ctx: &mut KernelCtx) -> Verdict {
    Verdict::Accept(SinkId::new("direct"))
}

fn reject_if_used(_event: &mut Event, _ctx: &mut KernelCtx) -> Verdict {
    Verdict::Reject(Reason::code("unwired_pipeline_used"))
}

fn jump_to_ghost(_event: &mut Event, _ctx: &mut KernelCtx) -> Verdict {
    Verdict::Jump(PipelineId::new("ghost"))
}

fn shared_ctx(handle: tokio::runtime::Handle) -> SharedHookCtx {
    SharedHookCtx {
        resolver: Arc::new(fixtures::NoopResolver),
        cache: Arc::new(mesh_bus_resolver::cache::DnsCache::new()),
        geoip: Arc::new(mb_geoip::GeoIpDb::empty()),
        geosite: Arc::new(mb_geosite::GeositeDb::empty()),
        rule_chain: Arc::new(mb_rule::RuleChain {
            rules: vec![],
            default: mb_rule::types::Action::Allow,
        }),
        rule_sets: Arc::new(mb_rule::RuleSetRegistry::empty()),
        candidates: Arc::new(vec![ExitCandidate {
            sink_id: "direct".into(),
            route_groups: vec![],
            supports_stream: true,
            supports_datagram: true,
            rtt_ms: 0,
            success_rate: 1.0,
            jitter_ms: 0,
        }]),
        tokio: handle,
    }
}

fn registry() -> (KernelRegistry, SourceId) {
    let wired_pid = PipelineId::new("forward");
    let unwired_pid = PipelineId::new("unwired");
    let source = SourceId::new("app");
    let accept_hook = HookId::new("transport.accept_direct");
    let reject_hook = HookId::new("transport.reject_if_used");
    let sink = SinkId::new("direct");
    let mut reg = KernelRegistry::default();
    reg.sources.insert(
        source.clone(),
        SourceSpec {
            id: source.clone(),
            kind: "application/source".into(),
            initial_writes: vec!["ext.seed".into()],
        },
    );
    reg.sinks.insert(
        sink.clone(),
        SinkSpec {
            id: sink.clone(),
            kind: "stream_egress".into(),
        },
    );
    reg.hooks.insert(
        accept_hook.clone(),
        HookSpec {
            id: accept_hook.clone(),
            kind: HookKind::Transport,
            allowed_namespaces: vec!["ext.*".into()],
            reads: vec!["ext.seed".into()],
            writes: vec![],
            may_terminate: true,
            may_jump: false,
            may_jump_to: vec![],
            may_accept_to: vec![sink],
            side_effect_only: false,
        },
    );
    reg.hooks.insert(
        reject_hook.clone(),
        HookSpec {
            id: reject_hook.clone(),
            kind: HookKind::Transport,
            allowed_namespaces: vec![],
            reads: vec![],
            writes: vec![],
            may_terminate: true,
            may_jump: false,
            may_jump_to: vec![],
            may_accept_to: vec![],
            side_effect_only: false,
        },
    );
    reg.fns.insert(accept_hook.clone(), accept_direct);
    reg.fns.insert(reject_hook.clone(), reject_if_used);
    reg.pipelines.insert(
        wired_pid.clone(),
        Pipeline {
            id: wired_pid.clone(),
            hooks: vec![accept_hook],
        },
    );
    reg.pipelines.insert(
        unwired_pid.clone(),
        Pipeline {
            id: unwired_pid,
            hooks: vec![reject_hook],
        },
    );
    reg.wirings.push(Wiring {
        source: source.clone(),
        pipeline: wired_pid,
    });
    (reg, source)
}

#[test]
fn runtime_fixture_uses_generic_application_source_kind() {
    let (reg, source_id) = registry();
    let source = reg.sources.get(&source_id).expect("source registered");
    assert_eq!(source.kind, "application/source");
}

fn jump_mismatch_registry() -> (KernelRegistry, SourceId) {
    let pid = PipelineId::new("entry");
    let declared_target = PipelineId::new("declared-target");
    let source = SourceId::new("app");
    let jump_hook = HookId::new("transport.jump_mismatch");
    let accept_hook = HookId::new("transport.accept_direct");
    let sink = SinkId::new("direct");
    let mut reg = KernelRegistry::default();
    reg.sources.insert(
        source.clone(),
        SourceSpec {
            id: source.clone(),
            kind: "application/source".into(),
            initial_writes: vec![],
        },
    );
    reg.sinks.insert(
        sink.clone(),
        SinkSpec {
            id: sink.clone(),
            kind: "stream_egress".into(),
        },
    );
    reg.hooks.insert(
        jump_hook.clone(),
        HookSpec {
            id: jump_hook.clone(),
            kind: HookKind::Transport,
            allowed_namespaces: vec![],
            reads: vec![],
            writes: vec![],
            may_terminate: false,
            may_jump: true,
            may_jump_to: vec![declared_target.clone()],
            may_accept_to: vec![],
            side_effect_only: false,
        },
    );
    reg.hooks.insert(
        accept_hook.clone(),
        HookSpec {
            id: accept_hook.clone(),
            kind: HookKind::Transport,
            allowed_namespaces: vec![],
            reads: vec![],
            writes: vec![],
            may_terminate: true,
            may_jump: false,
            may_jump_to: vec![],
            may_accept_to: vec![sink],
            side_effect_only: false,
        },
    );
    reg.fns.insert(jump_hook.clone(), jump_to_ghost);
    reg.fns.insert(accept_hook.clone(), accept_direct);
    reg.pipelines.insert(
        pid.clone(),
        Pipeline {
            id: pid.clone(),
            hooks: vec![jump_hook],
        },
    );
    reg.pipelines.insert(
        declared_target.clone(),
        Pipeline {
            id: declared_target,
            hooks: vec![accept_hook],
        },
    );
    reg.wirings.push(Wiring {
        source: source.clone(),
        pipeline: pid,
    });
    (reg, source)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn pipeline_runtime_rejects_unverified_registry_at_construction() {
    let (mut reg, source_id) = registry();
    reg.wirings.clear();

    let err = match PipelineRuntime::new(
        shared_ctx(tokio::runtime::Handle::current()),
        Arc::new(reg),
        source_id,
    ) {
        Ok(_) => panic!("runtime constructor must fail before first packet"),
        Err(err) => err,
    };

    assert!(err.to_string().contains("kernel registry verify"), "{err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn pipeline_runtime_returns_kernel_run_error() {
    let (registry, source_id) = jump_mismatch_registry();
    let runtime = Arc::new(
        PipelineRuntime::new(
            shared_ctx(tokio::runtime::Handle::current()),
            Arc::new(registry),
            source_id,
        )
        .expect("registry verifies from declared hook spec"),
    );

    let err = match run_pipeline_event(
        runtime,
        Event {
            payload: Bytes::new(),
            meta: TypedMap::default(),
        },
    )
    .await
    {
        Ok(_) => panic!("runtime execution errors must be observable"),
        Err(err) => err,
    };

    assert!(err.to_string().contains("pipeline run"), "{err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn pipeline_runtime_exposes_verified_state_by_accessor() {
    let (registry, source_id) = registry();
    let runtime = PipelineRuntime::new(
        shared_ctx(tokio::runtime::Handle::current()),
        Arc::new(registry),
        source_id.clone(),
    )
    .expect("verified runtime");

    assert_eq!(runtime.source_id(), &source_id);
    assert!(runtime.registry().sources.contains_key(&source_id));
    assert!(
        runtime
            .shared_ctx()
            .candidates
            .iter()
            .any(|c| c.sink_id == "direct")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn scoped_hook_context_clears_after_panic() {
    assert!(current().is_none());
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = install_scoped(shared_ctx(tokio::runtime::Handle::current()));
        assert!(current().is_some());
        panic!("hook panic");
    }));

    assert!(result.is_err());
    assert!(current().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn pipeline_runtime_runs_event_without_socks5_dependency() {
    let (registry, source_id) = registry();
    let runtime = Arc::new(
        PipelineRuntime::new(
            shared_ctx(tokio::runtime::Handle::current()),
            Arc::new(registry),
            source_id,
        )
        .expect("verified runtime"),
    );
    let mut event = Event {
        payload: Bytes::new(),
        meta: TypedMap::default(),
    };
    event.meta.ext.push(("seed", MetaValue::U64(1)));

    let run = run_pipeline_event(runtime, event)
        .await
        .expect("pipeline run succeeds");

    assert!(matches!(run.verdict, Verdict::Accept(_)));
    assert_eq!(run.hook_trace.len(), 1);
}

mod fixtures {
    use async_trait::async_trait;
    use mesh_bus_resolver::data_handle::ResolverHandle;
    use mesh_bus_resolver::types::*;

    pub struct NoopResolver;

    #[async_trait]
    impl ResolverHandle for NoopResolver {
        async fn resolve(
            &self,
            _req: ResolveRequest,
        ) -> Result<(ResolveAnswer, ResolutionSignals), (ResolveError, ResolutionSignals)> {
            unreachable!("runtime helper test must not call resolver")
        }
    }
}
