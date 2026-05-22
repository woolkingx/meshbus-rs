use async_trait::async_trait;
use bytes::Bytes;
use mb_rule::RuleSetRegistry;
use mb_rule::types::{Action, MatchExpr, Predicate, Rule, RuleChain};
use mesh_bus_core::kernel::{
    Event, HookId, KernelCtx, KernelRegistry, MetaValue, Pipeline, PipelineId, SinkId, SinkSpec,
    SourceId, SourceSpec, TypedMap, Verdict, Wiring, run_pipeline_with_registry,
};
use mesh_bus_pipeline_hooks::context::{ExitCandidate, SharedHookCtx, install};
use mesh_bus_resolver::data_handle::ResolverHandle;
use mesh_bus_resolver::types::*;
use std::net::Ipv4Addr;
use std::sync::Arc;

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn full_four_hook_pipeline_routes_by_hostname_rule() {
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        install(SharedHookCtx {
            resolver: Arc::new(FixedResolver(Ipv4Addr::new(93, 184, 216, 34))),
            cache: Arc::new(mesh_bus_resolver::cache::DnsCache::new()),
            geoip: Arc::new(mb_geoip::GeoIpDb::empty()),
            geosite: Arc::new(mb_geosite::GeositeDb::empty()),
            rule_chain: Arc::new(RuleChain {
                rules: vec![Rule {
                    id: Some("test-1".into()),
                    r#match: MatchExpr::Term(Predicate::HostnameExact("example.com".into())),
                    action: Action::Compose(vec![
                        Action::SetRouteGroup("us-pool".into()),
                        Action::SetCostBias(500),
                    ]),
                }],
                default: Action::Allow,
            }),
            rule_sets: Arc::new(RuleSetRegistry::empty()),
            candidates: Arc::new(vec![
                ExitCandidate {
                    sink_id: "us-sink".into(),
                    route_groups: vec!["us-pool".into()],
                    supports_stream: true,
                    supports_datagram: false,
                    rtt_ms: 100,
                    success_rate: 1.0,
                    jitter_ms: 0,
                },
                ExitCandidate {
                    sink_id: "other".into(),
                    route_groups: vec![],
                    supports_stream: true,
                    supports_datagram: false,
                    rtt_ms: 50,
                    success_rate: 1.0,
                    jitter_ms: 0,
                },
            ]),
            tokio: handle,
        });

        let mut reg = KernelRegistry::default();
        let pid = PipelineId::new("forward");
        reg.sources.insert(
            SourceId::new("app"),
            SourceSpec {
                id: SourceId::new("app"),
                kind: "application/source".into(),
                initial_writes: vec![
                    "net.dst_host".into(),
                    "net.dst_port".into(),
                    "net.protocol".into(),
                    "net.src_ip".into(),
                    "auth.user".into(),
                    "trace.flow_id".into(),
                    "ext.operation".into(),
                    "ext.dst_ip_primary".into(),
                ],
            },
        );
        reg.sinks.insert(
            SinkId::new("us-sink"),
            SinkSpec {
                id: SinkId::new("us-sink"),
                kind: "stream_egress".into(),
            },
        );
        reg.sinks.insert(
            SinkId::new("other"),
            SinkSpec {
                id: SinkId::new("other"),
                kind: "stream_egress".into(),
            },
        );
        for sink in reg.sinks.values() {
            assert_eq!(sink.kind, "stream_egress");
        }
        reg.hooks.insert(
            HookId::new("net.resolve_or_recover"),
            mesh_bus_pipeline_hooks::specs::RESOLVE_HOOK.clone(),
        );
        reg.hooks.insert(
            HookId::new("net.enrich_geo_asn"),
            mesh_bus_pipeline_hooks::specs::ENRICH_HOOK.clone(),
        );
        reg.hooks.insert(
            HookId::new("policy.rule_chain"),
            mesh_bus_pipeline_hooks::specs::RULE_HOOK.clone(),
        );
        reg.hooks.insert(
            HookId::new("transport.pick_sink_cake"),
            mesh_bus_pipeline_hooks::specs::pick_sink_hook_spec(vec![
                SinkId::new("us-sink"),
                SinkId::new("other"),
            ]),
        );
        reg.fns.insert(
            HookId::new("net.resolve_or_recover"),
            mesh_bus_pipeline_hooks::resolve::resolve_or_recover,
        );
        reg.fns.insert(
            HookId::new("net.enrich_geo_asn"),
            mesh_bus_pipeline_hooks::geo::enrich_geo_asn,
        );
        reg.fns.insert(
            HookId::new("policy.rule_chain"),
            mesh_bus_pipeline_hooks::rule::rule_chain,
        );
        reg.fns.insert(
            HookId::new("transport.pick_sink_cake"),
            mesh_bus_pipeline_hooks::pick_sink::pick_sink_cake,
        );
        reg.pipelines.insert(
            pid.clone(),
            Pipeline {
                id: pid.clone(),
                hooks: vec![
                    HookId::new("net.resolve_or_recover"),
                    HookId::new("net.enrich_geo_asn"),
                    HookId::new("policy.rule_chain"),
                    HookId::new("transport.pick_sink_cake"),
                ],
            },
        );
        reg.wirings.push(Wiring {
            source: SourceId::new("app"),
            pipeline: pid.clone(),
        });

        let mut event = Event {
            payload: Bytes::new(),
            meta: TypedMap::default(),
        };
        event.meta.net.dst_host = Some("example.com".into());
        event.meta.net.dst_port = Some(80);
        event.meta.net.protocol = Some("tcp".into());
        event.meta.trace.flow_id = Some("flow:1".into());

        let mut kctx = KernelCtx::default();
        let v = run_pipeline_with_registry(&reg, &pid, &mut event, &mut kctx).expect("pipeline");

        match v {
            Verdict::Accept(sid) => assert_eq!(sid.as_str(), "us-sink"),
            v => panic!("expected Accept(us-sink), got {v:?}"),
        }
        assert_eq!(
            event.meta.policy.route_group.as_deref(),
            Some("us-pool"),
            "rule_chain must set route_group"
        );
        let mode = event
            .meta
            .ext
            .iter()
            .find(|(k, _)| *k == "resolution_mode")
            .expect("resolution_mode recorded");
        assert!(
            matches!(&mode.1, MetaValue::String(s) if !s.is_empty()),
            "resolution_mode set: {:?}",
            mode.1
        );
    })
    .await
    .expect("blocking task completed");
}

struct FixedResolver(Ipv4Addr);

#[async_trait]
impl ResolverHandle for FixedResolver {
    async fn resolve(
        &self,
        req: ResolveRequest,
    ) -> Result<(ResolveAnswer, ResolutionSignals), (ResolveError, ResolutionSignals)> {
        let sig = ResolutionSignals {
            qname_key: req.qname.clone(),
            pool: "test".into(),
            resolver_rtt_ms: 5,
            ..Default::default()
        };
        Ok((
            ResolveAnswer {
                records: vec![AnswerRecord::A(self.0)],
                source: ResolverSource::System,
                truncated: false,
                rtt: std::time::Duration::from_millis(5),
                min_rr_ttl: 60,
            },
            sig,
        ))
    }
}
