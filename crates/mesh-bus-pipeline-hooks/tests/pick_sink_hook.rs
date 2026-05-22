use bytes::Bytes;
use mesh_bus_core::kernel::{Event, KernelCtx, TypedMap, Verdict};
use mesh_bus_pipeline_hooks::context::{ExitCandidate, SharedHookCtx, install};
use mesh_bus_pipeline_hooks::pick_sink::pick_sink_cake;
use std::sync::Arc;

fn install_with(handle: tokio::runtime::Handle, cands: Vec<ExitCandidate>) {
    install(SharedHookCtx {
        resolver: Arc::new(fixtures::NoopResolver),
        cache: Arc::new(mesh_bus_resolver::cache::DnsCache::new()),
        geoip: Arc::new(mb_geoip::GeoIpDb::empty()),
        geosite: Arc::new(mb_geosite::GeositeDb::empty()),
        rule_chain: Arc::new(mb_rule::RuleChain {
            rules: vec![],
            default: mb_rule::Action::Allow,
        }),
        rule_sets: Arc::new(mb_rule::RuleSetRegistry::empty()),
        candidates: Arc::new(cands),
        tokio: handle,
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn pick_sink_returns_accept_with_top_ranked() {
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        install_with(
            handle,
            vec![
                ExitCandidate {
                    sink_id: "fast".into(),
                    route_groups: vec![],
                    supports_stream: true,
                    supports_datagram: false,
                    rtt_ms: 10,
                    success_rate: 1.0,
                    jitter_ms: 1,
                },
                ExitCandidate {
                    sink_id: "slow".into(),
                    route_groups: vec![],
                    supports_stream: true,
                    supports_datagram: false,
                    rtt_ms: 200,
                    success_rate: 0.9,
                    jitter_ms: 50,
                },
            ],
        );
        let mut event = Event {
            payload: Bytes::new(),
            meta: TypedMap::default(),
        };
        event.meta.net.protocol = Some("tcp".into());
        event.meta.trace.flow_id = Some("flow:test".into());
        let v = pick_sink_cake(&mut event, &mut KernelCtx::default());
        match v {
            Verdict::Accept(sid) => assert_eq!(sid.as_str(), "fast"),
            v => panic!("expected Accept, got {v:?}"),
        }
    })
    .await
    .expect("blocking task completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn pick_sink_route_group_filter_pins_to_match() {
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        install_with(
            handle,
            vec![
                ExitCandidate {
                    sink_id: "a".into(),
                    route_groups: vec!["a-only".into()],
                    supports_stream: true,
                    supports_datagram: false,
                    rtt_ms: 100,
                    success_rate: 1.0,
                    jitter_ms: 0,
                },
                ExitCandidate {
                    sink_id: "b".into(),
                    route_groups: vec![],
                    supports_stream: true,
                    supports_datagram: false,
                    rtt_ms: 50,
                    success_rate: 1.0,
                    jitter_ms: 0,
                },
            ],
        );
        let mut event = Event {
            payload: Bytes::new(),
            meta: TypedMap::default(),
        };
        event.meta.net.protocol = Some("tcp".into());
        event.meta.policy.route_group = Some("a-only".into());
        event.meta.trace.flow_id = Some("flow:test".into());
        let v = pick_sink_cake(&mut event, &mut KernelCtx::default());
        match v {
            Verdict::Accept(sid) => assert_eq!(sid.as_str(), "a"),
            v => panic!("expected Accept(a) via route_group filter, got {v:?}"),
        }
    })
    .await
    .expect("blocking task completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn pick_sink_rejects_when_no_candidates_match() {
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        install_with(
            handle,
            vec![ExitCandidate {
                sink_id: "a".into(),
                route_groups: vec!["not-this".into()],
                supports_stream: true,
                supports_datagram: false,
                rtt_ms: 10,
                success_rate: 1.0,
                jitter_ms: 0,
            }],
        );
        let mut event = Event {
            payload: Bytes::new(),
            meta: TypedMap::default(),
        };
        event.meta.net.protocol = Some("tcp".into());
        event.meta.policy.route_group = Some("only-this".into());
        event.meta.trace.flow_id = Some("flow:test".into());
        let v = pick_sink_cake(&mut event, &mut KernelCtx::default());
        match v {
            Verdict::Reject(r) => assert_eq!(r.code, "no_usable_exit"),
            v => panic!("expected Reject, got {v:?}"),
        }
    })
    .await
    .expect("blocking task completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn pick_sink_rejects_when_candidate_list_is_empty() {
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        install_with(handle, vec![]);
        let mut event = Event {
            payload: Bytes::new(),
            meta: TypedMap::default(),
        };
        event.meta.net.protocol = Some("tcp".into());
        event.meta.trace.flow_id = Some("flow:test".into());
        let v = pick_sink_cake(&mut event, &mut KernelCtx::default());
        match v {
            Verdict::Reject(r) => assert_eq!(r.code, "no_usable_exit"),
            v => panic!("expected Reject, got {v:?}"),
        }
    })
    .await
    .expect("blocking task completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn pick_sink_rejects_missing_l4_transport_family() {
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        install_with(
            handle,
            vec![ExitCandidate {
                sink_id: "a".into(),
                route_groups: vec![],
                supports_stream: true,
                supports_datagram: true,
                rtt_ms: 10,
                success_rate: 1.0,
                jitter_ms: 0,
            }],
        );
        let mut event = Event {
            payload: Bytes::new(),
            meta: TypedMap::default(),
        };
        event.meta.trace.flow_id = Some("flow:test".into());
        let v = pick_sink_cake(&mut event, &mut KernelCtx::default());
        match v {
            Verdict::Reject(r) => assert_eq!(r.code, "missing_transport_family"),
            v => panic!("expected Reject for missing L4 transport family, got {v:?}"),
        }
    })
    .await
    .expect("blocking task completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn pick_sink_rejects_unknown_l4_transport_family() {
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        install_with(
            handle,
            vec![ExitCandidate {
                sink_id: "a".into(),
                route_groups: vec![],
                supports_stream: true,
                supports_datagram: true,
                rtt_ms: 10,
                success_rate: 1.0,
                jitter_ms: 0,
            }],
        );
        let mut event = Event {
            payload: Bytes::new(),
            meta: TypedMap::default(),
        };
        event.meta.net.protocol = Some("socks5".into());
        event.meta.trace.flow_id = Some("flow:test".into());
        let v = pick_sink_cake(&mut event, &mut KernelCtx::default());
        match v {
            Verdict::Reject(r) => assert_eq!(r.code, "invalid_transport_family"),
            v => panic!("expected Reject for unknown L4 transport family, got {v:?}"),
        }
    })
    .await
    .expect("blocking task completed");
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
            unreachable!("pick_sink hook must not call resolver")
        }
    }
}
