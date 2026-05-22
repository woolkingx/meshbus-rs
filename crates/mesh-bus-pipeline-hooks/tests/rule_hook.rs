use bytes::Bytes;
use mb_rule::types::{
    Action, FanOutParams, MatchExpr, Predicate, Rule, RuleChain, RuleNetwork, RuleScheduleHint,
};
use mesh_bus_core::kernel::{Event, KernelCtx, MetaValue, TypedMap, Verdict};
use mesh_bus_pipeline_hooks::context::{SharedHookCtx, clear, install};
use mesh_bus_pipeline_hooks::rule::rule_chain;
use std::sync::Arc;

fn install_chain(handle: tokio::runtime::Handle, rules: Vec<Rule>, default: Action) {
    install(SharedHookCtx {
        resolver: Arc::new(fixtures::NoopResolver),
        cache: Arc::new(mesh_bus_resolver::cache::DnsCache::new()),
        geoip: Arc::new(mb_geoip::GeoIpDb::empty()),
        geosite: Arc::new(mb_geosite::GeositeDb::empty()),
        rule_chain: Arc::new(RuleChain { rules, default }),
        rule_sets: Arc::new(mb_rule::RuleSetRegistry::empty()),
        candidates: Arc::new(vec![]),
        tokio: handle,
    });
}

fn event_with_transport_family(protocol: &str) -> Event {
    let mut event = Event {
        payload: Bytes::new(),
        meta: TypedMap::default(),
    };
    event.meta.net.protocol = Some(protocol.into());
    event
}

#[test]
fn rule_chain_without_shared_ctx_rejects() {
    clear();
    let mut event = Event {
        payload: Bytes::new(),
        meta: TypedMap::default(),
    };

    let v = rule_chain(&mut event, &mut KernelCtx::default());

    match v {
        Verdict::Reject(r) => assert_eq!(r.code, "hook_ctx_missing"),
        v => panic!("expected Reject, got {v:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn rule_chain_writes_route_group() {
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        install_chain(
            handle,
            vec![Rule {
                id: None,
                r#match: MatchExpr::Term(Predicate::DstGeoEq("CN".into())),
                action: Action::SetRouteGroup("cn-pool".into()),
            }],
            Action::Allow,
        );
        let mut event = event_with_transport_family("tcp");
        event
            .meta
            .ext
            .push(("geo_country", MetaValue::String("CN".into())));
        let v = rule_chain(&mut event, &mut KernelCtx::default());
        assert!(matches!(v, Verdict::Continue), "got {v:?}");
        assert_eq!(event.meta.policy.route_group.as_deref(), Some("cn-pool"));
    })
    .await
    .expect("blocking task completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn rule_chain_matches_generic_operation() {
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        install_chain(
            handle,
            vec![Rule {
                id: None,
                r#match: MatchExpr::Term(Predicate::OperationEq("connect".into())),
                action: Action::SetRouteGroup("stream-pool".into()),
            }],
            Action::Allow,
        );
        let mut event = event_with_transport_family("tcp");
        event
            .meta
            .ext
            .push(("operation", MetaValue::String("connect".into())));
        let v = rule_chain(&mut event, &mut KernelCtx::default());
        assert!(matches!(v, Verdict::Continue), "got {v:?}");
        assert_eq!(
            event.meta.policy.route_group.as_deref(),
            Some("stream-pool")
        );
    })
    .await
    .expect("blocking task completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn rule_chain_matches_generic_network_protocol() {
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        install_chain(
            handle,
            vec![Rule {
                id: None,
                r#match: MatchExpr::Term(Predicate::NetworkEq(RuleNetwork::Tcp)),
                action: Action::SetRouteGroup("stream-pool".into()),
            }],
            Action::Allow,
        );
        let mut event = event_with_transport_family("tcp");
        let v = rule_chain(&mut event, &mut KernelCtx::default());
        assert!(matches!(v, Verdict::Continue), "got {v:?}");
        assert_eq!(
            event.meta.policy.route_group.as_deref(),
            Some("stream-pool")
        );
    })
    .await
    .expect("blocking task completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn rule_chain_rejects_missing_l4_transport_family() {
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        install_chain(handle, vec![], Action::Allow);
        let mut event = Event {
            payload: Bytes::new(),
            meta: TypedMap::default(),
        };
        let v = rule_chain(&mut event, &mut KernelCtx::default());
        match v {
            Verdict::Reject(r) => assert_eq!(r.code, "missing_transport_family"),
            v => panic!("expected Reject for missing L4 transport family, got {v:?}"),
        }
    })
    .await
    .expect("blocking task completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn rule_chain_rejects_unknown_l4_transport_family() {
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        install_chain(handle, vec![], Action::Allow);
        let mut event = event_with_transport_family("tcp");
        event.meta.net.protocol = Some("socks5".into());
        let v = rule_chain(&mut event, &mut KernelCtx::default());
        match v {
            Verdict::Reject(r) => assert_eq!(r.code, "invalid_transport_family"),
            v => panic!("expected Reject for unknown L4 transport family, got {v:?}"),
        }
    })
    .await
    .expect("blocking task completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn rule_chain_rejects_invalid_src_ip_metadata() {
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        install_chain(handle, vec![], Action::Allow);
        let mut event = event_with_transport_family("tcp");
        event.meta.net.src_ip = Some("not-an-ip".into());
        let v = rule_chain(&mut event, &mut KernelCtx::default());
        match v {
            Verdict::Reject(r) => assert_eq!(r.code, "invalid_src_ip"),
            v => panic!("expected Reject for invalid src_ip, got {v:?}"),
        }
    })
    .await
    .expect("blocking task completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn rule_chain_rejects_invalid_dst_ip_primary_metadata() {
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        install_chain(handle, vec![], Action::Allow);
        let mut event = event_with_transport_family("tcp");
        event
            .meta
            .ext
            .push(("dst_ip_primary", MetaValue::String("not-an-ip".into())));
        let v = rule_chain(&mut event, &mut KernelCtx::default());
        match v {
            Verdict::Reject(r) => assert_eq!(r.code, "invalid_dst_ip_primary"),
            v => panic!("expected Reject for invalid dst_ip_primary, got {v:?}"),
        }
    })
    .await
    .expect("blocking task completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn rule_chain_writes_cost_bias_positive() {
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        install_chain(
            handle,
            vec![Rule {
                id: None,
                r#match: MatchExpr::Term(Predicate::AsnEq(13335)),
                action: Action::SetCostBias(500),
            }],
            Action::Allow,
        );
        let mut event = event_with_transport_family("tcp");
        event.meta.ext.push(("asn", MetaValue::U64(13335)));
        let v = rule_chain(&mut event, &mut KernelCtx::default());
        assert!(matches!(v, Verdict::Continue), "got {v:?}");
        let bias = event
            .meta
            .ext
            .iter()
            .find(|(k, _)| *k == "cost_bias")
            .expect("cost_bias filled");
        assert_eq!(bias.1, MetaValue::U64(500));
    })
    .await
    .expect("blocking task completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn rule_chain_negative_bias_uses_sign_bit() {
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        install_chain(
            handle,
            vec![Rule {
                id: None,
                r#match: MatchExpr::Term(Predicate::AsnEq(13335)),
                action: Action::SetCostBias(-200),
            }],
            Action::Allow,
        );
        let mut event = event_with_transport_family("tcp");
        event.meta.ext.push(("asn", MetaValue::U64(13335)));
        let _ = rule_chain(&mut event, &mut KernelCtx::default());
        let bias = event
            .meta
            .ext
            .iter()
            .find(|(k, _)| *k == "cost_bias")
            .expect("cost_bias filled");
        let expected = (1u64 << 63) | 200;
        assert_eq!(bias.1, MetaValue::U64(expected));
    })
    .await
    .expect("blocking task completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn rule_chain_bias_clamped_at_9000() {
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        install_chain(
            handle,
            vec![Rule {
                id: None,
                r#match: MatchExpr::Term(Predicate::AsnEq(1)),
                action: Action::SetCostBias(50_000),
            }],
            Action::Allow,
        );
        let mut event = event_with_transport_family("tcp");
        event.meta.ext.push(("asn", MetaValue::U64(1)));
        let _ = rule_chain(&mut event, &mut KernelCtx::default());
        let bias = event
            .meta
            .ext
            .iter()
            .find(|(k, _)| *k == "cost_bias")
            .expect("cost_bias filled");
        assert_eq!(bias.1, MetaValue::U64(9000));
    })
    .await
    .expect("blocking task completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn rule_chain_deny_returns_reject() {
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        install_chain(
            handle,
            vec![Rule {
                id: None,
                r#match: MatchExpr::Term(Predicate::DstGeoEq("XX".into())),
                action: Action::Deny,
            }],
            Action::Allow,
        );
        let mut event = event_with_transport_family("tcp");
        event
            .meta
            .ext
            .push(("geo_country", MetaValue::String("XX".into())));
        let v = rule_chain(&mut event, &mut KernelCtx::default());
        match v {
            Verdict::Reject(r) => assert_eq!(r.code, "denied_by_rule"),
            v => panic!("expected Reject, got {v:?}"),
        }
    })
    .await
    .expect("blocking task completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn rule_chain_schedule_hint_auto_preserves_core_auto_default() {
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        install_chain(
            handle,
            vec![Rule {
                id: None,
                r#match: MatchExpr::Term(Predicate::DstPortEq(443)),
                action: Action::SetScheduleHint(RuleScheduleHint::Auto),
            }],
            Action::Deny,
        );
        let mut event = event_with_transport_family("tcp");
        event.meta.net.dst_port = Some(443);
        let v = rule_chain(&mut event, &mut KernelCtx::default());
        assert!(matches!(v, Verdict::Continue), "got {v:?}");
        assert_eq!(
            event.meta.transport.schedule_hint, None,
            "metadata None is the pipeline representation of core ScheduleHint::Auto"
        );
    })
    .await
    .expect("blocking task completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn rule_chain_schedule_hint_fanout_writes_fanout_label() {
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        install_chain(
            handle,
            vec![Rule {
                id: None,
                r#match: MatchExpr::Term(Predicate::DstPortEq(443)),
                action: Action::SetScheduleHint(RuleScheduleHint::FanOut {
                    fanout: FanOutParams { k: 2 },
                }),
            }],
            Action::Deny,
        );
        let mut event = event_with_transport_family("tcp");
        event.meta.net.dst_port = Some(443);
        let v = rule_chain(&mut event, &mut KernelCtx::default());
        assert!(matches!(v, Verdict::Continue), "got {v:?}");
        assert_eq!(
            event.meta.transport.schedule_hint,
            Some(mesh_bus_core::kernel::ScheduleHintLabel::FanOut)
        );
        assert_eq!(event.meta.transport.schedule_fanout_k, Some(2));
    })
    .await
    .expect("blocking task completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn rule_chain_default_allow_is_continue() {
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        install_chain(handle, vec![], Action::Allow);
        let mut event = event_with_transport_family("tcp");
        let v = rule_chain(&mut event, &mut KernelCtx::default());
        assert!(matches!(v, Verdict::Continue), "got {v:?}");
        assert_eq!(event.meta.policy.route_group, None);
    })
    .await
    .expect("blocking task completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn rule_chain_unsupported_forward_action_rejects() {
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        install_chain(handle, vec![], Action::SetResolverPool("dns-cn".into()));
        let mut event = event_with_transport_family("tcp");
        let v = rule_chain(&mut event, &mut KernelCtx::default());
        match v {
            Verdict::Reject(reason) => assert_eq!(reason.code, "unsupported_forward_rule_action"),
            other => panic!("unsupported forward action must fail closed, got {other:?}"),
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
            unreachable!("rule_chain hook must not call resolver")
        }
    }
}
