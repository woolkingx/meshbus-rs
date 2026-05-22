use bytes::Bytes;
use mesh_bus_core::kernel::{Event, KernelCtx, MetaValue, TypedMap, Verdict};
use mesh_bus_pipeline_hooks::context::{SharedHookCtx, install};
use mesh_bus_pipeline_hooks::resolve::resolve_or_recover;
use std::sync::Arc;

// Hooks are sync — production wires them from inside `tokio::task::spawn_blocking`
// so block_on doesn't deadlock on the runtime worker. Tests mirror that pattern
// via `#[tokio::test(flavor = "multi_thread")]` + `spawn_blocking`.

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn resolve_hook_fills_dst_ip_primary_from_host() {
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        install(SharedHookCtx {
            resolver: Arc::new(fixtures::FixedResolver::new("93.184.216.34")),
            cache: Arc::new(mesh_bus_resolver::cache::DnsCache::new()),
            geoip: Arc::new(mb_geoip::GeoIpDb::empty()),
            geosite: Arc::new(mb_geosite::GeositeDb::empty()),
            rule_chain: Arc::new(mb_rule::RuleChain {
                rules: vec![],
                default: mb_rule::Action::Allow,
            }),
            rule_sets: Arc::new(mb_rule::RuleSetRegistry::empty()),
            candidates: Arc::new(vec![]),
            tokio: handle,
        });

        let mut event = Event {
            payload: Bytes::new(),
            meta: TypedMap::default(),
        };
        event.meta.net.dst_host = Some("example.com".into());
        event.meta.net.dst_port = Some(80);
        let mut ctx = KernelCtx::default();

        let verdict = resolve_or_recover(&mut event, &mut ctx);
        assert!(matches!(verdict, Verdict::Continue), "got {verdict:?}");

        let ip = event
            .meta
            .ext
            .iter()
            .find(|(k, _)| *k == "dst_ip_primary")
            .map(|(_, v)| v.clone())
            .expect("dst_ip_primary filled");
        assert_eq!(ip, MetaValue::String("93.184.216.34".into()));

        let mode = event
            .meta
            .ext
            .iter()
            .find(|(k, _)| *k == "resolution_mode")
            .expect("resolution_mode filled");
        assert_eq!(mode.1, MetaValue::String("m3".into()));

        let dst_ips = event
            .meta
            .ext
            .iter()
            .find(|(k, _)| *k == "dst_ips")
            .expect("dst_ips packed");
        match &dst_ips.1 {
            MetaValue::Bytes(b) => assert_eq!(&b[..], &[4, 93, 184, 216, 34]),
            v => panic!("dst_ips not Bytes: {v:?}"),
        }
    })
    .await
    .expect("blocking task completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn resolve_hook_rejects_when_neither_host_nor_ip() {
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        install(SharedHookCtx {
            resolver: Arc::new(fixtures::FixedResolver::new("0.0.0.0")),
            cache: Arc::new(mesh_bus_resolver::cache::DnsCache::new()),
            geoip: Arc::new(mb_geoip::GeoIpDb::empty()),
            geosite: Arc::new(mb_geosite::GeositeDb::empty()),
            rule_chain: Arc::new(mb_rule::RuleChain {
                rules: vec![],
                default: mb_rule::Action::Allow,
            }),
            rule_sets: Arc::new(mb_rule::RuleSetRegistry::empty()),
            candidates: Arc::new(vec![]),
            tokio: handle,
        });

        let mut event = Event {
            payload: Bytes::new(),
            meta: TypedMap::default(),
        };
        let mut ctx = KernelCtx::default();
        let verdict = resolve_or_recover(&mut event, &mut ctx);
        match verdict {
            Verdict::Reject(r) => assert_eq!(r.code, "no_target"),
            v => panic!("expected Reject, got {v:?}"),
        }
    })
    .await
    .expect("blocking task completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn resolve_hook_rejects_empty_dst_host() {
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        install(SharedHookCtx {
            resolver: Arc::new(fixtures::FixedResolver::new("0.0.0.0")),
            cache: Arc::new(mesh_bus_resolver::cache::DnsCache::new()),
            geoip: Arc::new(mb_geoip::GeoIpDb::empty()),
            geosite: Arc::new(mb_geosite::GeositeDb::empty()),
            rule_chain: Arc::new(mb_rule::RuleChain {
                rules: vec![],
                default: mb_rule::Action::Allow,
            }),
            rule_sets: Arc::new(mb_rule::RuleSetRegistry::empty()),
            candidates: Arc::new(vec![]),
            tokio: handle,
        });

        let mut event = Event {
            payload: Bytes::new(),
            meta: TypedMap::default(),
        };
        event.meta.net.dst_host = Some(String::new());
        let verdict = resolve_or_recover(&mut event, &mut KernelCtx::default());
        match verdict {
            Verdict::Reject(r) => assert_eq!(r.code, "invalid_dst_host"),
            v => panic!("expected Reject for empty dst_host, got {v:?}"),
        }
    })
    .await
    .expect("blocking task completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn resolve_hook_passthrough_ip_when_only_dst_ip_primary() {
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        install(SharedHookCtx {
            resolver: Arc::new(fixtures::FixedResolver::new("0.0.0.0")),
            cache: Arc::new(mesh_bus_resolver::cache::DnsCache::new()),
            geoip: Arc::new(mb_geoip::GeoIpDb::empty()),
            geosite: Arc::new(mb_geosite::GeositeDb::empty()),
            rule_chain: Arc::new(mb_rule::RuleChain {
                rules: vec![],
                default: mb_rule::Action::Allow,
            }),
            rule_sets: Arc::new(mb_rule::RuleSetRegistry::empty()),
            candidates: Arc::new(vec![]),
            tokio: handle,
        });

        let mut event = Event {
            payload: Bytes::new(),
            meta: TypedMap::default(),
        };
        event
            .meta
            .ext
            .push(("dst_ip_primary", MetaValue::String("8.8.8.8".into())));
        let mut ctx = KernelCtx::default();
        let verdict = resolve_or_recover(&mut event, &mut ctx);
        assert!(matches!(verdict, Verdict::Continue), "got {verdict:?}");

        let mode = event
            .meta
            .ext
            .iter()
            .find(|(k, _)| *k == "resolution_mode")
            .expect("resolution_mode filled");
        assert_eq!(mode.1, MetaValue::String("passthrough_ip".into()));

        let dst_ips = event
            .meta
            .ext
            .iter()
            .find(|(k, _)| *k == "dst_ips")
            .expect("dst_ips packed");
        match &dst_ips.1 {
            MetaValue::Bytes(b) => assert_eq!(&b[..], &[4, 8, 8, 8, 8]),
            v => panic!("dst_ips not Bytes: {v:?}"),
        }
    })
    .await
    .expect("blocking task completed");
}

mod fixtures {
    use async_trait::async_trait;
    use mesh_bus_resolver::data_handle::ResolverHandle;
    use mesh_bus_resolver::types::*;

    pub struct FixedResolver(pub std::net::Ipv4Addr);

    impl FixedResolver {
        pub fn new(ip: &str) -> Self {
            Self(ip.parse().expect("ipv4 literal parses"))
        }
    }

    #[async_trait]
    impl ResolverHandle for FixedResolver {
        async fn resolve(
            &self,
            req: ResolveRequest,
        ) -> Result<(ResolveAnswer, ResolutionSignals), (ResolveError, ResolutionSignals)> {
            let sig = ResolutionSignals {
                qname_key: req.qname.clone(),
                pool: "fixed".into(),
                resolver_rtt_ms: 7,
                ..Default::default()
            };
            Ok((
                ResolveAnswer {
                    records: vec![AnswerRecord::A(self.0)],
                    source: ResolverSource::System,
                    truncated: false,
                    rtt: std::time::Duration::from_millis(7),
                    min_rr_ttl: 60,
                },
                sig,
            ))
        }
    }
}
