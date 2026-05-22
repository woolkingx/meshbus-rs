use bytes::Bytes;
use mesh_bus_core::kernel::{Event, KernelCtx, MetaValue, TypedMap, Verdict};
use mesh_bus_pipeline_hooks::context::{SharedHookCtx, install};
use mesh_bus_pipeline_hooks::geo::enrich_geo_asn;
use std::sync::Arc;

// Tests wrap their bodies in spawn_blocking to mirror production ingress:
// the hook is sync, but SharedHookCtx is installed in a thread-local that
// must be re-installed per blocking worker. Using `flavor = "multi_thread"`
// + `spawn_blocking` keeps us off the runtime worker entirely.

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn enrich_with_empty_db_writes_xx_zero() {
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
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
            candidates: Arc::new(vec![]),
            tokio: handle,
        });

        let mut event = Event {
            payload: Bytes::new(),
            meta: TypedMap::default(),
        };
        event.meta.ext.push((
            "dst_ips",
            MetaValue::Bytes(Bytes::from(vec![4, 1, 1, 1, 1])),
        ));
        let mut ctx = KernelCtx::default();
        let verdict = enrich_geo_asn(&mut event, &mut ctx);
        assert!(matches!(verdict, Verdict::Continue), "got {verdict:?}");

        let geo = event
            .meta
            .ext
            .iter()
            .find(|(k, _)| *k == "geo_country")
            .expect("geo_country filled");
        assert_eq!(geo.1, MetaValue::String("XX".into()));

        let asn = event
            .meta
            .ext
            .iter()
            .find(|(k, _)| *k == "asn")
            .expect("asn filled");
        assert_eq!(asn.1, MetaValue::U64(0));

        let tags = event
            .meta
            .ext
            .iter()
            .find(|(k, _)| *k == "geosite_tags")
            .expect("geosite_tags filled");
        match &tags.1 {
            MetaValue::Bytes(b) => {
                assert!(b.is_empty(), "empty geosite DB should emit empty tags")
            }
            v => panic!("geosite_tags not Bytes: {v:?}"),
        }
    })
    .await
    .expect("blocking task completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn enrich_writes_geosite_tags_from_dst_host() {
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        install(SharedHookCtx {
            resolver: Arc::new(fixtures::NoopResolver),
            cache: Arc::new(mesh_bus_resolver::cache::DnsCache::new()),
            geoip: Arc::new(mb_geoip::GeoIpDb::empty()),
            geosite: Arc::new(
                mb_geosite::GeositeDb::parse("ad:ads.example.com\n")
                    .expect("parse geosite fixture"),
            ),
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
        event.meta.net.dst_host = Some("cdn.ads.example.com".into());
        event.meta.ext.push((
            "dst_ips",
            MetaValue::Bytes(Bytes::from(vec![4, 1, 1, 1, 1])),
        ));

        let verdict = enrich_geo_asn(&mut event, &mut KernelCtx::default());
        assert!(matches!(verdict, Verdict::Continue), "got {verdict:?}");
        let tags = event
            .meta
            .ext
            .iter()
            .find(|(k, _)| *k == "geosite_tags")
            .expect("geosite_tags filled");
        assert_eq!(tags.1, MetaValue::Bytes(Bytes::from_static(b"ad")));
    })
    .await
    .expect("blocking task completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn enrich_continues_when_dst_ips_missing() {
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
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
            candidates: Arc::new(vec![]),
            tokio: handle,
        });

        let mut event = Event {
            payload: Bytes::new(),
            meta: TypedMap::default(),
        };
        let verdict = enrich_geo_asn(&mut event, &mut KernelCtx::default());
        assert!(matches!(verdict, Verdict::Continue), "got {verdict:?}");

        assert!(event.meta.ext.iter().all(|(k, _)| *k != "geo_country"));
        assert!(event.meta.ext.iter().all(|(k, _)| *k != "asn"));
    })
    .await
    .expect("blocking task completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn enrich_rejects_malformed_dst_ips() {
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
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
            .push(("dst_ips", MetaValue::Bytes(Bytes::from_static(&[4, 1, 2]))));
        let verdict = enrich_geo_asn(&mut event, &mut KernelCtx::default());
        match verdict {
            Verdict::Reject(r) => assert_eq!(r.code, "invalid_dst_ips"),
            v => panic!("expected Reject for malformed dst_ips, got {v:?}"),
        }
    })
    .await
    .expect("blocking task completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn enrich_decodes_ipv6_first_record() {
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
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
            candidates: Arc::new(vec![]),
            tokio: handle,
        });

        let mut buf = vec![16u8];
        buf.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ]);
        let mut event = Event {
            payload: Bytes::new(),
            meta: TypedMap::default(),
        };
        event
            .meta
            .ext
            .push(("dst_ips", MetaValue::Bytes(Bytes::from(buf))));
        let verdict = enrich_geo_asn(&mut event, &mut KernelCtx::default());
        assert!(matches!(verdict, Verdict::Continue), "got {verdict:?}");

        let geo = event
            .meta
            .ext
            .iter()
            .find(|(k, _)| *k == "geo_country")
            .expect("geo_country filled for v6");
        assert_eq!(geo.1, MetaValue::String("XX".into()));
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
            unreachable!("geo hook must not call resolver")
        }
    }
}
