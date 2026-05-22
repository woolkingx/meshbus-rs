use mesh_bus_resolver::*;

#[tokio::test(flavor = "multi_thread")]
async fn m3_resolves_localhost_via_special_use_before_libc() {
    // Even with empty pools, "localhost." must resolve loopback per RFC 6761
    let pool = Pool {
        id: "sys".into(),
        mode: PoolMode::SystemMode,
        servers: vec![],
        route_group: None,
    };
    let r = ResolverBuilder::new()
        .with_pool(pool)
        .with_default_pool("sys")
        .build()
        .expect("build");
    let (ans, _sig) = r
        .resolve(ResolveRequest {
            qname: "localhost.".into(),
            qtype: QType::A,
            consumer: ConsumerId("test".into()),
        })
        .await
        .expect("resolve");
    assert!(
        ans.records
            .iter()
            .any(|r| matches!(r, AnswerRecord::A(ip) if ip.is_loopback()))
    );
    assert_eq!(ans.source, ResolverSource::System);
}

#[tokio::test(flavor = "multi_thread")]
async fn m3_libc_resolves_real_loopback_address() {
    let pool = Pool {
        id: "sys".into(),
        mode: PoolMode::SystemMode,
        servers: vec![],
        route_group: None,
    };
    let r = ResolverBuilder::new()
        .with_pool(pool)
        .with_default_pool("sys")
        .build()
        .expect("build");
    // Use a literal that always parses
    let (ans, _) = r
        .resolve(ResolveRequest {
            qname: "127.0.0.1".into(),
            qtype: QType::A,
            consumer: ConsumerId("t".into()),
        })
        .await
        .expect("resolve");
    assert!(
        matches!(ans.records[0], AnswerRecord::A(ip) if ip == std::net::Ipv4Addr::new(127,0,0,1))
    );
}
