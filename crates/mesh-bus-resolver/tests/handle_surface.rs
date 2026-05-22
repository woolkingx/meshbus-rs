use mesh_bus_resolver::*;

#[tokio::test]
async fn resolver_builder_requires_at_least_one_pool() {
    let err = ResolverBuilder::new()
        .build()
        .expect_err("must reject empty");
    let msg = format!("{err}").to_lowercase();
    assert!(msg.contains("pool") || msg.contains("at least one"));
}

#[tokio::test]
async fn resolver_builder_rejects_duplicate_pool_id() {
    let pool_a = Pool {
        id: "p".into(),
        mode: PoolMode::SystemMode,
        servers: vec![],
        route_group: None,
    };
    let err = ResolverBuilder::new()
        .with_pool(pool_a.clone())
        .with_pool(pool_a)
        .build()
        .expect_err("must reject duplicate");
    assert!(format!("{err}").to_lowercase().contains("duplicate"));
}
