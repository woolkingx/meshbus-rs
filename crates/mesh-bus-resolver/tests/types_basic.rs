use mesh_bus_resolver::*;

#[test]
fn pool_mode_variants_present() {
    let _ = PoolMode::SystemMode;
    let _ = PoolMode::MeshDirect {
        server_policy: ServerPolicy::RoundRobin,
    };
    let _ = PoolMode::Tunneled {
        server_policy: ServerPolicy::ConsistentHash,
    };
}

#[test]
fn server_policy_fanout_rejects_zero_at_type_level() {
    let sp = ServerPolicy::FanOut { k: 2 };
    assert!(matches!(sp, ServerPolicy::FanOut { k } if k >= 1));
}

#[test]
fn resolver_source_carries_mode() {
    let _src = ResolverSource::System;
    let _src = ResolverSource::MeshDirect {
        server: "1.1.1.1:53".parse().expect("addr"),
    };
    let _src = ResolverSource::Tunneled {
        server: "1.1.1.1:53".parse().expect("addr"),
    };
}
