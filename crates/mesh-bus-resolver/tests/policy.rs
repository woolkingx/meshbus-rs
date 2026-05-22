use mesh_bus_resolver::policy::*;
use mesh_bus_resolver::types::{ServerPolicy, UpstreamScheme, UpstreamServer};
use std::net::SocketAddr;
use std::sync::atomic::AtomicUsize;

fn make_servers(n: usize) -> Vec<UpstreamServer> {
    (0..n)
        .map(|i| UpstreamServer {
            scheme: UpstreamScheme::Udp,
            addr: format!("127.0.0.{i}:53")
                .parse::<SocketAddr>()
                .expect("valid addr"),
        })
        .collect()
}

#[test]
fn round_robin_wraps_around() {
    let servers = make_servers(3);
    let counter = AtomicUsize::new(0);
    let a = select_round_robin(&servers, &counter);
    let b = select_round_robin(&servers, &counter);
    let c = select_round_robin(&servers, &counter);
    let d = select_round_robin(&servers, &counter); // wraps
    assert_eq!(a.addr, servers[0].addr);
    assert_eq!(b.addr, servers[1].addr);
    assert_eq!(c.addr, servers[2].addr);
    assert_eq!(d.addr, servers[0].addr);
}

#[test]
fn round_robin_single_server_always_returns_same() {
    let servers = make_servers(1);
    let counter = AtomicUsize::new(0);
    for _ in 0..5 {
        assert_eq!(select_round_robin(&servers, &counter).addr, servers[0].addr);
    }
}

#[test]
fn consistent_hash_stable_across_calls() {
    let servers = make_servers(3);
    let s1 = select_consistent_hash(&servers, "example.com.:A");
    let s2 = select_consistent_hash(&servers, "example.com.:A");
    assert_eq!(s1.addr, s2.addr);
}

#[test]
fn consistent_hash_different_qnames_can_differ() {
    let servers = make_servers(3);
    // With 3 servers and many distinct qnames, we expect at least two distinct servers
    let picked: std::collections::HashSet<String> = (0..30)
        .map(|i| {
            let s = select_consistent_hash(&servers, &format!("host{i}.example.com.:A"));
            format!("{}", s.addr)
        })
        .collect();
    assert!(
        picked.len() >= 2,
        "consistent_hash should distribute across servers"
    );
}

#[test]
fn fanout_k_zero_returns_empty() {
    let servers = make_servers(3);
    let result = select_fanout(&servers, 0);
    assert!(result.is_empty());
}

#[test]
fn fanout_k_one_returns_first() {
    let servers = make_servers(3);
    let result = select_fanout(&servers, 1);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].addr, servers[0].addr);
}

#[test]
fn fanout_k_larger_than_list_clamps_to_list_size() {
    let servers = make_servers(2);
    let result = select_fanout(&servers, 10);
    assert_eq!(result.len(), 2);
}

#[test]
fn fanout_deterministic_order() {
    let servers = make_servers(3);
    let a = select_fanout(&servers, 3);
    let b = select_fanout(&servers, 3);
    let addrs_a: Vec<_> = a.iter().map(|s| s.addr).collect();
    let addrs_b: Vec<_> = b.iter().map(|s| s.addr).collect();
    assert_eq!(addrs_a, addrs_b);
}

#[test]
fn server_policy_roundrobin_variant() {
    let _p: ServerPolicy = ServerPolicy::RoundRobin;
}
