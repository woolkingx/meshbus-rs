//! Verifies that rule_ctx_build maps SOCKS5 connection state onto mb_rule::RuleCtx
//! without leaking bus-core L4 types into the L7 stitcher.

use mb_endpoint::Endpoint;
use mb_rule::{RuleNetwork, RuleSessionShape, RuleSocks5Command};
use mesh_bus_ingress_socks5::rule_ctx_build::{
    build_connect_ctx, build_udp_associate_ctx, build_udp_packet_ctx,
};
use std::net::{IpAddr, SocketAddr};

fn peer(ip: &str, port: u16) -> SocketAddr {
    SocketAddr::new(ip.parse::<IpAddr>().expect("ip literal"), port)
}

#[test]
fn connect_hostname_target_fills_hostname_and_port_only() {
    let target = Endpoint::new("Example.COM", 443).expect("endpoint");
    let ctx = build_connect_ctx(peer("203.0.113.5", 51242), &target, None);

    assert_eq!(ctx.hostname.as_deref(), Some("example.com"));
    assert_eq!(ctx.dst_ip, None);
    assert_eq!(ctx.dst_port, Some(443));
    assert_eq!(
        ctx.src_ip,
        Some("203.0.113.5".parse::<IpAddr>().expect("src"))
    );
    assert_eq!(ctx.network, Some(RuleNetwork::Tcp));
    assert_eq!(ctx.session_shape, Some(RuleSessionShape::Stream));
    assert_eq!(ctx.operation.as_deref(), Some("connect"));
    assert_eq!(ctx.socks5_command, Some(RuleSocks5Command::Connect));
}

#[test]
fn connect_ip_literal_target_fills_dst_ip_and_hostname_none() {
    let target = Endpoint::new("198.51.100.7", 80).expect("endpoint");
    let ctx = build_connect_ctx(peer("198.51.100.10", 60000), &target, None);

    assert_eq!(ctx.hostname, None);
    assert_eq!(
        ctx.dst_ip,
        Some("198.51.100.7".parse::<IpAddr>().expect("dst"))
    );
    assert_eq!(ctx.dst_port, Some(80));
    assert_eq!(ctx.network, Some(RuleNetwork::Tcp));
    assert_eq!(ctx.session_shape, Some(RuleSessionShape::Stream));
    assert_eq!(ctx.operation.as_deref(), Some("connect"));
    assert_eq!(ctx.socks5_command, Some(RuleSocks5Command::Connect));
}

#[test]
fn udp_associate_uses_udp_network_and_datagram_shape() {
    let declared = Endpoint::new("203.0.113.5", 51242).expect("endpoint");
    let ctx = build_udp_associate_ctx(peer("203.0.113.5", 51242), &declared, None);

    assert_eq!(ctx.network, Some(RuleNetwork::Udp));
    assert_eq!(ctx.session_shape, Some(RuleSessionShape::Datagram));
    assert_eq!(ctx.operation.as_deref(), Some("datagram_associate"));
    assert_eq!(ctx.socks5_command, Some(RuleSocks5Command::UdpAssociate));
    assert_eq!(
        ctx.src_ip,
        Some("203.0.113.5".parse::<IpAddr>().expect("src"))
    );
    // No target-specific dst at associate-open time
    assert_eq!(ctx.dst_ip, None);
    assert_eq!(ctx.hostname, None);
    assert_eq!(ctx.dst_port, None);
}

#[test]
fn udp_packet_ctx_fills_target_per_datagram() {
    let target = Endpoint::new("dns.example.net", 53).expect("endpoint");
    let ctx = build_udp_packet_ctx(peer("203.0.113.5", 51242), &target, None);

    assert_eq!(ctx.hostname.as_deref(), Some("dns.example.net"));
    assert_eq!(ctx.dst_ip, None);
    assert_eq!(ctx.dst_port, Some(53));
    assert_eq!(ctx.network, Some(RuleNetwork::Udp));
    assert_eq!(ctx.session_shape, Some(RuleSessionShape::Datagram));
    assert_eq!(ctx.operation.as_deref(), Some("datagram_send"));
    assert_eq!(ctx.socks5_command, Some(RuleSocks5Command::UdpAssociate));
}

#[test]
fn hostname_is_lowercased() {
    let target = Endpoint::new("WWW.EXAMPLE.CN", 443).expect("endpoint");
    let ctx = build_connect_ctx(peer("198.51.100.10", 11111), &target, None);
    assert_eq!(ctx.hostname.as_deref(), Some("www.example.cn"));
}

#[test]
fn authenticated_user_threads_into_connect_ctx() {
    let target = Endpoint::new("example.com", 443).expect("endpoint");
    let ctx = build_connect_ctx(peer("203.0.113.5", 51242), &target, Some("alice"));
    assert_eq!(ctx.authenticated_user.as_deref(), Some("alice"));
}

#[test]
fn authenticated_user_threads_into_udp_associate_ctx() {
    let declared = Endpoint::new("203.0.113.5", 51242).expect("endpoint");
    let ctx = build_udp_associate_ctx(peer("203.0.113.5", 51242), &declared, Some("bob"));
    assert_eq!(ctx.authenticated_user.as_deref(), Some("bob"));
}

#[test]
fn authenticated_user_threads_into_udp_packet_ctx() {
    let target = Endpoint::new("dns.example.net", 53).expect("endpoint");
    let ctx = build_udp_packet_ctx(peer("203.0.113.5", 51242), &target, Some("carol"));
    assert_eq!(ctx.authenticated_user.as_deref(), Some("carol"));
}

#[test]
fn authenticated_user_none_when_no_auth() {
    let target = Endpoint::new("example.com", 443).expect("endpoint");
    let ctx = build_connect_ctx(peer("203.0.113.5", 51242), &target, None);
    assert_eq!(ctx.authenticated_user, None);
}
