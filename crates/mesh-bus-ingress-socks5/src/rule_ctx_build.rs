//! Maps SOCKS5 connection state onto `mb_rule::RuleCtx`.
//!
//! L7 stitcher hook point: produces a flat rule context from peer + target +
//! SOCKS5 command shape. No bus-core L4 types appear here.

use mb_endpoint::Endpoint;
use mb_rule::{RuleCtx, RuleNetwork, RuleSessionShape, RuleSocks5Command};
use std::net::{IpAddr, SocketAddr};

fn host_to_fields(target: &Endpoint) -> (Option<String>, Option<IpAddr>) {
    let host = target.host();
    match host.parse::<IpAddr>() {
        Ok(ip) => (None, Some(ip)),
        Err(_) => (Some(host.to_ascii_lowercase()), None),
    }
}

pub fn build_connect_ctx(
    peer: SocketAddr,
    target: &Endpoint,
    authenticated_user: Option<&str>,
) -> RuleCtx {
    let (hostname, dst_ip) = host_to_fields(target);
    RuleCtx {
        src_ip: Some(peer.ip()),
        dst_ip,
        dst_port: Some(target.port()),
        network: Some(RuleNetwork::Tcp),
        session_shape: Some(RuleSessionShape::Stream),
        operation: Some("connect".into()),
        socks5_command: Some(RuleSocks5Command::Connect),
        hostname,
        authenticated_user: authenticated_user.map(|s| s.to_string()),
        ..RuleCtx::empty()
    }
}

pub fn build_bind_ctx(
    peer: SocketAddr,
    declared: &Endpoint,
    authenticated_user: Option<&str>,
) -> RuleCtx {
    let (hostname, dst_ip) = host_to_fields(declared);
    RuleCtx {
        src_ip: Some(peer.ip()),
        dst_ip,
        dst_port: Some(declared.port()),
        network: Some(RuleNetwork::Tcp),
        session_shape: Some(RuleSessionShape::Stream),
        operation: Some("bind".into()),
        socks5_command: Some(RuleSocks5Command::Bind),
        hostname,
        authenticated_user: authenticated_user.map(|s| s.to_string()),
        ..RuleCtx::empty()
    }
}

pub fn build_udp_associate_ctx(
    peer: SocketAddr,
    _declared_peer: &Endpoint,
    authenticated_user: Option<&str>,
) -> RuleCtx {
    RuleCtx {
        src_ip: Some(peer.ip()),
        network: Some(RuleNetwork::Udp),
        session_shape: Some(RuleSessionShape::Datagram),
        operation: Some("datagram_associate".into()),
        socks5_command: Some(RuleSocks5Command::UdpAssociate),
        authenticated_user: authenticated_user.map(|s| s.to_string()),
        ..RuleCtx::empty()
    }
}

pub fn build_udp_packet_ctx(
    peer: SocketAddr,
    target: &Endpoint,
    authenticated_user: Option<&str>,
) -> RuleCtx {
    let (hostname, dst_ip) = host_to_fields(target);
    RuleCtx {
        src_ip: Some(peer.ip()),
        dst_ip,
        dst_port: Some(target.port()),
        network: Some(RuleNetwork::Udp),
        session_shape: Some(RuleSessionShape::Datagram),
        operation: Some("datagram_send".into()),
        socks5_command: Some(RuleSocks5Command::UdpAssociate),
        hostname,
        authenticated_user: authenticated_user.map(|s| s.to_string()),
        ..RuleCtx::empty()
    }
}
