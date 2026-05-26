//! Access-log projection and SOCKS5 affinity keys.

use mb_endpoint::Endpoint;
use mesh_bus_core::BusSessionInfo;
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone)]
pub(crate) struct AccessTrace {
    pub(crate) matched_rule_id: String,
    pub(crate) matched_rule_index: String,
    pub(crate) default_used: bool,
    pub(crate) action: String,
    pub(crate) route_group: String,
    pub(crate) schedule_hint: String,
}

pub(crate) fn log_connect_open(
    peer: SocketAddr,
    target: &Endpoint,
    authenticated_user: Option<&str>,
    trace: Option<&AccessTrace>,
) {
    let user = authenticated_user.unwrap_or("-");
    match trace {
        Some(t) => tracing::info!(
            target: "mesh_bus.ingress.socks5",
            %peer,
            target = %target,
            authenticated_user = %user,
            matched_rule_id = %t.matched_rule_id,
            matched_rule_index = %t.matched_rule_index,
            default_used = t.default_used,
            action = %t.action,
            route_group = %t.route_group,
            schedule_hint = %t.schedule_hint,
            "connect_open"
        ),
        None => tracing::info!(
            target: "mesh_bus.ingress.socks5",
            %peer,
            target = %target,
            authenticated_user = %user,
            "connect_open"
        ),
    }
}

pub(crate) fn log_flow_opened(
    peer: SocketAddr,
    target: &Endpoint,
    info: &BusSessionInfo,
    trace: Option<&AccessTrace>,
) {
    let primary = info.paths.get(info.primary);
    let selected_exit = primary.map(|path| path.exit_id.0.as_str()).unwrap_or("-");
    let route_group = trace.map(|t| t.route_group.as_str()).unwrap_or("-");
    let schedule_hint = trace.map(|t| t.schedule_hint.as_str()).unwrap_or("-");
    tracing::info!(
        target: "mesh_bus.ingress.socks5",
        %peer,
        target = %target,
        flow_id = %info.flow_id.0,
        packet_id = 0u64,
        exit_id = %selected_exit,
        selected_exit = %selected_exit,
        route_group = %route_group,
        schedule_hint = %schedule_hint,
        candidate_count = info.paths.len() as u64,
        success = true,
        "flow_opened"
    );
}

pub(crate) fn log_udp_associate_open(
    peer: SocketAddr,
    declared_peer: &Endpoint,
    authenticated_user: Option<&str>,
    trace: Option<&AccessTrace>,
) {
    let user = authenticated_user.unwrap_or("-");
    match trace {
        Some(t) => tracing::info!(
            target: "mesh_bus.ingress.socks5",
            %peer,
            declared_peer = %declared_peer,
            authenticated_user = %user,
            matched_rule_id = %t.matched_rule_id,
            matched_rule_index = %t.matched_rule_index,
            default_used = t.default_used,
            action = %t.action,
            route_group = %t.route_group,
            schedule_hint = %t.schedule_hint,
            "udp_associate_open"
        ),
        None => tracing::info!(
            target: "mesh_bus.ingress.socks5",
            %peer,
            declared_peer = %declared_peer,
            authenticated_user = %user,
            "udp_associate_open"
        ),
    }
}

pub(crate) fn socks5_source_key(peer: &SocketAddr) -> String {
    peer.ip().to_string()
}

pub(crate) fn socks5_target_key(target: &Endpoint) -> String {
    let host = target.host();
    let normalized = match host.parse::<IpAddr>() {
        Ok(ip) => ip.to_string(),
        Err(_) => host.to_ascii_lowercase(),
    };
    format!("{normalized}:{}", target.port())
}
