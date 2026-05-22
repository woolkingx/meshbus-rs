//! Builds target-bearing `Event { TypedMap }` values from SOCKS5 connection
//! state for the event-pipeline kernel. CONNECT and UDP relay packets carry a
//! real destination and may run PipelineRuntime; UDP ASSOCIATE control only
//! opens the relay and is intentionally not represented here. Hostnames are
//! lowercased; IP literals go to `ext.dst_ip_primary`. `trace.flow_id` is
//! composed from peer + target so pick_sink can pin replicas through the
//! flow-affinity hash.

use bytes::Bytes;
use mb_endpoint::Endpoint;
use mesh_bus_core::kernel::{Event, MetaValue, TypedMap};
use std::net::{IpAddr, SocketAddr};

fn set_host_fields(meta: &mut TypedMap, target: &Endpoint) {
    match target.host().parse::<IpAddr>() {
        Ok(ip) => {
            meta.ext
                .push(("dst_ip_primary", MetaValue::String(ip.to_string())));
        }
        Err(_) => {
            meta.net.dst_host = Some(target.host().to_ascii_lowercase());
        }
    }
}

fn set_operation(meta: &mut TypedMap, operation: &'static str) {
    meta.ext
        .push(("operation", MetaValue::String(operation.into())));
}

fn flow_id(peer: SocketAddr, target: &Endpoint) -> String {
    format!("{}->{}:{}", peer, target.host(), target.port())
}

pub fn build_connect_event(
    peer: SocketAddr,
    target: &Endpoint,
    authenticated_user: Option<&str>,
) -> Event {
    let mut meta = TypedMap::default();
    set_operation(&mut meta, "connect");
    set_host_fields(&mut meta, target);
    meta.net.dst_port = Some(target.port());
    meta.net.protocol = Some("tcp".into());
    meta.net.src_ip = Some(peer.ip().to_string());
    meta.auth.user = authenticated_user.map(|s| s.to_string());
    meta.trace.flow_id = Some(flow_id(peer, target));
    Event {
        payload: Bytes::new(),
        meta,
    }
}

pub fn build_bind_event(
    peer: SocketAddr,
    declared: &Endpoint,
    authenticated_user: Option<&str>,
) -> Event {
    let mut meta = TypedMap::default();
    set_operation(&mut meta, "bind");
    set_host_fields(&mut meta, declared);
    meta.net.dst_port = Some(declared.port());
    meta.net.protocol = Some("tcp".into());
    meta.net.src_ip = Some(peer.ip().to_string());
    meta.auth.user = authenticated_user.map(|s| s.to_string());
    meta.trace.flow_id = Some(flow_id(peer, declared));
    Event {
        payload: Bytes::new(),
        meta,
    }
}

pub fn build_udp_packet_event(
    peer: SocketAddr,
    target: &Endpoint,
    authenticated_user: Option<&str>,
) -> Event {
    let mut meta = TypedMap::default();
    set_operation(&mut meta, "datagram_send");
    set_host_fields(&mut meta, target);
    meta.net.dst_port = Some(target.port());
    meta.net.protocol = Some("udp".into());
    meta.net.src_ip = Some(peer.ip().to_string());
    meta.auth.user = authenticated_user.map(|s| s.to_string());
    meta.trace.flow_id = Some(flow_id(peer, target));
    Event {
        payload: Bytes::new(),
        meta,
    }
}
