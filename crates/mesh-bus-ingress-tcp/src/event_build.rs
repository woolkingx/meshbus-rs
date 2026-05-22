//! Builds a target-bearing `Event { TypedMap }` from a direct TCP connection
//! for the event-pipeline kernel. The plain TCP ingress has one fixed target
//! per listener and no protocol negotiation, so the event is the connection
//! peer projected against that target. Hostnames are lowercased; IP literals
//! go to `ext.dst_ip_primary`. `trace.flow_id` is composed from peer + target
//! so pick_sink can pin replicas through the flow-affinity hash. Metadata is
//! protocol-neutral L4 only; no adapter labels enter kernel metadata.

use bytes::Bytes;
use mb_endpoint::Endpoint;
use mesh_bus_core::kernel::{Event, MetaValue, TypedMap};
use std::net::{IpAddr, SocketAddr};

pub fn build_direct_stream_event(peer: SocketAddr, target: &Endpoint) -> Event {
    let mut meta = TypedMap::default();
    meta.ext
        .push(("operation", MetaValue::String("direct_stream_open".into())));
    match target.host().parse::<IpAddr>() {
        Ok(ip) => {
            meta.ext
                .push(("dst_ip_primary", MetaValue::String(ip.to_string())));
        }
        Err(_) => {
            meta.net.dst_host = Some(target.host().to_ascii_lowercase());
        }
    }
    meta.net.dst_port = Some(target.port());
    meta.net.protocol = Some("tcp".into());
    meta.net.src_ip = Some(peer.ip().to_string());
    meta.trace.flow_id = Some(format!("{}->{}:{}", peer, target.host(), target.port()));
    Event {
        payload: Bytes::new(),
        meta,
    }
}
