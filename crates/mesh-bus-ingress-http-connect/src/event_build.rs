use bytes::Bytes;
use mb_endpoint::Endpoint;
use mesh_bus_core::kernel::{Event, MetaValue, TypedMap};
use std::net::{IpAddr, SocketAddr};

pub fn build_http_proxy_event(peer: SocketAddr, target: &Endpoint, operation: &str) -> Event {
    let mut meta = TypedMap::default();
    meta.ext
        .push(("operation", MetaValue::String(operation.into())));
    match target.host().parse::<IpAddr>() {
        Ok(ip) => meta
            .ext
            .push(("dst_ip_primary", MetaValue::String(ip.to_string()))),
        Err(_) => meta.net.dst_host = Some(target.host().to_ascii_lowercase()),
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
