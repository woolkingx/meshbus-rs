use mb_endpoint::Endpoint;
use mesh_bus_core::kernel::{Event, MetaValue};
use mesh_bus_ingress_socks5::event_build::{build_connect_event, build_udp_packet_event};
use std::net::SocketAddr;

fn peer() -> SocketAddr {
    "127.0.0.1:50000".parse().expect("peer addr")
}

fn ext_string<'a>(event: &'a Event, key: &str) -> Option<&'a str> {
    event.meta.ext.iter().find_map(|(k, v)| match (*k, v) {
        (found, MetaValue::String(s)) if found == key => Some(s.as_str()),
        _ => None,
    })
}

#[test]
fn connect_event_sets_generic_operation() {
    let target = Endpoint::new("example.com", 443).expect("endpoint");

    let event = build_connect_event(peer(), &target, Some("alice"));

    assert_eq!(ext_string(&event, "operation"), Some("connect"));
}

#[test]
fn connect_event_sets_l4_transport_family_not_adapter_label() {
    let target = Endpoint::new("example.com", 443).expect("endpoint");

    let event = build_connect_event(peer(), &target, Some("alice"));

    assert_eq!(event.meta.net.protocol.as_deref(), Some("tcp"));
}

#[test]
fn udp_packet_event_sets_generic_operation() {
    let target = Endpoint::new("example.com", 53).expect("endpoint");

    let event = build_udp_packet_event(peer(), &target, Some("alice"));

    assert_eq!(ext_string(&event, "operation"), Some("datagram_send"));
}

#[test]
fn udp_packet_event_sets_l4_transport_family_not_adapter_label() {
    let target = Endpoint::new("example.com", 53).expect("endpoint");

    let event = build_udp_packet_event(peer(), &target, Some("alice"));

    assert_eq!(event.meta.net.protocol.as_deref(), Some("udp"));
}
