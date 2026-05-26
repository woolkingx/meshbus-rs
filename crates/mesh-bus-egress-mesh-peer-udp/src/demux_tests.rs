use super::*;
use crate::{DeliveryCoord, EgressPolicy};
use mb_proto_mesh::{DeliveryMode, NativeEventMode};
use mesh_bus_core::transport::udp_loop::UdpPacketLoop;
use std::net::{IpAddr, Ipv4Addr};
use tokio::net::UdpSocket;

async fn bind_loop() -> (Arc<UdpPacketLoop>, SocketAddr) {
    let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
    let peer_addr = peer.local_addr().expect("peer addr");
    let loopback = Arc::new(
        UdpPacketLoop::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind udp loop")
            .with_peer(peer_addr),
    );
    let local_addr = loopback.local_addr().expect("udp loop addr");
    (loopback, local_addr)
}

#[tokio::test]
async fn stream_driver_drop_releases_udp_socket_without_peer_packet() {
    let (packet_loop, local_addr) = bind_loop().await;
    let coord = DeliveryCoord::new(packet_loop.peer().expect("peer"));
    let policy = EgressPolicy::new(DeliveryMode::Steer, 1, 0);
    let sender = MeshPeerSender::spawn(
        packet_loop.clone(),
        coord.clone(),
        policy.clone(),
        std::time::Duration::from_secs(1),
        NativeEventMode::MeshFrame,
        None,
    );
    let handle = spawn_stream_driver(
        packet_loop.clone(),
        coord,
        policy,
        sender,
        NativeEventMode::MeshFrame,
        None,
        "session-a".to_string(),
    );

    drop(packet_loop);
    drop(handle);
    tokio::task::yield_now().await;

    UdpSocket::bind(local_addr)
        .await
        .expect("driver drop must release udp socket");
}

#[tokio::test]
async fn datagram_driver_drop_releases_udp_socket_without_peer_packet() {
    let (packet_loop, local_addr) = bind_loop().await;
    let coord = DeliveryCoord::new(packet_loop.peer().expect("peer"));
    let policy = EgressPolicy::new(DeliveryMode::Steer, 1, 0);
    let sender = MeshPeerSender::spawn(
        packet_loop.clone(),
        coord.clone(),
        policy.clone(),
        std::time::Duration::from_secs(1),
        NativeEventMode::MeshFrame,
        None,
    );
    let handle = spawn_datagram_driver(
        packet_loop.clone(),
        coord,
        policy,
        sender,
        NativeEventMode::MeshFrame,
        None,
        "session-a".to_string(),
    );

    drop(packet_loop);
    drop(handle);
    tokio::task::yield_now().await;

    UdpSocket::bind(local_addr)
        .await
        .expect("driver drop must release udp socket");
}
