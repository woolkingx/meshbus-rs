use super::*;
use mb_endpoint::Endpoint;
use mb_proto_mesh::DeliveryMode;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;

#[test]
fn packetizer_classifies_control_and_data_frames() {
    assert!(is_control_frame(&MeshFrame::StreamShutdownWrite {
        session_id: "s".into()
    }));
    assert!(is_control_frame(&MeshFrame::DatagramClose {
        session_id: "s".into(),
        close_reason: mb_proto_mesh::CloseReasonWire::Normal,
    }));
    assert!(!is_control_frame(&MeshFrame::DatagramSend {
        session_id: "s".into(),
        seq: 1,
        target: Endpoint::new("127.0.0.1", 53).unwrap(),
        payload: Bytes::from_static(b"x"),
    }));
    assert!(!is_control_frame(&MeshFrame::StreamData {
        session_id: "s".into(),
        seq: 1,
        payload: Bytes::from_static(b"x"),
    }));
}

#[tokio::test]
async fn data_frames_flush_as_one_packetizer_batch() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
    let peer_addr = peer.local_addr().expect("peer addr");
    let packet_loop = Arc::new(
        UdpPacketLoop::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind packet loop")
            .with_peer(peer_addr),
    );
    let sender = MeshPeerSender::spawn(
        packet_loop.clone(),
        DeliveryCoord::new(peer_addr),
        EgressPolicy::new(DeliveryMode::Steer, 1, 0),
        Duration::from_secs(1),
        NativeEventMode::MeshFrame,
        None,
    );
    let target = Endpoint::new("127.0.0.1", 53).unwrap();
    let frames = (1..=64)
        .map(|seq| MeshFrame::DatagramSend {
            session_id: "s".into(),
            seq,
            target: target.clone(),
            payload: Bytes::from_static(b"same-sized-payload"),
        })
        .collect();

    sender
        .send_data_frames(frames)
        .await
        .expect("send data batch");

    let stats = packet_loop.batch_io_stats();
    assert_eq!(stats.send_datagrams, 64);
    if stats.batch_send_supported {
        assert!(
            stats.send_syscalls < stats.send_datagrams,
            "batch sender should use fewer syscalls than datagrams: {stats:?}"
        );
    }
}
