use bytes::Bytes;
use mb_endpoint::Endpoint;
use mesh_bus_core::{BusSessionInfo, BusSessionRequest, DatagramEgress, ExitId, ScheduleMode};
use mesh_bus_egress_udp::UdpEgress;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

async fn spawn_udp_echo() -> u16 {
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp echo");
    let port = sock.local_addr().expect("udp echo addr").port();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            let (n, peer) = sock.recv_from(&mut buf).await.expect("recv udp");
            sock.send_to(&buf[..n], peer).await.expect("send udp");
        }
    });
    port
}

#[tokio::test]
async fn sends_and_reads_udp_echo() {
    let port = spawn_udp_echo().await;
    let exit = UdpEgress::new(ExitId("udp".into()), Duration::from_millis(500));
    let target = Endpoint::new("127.0.0.1", port).expect("endpoint");
    let request = BusSessionRequest::datagram(target.clone());
    let mut session = exit
        .open_datagram(
            &request,
            BusSessionInfo::empty_for_test(ScheduleMode::Ordered),
        )
        .await
        .expect("open datagram");

    session
        .send_to(target, Bytes::from_static(b"ping"))
        .await
        .expect("send datagram");
    let (_source, payload) = session.recv_from().await.expect("response");
    assert_eq!(&payload[..], b"ping");
}

#[tokio::test]
async fn udp_send_to_does_not_wait_for_response() {
    // Bind a sink that never replies
    let sink = UdpSocket::bind("127.0.0.1:0").await.expect("bind sink");
    let port = sink.local_addr().expect("sink addr").port();
    // Keep sink alive but never read/reply
    tokio::spawn(async move {
        let _keep = sink;
        tokio::time::sleep(Duration::from_secs(60)).await;
    });

    let exit = UdpEgress::new(ExitId("udp".into()), Duration::from_millis(500));
    let target = Endpoint::new("127.0.0.1", port).expect("endpoint");
    let request = BusSessionRequest::datagram(target.clone());
    let mut session = exit
        .open_datagram(
            &request,
            BusSessionInfo::empty_for_test(ScheduleMode::Ordered),
        )
        .await
        .expect("open datagram");

    // send_to must complete without waiting for a response
    timeout(
        Duration::from_millis(50),
        session.send_to(target, Bytes::from_static(b"fire")),
    )
    .await
    .expect("send_to must not block waiting for response")
    .expect("send ok");
}

#[tokio::test]
async fn udp_datagram_split_send_does_not_wait_for_response() {
    // Bind a sink that never replies
    let sink = UdpSocket::bind("127.0.0.1:0").await.expect("bind sink");
    let port = sink.local_addr().expect("sink addr").port();
    tokio::spawn(async move {
        let _keep = sink;
        tokio::time::sleep(Duration::from_secs(60)).await;
    });

    let exit = UdpEgress::new(ExitId("udp".into()), Duration::from_millis(500));
    let target = Endpoint::new("127.0.0.1", port).expect("endpoint");
    let request = BusSessionRequest::datagram(target.clone());
    let session = exit
        .open_datagram(
            &request,
            BusSessionInfo::empty_for_test(ScheduleMode::Ordered),
        )
        .await
        .expect("open datagram");

    let (mut send_half, _recv_half) = session.split();

    timeout(
        Duration::from_millis(50),
        send_half.send_to(target, Bytes::from_static(b"fire")),
    )
    .await
    .expect("send_half.send_to must not block")
    .expect("send ok");
}

#[tokio::test]
async fn udp_recv_half_wakes_when_send_half_closes() {
    let sink = UdpSocket::bind("127.0.0.1:0").await.expect("bind sink");
    let port = sink.local_addr().expect("sink addr").port();
    tokio::spawn(async move {
        let _keep = sink;
        tokio::time::sleep(Duration::from_secs(60)).await;
    });

    let exit = UdpEgress::new(ExitId("udp".into()), Duration::from_millis(500));
    let target = Endpoint::new("127.0.0.1", port).expect("endpoint");
    let request = BusSessionRequest::datagram(target);
    let session = exit
        .open_datagram(
            &request,
            BusSessionInfo::empty_for_test(ScheduleMode::Ordered),
        )
        .await
        .expect("open datagram");

    let (mut send_half, mut recv_half) = session.split();
    send_half.close().await;

    let closed = timeout(Duration::from_millis(50), recv_half.recv_from())
        .await
        .expect("recv half should wake when send half closes");
    assert!(closed.is_none());
}

#[tokio::test]
async fn udp_fixed_target_direct_session_preserves_sources() {
    let port = spawn_udp_echo().await;
    let exit = UdpEgress::new(ExitId("udp".into()), Duration::from_millis(500));
    let target = Endpoint::new("127.0.0.1", port).expect("endpoint");
    let request = BusSessionRequest::datagram(target.clone());
    let mut session = exit
        .open_datagram(
            &request,
            BusSessionInfo::empty_for_test(ScheduleMode::Ordered),
        )
        .await
        .expect("open datagram");

    session
        .send_to(target.clone(), Bytes::from_static(b"pkt1"))
        .await
        .expect("send 1");
    let (source1, payload1) = session.recv_from().await.expect("recv 1");
    assert_eq!(&payload1[..], b"pkt1");
    assert_eq!(source1, target);

    session
        .send_to(target.clone(), Bytes::from_static(b"pkt2"))
        .await
        .expect("send 2");
    let (source2, payload2) = session.recv_from().await.expect("recv 2");
    assert_eq!(&payload2[..], b"pkt2");
    assert_eq!(source2, target);
}

#[tokio::test]
async fn udp_egress_datagram_conformance_preserves_one_packet_boundary() {
    let port = spawn_udp_echo().await;
    let exit = UdpEgress::new(ExitId("udp".into()), Duration::from_millis(500));
    let caps = exit.capabilities();
    assert!(!caps.supports_stream);
    assert!(caps.supports_datagram);

    let target = Endpoint::new("127.0.0.1", port).expect("endpoint");
    let request = BusSessionRequest::datagram(target.clone());
    let mut session = exit
        .open_datagram(
            &request,
            BusSessionInfo::empty_for_test(ScheduleMode::Ordered),
        )
        .await
        .expect("open datagram");
    session
        .send_to(target, Bytes::from_static(b"one logical datagram"))
        .await
        .expect("send datagram");
    let (_source, payload) = session.recv_from().await.expect("response");
    assert_eq!(&payload[..], b"one logical datagram");
}
