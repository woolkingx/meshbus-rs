use bytes::Bytes;
use mb_endpoint::Endpoint;
use mesh_bus_core::{
    BusSessionInfo, BusSessionRequest, DatagramEgress, ExitId, ScheduleMode, StreamEgress,
};
use mesh_bus_egress_service::{ServiceTcpEgress, ServiceUdpEgress};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::UdpSocket;
use tokio::time::timeout;

async fn spawn_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind echo listener");
    let port = listener.local_addr().expect("local addr").port();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.expect("accept");
            tokio::spawn(async move {
                let mut buf = vec![0; 1024];
                loop {
                    let n = sock.read(&mut buf).await.expect("read");
                    if n == 0 {
                        break;
                    }
                    sock.write_all(&buf[..n]).await.expect("write");
                }
            });
        }
    });
    port
}

async fn spawn_udp_echo() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp echo");
    let port = socket.local_addr().expect("udp echo addr").port();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            let (n, peer) = socket.recv_from(&mut buf).await.expect("recv udp");
            socket.send_to(&buf[..n], peer).await.expect("send udp");
        }
    });
    port
}

#[tokio::test]
async fn service_sink_ignores_request_target_and_dials_configured_connect() {
    let port = spawn_echo().await;
    let connect = Endpoint::new("127.0.0.1", port).expect("connect endpoint");
    let exit = ServiceTcpEgress::new(
        ExitId("svc".into()),
        "echo-service".into(),
        connect,
        Duration::from_millis(500),
    );

    assert_eq!(exit.service_id(), "echo-service");
    let caps = exit.capabilities();
    assert!(caps.supports_stream);
    assert!(!caps.supports_datagram);

    // request.target is a black-hole address. If the dial used it, connect
    // would hang/fail. Echo proves the configured connect endpoint was used.
    let bogus = Endpoint::new("10.255.255.1", 9).expect("bogus endpoint");
    let request = BusSessionRequest::stream(bogus);
    let mut session = exit
        .open_stream(
            &request,
            BusSessionInfo::empty_for_test(ScheduleMode::Ordered),
        )
        .await
        .expect("open stream");
    let info = session.connect().await.expect("connect");
    assert_eq!(info.paths[info.primary].exit_id, ExitId("svc".into()));
    assert_eq!(info.paths[info.primary].remote.port(), port);

    let (mut send, mut recv) = session.split();
    send.send(Bytes::from_static(b"ping")).await.expect("send");
    let payload = timeout(Duration::from_millis(500), recv.recv())
        .await
        .expect("poll timeout")
        .expect("payload");
    assert_eq!(&payload[..], b"ping");
}

#[tokio::test]
async fn service_sink_honors_route_group_membership() {
    let exit = ServiceTcpEgress::new(
        ExitId("svc".into()),
        "echo-service".into(),
        Endpoint::new("127.0.0.1", 1).expect("endpoint"),
        Duration::from_millis(100),
    )
    .with_groups(vec!["reverse".into()]);
    assert_eq!(exit.capabilities().groups, vec!["reverse".to_string()]);
}

#[tokio::test]
async fn service_udp_sink_ignores_request_target_and_sends_configured_connect() {
    let port = spawn_udp_echo().await;
    let connect = Endpoint::new("127.0.0.1", port).expect("connect endpoint");
    let exit = ServiceUdpEgress::new(
        ExitId("svc-udp".into()),
        "dns-service".into(),
        connect.clone(),
        Duration::from_millis(500),
    );

    assert_eq!(exit.service_id(), "dns-service");
    let caps = exit.capabilities();
    assert!(!caps.supports_stream);
    assert!(caps.supports_datagram);

    let bogus = Endpoint::new("10.255.255.1", 9).expect("bogus endpoint");
    let request = BusSessionRequest::datagram(bogus.clone());
    let mut session = exit
        .open_datagram(
            &request,
            BusSessionInfo::empty_for_test(ScheduleMode::Ordered),
        )
        .await
        .expect("open datagram");
    session
        .send_to(bogus, Bytes::from_static(b"ping"))
        .await
        .expect("send");
    let (source, payload) = timeout(Duration::from_millis(500), session.recv_from())
        .await
        .expect("recv timeout")
        .expect("payload");
    assert_eq!(source, connect);
    assert_eq!(&payload[..], b"ping");
}

#[tokio::test]
async fn service_udp_sink_honors_route_group_membership() {
    let exit = ServiceUdpEgress::new(
        ExitId("svc-udp".into()),
        "dns-service".into(),
        Endpoint::new("127.0.0.1", 53).expect("endpoint"),
        Duration::from_millis(100),
    )
    .with_groups(vec!["reverse".into()]);
    assert_eq!(exit.capabilities().groups, vec!["reverse".to_string()]);
}
