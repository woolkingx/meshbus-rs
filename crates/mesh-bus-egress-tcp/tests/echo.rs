use bytes::Bytes;
use mb_endpoint::Endpoint;
use mesh_bus_core::{BusSessionInfo, BusSessionRequest, ExitId, ScheduleMode, StreamEgress};
use mesh_bus_egress_tcp::TcpEgress;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
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

async fn connected_session(
    exit: &TcpEgress,
    target: Endpoint,
) -> (
    Box<dyn mesh_bus_core::StreamSendHalf>,
    Box<dyn mesh_bus_core::StreamRecvHalf>,
) {
    let request = BusSessionRequest::stream(target);
    let mut session = exit
        .open_stream(
            &request,
            BusSessionInfo::empty_for_test(ScheduleMode::Ordered),
        )
        .await
        .expect("open stream");
    let info = session.connect().await.expect("connect");
    assert_eq!(info.paths[info.primary].exit_id, ExitId("tcp".into()));
    session.split()
}

#[tokio::test]
async fn sends_and_reads_echo() {
    let port = spawn_echo().await;
    let exit = TcpEgress::new(ExitId("tcp".into()), Duration::from_millis(500));
    let target = Endpoint::new("127.0.0.1", port).expect("endpoint");
    let (mut send, mut recv) = connected_session(&exit, target).await;

    send.send(Bytes::from_static(b"ping")).await.expect("send");
    let payload = timeout(Duration::from_millis(500), recv.recv())
        .await
        .expect("poll timeout")
        .expect("payload");
    assert_eq!(&payload[..], b"ping");
}

#[tokio::test]
async fn tcp_egress_stream_conformance_open_path_echo_and_close() {
    let port = spawn_echo().await;
    let exit = TcpEgress::new(ExitId("tcp".into()), Duration::from_millis(500));
    let caps = exit.capabilities();
    assert!(caps.supports_stream);
    assert!(!caps.supports_datagram);

    let target = Endpoint::new("127.0.0.1", port).expect("endpoint");
    let (mut send, mut recv) = connected_session(&exit, target).await;
    send.send(Bytes::from_static(b"hello")).await.expect("send");
    let payload = timeout(Duration::from_millis(500), recv.recv())
        .await
        .expect("poll timeout")
        .expect("payload");
    assert_eq!(&payload[..], b"hello");
    send.abort(mesh_bus_core::DisconnectReason::SessionClosed)
        .await;
}

#[tokio::test]
async fn poll_streams_large_response_after_single_send() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("accept");
        let mut request = [0u8; 4];
        sock.read_exact(&mut request).await.expect("read request");
        sock.write_all(&vec![b'a'; 16 * 1024])
            .await
            .expect("write first chunk");
        sock.write_all(&vec![b'b'; 16 * 1024])
            .await
            .expect("write second chunk");
    });

    let exit = TcpEgress::new(ExitId("tcp".into()), Duration::from_millis(500));
    let target = Endpoint::new("127.0.0.1", port).expect("endpoint");
    let (mut send, mut recv) = connected_session(&exit, target).await;
    send.send(Bytes::from_static(b"GET ")).await.expect("send");

    let mut payload = Vec::new();
    while payload.len() < 32 * 1024 {
        let chunk = timeout(Duration::from_millis(500), recv.recv())
            .await
            .expect("poll timeout")
            .expect("payload");
        payload.extend_from_slice(&chunk);
    }
    assert_eq!(payload.len(), 32 * 1024);
    assert!(payload[..16 * 1024].iter().all(|b| *b == b'a'));
    assert!(payload[16 * 1024..].iter().all(|b| *b == b'b'));
}

#[tokio::test]
async fn delayed_polling_drains_bounded_reader_queue_without_losing_stream_bytes() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("accept");
        let mut request = [0u8; 4];
        sock.read_exact(&mut request).await.expect("read request");
        for i in 0..96_u8 {
            sock.write_all(&vec![i; 1024]).await.expect("write chunk");
        }
    });

    let exit = TcpEgress::new(ExitId("tcp".into()), Duration::from_millis(500));
    let target = Endpoint::new("127.0.0.1", port).expect("endpoint");
    let (mut send, mut recv) = connected_session(&exit, target).await;
    send.send(Bytes::from_static(b"GET ")).await.expect("send");
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut payload = Vec::new();
    while payload.len() < 96 * 1024 {
        let chunk = timeout(Duration::from_millis(500), recv.recv())
            .await
            .expect("poll timeout")
            .expect("payload");
        payload.extend_from_slice(&chunk);
    }
    assert_eq!(payload.len(), 96 * 1024);
    for i in 0..96_usize {
        assert!(
            payload[i * 1024..(i + 1) * 1024]
                .iter()
                .all(|b| *b == i as u8)
        );
    }
}

#[tokio::test]
async fn connect_timeout_fails_fast() {
    let exit = TcpEgress::new(ExitId("tcp".into()), Duration::from_millis(100));
    let request = BusSessionRequest::stream(Endpoint::new("10.255.255.1", 1).expect("endpoint"));
    let mut session = exit
        .open_stream(
            &request,
            BusSessionInfo::empty_for_test(ScheduleMode::Ordered),
        )
        .await
        .expect("open stream");
    let start = std::time::Instant::now();
    let result = session.connect().await;
    let elapsed = start.elapsed();
    assert!(result.is_err());
    assert!(
        elapsed < Duration::from_millis(500),
        "connect timeout did not fire: {elapsed:?}"
    );
}
