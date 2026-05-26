use bytes::{Bytes, BytesMut};
use mb_endpoint::Endpoint;
use mb_proto_mesh::{
    CloseReasonWire, FlowSemanticsWire, MESHSEC_ACCEPTED_EPOCH_SKEW_SLOTS,
    MESHSEC_REPLAY_WINDOW_BITS, MeshFrame, MeshSecOpenKey, MeshSecReplayCache, MeshSecSealContext,
    NativeEventMode, ReturnSemanticsWire, StreamOpen, decode_frame, encode_frame,
    meshsec_epoch_number, open_mesh_frame, seal_mesh_frame,
};
use mesh_bus_core::{
    BusSessionInfo, BusSessionRequest, DatagramEgress, DisconnectReason, ExitId, ScheduleMode,
    SendError, StreamEgress, StreamSession,
};
use mesh_bus_egress_mesh_peer_udp::MeshPeerUdpEgress;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

fn endpoint(host: &str, port: u16) -> Endpoint {
    Endpoint::new(host.to_string(), port).unwrap()
}

async fn recv_mesh_frame(sock: &UdpSocket) -> (MeshFrame, SocketAddr) {
    let mut buf = vec![0u8; 2048];
    let (n, peer) = sock.recv_from(&mut buf).await.expect("recv mesh frame");
    let frame = decode_frame(&mut BytesMut::from(&buf[..n])).expect("decode mesh frame");
    (frame, peer)
}

async fn connect_with_accept(
    mut session: Box<dyn StreamSession>,
    peer: &UdpSocket,
) -> (Box<dyn StreamSession>, SocketAddr, MeshFrame) {
    let connect = tokio::spawn(async move {
        session.connect().await.expect("connect mesh peer stream");
        session
    });
    let (frame, client) = recv_mesh_frame(peer).await;
    let open_token = match &frame {
        MeshFrame::StreamOpen(open) => open.open_token,
        other => panic!("expected stream open, got {other:?}"),
    };
    let accepted = encode_frame(&MeshFrame::StreamOpenAccepted {
        session_id: "test-session".into(),
        open_token,
    })
    .expect("encode stream open accepted");
    peer.send_to(&accepted, client)
        .await
        .expect("send stream open accepted");
    let session = connect.await.expect("connect task");
    (session, client, frame)
}

#[test]
fn capabilities_advertise_stream_and_datagram() {
    let peer_addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let egress = MeshPeerUdpEgress::new(
        ExitId("peer-udp".into()),
        peer_addr,
        Duration::from_millis(500),
    );
    assert!(StreamEgress::capabilities(&egress).supports_stream);
    assert!(DatagramEgress::capabilities(&egress).supports_datagram);
}

#[test]
fn adapter_projections_advertise_only_their_flow_family() {
    let peer_addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let owner = MeshPeerUdpEgress::new(
        ExitId("peer-udp".into()),
        peer_addr,
        Duration::from_millis(500),
    );

    let stream = owner.clone().as_stream_adapter();
    assert!(StreamEgress::capabilities(&stream).supports_stream);
    assert!(!StreamEgress::capabilities(&stream).supports_datagram);

    let datagram = owner.as_datagram_adapter();
    assert!(!DatagramEgress::capabilities(&datagram).supports_stream);
    assert!(DatagramEgress::capabilities(&datagram).supports_datagram);
}

#[tokio::test]
async fn stream_open_emits_mesh_stream_open() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
    let peer_addr = peer.local_addr().expect("peer addr");

    let egress = MeshPeerUdpEgress::new(
        ExitId("peer-udp".into()),
        peer_addr,
        Duration::from_millis(500),
    )
    .with_native_event_mode(NativeEventMode::MeshFrame);
    let target = endpoint("example.com", 443);
    let request = BusSessionRequest::stream(target.clone()).with_route_group("mesh-upstream");
    let session = egress
        .open_stream(
            &request,
            BusSessionInfo::empty_for_test(ScheduleMode::Ordered),
        )
        .await
        .expect("open mesh peer stream");
    let (_session, _client, frame) = connect_with_accept(session, &peer).await;
    let open_token = match &frame {
        MeshFrame::StreamOpen(open) => open.open_token,
        other => panic!("expected stream open, got {other:?}"),
    };
    assert_eq!(
        frame,
        MeshFrame::StreamOpen(StreamOpen {
            session_id: "test-session".into(),
            open_token,
            target,
            route_group: Some("mesh-upstream".into()),
            flow_semantics: FlowSemanticsWire::ByteStream,
            return_semantics: ReturnSemanticsWire::Direct,
            source_node_id: "local".into(),
            path_trace: Vec::new(),
        })
    );
}

#[tokio::test]
async fn stream_connect_requires_open_ack() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
    let peer_addr = peer.local_addr().expect("peer addr");

    let egress = MeshPeerUdpEgress::new(
        ExitId("peer-udp".into()),
        peer_addr,
        Duration::from_millis(50),
    )
    .with_native_event_mode(NativeEventMode::MeshFrame);
    let request = BusSessionRequest::stream(endpoint("example.com", 443));
    let mut session = egress
        .open_stream(
            &request,
            BusSessionInfo::empty_for_test(ScheduleMode::Ordered),
        )
        .await
        .expect("open mesh peer stream");

    let result = session.connect().await;
    assert!(
        matches!(result, Err(DisconnectReason::TimedOut)),
        "stream connect must fail when peer never acknowledges StreamOpen: {result:?}"
    );

    let (frame, _) = recv_mesh_frame(&peer).await;
    assert!(matches!(frame, MeshFrame::StreamOpen(_)));
}

#[tokio::test]
async fn stream_connect_ignores_stale_open_ack_token() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
    let peer_addr = peer.local_addr().expect("peer addr");

    let egress = MeshPeerUdpEgress::new(
        ExitId("peer-udp".into()),
        peer_addr,
        Duration::from_millis(50),
    )
    .with_native_event_mode(NativeEventMode::MeshFrame);
    let request = BusSessionRequest::stream(endpoint("example.com", 443));
    let mut session = egress
        .open_stream(
            &request,
            BusSessionInfo::empty_for_test(ScheduleMode::Ordered),
        )
        .await
        .expect("open mesh peer stream");

    let connect = tokio::spawn(async move {
        let result = session.connect().await;
        assert!(
            matches!(result, Err(DisconnectReason::TimedOut)),
            "stale token must not acknowledge a new StreamOpen: {result:?}"
        );
    });
    let (frame, client) = recv_mesh_frame(&peer).await;
    let open_token = match frame {
        MeshFrame::StreamOpen(open) => open.open_token,
        other => panic!("expected stream open, got {other:?}"),
    };
    let stale = encode_frame(&MeshFrame::StreamOpenAccepted {
        session_id: "test-session".into(),
        open_token: open_token.saturating_add(1),
    })
    .expect("encode stale stream open accepted");
    peer.send_to(&stale, client)
        .await
        .expect("send stale stream open accepted");
    connect.await.expect("connect task");
}

#[tokio::test]
async fn stream_connect_preserves_data_that_arrives_before_open_ack() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
    let peer_addr = peer.local_addr().expect("peer addr");

    let egress = MeshPeerUdpEgress::new(
        ExitId("peer-udp".into()),
        peer_addr,
        Duration::from_millis(500),
    )
    .with_native_event_mode(NativeEventMode::MeshFrame);
    let request = BusSessionRequest::stream(endpoint("example.com", 443));
    let mut session = egress
        .open_stream(
            &request,
            BusSessionInfo::empty_for_test(ScheduleMode::Ordered),
        )
        .await
        .expect("open mesh peer stream");

    let connect = tokio::spawn(async move {
        session.connect().await.expect("connect mesh peer stream");
        session
    });
    let (frame, client) = recv_mesh_frame(&peer).await;
    let open_token = match frame {
        MeshFrame::StreamOpen(open) => open.open_token,
        other => panic!("expected stream open, got {other:?}"),
    };
    let early_data = encode_frame(&MeshFrame::StreamData {
        session_id: "test-session".into(),
        seq: 1,
        payload: Bytes::from_static(b"early-server-data"),
    })
    .expect("encode early stream data");
    peer.send_to(&early_data, client)
        .await
        .expect("send early stream data");
    let accepted = encode_frame(&MeshFrame::StreamOpenAccepted {
        session_id: "test-session".into(),
        open_token,
    })
    .expect("encode stream open accepted");
    peer.send_to(&accepted, client)
        .await
        .expect("send stream open accepted");

    let session = connect.await.expect("connect task");
    let (_send, mut recv) = session.split();
    let payload = tokio::time::timeout(Duration::from_secs(1), recv.recv())
        .await
        .expect("early stream data must not be swallowed by open-ack wait")
        .expect("early stream payload");
    assert_eq!(&payload[..], b"early-server-data");
}

#[tokio::test]
async fn meshsec_stream_connect_preserves_data_that_arrives_before_open_ack() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
    let peer_addr = peer.local_addr().expect("peer addr");

    let egress = MeshPeerUdpEgress::new(
        ExitId("peer-udp".into()),
        peer_addr,
        Duration::from_millis(500),
    )
    .with_native_event_mode(NativeEventMode::MeshFrame)
    .with_meshsec(MeshSecSealContext {
        local_node_id: "node-a".into(),
        remote_node_id: "node-b".into(),
        static_key: TEST_KEY,
        boot_salt: [1, 2, 3, 4],
    });
    let request = BusSessionRequest::stream(endpoint("example.com", 443));
    let mut session = egress
        .open_stream(
            &request,
            BusSessionInfo::empty_for_test(ScheduleMode::Ordered),
        )
        .await
        .expect("open mesh peer stream");

    let connect = tokio::spawn(async move {
        session.connect().await.expect("connect mesh peer stream");
        session
    });
    let (frame, client) = recv_sealed_frame_opened_from_node_a(&peer).await;
    let open_token = match frame {
        MeshFrame::StreamOpen(open) => open.open_token,
        other => panic!("expected stream open, got {other:?}"),
    };

    let early = seal_reply_frame(
        &MeshFrame::StreamData {
            session_id: "test-session".into(),
            seq: 1,
            payload: Bytes::from_static(b"meshsec-early-server-data"),
        },
        1,
    );
    peer.send_to(&early, client)
        .await
        .expect("send sealed early stream data");
    let accepted = seal_reply_frame(
        &MeshFrame::StreamOpenAccepted {
            session_id: "test-session".into(),
            open_token,
        },
        2,
    );
    peer.send_to(&accepted, client)
        .await
        .expect("send sealed stream open accepted");

    let session = connect.await.expect("connect task");
    let (_send, mut recv) = session.split();
    let payload = tokio::time::timeout(Duration::from_secs(1), recv.recv())
        .await
        .expect("MeshSec early stream data must not be replay-dropped after connect")
        .expect("early stream payload");
    assert_eq!(&payload[..], b"meshsec-early-server-data");
}

#[tokio::test]
async fn stream_send_emits_ordered_stream_data() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
    let peer_addr = peer.local_addr().expect("peer addr");

    let egress = MeshPeerUdpEgress::new(
        ExitId("peer-udp".into()),
        peer_addr,
        Duration::from_millis(500),
    )
    .with_native_event_mode(NativeEventMode::MeshFrame);
    let target = endpoint("example.com", 443);
    let request = BusSessionRequest::stream(target);
    let session = egress
        .open_stream(
            &request,
            BusSessionInfo::empty_for_test(ScheduleMode::Ordered),
        )
        .await
        .expect("open mesh peer stream");
    let (session, _client, _open) = connect_with_accept(session, &peer).await;

    let (mut send, _recv) = session.split();
    send.send(Bytes::from_static(b"stream-sdu"))
        .await
        .expect("send stream bytes");

    let (frame, _) = recv_mesh_frame(&peer).await;
    assert_eq!(
        frame,
        MeshFrame::StreamData {
            session_id: "test-session".into(),
            seq: 1,
            payload: Bytes::from_static(b"stream-sdu"),
        }
    );
}

#[tokio::test]
async fn stream_recv_preserves_same_drain_multiple_data_frames() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
    let peer_addr = peer.local_addr().expect("peer addr");

    let egress = MeshPeerUdpEgress::new(
        ExitId("peer-udp".into()),
        peer_addr,
        Duration::from_millis(500),
    )
    .with_native_event_mode(NativeEventMode::MeshFrame);
    let target = endpoint("example.com", 443);
    let request = BusSessionRequest::stream(target);
    let session = egress
        .open_stream(
            &request,
            BusSessionInfo::empty_for_test(ScheduleMode::Ordered),
        )
        .await
        .expect("open mesh peer stream");
    let (session, client, _open) = connect_with_accept(session, &peer).await;

    let (_send, mut recv) = session.split();
    for (seq, payload) in [(1, b"tls-server-hello".as_slice()), (2, b"tls-cert-chain")] {
        let packet = encode_frame(&MeshFrame::StreamData {
            session_id: "test-session".into(),
            seq,
            payload: Bytes::copy_from_slice(payload),
        })
        .expect("encode stream data");
        peer.send_to(&packet, client)
            .await
            .expect("send stream data");
    }

    let first = tokio::time::timeout(Duration::from_secs(1), recv.recv())
        .await
        .expect("first recv must not hang")
        .expect("first stream payload");
    let second = tokio::time::timeout(Duration::from_millis(200), recv.recv())
        .await
        .expect("second recv must be buffered from same drain")
        .expect("second stream payload");

    assert_eq!(&first[..], b"tls-server-hello");
    assert_eq!(&second[..], b"tls-cert-chain");
}

#[tokio::test]
async fn stream_recv_delivers_buffered_payloads_before_close() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
    let peer_addr = peer.local_addr().expect("peer addr");

    let egress = MeshPeerUdpEgress::new(
        ExitId("peer-udp".into()),
        peer_addr,
        Duration::from_millis(500),
    )
    .with_native_event_mode(NativeEventMode::MeshFrame);
    let request = BusSessionRequest::stream(endpoint("example.com", 443));
    let session = egress
        .open_stream(
            &request,
            BusSessionInfo::empty_for_test(ScheduleMode::Ordered),
        )
        .await
        .expect("open mesh peer stream");
    let (session, client, _open) = connect_with_accept(session, &peer).await;

    let (_send, mut recv) = session.split();
    for frame in [
        MeshFrame::StreamData {
            session_id: "test-session".into(),
            seq: 1,
            payload: Bytes::from_static(b"one"),
        },
        MeshFrame::StreamData {
            session_id: "test-session".into(),
            seq: 2,
            payload: Bytes::from_static(b"two"),
        },
        MeshFrame::StreamShutdownWrite {
            session_id: "test-session".into(),
        },
    ] {
        let packet = encode_frame(&frame).expect("encode stream frame");
        peer.send_to(&packet, client)
            .await
            .expect("send stream frame");
    }

    let first = tokio::time::timeout(Duration::from_secs(1), recv.recv())
        .await
        .expect("first recv must not hang")
        .expect("first stream payload");
    let second = tokio::time::timeout(Duration::from_millis(200), recv.recv())
        .await
        .expect("second recv must be buffered from same drain")
        .expect("second stream payload");
    let eof = tokio::time::timeout(Duration::from_millis(200), recv.recv())
        .await
        .expect("close event from same drain must be remembered");

    assert_eq!(&first[..], b"one");
    assert_eq!(&second[..], b"two");
    assert!(eof.is_none());
}

#[tokio::test]
async fn stream_close_removes_session_state() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
    let peer_addr = peer.local_addr().expect("peer addr");

    let egress = MeshPeerUdpEgress::new(
        ExitId("peer-udp".into()),
        peer_addr,
        Duration::from_millis(500),
    )
    .with_native_event_mode(NativeEventMode::MeshFrame);
    let target = endpoint("example.com", 443);
    let request = BusSessionRequest::stream(target);
    let session = egress
        .open_stream(
            &request,
            BusSessionInfo::empty_for_test(ScheduleMode::Ordered),
        )
        .await
        .expect("open mesh peer stream");
    let (session, _client, _open) = connect_with_accept(session, &peer).await;

    let (mut send, _recv) = session.split();
    send.abort(DisconnectReason::ConnectionReset).await;

    let (frame, _) = recv_mesh_frame(&peer).await;
    assert_eq!(
        frame,
        MeshFrame::StreamClose {
            session_id: "test-session".into(),
            close_reason: CloseReasonWire::Normal,
        }
    );
    assert!(matches!(
        send.send(Bytes::from_static(b"after-close")).await,
        Err(DisconnectReason::SessionClosed)
    ));
}

#[tokio::test]
async fn datagram_session_exchanges_mesh_datagram_frames() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
    let peer_addr = peer.local_addr().expect("peer addr");
    let (seen_tx, mut seen_rx) = mpsc::channel::<MeshFrame>(2);

    tokio::spawn(async move {
        let (open, client) = recv_mesh_frame(&peer).await;
        seen_tx.send(open).await.expect("record open");

        let (send, client_again) = recv_mesh_frame(&peer).await;
        assert_eq!(client_again, client);
        seen_tx.send(send).await.expect("record send");

        let reply = encode_frame(&MeshFrame::DatagramReturn {
            session_id: "test-session".into(),
            seq: 1,
            source: endpoint("8.8.8.8", 53),
            payload: Bytes::from_static(b"dns-reply"),
        })
        .expect("encode reply");
        peer.send_to(&reply, client).await.expect("send reply");
    });

    let egress = MeshPeerUdpEgress::new(
        ExitId("peer-udp".into()),
        peer_addr,
        Duration::from_millis(500),
    )
    .with_native_event_mode(NativeEventMode::MeshFrame);
    let max_datagram_bytes = egress.max_payload_bytes() as u64;
    let target = endpoint("8.8.8.8", 53);
    let request = BusSessionRequest::datagram(target.clone());
    let mut session = egress
        .open_datagram(
            &request,
            BusSessionInfo::empty_for_test(ScheduleMode::Ordered),
        )
        .await
        .expect("open mesh peer datagram");

    session
        .send_to(target.clone(), Bytes::from_static(b"dns-query"))
        .await
        .expect("send datagram");

    assert_eq!(
        seen_rx.recv().await.expect("open frame"),
        MeshFrame::DatagramOpen(mb_proto_mesh::DatagramOpen {
            session_id: "test-session".into(),
            fixed_target: Some(target.clone()),
            max_datagram_bytes,
        })
    );
    assert_eq!(
        seen_rx.recv().await.expect("send frame"),
        MeshFrame::DatagramSend {
            session_id: "test-session".into(),
            seq: 1,
            target: target.clone(),
            payload: Bytes::from_static(b"dns-query"),
        }
    );

    let (source, payload) = session.recv_from().await.expect("recv datagram return");
    assert_eq!(source, target);
    assert_eq!(&payload[..], b"dns-reply");
}

#[tokio::test]
async fn datagram_close_closes_recv_half_without_local_timeout() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
    let peer_addr = peer.local_addr().expect("peer addr");

    let egress = MeshPeerUdpEgress::new(
        ExitId("peer-udp".into()),
        peer_addr,
        Duration::from_millis(500),
    )
    .with_native_event_mode(NativeEventMode::MeshFrame);
    let request = BusSessionRequest::datagram(endpoint("8.8.8.8", 53));
    let session = egress
        .open_datagram(
            &request,
            BusSessionInfo::empty_for_test(ScheduleMode::Ordered),
        )
        .await
        .expect("open mesh peer datagram");

    let (open, client) = recv_mesh_frame(&peer).await;
    assert!(matches!(open, MeshFrame::DatagramOpen(_)));

    let (_send, mut recv) = session.split();
    let close = encode_frame(&MeshFrame::DatagramClose {
        session_id: "test-session".into(),
        close_reason: CloseReasonWire::Normal,
    })
    .expect("encode datagram close");
    peer.send_to(&close, client)
        .await
        .expect("send datagram close");

    let result = tokio::time::timeout(Duration::from_millis(200), recv.recv_from()).await;
    assert!(
        matches!(result, Ok(None)),
        "DatagramClose must close the recv half promptly, got {result:?}"
    );
}

#[tokio::test]
async fn datagram_return_queue_full_sets_recv_last_error() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
    let peer_addr = peer.local_addr().expect("peer addr");

    let egress = MeshPeerUdpEgress::new(
        ExitId("peer-udp".into()),
        peer_addr,
        Duration::from_millis(500),
    )
    .with_native_event_mode(NativeEventMode::MeshFrame);
    let request = BusSessionRequest::datagram(endpoint("8.8.8.8", 53));
    let session = egress
        .open_datagram(
            &request,
            BusSessionInfo::empty_for_test(ScheduleMode::Ordered),
        )
        .await
        .expect("open mesh peer datagram");

    let (open, client) = recv_mesh_frame(&peer).await;
    assert!(matches!(open, MeshFrame::DatagramOpen(_)));
    let (_send, mut recv) = session.split();

    for seq in 0..384 {
        let packet = encode_frame(&MeshFrame::DatagramReturn {
            session_id: "test-session".into(),
            seq,
            source: endpoint("8.8.8.8", 53),
            payload: Bytes::from_static(b"dns-reply"),
        })
        .expect("encode datagram return");
        peer.send_to(&packet, client)
            .await
            .expect("send datagram return");
    }

    for _ in 0..384 {
        match tokio::time::timeout(Duration::from_secs(1), recv.recv_from()).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                assert_eq!(recv.last_error(), Some(&DisconnectReason::QueueFull));
                return;
            }
            Err(_) => panic!("datagram queue overflow did not surface as QueueFull"),
        }
    }
    panic!("datagram queue overflow did not close the recv half");
}

#[tokio::test]
async fn mesh_peer_udp_oversize_send_reports_payload_too_large() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
    let peer_addr = peer.local_addr().expect("peer addr");

    let egress = MeshPeerUdpEgress::new(
        ExitId("peer-udp".into()),
        peer_addr,
        Duration::from_millis(500),
    );
    let target = endpoint("8.8.8.8", 53);
    let request = BusSessionRequest::datagram(target.clone());
    let mut session = egress
        .open_datagram(
            &request,
            BusSessionInfo::empty_for_test(ScheduleMode::Ordered),
        )
        .await
        .expect("open mesh peer datagram");

    // Within the 65000-byte app ceiling but well past the conservative PMTU:
    // the substrate must surface this as a typed failure, not a silent Ok(()).
    let oversize = Bytes::from(vec![0u8; 4096]);
    let result = session.send_to(target, oversize).await;
    assert!(
        matches!(result, Err(SendError::PayloadTooLarge)),
        "oversize datagram is a typed failure, not a silent Ok: got {result:?}"
    );
}

#[test]
fn meshsec_advertised_budget_fits_seal_clear_cap() {
    use mb_proto_mesh::meshsec::MESHSEC_MAX_CLEAR_LEN;
    // With MeshSec configured the sealed clear (encoded MeshFrame) must fit the
    // 1024 padding bucket (MESHSEC_MAX_CLEAR_LEN=1022). The advertised datagram
    // budget must therefore be <= MESHSEC_MAX_CLEAR_LEN minus frame overhead,
    // never the unsealed 65_000 (~64x over-advertise = silent drop).
    let sealed_budget = mesh_bus_egress_mesh_peer_udp::meshsec_max_payload_bytes();
    assert!(
        sealed_budget <= MESHSEC_MAX_CLEAR_LEN,
        "sealed budget {sealed_budget} exceeds seal clear cap {MESHSEC_MAX_CLEAR_LEN}"
    );
    assert!(sealed_budget > 0);
}

const TEST_KEY: [u8; 32] = [11u8; 32];

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

fn seal_reply_frame(frame: &MeshFrame, counter: u64) -> Vec<u8> {
    let reply_ctx = MeshSecSealContext {
        local_node_id: "node-b".into(),
        remote_node_id: "node-a".into(),
        static_key: TEST_KEY,
        boot_salt: [3, 3, 3, 3],
    };
    seal_mesh_frame(frame, &reply_ctx, meshsec_epoch_number(now_secs()), counter)
        .expect("seal reply frame")
}

async fn recv_sealed_frame_opened_from_node_a(sock: &UdpSocket) -> (MeshFrame, SocketAddr) {
    let mut buf = vec![0u8; 2048];
    let (n, peer) = sock.recv_from(&mut buf).await.expect("recv sealed frame");
    assert!(
        decode_frame(&mut BytesMut::from(&buf[..n])).is_err(),
        "egress must seal outbound frames, not send them in clear"
    );
    let keys = vec![MeshSecOpenKey {
        peer_id: "peer-a".into(),
        remote_node_id: "node-a".into(),
        static_key: TEST_KEY,
    }];
    let mut replay = MeshSecReplayCache::new(MESHSEC_REPLAY_WINDOW_BITS);
    let epoch = meshsec_epoch_number(now_secs());
    let (_, frame) = open_mesh_frame(
        &buf[..n],
        &keys,
        "node-b",
        epoch.saturating_sub(MESHSEC_ACCEPTED_EPOCH_SKEW_SLOTS)
            ..=epoch + MESHSEC_ACCEPTED_EPOCH_SKEW_SLOTS,
        &mut replay,
    )
    .expect("open sealed egress frame");
    (frame, peer)
}

#[tokio::test]
async fn meshsec_egress_seals_outbound_and_opens_sealed_return() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
    let peer_addr = peer.local_addr().expect("peer addr");
    let (seen_tx, mut seen_rx) = mpsc::channel::<MeshFrame>(2);

    tokio::spawn(async move {
        let (open, client) = recv_sealed_frame_opened_from_node_a(&peer).await;
        seen_tx.send(open).await.expect("record open");
        let (send, client_again) = recv_sealed_frame_opened_from_node_a(&peer).await;
        assert_eq!(client_again, client);
        seen_tx.send(send).await.expect("record send");

        let reply = seal_reply_frame(
            &MeshFrame::DatagramReturn {
                session_id: "test-session".into(),
                seq: 1,
                source: endpoint("8.8.8.8", 53),
                payload: Bytes::from_static(b"dns-reply"),
            },
            1,
        );
        peer.send_to(&reply, client).await.expect("send reply");
    });

    let egress = MeshPeerUdpEgress::new(
        ExitId("peer-udp".into()),
        peer_addr,
        Duration::from_millis(500),
    )
    .with_native_event_mode(NativeEventMode::MeshFrame)
    .with_meshsec(MeshSecSealContext {
        local_node_id: "node-a".into(),
        remote_node_id: "node-b".into(),
        static_key: TEST_KEY,
        boot_salt: [1, 2, 3, 4],
    });
    let target = endpoint("8.8.8.8", 53);
    let request = BusSessionRequest::datagram(target.clone());
    let mut session = egress
        .open_datagram(
            &request,
            BusSessionInfo::empty_for_test(ScheduleMode::Ordered),
        )
        .await
        .expect("open mesh peer datagram");

    session
        .send_to(target.clone(), Bytes::from_static(b"dns-query"))
        .await
        .expect("send datagram");

    assert!(matches!(
        seen_rx.recv().await.expect("open frame"),
        MeshFrame::DatagramOpen(_)
    ));
    assert_eq!(
        seen_rx.recv().await.expect("send frame"),
        MeshFrame::DatagramSend {
            session_id: "test-session".into(),
            seq: 1,
            target: target.clone(),
            payload: Bytes::from_static(b"dns-query"),
        }
    );

    let (source, payload) = session.recv_from().await.expect("recv datagram return");
    assert_eq!(source, target);
    assert_eq!(&payload[..], b"dns-reply");
}

#[tokio::test]
async fn meshsec_stream_send_has_no_artificial_per_chunk_delay() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
    let peer_addr = peer.local_addr().expect("peer addr");

    let egress = MeshPeerUdpEgress::new(
        ExitId("peer-udp".into()),
        peer_addr,
        Duration::from_millis(500),
    )
    .with_native_event_mode(NativeEventMode::MeshFrame)
    .with_meshsec(MeshSecSealContext {
        local_node_id: "node-a".into(),
        remote_node_id: "node-b".into(),
        static_key: TEST_KEY,
        boot_salt: [1, 2, 3, 4],
    });
    let target = endpoint("example.com", 443);
    let request = BusSessionRequest::stream(target);
    let session = egress
        .open_stream(
            &request,
            BusSessionInfo::empty_for_test(ScheduleMode::Ordered),
        )
        .await
        .expect("open mesh peer stream");

    let connect = tokio::spawn(async move {
        let mut session = session;
        session.connect().await.expect("connect mesh peer stream");
        session
    });
    let (open, client) = recv_sealed_frame_opened_from_node_a(&peer).await;
    let open_token = match &open {
        MeshFrame::StreamOpen(open) => open.open_token,
        other => panic!("expected stream open, got {other:?}"),
    };
    let accepted = seal_reply_frame(
        &MeshFrame::StreamOpenAccepted {
            session_id: "test-session".into(),
            open_token,
        },
        1,
    );
    peer.send_to(&accepted, client)
        .await
        .expect("send stream open accepted");
    let session = connect.await.expect("connect task");

    let (mut send, _recv) = session.split();
    let payload = Bytes::from(vec![7u8; 40_000]);
    tokio::time::timeout(Duration::from_millis(150), send.send(payload))
        .await
        .expect("sealed stream send must not sleep once per small chunk")
        .expect("send stream payload");
}
