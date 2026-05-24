use bytes::{Bytes, BytesMut};
use mb_endpoint::Endpoint;
use mb_proto_mesh::{
    CloseReasonWire, FlowSemanticsWire, MESHSEC_ACCEPTED_EPOCH_SKEW_SLOTS,
    MESHSEC_REPLAY_WINDOW_BITS, MeshFrame, MeshSecOpenKey, MeshSecReplayCache, MeshSecSealContext,
    NativeEventMode, ReturnSemanticsWire, StreamOpen, StreamOpenRejectReason, decode_frame,
    encode_frame, meshsec_epoch_number, open_mesh_frame, seal_mesh_frame,
};
use mesh_bus_core::transport::udp_loop::UdpPacketLoop;
use mesh_bus_core::{
    BusBuilder, BusEvent, ExitId, ExitResult, IngressPlugin, ObserverPlugin, RankContext,
    ScheduleDecision, SchedulerPlugin,
    kernel::observation::{EventEnvelope, EventTypeId, OBS_MESHSEC_DROP, OBS_NATIVE_DROP},
};
use mesh_bus_egress_tcp::TcpEgress;
use mesh_bus_egress_udp::UdpEgress;
use mesh_bus_ingress_mesh_peer_udp::MeshPeerUdpIngress;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

struct First;

impl SchedulerPlugin for First {
    fn schedule(&self, candidates: &[ExitId], _ctx: &RankContext) -> ScheduleDecision {
        ScheduleDecision::ordered((0..candidates.len()).collect())
    }

    fn feedback(&self, _result: &ExitResult, _payload_bytes: u64, _at_ms: u64) {}
}

struct DropRecorder {
    events: Arc<Mutex<Vec<EventEnvelope>>>,
}

impl ObserverPlugin for DropRecorder {
    fn subscribed_core_events(&self) -> &'static [mesh_bus_core::kernel::observation::CoreEventId] {
        &[]
    }

    fn subscribed_events(&self) -> &'static [EventTypeId] {
        &[OBS_MESHSEC_DROP, OBS_NATIVE_DROP]
    }

    fn on_event(&self, event: &BusEvent) {
        if let BusEvent::Observation(env) = event {
            self.events.lock().expect("drop events").push(env.clone());
        }
    }
}

async fn wait_for_drop_reason(
    events: &Arc<Mutex<Vec<EventEnvelope>>>,
    type_id: EventTypeId,
    reason: &str,
) -> EventEnvelope {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(env) = events
            .lock()
            .expect("drop events")
            .iter()
            .find(|env| env.type_id == type_id && env.payload.0.reason.as_deref() == Some(reason))
            .cloned()
        {
            return env;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "missing {type_id:?} reason={reason}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn endpoint(host: &str, port: u16) -> Endpoint {
    Endpoint::new(host.to_string(), port).unwrap()
}

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

async fn spawn_tcp_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind tcp echo");
    let port = listener.local_addr().expect("tcp echo addr").port();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 2048];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    port
}

async fn recv_mesh_frame(sock: &UdpSocket) -> MeshFrame {
    let mut buf = vec![0u8; 2048];
    let (n, _) = sock.recv_from(&mut buf).await.expect("recv mesh frame");
    decode_frame(&mut BytesMut::from(&buf[..n])).expect("decode mesh frame")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn datagram_send_reenters_bus_and_returns_source_endpoint() {
    let echo_port = spawn_udp_echo().await;
    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_datagram_egress(Box::new(UdpEgress::new(
            ExitId("udp".into()),
            Duration::from_millis(500),
        )))
        .build()
        .await;
    let port = bus.port();
    let _handle = bus.spawn();

    let ingress_loop = UdpPacketLoop::bind("127.0.0.1:0".parse().expect("ingress bind addr"))
        .await
        .expect("bind mesh ingress");
    let ingress_addr = ingress_loop.local_addr().expect("ingress addr");
    let ingress =
        MeshPeerUdpIngress::new(ingress_loop).with_native_event_mode(NativeEventMode::MeshFrame);
    tokio::spawn(async move {
        let _ = Box::new(ingress).run(port).await;
    });

    let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
    let target = endpoint("127.0.0.1", echo_port);
    let open = encode_frame(&MeshFrame::DatagramOpen(mb_proto_mesh::DatagramOpen {
        session_id: "remote-d-1".into(),
        fixed_target: Some(target.clone()),
        max_datagram_bytes: 1200,
    }))
    .expect("encode open");
    peer.send_to(&open, ingress_addr).await.expect("send open");

    let send = encode_frame(&MeshFrame::DatagramSend {
        session_id: "remote-d-1".into(),
        seq: 7,
        target: target.clone(),
        payload: Bytes::from_static(b"hello"),
    })
    .expect("encode send");
    peer.send_to(&send, ingress_addr)
        .await
        .expect("send datagram");

    let returned = recv_mesh_frame(&peer).await;
    assert_eq!(
        returned,
        MeshFrame::DatagramReturn {
            session_id: "remote-d-1".into(),
            seq: 0,
            source: target,
            payload: Bytes::from_static(b"hello"),
        }
    );
}

#[tokio::test]
async fn stream_open_rejects_when_local_open_fails() {
    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_datagram_egress(Box::new(UdpEgress::new(
            ExitId("udp".into()),
            Duration::from_millis(500),
        )))
        .build()
        .await;
    let port = bus.port();
    let _handle = bus.spawn();

    let ingress_loop = UdpPacketLoop::bind("127.0.0.1:0".parse().expect("ingress bind addr"))
        .await
        .expect("bind mesh ingress");
    let ingress_addr = ingress_loop.local_addr().expect("ingress addr");
    let ingress =
        MeshPeerUdpIngress::new(ingress_loop).with_native_event_mode(NativeEventMode::MeshFrame);
    tokio::spawn(async move {
        let _ = Box::new(ingress).run(port).await;
    });

    let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
    let open = encode_frame(&MeshFrame::StreamOpen(StreamOpen {
        session_id: "remote-s-1".into(),
        open_token: 11,
        target: endpoint("example.com", 443),
        route_group: None,
        flow_semantics: FlowSemanticsWire::ByteStream,
        return_semantics: ReturnSemanticsWire::Direct,
        source_node_id: "node-a".into(),
        path_trace: vec!["node-a".into()],
    }))
    .expect("encode stream open");
    peer.send_to(&open, ingress_addr)
        .await
        .expect("send stream open");

    let rejected = recv_mesh_frame(&peer).await;
    assert_eq!(
        rejected,
        MeshFrame::StreamOpenReject {
            session_id: "remote-s-1".into(),
            open_token: 11,
            reason: StreamOpenRejectReason::NoUsableExit,
            close_reason: CloseReasonWire::NoUsableExit,
        }
    );
}

async fn run_stream_reentry_gate() {
    let echo_port = spawn_tcp_echo().await;
    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_stream_egress(Box::new(TcpEgress::new(
            ExitId("tcp".into()),
            Duration::from_millis(500),
        )))
        .build()
        .await;
    let port = bus.port();
    let _handle = bus.spawn();

    let ingress_loop = UdpPacketLoop::bind("127.0.0.1:0".parse().expect("ingress bind addr"))
        .await
        .expect("bind mesh ingress");
    let ingress_addr = ingress_loop.local_addr().expect("ingress addr");
    let ingress =
        MeshPeerUdpIngress::new(ingress_loop).with_native_event_mode(NativeEventMode::MeshFrame);
    tokio::spawn(async move {
        let _ = Box::new(ingress).run(port).await;
    });

    let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
    let open = encode_frame(&MeshFrame::StreamOpen(StreamOpen {
        session_id: "remote-s-1".into(),
        open_token: 22,
        target: endpoint("127.0.0.1", echo_port),
        route_group: None,
        flow_semantics: FlowSemanticsWire::ByteStream,
        return_semantics: ReturnSemanticsWire::Direct,
        source_node_id: "node-a".into(),
        path_trace: vec!["node-a".into()],
    }))
    .expect("encode stream open");
    peer.send_to(&open, ingress_addr)
        .await
        .expect("send stream open");

    let data = encode_frame(&MeshFrame::StreamData {
        session_id: "remote-s-1".into(),
        seq: 1,
        payload: Bytes::from_static(b"stream-reentry"),
    })
    .expect("encode stream data");
    peer.send_to(&data, ingress_addr)
        .await
        .expect("send stream data");

    assert_eq!(
        recv_mesh_frame(&peer).await,
        MeshFrame::StreamOpenAccepted {
            session_id: "remote-s-1".into(),
            open_token: 22,
        }
    );
    assert_eq!(
        recv_mesh_frame(&peer).await,
        MeshFrame::StreamData {
            session_id: "remote-s-1".into(),
            seq: 1,
            payload: Bytes::from_static(b"stream-reentry"),
        }
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_open_reenters_local_bus() {
    run_stream_reentry_gate().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_data_forwards_to_local_send_half() {
    run_stream_reentry_gate().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_stream_recv_pump_returns_stream_data_to_peer() {
    run_stream_reentry_gate().await;
}

const TEST_KEY: [u8; 32] = [7u8; 32];

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

/// Seal a frame as remote sender `node-a` toward receiver `node-b`.
fn seal_as_node_a(frame: &MeshFrame, key: [u8; 32], counter: u64) -> Vec<u8> {
    let ctx = MeshSecSealContext {
        local_node_id: "node-a".into(),
        remote_node_id: "node-b".into(),
        static_key: key,
        boot_salt: [9, 8, 7, 6],
    };
    seal_mesh_frame(frame, &ctx, meshsec_epoch_number(now_secs()), counter).expect("seal frame")
}

/// Open a reverse reply sealed by the ingress (`node-b` sender).
fn open_reverse_reply(packet: &[u8]) -> MeshFrame {
    let keys = vec![MeshSecOpenKey {
        peer_id: "peer-b".into(),
        remote_node_id: "node-b".into(),
        static_key: TEST_KEY,
    }];
    let mut replay = MeshSecReplayCache::new(MESHSEC_REPLAY_WINDOW_BITS);
    let epoch = meshsec_epoch_number(now_secs());
    let (_, frame) = open_mesh_frame(
        packet,
        &keys,
        "node-a",
        epoch.saturating_sub(MESHSEC_ACCEPTED_EPOCH_SKEW_SLOTS)
            ..=epoch + MESHSEC_ACCEPTED_EPOCH_SKEW_SLOTS,
        &mut replay,
    )
    .expect("open reverse reply");
    frame
}

async fn spawn_keyed_ingress(port: mesh_bus_core::BusPort) -> std::net::SocketAddr {
    let ingress_loop = UdpPacketLoop::bind("127.0.0.1:0".parse().expect("ingress bind addr"))
        .await
        .expect("bind mesh ingress");
    let ingress_addr = ingress_loop.local_addr().expect("ingress addr");
    let keys = vec![MeshSecOpenKey {
        peer_id: "peer-a".into(),
        remote_node_id: "node-a".into(),
        static_key: TEST_KEY,
    }];
    let ingress = MeshPeerUdpIngress::new(ingress_loop)
        .with_native_event_mode(NativeEventMode::MeshFrame)
        .with_meshsec_keys("node-b".into(), keys);
    tokio::spawn(async move {
        let _ = Box::new(ingress).run(port).await;
    });
    ingress_addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn meshsec_sealed_datagram_reenters_bus_and_seals_return() {
    let echo_port = spawn_udp_echo().await;
    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_datagram_egress(Box::new(UdpEgress::new(
            ExitId("udp".into()),
            Duration::from_millis(500),
        )))
        .build()
        .await;
    let port = bus.port();
    let _handle = bus.spawn();
    let ingress_addr = spawn_keyed_ingress(port).await;

    let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
    let target = endpoint("127.0.0.1", echo_port);

    let open = seal_as_node_a(
        &MeshFrame::DatagramOpen(mb_proto_mesh::DatagramOpen {
            session_id: "sec-d-1".into(),
            fixed_target: Some(target.clone()),
            max_datagram_bytes: 1200,
        }),
        TEST_KEY,
        1,
    );
    peer.send_to(&open, ingress_addr).await.expect("send open");

    let send = seal_as_node_a(
        &MeshFrame::DatagramSend {
            session_id: "sec-d-1".into(),
            seq: 7,
            target: target.clone(),
            payload: Bytes::from_static(b"hello"),
        },
        TEST_KEY,
        2,
    );
    peer.send_to(&send, ingress_addr)
        .await
        .expect("send datagram");

    let mut buf = vec![0u8; 2048];
    let (n, _) = peer.recv_from(&mut buf).await.expect("recv sealed return");
    // The wire bytes must not be a clear Mesh frame.
    assert!(
        decode_frame(&mut BytesMut::from(&buf[..n])).is_err(),
        "DatagramReturn must travel sealed, not in clear"
    );
    let returned = open_reverse_reply(&buf[..n]);
    assert_eq!(
        returned,
        MeshFrame::DatagramReturn {
            session_id: "sec-d-1".into(),
            seq: 0,
            source: target,
            payload: Bytes::from_static(b"hello"),
        }
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn meshsec_clear_and_wrong_key_packets_are_dropped() {
    let echo_port = spawn_udp_echo().await;
    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_datagram_egress(Box::new(UdpEgress::new(
            ExitId("udp".into()),
            Duration::from_millis(500),
        )))
        .build()
        .await;
    let port = bus.port();
    let _handle = bus.spawn();
    let ingress_addr = spawn_keyed_ingress(port).await;

    let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
    let target = endpoint("127.0.0.1", echo_port);

    // Clear (unsealed) frames must be dropped when MeshSec keys are configured.
    let clear_open = encode_frame(&MeshFrame::DatagramOpen(mb_proto_mesh::DatagramOpen {
        session_id: "clear-1".into(),
        fixed_target: Some(target.clone()),
        max_datagram_bytes: 1200,
    }))
    .expect("encode clear open");
    peer.send_to(&clear_open, ingress_addr)
        .await
        .expect("send clear open");
    let clear_send = encode_frame(&MeshFrame::DatagramSend {
        session_id: "clear-1".into(),
        seq: 1,
        target: target.clone(),
        payload: Bytes::from_static(b"clear"),
    })
    .expect("encode clear send");
    peer.send_to(&clear_send, ingress_addr)
        .await
        .expect("send clear send");

    // Wrong-key sealed frames must never open a bus session.
    let wrong = seal_as_node_a(
        &MeshFrame::DatagramOpen(mb_proto_mesh::DatagramOpen {
            session_id: "wrong-1".into(),
            fixed_target: Some(target.clone()),
            max_datagram_bytes: 1200,
        }),
        [1u8; 32],
        1,
    );
    peer.send_to(&wrong, ingress_addr)
        .await
        .expect("send wrong-key open");

    let mut buf = vec![0u8; 2048];
    let quiet = tokio::time::timeout(Duration::from_millis(300), peer.recv_from(&mut buf)).await;
    assert!(
        quiet.is_err(),
        "clear and wrong-key packets must not produce any datagram return"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn meshsec_wrong_key_and_replay_publish_drop_events_without_sessions() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_datagram_egress(Box::new(UdpEgress::new(
            ExitId("udp".into()),
            Duration::from_millis(500),
        )))
        .add_observer(Box::new(DropRecorder {
            events: events.clone(),
        }))
        .build()
        .await;
    let port = bus.port();
    let handle = bus.spawn();
    let ingress_addr = spawn_keyed_ingress(port).await;

    let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
    let target = endpoint("127.0.0.1", spawn_udp_echo().await);
    let wrong = seal_as_node_a(
        &MeshFrame::DatagramOpen(mb_proto_mesh::DatagramOpen {
            session_id: "wrong-obs".into(),
            fixed_target: Some(target),
            max_datagram_bytes: 1200,
        }),
        [1u8; 32],
        44,
    );
    peer.send_to(&wrong, ingress_addr)
        .await
        .expect("send wrong-key open");
    let auth = wait_for_drop_reason(&events, OBS_MESHSEC_DROP, "auth").await;
    assert_eq!(auth.payload.0.secure, Some(true));

    let port_open = seal_as_node_a(
        &MeshFrame::PortOpen(mb_proto_mesh::ReceiverMouth {
            mouth_id: "mouth-a".into(),
            udp_addr: "127.0.0.1:19000".into(),
            family_filter: vec!["control".into()],
            advertised_capacity: 1,
            epoch: 1,
        }),
        TEST_KEY,
        45,
    );
    peer.send_to(&port_open, ingress_addr)
        .await
        .expect("send port open");
    peer.send_to(&port_open, ingress_addr)
        .await
        .expect("send replayed port open");
    let replay = wait_for_drop_reason(&events, OBS_MESHSEC_DROP, "replay").await;
    assert_eq!(replay.payload.0.source_addr.is_some(), true);

    let snapshot = handle.snapshot().await;
    assert_eq!(snapshot.dispatch_success, 0);
    assert_eq!(snapshot.dispatch_failure, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_native_packet_publishes_native_drop_without_session() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_datagram_egress(Box::new(UdpEgress::new(
            ExitId("udp".into()),
            Duration::from_millis(500),
        )))
        .add_observer(Box::new(DropRecorder {
            events: events.clone(),
        }))
        .build()
        .await;
    let port = bus.port();
    let handle = bus.spawn();

    let ingress_loop = UdpPacketLoop::bind("127.0.0.1:0".parse().expect("ingress bind addr"))
        .await
        .expect("bind mesh ingress");
    let ingress_addr = ingress_loop.local_addr().expect("ingress addr");
    let ingress = MeshPeerUdpIngress::new(ingress_loop)
        .with_native_event_mode(NativeEventMode::SecureUdpNative);
    tokio::spawn(async move {
        let _ = Box::new(ingress).run(port).await;
    });

    let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
    peer.send_to(b"not-a-native-event", ingress_addr)
        .await
        .expect("send malformed native packet");
    let event = wait_for_drop_reason(&events, OBS_NATIVE_DROP, "event_decode").await;
    assert_eq!(event.payload.0.secure, Some(false));

    let snapshot = handle.snapshot().await;
    assert_eq!(snapshot.dispatch_success, 0);
    assert_eq!(snapshot.dispatch_failure, 0);
}
