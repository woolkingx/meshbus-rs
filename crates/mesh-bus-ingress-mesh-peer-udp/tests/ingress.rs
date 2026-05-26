use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use mb_endpoint::Endpoint;
use mb_proto_mesh::{
    CloseReasonWire, FlowSemanticsWire, MESHSEC_ACCEPTED_EPOCH_SKEW_SLOTS,
    MESHSEC_REPLAY_WINDOW_BITS, MeshFrame, MeshSecOpenKey, MeshSecReplayCache, MeshSecSealContext,
    NativeEventMode, ReturnSemanticsWire, STEER_DELIVERY_POLICY_ID, StreamOpen,
    StreamOpenRejectReason, decode_event, decode_frame, encode_event, encode_frame,
    event_frame_payload, frame_event_meta, meshsec_epoch_number, open_bytes, open_mesh_frame,
    seal_bytes, seal_mesh_frame, wrap_frame_event,
};
use mesh_bus_core::transport::udp_loop::UdpPacketLoop;
use mesh_bus_core::{
    BusBuilder, BusEvent, BusSessionInfo, BusSessionRequest, Capabilities, DisconnectReason,
    ExitId, ExitResult, IngressPlugin, ObserverPlugin, RankContext, ScheduleDecision,
    SchedulerPlugin, StreamEgress, StreamRecvHalf, StreamSendHalf, StreamSession, TcpSpliceSession,
    kernel::observation::{EventEnvelope, EventTypeId, OBS_MESHSEC_DROP, OBS_NATIVE_DROP},
};
use mesh_bus_egress_tcp::TcpEgress;
use mesh_bus_egress_udp::UdpEgress;
use mesh_bus_ingress_mesh_peer_udp::MeshPeerUdpIngress;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

#[path = "ingress/meshsec_cases.rs"]
mod meshsec_cases;

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

struct BurstStreamEgress {
    id: ExitId,
    caps: Capabilities,
    payload: Bytes,
}

impl BurstStreamEgress {
    fn new(payload: Bytes) -> Self {
        Self {
            id: ExitId("burst".into()),
            caps: Capabilities {
                protocol: "burst-stream".into(),
                supports_stream: true,
                supports_datagram: false,
                max_payload_bytes: None,
                groups: Vec::new(),
            },
            payload,
        }
    }
}

#[async_trait]
impl StreamEgress for BurstStreamEgress {
    fn id(&self) -> &ExitId {
        &self.id
    }

    fn capabilities(&self) -> &Capabilities {
        &self.caps
    }

    async fn open_stream(
        &self,
        _request: &BusSessionRequest,
        info: BusSessionInfo,
    ) -> Result<Box<dyn StreamSession>, DisconnectReason> {
        Ok(Box::new(BurstStreamSession {
            info,
            payload: Some(self.payload.clone()),
            last_error: None,
        }))
    }
}

struct BurstStreamSession {
    info: BusSessionInfo,
    payload: Option<Bytes>,
    last_error: Option<DisconnectReason>,
}

#[async_trait]
impl StreamSession for BurstStreamSession {
    async fn connect(&mut self) -> Result<&BusSessionInfo, DisconnectReason> {
        Ok(&self.info)
    }

    fn into_tcp_splice(self: Box<Self>) -> Result<TcpSpliceSession, Box<dyn StreamSession>> {
        Err(self)
    }

    fn split(self: Box<Self>) -> (Box<dyn StreamSendHalf>, Box<dyn StreamRecvHalf>) {
        (
            Box::new(BurstSendHalf),
            Box::new(BurstRecvHalf {
                payload: self.payload,
                last_error: self.last_error,
            }),
        )
    }

    async fn abort(&mut self, reason: DisconnectReason) {
        self.last_error = Some(reason);
    }

    fn info(&self) -> &BusSessionInfo {
        &self.info
    }

    fn last_error(&self) -> Option<&DisconnectReason> {
        self.last_error.as_ref()
    }
}

struct BurstSendHalf;

#[async_trait]
impl StreamSendHalf for BurstSendHalf {
    async fn send(&mut self, _payload: Bytes) -> Result<(), DisconnectReason> {
        Ok(())
    }

    async fn shutdown_write(&mut self) {}

    async fn abort(&mut self, _reason: DisconnectReason) {}
}

struct BurstRecvHalf {
    payload: Option<Bytes>,
    last_error: Option<DisconnectReason>,
}

#[async_trait]
impl StreamRecvHalf for BurstRecvHalf {
    async fn recv(&mut self) -> Option<Bytes> {
        self.payload.take()
    }

    fn last_error(&self) -> Option<&DisconnectReason> {
        self.last_error.as_ref()
    }
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
            seq: 1,
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

/// Seal a native MeshEvent as remote sender `node-a` toward receiver `node-b`.
fn seal_native_as_node_a(frame: &MeshFrame, key: [u8; 32], counter: u64) -> Vec<u8> {
    let ctx = MeshSecSealContext {
        local_node_id: "node-a".into(),
        remote_node_id: "node-b".into(),
        static_key: key,
        boot_salt: [9, 8, 7, 6],
    };
    let frame_clear = encode_frame(frame).expect("encode frame");
    let (family_id, seq, semantic) = frame_event_meta(frame);
    let event = wrap_frame_event(
        family_id,
        seq,
        semantic,
        STEER_DELIVERY_POLICY_ID,
        &frame_clear,
    );
    let event_bytes = encode_event(&event).expect("encode event");
    seal_bytes(
        &event_bytes,
        &ctx,
        meshsec_epoch_number(now_secs()),
        counter,
    )
    .expect("seal native event")
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

/// Open a reverse native MeshEvent reply sealed by the ingress (`node-b` sender).
fn open_reverse_native_reply(packet: &[u8]) -> MeshFrame {
    let keys = vec![MeshSecOpenKey {
        peer_id: "peer-b".into(),
        remote_node_id: "node-b".into(),
        static_key: TEST_KEY,
    }];
    let mut replay = MeshSecReplayCache::new(MESHSEC_REPLAY_WINDOW_BITS);
    let epoch = meshsec_epoch_number(now_secs());
    let (_, clear) = open_bytes(
        packet,
        &keys,
        "node-a",
        epoch.saturating_sub(MESHSEC_ACCEPTED_EPOCH_SKEW_SLOTS)
            ..=epoch + MESHSEC_ACCEPTED_EPOCH_SKEW_SLOTS,
        &mut replay,
    )
    .expect("open reverse native reply");
    let event = decode_event(&mut BytesMut::from(&clear[..])).expect("decode reverse event");
    let payload = event_frame_payload(&event).expect("reverse event payload");
    decode_frame(&mut BytesMut::from(payload)).expect("decode reverse frame")
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

async fn spawn_keyed_native_ingress(port: mesh_bus_core::BusPort) -> std::net::SocketAddr {
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
        .with_native_event_mode(NativeEventMode::SecureUdpNative)
        .with_meshsec_keys("node-b".into(), keys);
    tokio::spawn(async move {
        let _ = Box::new(ingress).run(port).await;
    });
    ingress_addr
}
