//! Raw UDP Mesh Protocol egress adapter.

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use mb_endpoint::Endpoint;
use mb_proto_mesh::{
    AckNack, CloseReasonWire, DatagramOpen, DeliveryMode, FlowSemanticsWire,
    MESHSEC_ACCEPTED_EPOCH_SKEW_SLOTS, MESHSEC_REPLAY_WINDOW_BITS, MeshFrame, MeshSecOpenKey,
    MeshSecReplayCache, MeshSecSealContext, NativeEventMode, ReceiverMouth, ReturnSemanticsWire,
    StreamOpen, decode_frame, encode_event, encode_frame, frame_event_meta, meshsec_epoch_number,
    open_mesh_frame, seal_bytes, seal_mesh_frame, wrap_frame_event,
};
use mesh_bus_core::transport::udp_loop::{OutboundDatagram, UdpPacketLoop};
use mesh_bus_core::{
    BusPathInfo, BusSessionInfo, BusSessionRequest, Capabilities, DatagramEgress, DatagramRecvHalf,
    DatagramSendHalf, DatagramSession, DisconnectReason, ExitId, FlowSemantics, Measurement,
    PathState, ReturnSemantics, SendError, StreamEgress, StreamRecvHalf, StreamSendHalf,
    StreamSession,
};
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::watch;

const MAX_MESH_DATAGRAM_PAYLOAD_BYTES: usize = 65_000;

/// Upper bound on bincode MeshFrame::DatagramSend framing minus the payload
/// (enum tag + session_id string + Endpoint + seq). Conservative; sealed clear
/// = framing + payload must fit MESHSEC_MAX_CLEAR_LEN.
const MESH_DATAGRAM_FRAME_OVERHEAD: usize = 256;
const MESHSEC_STREAM_CHUNK_BYTES: usize = 832;

/// Advertised datagram payload budget when the configured peer carries MeshSec:
/// the sealed clear (encoded frame) must fit the 1024 padding bucket.
pub fn meshsec_max_payload_bytes() -> usize {
    mb_proto_mesh::meshsec::MESHSEC_MAX_CLEAR_LEN - MESH_DATAGRAM_FRAME_OVERHEAD
}

fn stream_chunk_bytes(seal: Option<&MeshSecEgress>) -> usize {
    if seal.is_some() {
        MESHSEC_STREAM_CHUNK_BYTES
    } else {
        MAX_MESH_DATAGRAM_PAYLOAD_BYTES
    }
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Shared, interior-mutable outbound delivery coordinate for one datagram
/// session. A peer PortOpen rotates the udp destination here and nowhere else:
/// session id, `next_seq`, route group, and family identity live in separate
/// session fields and are provably untouched by a coordinate rotation.
struct DeliveryCoord {
    addr: std::sync::Mutex<SocketAddr>,
    epoch: AtomicU64,
}

impl DeliveryCoord {
    fn new(addr: SocketAddr) -> Arc<Self> {
        Arc::new(Self {
            addr: std::sync::Mutex::new(addr),
            epoch: AtomicU64::new(0),
        })
    }

    fn addr(&self) -> SocketAddr {
        *self.addr.lock().unwrap()
    }

    /// Apply a peer PortOpen. Updates only the udp coordinate and its epoch.
    /// A strictly-older epoch is rejected (stale rotation). Make-before-break:
    /// the new coordinate is live the instant this returns true.
    fn apply_port_open(&self, mouth: &ReceiverMouth) -> bool {
        let Ok(new_addr) = mouth.udp_addr.parse::<SocketAddr>() else {
            return false;
        };
        if mouth.epoch < self.epoch.load(Ordering::Relaxed) {
            return false;
        }
        *self.addr.lock().unwrap() = new_addr;
        self.epoch.store(mouth.epoch, Ordering::Relaxed);
        true
    }
}

/// Bounded retransmit ring depth for `DeliveryMode::Repair`. One generation of
/// in-flight data packages; older entries fall off the front.
const REPAIR_RING_DEPTH: usize = 64;

/// Clamp config-supplied replicate fanout into a bounded duplicate-send count.
/// 0 is meaningless (no send), > 4 is unbounded amplification; both are
/// rejected to the nearest legal value.
fn replicate_count(fanout: u8) -> usize {
    (fanout as usize).clamp(1, 4)
}

/// Which configured mouth a striped DataPackage rides, by seq. Round-robin so
/// consecutive packages spread across mouths; with one mouth it is always 0
/// (Stripe degrades to Steer). Family identity/order is unaffected — the
/// receiver `FamilyReorderState` restores order regardless of arrival mouth.
/// Contract surface proven by `policy_tests`; multi-mouth wiring is the
/// documented D-M7.5 follow-up (egress holds one rotating coord today).
#[allow(dead_code)]
fn stripe_index(seq: u64, mouth_count: usize) -> usize {
    if mouth_count <= 1 {
        0
    } else {
        (seq as usize) % mouth_count
    }
}

/// Per-egress delivery policy. It changes only delivery coordinates (how the
/// one logical event stream maps onto sends); it never alters session id,
/// family id, seq, route_group, or target endpoint.
struct EgressPolicy {
    mode: DeliveryMode,
    replicate_fanout: u8,
    // Probe budget mechanism is test-proven (`policy_tests`); the periodic
    // probe sender loop is the documented D-M7.5 follow-up.
    #[allow(dead_code)]
    probe_budget: u8,
    #[allow(dead_code)]
    probe_used: AtomicU64,
    retransmit: std::sync::Mutex<std::collections::VecDeque<(u64, Vec<u8>)>>,
}

impl EgressPolicy {
    fn new(mode: DeliveryMode, replicate_fanout: u8, probe_budget: u8) -> Arc<Self> {
        Arc::new(Self {
            mode,
            replicate_fanout,
            probe_budget,
            probe_used: AtomicU64::new(0),
            retransmit: std::sync::Mutex::new(std::collections::VecDeque::new()),
        })
    }

    /// Stable wire policy id stamped on every event this egress wraps.
    fn policy_id(&self) -> &'static str {
        self.mode.policy_id()
    }

    /// How many copies of one logical event to send. Replicate fans out a
    /// bounded duplicate send; every other mode sends exactly once.
    fn send_copies(&self) -> usize {
        match self.mode {
            DeliveryMode::Replicate => replicate_count(self.replicate_fanout),
            _ => 1,
        }
    }

    /// Remember a data send so an inbound AckNack can retransmit it. Only used
    /// by Repair; the ring is bounded so it never grows without limit.
    fn remember(&self, seq: u64, bytes: &[u8]) {
        if self.mode != DeliveryMode::Repair || seq == 0 {
            return;
        }
        let mut ring = self.retransmit.lock().unwrap();
        ring.push_back((seq, bytes.to_vec()));
        while ring.len() > REPAIR_RING_DEPTH {
            ring.pop_front();
        }
    }

    /// Buffered (seq, bytes) the peer's AckNack says it is still missing.
    fn to_retransmit(&self, ack: &AckNack) -> Vec<Vec<u8>> {
        let ring = self.retransmit.lock().unwrap();
        ring.iter()
            .filter(|(seq, _)| {
                ack.missing_ranges
                    .iter()
                    .any(|r| *seq >= r.start && *seq <= r.end)
            })
            .map(|(_, bytes)| bytes.clone())
            .collect()
    }

    /// Budget gate for probe sends. Returns true at most `probe_budget` times;
    /// a probe never creates route truth, so an exhausted budget simply skips.
    #[allow(dead_code)]
    fn take_probe_token(&self) -> bool {
        let used = self.probe_used.fetch_add(1, Ordering::Relaxed);
        used < self.probe_budget as u64
    }
}

/// Sender-side MeshSec state for one datagram session: the sealing context plus
/// a session-monotonic counter shared by every outbound frame.
#[derive(Clone)]
struct MeshSecEgress {
    ctx: MeshSecSealContext,
    counter: Arc<AtomicU64>,
}

impl MeshSecEgress {
    /// Reverse-direction open key so the egress can authenticate the peer's
    /// sealed `DatagramReturn` / `DatagramClose` replies.
    fn reply_recv(&self) -> MeshSecRecv {
        MeshSecRecv {
            local_node_id: self.ctx.local_node_id.clone(),
            keys: vec![MeshSecOpenKey {
                peer_id: self.ctx.remote_node_id.clone(),
                remote_node_id: self.ctx.remote_node_id.clone(),
                static_key: self.ctx.static_key,
            }],
            replay: MeshSecReplayCache::new(MESHSEC_REPLAY_WINDOW_BITS),
        }
    }
}

/// Receiver-side MeshSec state for opening sealed reply frames.
struct MeshSecRecv {
    local_node_id: String,
    keys: Vec<MeshSecOpenKey>,
    replay: MeshSecReplayCache,
}

#[derive(Clone)]
pub struct MeshPeerUdpEgress {
    id: ExitId,
    caps: Capabilities,
    peer: SocketAddr,
    timeout: Duration,
    meshsec: Option<MeshSecEgress>,
    native_event_mode: NativeEventMode,
    delivery_mode: DeliveryMode,
    replicate_fanout: u8,
    probe_budget: u8,
}

impl MeshPeerUdpEgress {
    pub fn new(id: ExitId, peer: SocketAddr, timeout: Duration) -> Self {
        Self {
            id,
            caps: Capabilities {
                protocol: "mesh-peer-udp".into(),
                supports_stream: true,
                supports_datagram: true,
                max_payload_bytes: Some(MAX_MESH_DATAGRAM_PAYLOAD_BYTES as u64),
                groups: Vec::new(),
            },
            peer,
            timeout,
            meshsec: None,
            native_event_mode: NativeEventMode::default(),
            delivery_mode: DeliveryMode::Steer,
            replicate_fanout: 2,
            probe_budget: 4,
        }
    }

    pub fn with_groups(mut self, groups: Vec<String>) -> Self {
        self.caps.groups = groups;
        self
    }

    /// Runtime registers this owner through separate stream/datagram adapter
    /// projections. The owner capability is stream+datagram, but each adapter
    /// must expose only the flow family it can actually handle inside core
    /// dispatch.
    pub fn as_stream_adapter(mut self) -> Self {
        self.caps.supports_stream = true;
        self.caps.supports_datagram = false;
        self
    }

    /// Runtime registers this owner through separate stream/datagram adapter
    /// projections. The owner capability is stream+datagram, but each adapter
    /// must expose only the flow family it can actually handle inside core
    /// dispatch.
    pub fn as_datagram_adapter(mut self) -> Self {
        self.caps.supports_stream = false;
        self.caps.supports_datagram = true;
        self
    }

    /// Select the delivery policy. It changes only delivery coordinates;
    /// `Steer` (the default) keeps existing configs byte-for-byte unchanged.
    /// `replicate_fanout` is clamped to 1..=4; `probe_budget` caps probe sends.
    pub fn with_delivery_policy(
        mut self,
        mode: DeliveryMode,
        replicate_fanout: u8,
        probe_budget: u8,
    ) -> Self {
        self.delivery_mode = mode;
        self.replicate_fanout = replicate_fanout;
        self.probe_budget = probe_budget;
        self
    }

    /// Select the wire envelope this egress emits. `SecureUdpNative` wraps each
    /// frame as a native `MeshEvent`/`DataPackage`; `MeshFrame` keeps the legacy
    /// bincode `MeshFrame` path byte-for-byte.
    pub fn with_native_event_mode(mut self, mode: NativeEventMode) -> Self {
        self.native_event_mode = mode;
        self
    }

    /// Seal every outbound frame and open every sealed reply with the
    /// MeshSec-0RTT-PSK-XChaCha envelope for this adjacent peer. Without it the
    /// adapter stays debug-clear for loopback tests.
    pub fn with_meshsec(mut self, ctx: MeshSecSealContext) -> Self {
        self.meshsec = Some(MeshSecEgress {
            ctx,
            counter: Arc::new(AtomicU64::new(1)),
        });
        // Sealed clear must fit the MeshSec padding bucket; the advertised cap
        // drives pick_sink, so recompute it now that MeshSec is configured.
        self.caps.max_payload_bytes = Some(meshsec_max_payload_bytes() as u64);
        self
    }

    fn meshsec_enabled(&self) -> bool {
        self.meshsec.is_some()
    }
}

#[async_trait]
impl StreamEgress for MeshPeerUdpEgress {
    fn id(&self) -> &ExitId {
        &self.id
    }

    fn capabilities(&self) -> &Capabilities {
        &self.caps
    }

    async fn open_stream(
        &self,
        request: &BusSessionRequest,
        info: BusSessionInfo,
    ) -> Result<Box<dyn StreamSession>, DisconnectReason> {
        let bind_addr = if self.peer.is_ipv4() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        };
        let packet_loop = Arc::new(
            UdpPacketLoop::bind(bind_addr)
                .await
                .map_err(|_| DisconnectReason::ConnectionRefused)?
                .with_peer(self.peer),
        );
        let (closed_tx, closed_rx) = watch::channel(false);
        let session_id = info.session_id.0.clone();
        let seal = self.meshsec.clone();
        let meshsec_recv = seal.as_ref().map(MeshSecEgress::reply_recv);
        let coord = DeliveryCoord::new(self.peer);
        let policy =
            EgressPolicy::new(self.delivery_mode, self.replicate_fanout, self.probe_budget);

        Ok(Box::new(MeshPeerUdpStreamSession {
            exit_id: self.id.clone(),
            info,
            request: request.clone(),
            coord,
            policy,
            timeout: self.timeout,
            packet_loop,
            session_id,
            next_seq: Arc::new(AtomicU64::new(1)),
            connected: false,
            closed_tx,
            closed_rx,
            last_error: None,
            seal,
            meshsec_recv,
            native_event_mode: self.native_event_mode,
        }))
    }
}

#[async_trait]
impl DatagramEgress for MeshPeerUdpEgress {
    fn id(&self) -> &ExitId {
        &self.id
    }

    fn capabilities(&self) -> &Capabilities {
        &self.caps
    }

    fn max_payload_bytes(&self) -> usize {
        if self.meshsec_enabled() {
            meshsec_max_payload_bytes()
        } else {
            MAX_MESH_DATAGRAM_PAYLOAD_BYTES
        }
    }

    async fn open_datagram(
        &self,
        request: &BusSessionRequest,
        info: BusSessionInfo,
    ) -> Result<Box<dyn DatagramSession>, DisconnectReason> {
        let bind_addr = if self.peer.is_ipv4() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        };
        let packet_loop = Arc::new(
            UdpPacketLoop::bind(bind_addr)
                .await
                .map_err(|_| DisconnectReason::ConnectionRefused)?
                .with_peer(self.peer),
        );
        let (closed_tx, closed_rx) = watch::channel(false);
        let session_id = info.session_id.0.clone();
        let seal = self.meshsec.clone();
        let meshsec_recv = seal.as_ref().map(MeshSecEgress::reply_recv);
        let coord = DeliveryCoord::new(self.peer);
        let policy =
            EgressPolicy::new(self.delivery_mode, self.replicate_fanout, self.probe_budget);
        send_mesh_frame(
            &packet_loop,
            &coord,
            &policy,
            self.timeout,
            self.native_event_mode,
            seal.as_ref(),
            &MeshFrame::DatagramOpen(DatagramOpen {
                session_id: session_id.clone(),
                fixed_target: Some(request.target.clone()),
                max_datagram_bytes: self.max_payload_bytes() as u64,
            }),
        )
        .await
        .map_err(send_error_to_disconnect)?;

        Ok(Box::new(MeshPeerUdpDatagramSession {
            info,
            coord,
            policy,
            timeout: self.timeout,
            packet_loop,
            session_id,
            next_seq: Arc::new(AtomicU64::new(1)),
            closed_tx,
            closed_rx,
            last_error: None,
            seal,
            meshsec_recv,
            native_event_mode: self.native_event_mode,
        }))
    }
}

struct MeshPeerUdpStreamSession {
    exit_id: ExitId,
    info: BusSessionInfo,
    request: BusSessionRequest,
    coord: Arc<DeliveryCoord>,
    policy: Arc<EgressPolicy>,
    timeout: Duration,
    packet_loop: Arc<UdpPacketLoop>,
    session_id: String,
    next_seq: Arc<AtomicU64>,
    connected: bool,
    closed_tx: watch::Sender<bool>,
    closed_rx: watch::Receiver<bool>,
    last_error: Option<DisconnectReason>,
    seal: Option<MeshSecEgress>,
    meshsec_recv: Option<MeshSecRecv>,
    native_event_mode: NativeEventMode,
}

#[async_trait]
impl StreamSession for MeshPeerUdpStreamSession {
    async fn connect(&mut self) -> Result<&BusSessionInfo, DisconnectReason> {
        if self.connected {
            return Ok(&self.info);
        }
        send_mesh_frame(
            &self.packet_loop,
            &self.coord,
            &self.policy,
            self.timeout,
            self.native_event_mode,
            self.seal.as_ref(),
            &MeshFrame::StreamOpen(StreamOpen {
                session_id: self.session_id.clone(),
                target: self.request.target.clone(),
                route_group: self.request.route_group.clone(),
                flow_semantics: flow_semantics_wire(&self.request),
                return_semantics: return_semantics_wire(&self.request),
                source_node_id: "local".into(),
                path_trace: self.info.path_trace.iter().map(|id| id.0.clone()).collect(),
            }),
        )
        .await
        .map_err(send_error_to_disconnect)?;

        let local = endpoint_from_socket_addr(
            self.packet_loop
                .local_addr()
                .map_err(|e| DisconnectReason::Other(e.to_string()))?,
        );
        self.info.paths.clear();
        self.info.paths.push(BusPathInfo {
            exit_id: self.exit_id.clone(),
            local,
            remote: self.request.target.clone(),
            measurement: Measurement {
                exit_id: self.exit_id.clone(),
                at_ms: 0,
                rtt_ms: 0,
                payload_bytes: 0,
                jitter_ms: None,
                throughput_bps: None,
                success: true,
            },
            state: PathState::Active,
        });
        self.info.primary = 0;
        self.connected = true;
        Ok(&self.info)
    }

    fn into_tcp_splice(
        self: Box<Self>,
    ) -> Result<mesh_bus_core::TcpSpliceSession, Box<dyn StreamSession>> {
        Err(self)
    }

    fn split(self: Box<Self>) -> (Box<dyn StreamSendHalf>, Box<dyn StreamRecvHalf>) {
        let session = *self;
        let send = MeshPeerUdpStreamSendHalf {
            coord: session.coord.clone(),
            policy: session.policy.clone(),
            timeout: session.timeout,
            packet_loop: session.packet_loop.clone(),
            session_id: session.session_id.clone(),
            next_seq: session.next_seq.clone(),
            closed: session.closed_tx,
            seal: session.seal,
            native_event_mode: session.native_event_mode,
        };
        let recv = MeshPeerUdpStreamRecvHalf {
            coord: session.coord,
            policy: session.policy,
            packet_loop: session.packet_loop,
            session_id: session.session_id,
            closed: session.closed_rx,
            last_error: session.last_error,
            meshsec_recv: session.meshsec_recv,
            pending: VecDeque::new(),
        };
        (Box::new(send), Box::new(recv))
    }

    async fn abort(&mut self, reason: DisconnectReason) {
        self.last_error = Some(reason.clone());
        let _ = send_stream_close(
            &self.packet_loop,
            &self.coord,
            &self.policy,
            self.timeout,
            self.native_event_mode,
            &self.session_id,
            self.seal.as_ref(),
            close_reason_wire(&reason),
        )
        .await;
        let _ = self.closed_tx.send(true);
    }

    fn info(&self) -> &BusSessionInfo {
        &self.info
    }

    fn last_error(&self) -> Option<&DisconnectReason> {
        self.last_error.as_ref()
    }
}

struct MeshPeerUdpStreamSendHalf {
    coord: Arc<DeliveryCoord>,
    policy: Arc<EgressPolicy>,
    timeout: Duration,
    packet_loop: Arc<UdpPacketLoop>,
    session_id: String,
    next_seq: Arc<AtomicU64>,
    closed: watch::Sender<bool>,
    seal: Option<MeshSecEgress>,
    native_event_mode: NativeEventMode,
}

#[async_trait]
impl StreamSendHalf for MeshPeerUdpStreamSendHalf {
    async fn send(&mut self, payload: Bytes) -> Result<(), DisconnectReason> {
        if *self.closed.borrow() {
            return Err(DisconnectReason::SessionClosed);
        }
        let chunk_bytes = stream_chunk_bytes(self.seal.as_ref());
        for chunk in payload.chunks(chunk_bytes) {
            let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
            send_mesh_frame(
                &self.packet_loop,
                &self.coord,
                &self.policy,
                self.timeout,
                self.native_event_mode,
                self.seal.as_ref(),
                &MeshFrame::StreamData {
                    session_id: self.session_id.clone(),
                    seq,
                    payload: Bytes::copy_from_slice(chunk),
                },
            )
            .await
            .map_err(send_error_to_disconnect)?;
            if self.seal.is_some() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
        Ok(())
    }

    async fn shutdown_write(&mut self) {
        let _ = send_mesh_frame(
            &self.packet_loop,
            &self.coord,
            &self.policy,
            self.timeout,
            self.native_event_mode,
            self.seal.as_ref(),
            &MeshFrame::StreamShutdownWrite {
                session_id: self.session_id.clone(),
            },
        )
        .await;
    }

    async fn abort(&mut self, reason: DisconnectReason) {
        let _ = send_stream_close(
            &self.packet_loop,
            &self.coord,
            &self.policy,
            self.timeout,
            self.native_event_mode,
            &self.session_id,
            self.seal.as_ref(),
            close_reason_wire(&reason),
        )
        .await;
        let _ = self.closed.send(true);
    }
}

struct MeshPeerUdpStreamRecvHalf {
    coord: Arc<DeliveryCoord>,
    policy: Arc<EgressPolicy>,
    packet_loop: Arc<UdpPacketLoop>,
    session_id: String,
    closed: watch::Receiver<bool>,
    last_error: Option<DisconnectReason>,
    meshsec_recv: Option<MeshSecRecv>,
    pending: VecDeque<Bytes>,
}

#[async_trait]
impl StreamRecvHalf for MeshPeerUdpStreamRecvHalf {
    async fn recv(&mut self) -> Option<Bytes> {
        mesh_recv_stream(
            &self.packet_loop,
            &self.coord,
            &self.policy,
            &self.session_id,
            &mut self.closed,
            &mut self.last_error,
            self.meshsec_recv.as_mut(),
            &mut self.pending,
        )
        .await
    }

    fn last_error(&self) -> Option<&DisconnectReason> {
        self.last_error.as_ref()
    }
}

struct MeshPeerUdpDatagramSession {
    info: BusSessionInfo,
    coord: Arc<DeliveryCoord>,
    policy: Arc<EgressPolicy>,
    timeout: Duration,
    packet_loop: Arc<UdpPacketLoop>,
    session_id: String,
    next_seq: Arc<AtomicU64>,
    closed_tx: watch::Sender<bool>,
    closed_rx: watch::Receiver<bool>,
    last_error: Option<DisconnectReason>,
    seal: Option<MeshSecEgress>,
    meshsec_recv: Option<MeshSecRecv>,
    native_event_mode: NativeEventMode,
}

#[async_trait]
impl DatagramSession for MeshPeerUdpDatagramSession {
    async fn send_to(&mut self, target: Endpoint, payload: Bytes) -> Result<(), SendError> {
        mesh_send_to(
            &self.packet_loop,
            &self.coord,
            &self.policy,
            self.timeout,
            self.native_event_mode,
            &self.session_id,
            &self.next_seq,
            &self.closed_tx,
            self.seal.as_ref(),
            target,
            payload,
        )
        .await
    }

    async fn recv_from(&mut self) -> Option<(Endpoint, Bytes)> {
        mesh_recv_from(
            &self.packet_loop,
            &self.coord,
            &self.policy,
            &self.session_id,
            &mut self.closed_rx,
            Some(self.timeout),
            &mut self.last_error,
            self.meshsec_recv.as_mut(),
        )
        .await
    }

    fn info(&self) -> &BusSessionInfo {
        &self.info
    }

    fn max_payload_bytes(&self) -> usize {
        MAX_MESH_DATAGRAM_PAYLOAD_BYTES
    }

    async fn close(&mut self) {
        let _ = send_close(
            &self.packet_loop,
            &self.coord,
            &self.policy,
            self.timeout,
            self.native_event_mode,
            &self.session_id,
            self.seal.as_ref(),
        )
        .await;
        let _ = self.closed_tx.send(true);
    }

    fn split(self: Box<Self>) -> (Box<dyn DatagramSendHalf>, Box<dyn DatagramRecvHalf>) {
        let session = *self;
        let send = MeshPeerUdpDatagramSendHalf {
            coord: session.coord.clone(),
            policy: session.policy.clone(),
            timeout: session.timeout,
            packet_loop: session.packet_loop.clone(),
            session_id: session.session_id.clone(),
            next_seq: session.next_seq.clone(),
            closed: session.closed_tx,
            seal: session.seal,
            native_event_mode: session.native_event_mode,
        };
        let recv = MeshPeerUdpDatagramRecvHalf {
            coord: session.coord,
            policy: session.policy,
            packet_loop: session.packet_loop,
            session_id: session.session_id,
            closed: session.closed_rx,
            last_error: None,
            meshsec_recv: session.meshsec_recv,
        };
        (Box::new(send), Box::new(recv))
    }
}

struct MeshPeerUdpDatagramSendHalf {
    coord: Arc<DeliveryCoord>,
    policy: Arc<EgressPolicy>,
    timeout: Duration,
    packet_loop: Arc<UdpPacketLoop>,
    session_id: String,
    next_seq: Arc<AtomicU64>,
    closed: watch::Sender<bool>,
    seal: Option<MeshSecEgress>,
    native_event_mode: NativeEventMode,
}

#[async_trait]
impl DatagramSendHalf for MeshPeerUdpDatagramSendHalf {
    async fn send_to(&mut self, target: Endpoint, payload: Bytes) -> Result<(), SendError> {
        mesh_send_to(
            &self.packet_loop,
            &self.coord,
            &self.policy,
            self.timeout,
            self.native_event_mode,
            &self.session_id,
            &self.next_seq,
            &self.closed,
            self.seal.as_ref(),
            target,
            payload,
        )
        .await
    }

    async fn close(&mut self) {
        let _ = send_close(
            &self.packet_loop,
            &self.coord,
            &self.policy,
            self.timeout,
            self.native_event_mode,
            &self.session_id,
            self.seal.as_ref(),
        )
        .await;
        let _ = self.closed.send(true);
    }
}

struct MeshPeerUdpDatagramRecvHalf {
    coord: Arc<DeliveryCoord>,
    policy: Arc<EgressPolicy>,
    packet_loop: Arc<UdpPacketLoop>,
    session_id: String,
    closed: watch::Receiver<bool>,
    last_error: Option<DisconnectReason>,
    meshsec_recv: Option<MeshSecRecv>,
}

#[async_trait]
impl DatagramRecvHalf for MeshPeerUdpDatagramRecvHalf {
    async fn recv_from(&mut self) -> Option<(Endpoint, Bytes)> {
        mesh_recv_from(
            &self.packet_loop,
            &self.coord,
            &self.policy,
            &self.session_id,
            &mut self.closed,
            None,
            &mut self.last_error,
            self.meshsec_recv.as_mut(),
        )
        .await
    }

    fn last_error(&self) -> Option<&DisconnectReason> {
        self.last_error.as_ref()
    }
}

#[allow(clippy::too_many_arguments)]
async fn mesh_send_to(
    packet_loop: &UdpPacketLoop,
    coord: &DeliveryCoord,
    policy: &EgressPolicy,
    timeout: Duration,
    native_event_mode: NativeEventMode,
    session_id: &str,
    next_seq: &AtomicU64,
    closed: &watch::Sender<bool>,
    seal: Option<&MeshSecEgress>,
    target: Endpoint,
    payload: Bytes,
) -> Result<(), SendError> {
    if *closed.borrow() {
        return Err(SendError::Closed);
    }
    if payload.len() > MAX_MESH_DATAGRAM_PAYLOAD_BYTES {
        return Err(SendError::PayloadTooLarge);
    }
    let seq = next_seq.fetch_add(1, Ordering::Relaxed);
    send_mesh_frame(
        packet_loop,
        coord,
        policy,
        timeout,
        native_event_mode,
        seal,
        &MeshFrame::DatagramSend {
            session_id: session_id.to_owned(),
            seq,
            target,
            payload,
        },
    )
    .await
}

async fn mesh_recv_from(
    packet_loop: &UdpPacketLoop,
    coord: &DeliveryCoord,
    policy: &EgressPolicy,
    session_id: &str,
    closed: &mut watch::Receiver<bool>,
    timeout: Option<Duration>,
    last_error: &mut Option<DisconnectReason>,
    mut meshsec: Option<&mut MeshSecRecv>,
) -> Option<(Endpoint, Bytes)> {
    if *closed.borrow() {
        return None;
    }
    let recv = async {
        loop {
            for inbound in packet_loop.drain_inbound() {
                let decoded = match meshsec.as_deref_mut() {
                    Some(mc) => {
                        let epoch = meshsec_epoch_number(now_unix_secs());
                        match open_mesh_frame(
                            &inbound.payload,
                            &mc.keys,
                            &mc.local_node_id,
                            epoch.saturating_sub(MESHSEC_ACCEPTED_EPOCH_SKEW_SLOTS)
                                ..=epoch + MESHSEC_ACCEPTED_EPOCH_SKEW_SLOTS,
                            &mut mc.replay,
                        ) {
                            Ok((_, frame)) => Ok(frame),
                            Err(_) => continue,
                        }
                    }
                    None => {
                        let mut frame_buf = BytesMut::from(&inbound.payload[..]);
                        decode_frame(&mut frame_buf)
                    }
                };
                match decoded {
                    Ok(MeshFrame::DatagramReturn {
                        session_id: frame_session_id,
                        source,
                        payload,
                        ..
                    }) if frame_session_id == session_id => {
                        return Ok::<_, std::io::Error>(Some((source, payload)));
                    }
                    Ok(MeshFrame::DatagramClose {
                        session_id: frame_session_id,
                        ..
                    }) if frame_session_id == session_id => return Ok(None),
                    Ok(MeshFrame::PortOpen(mouth)) => {
                        coord.apply_port_open(&mouth);
                        continue;
                    }
                    Ok(MeshFrame::PortClose { .. }) => continue,
                    Ok(MeshFrame::AckNack(ack)) => {
                        // L5 feedback: retransmit only the seqs the peer says
                        // it is still missing. Repair changes delivery
                        // coordinates (a resend) only; family id/seq/order are
                        // untouched and the receiver re-orders by seq.
                        let resend = policy.to_retransmit(&ack);
                        if !resend.is_empty() {
                            let dst = coord.addr();
                            for bytes in resend {
                                let _ = packet_loop.try_enqueue(OutboundDatagram {
                                    destination: dst,
                                    payload: Bytes::from(bytes),
                                });
                            }
                            let _ = packet_loop.flush().await;
                        }
                        continue;
                    }
                    Ok(_) => continue,
                    Err(err) => return Err(std::io::Error::other(err.to_string())),
                }
            }
            packet_loop.poll_recv().await?;
        }
    };

    tokio::select! {
        _ = closed.changed() => None,
        result = async {
            if let Some(timeout) = timeout {
                match tokio::time::timeout(timeout, recv).await {
                    Ok(result) => result,
                    Err(_) => Ok(None),
                }
            } else {
                recv.await
            }
        } => match result {
            Ok(result) => result,
            Err(err) => {
                *last_error = Some(DisconnectReason::Other(err.to_string()));
                None
            }
        },
    }
}

async fn mesh_recv_stream(
    packet_loop: &UdpPacketLoop,
    coord: &DeliveryCoord,
    policy: &EgressPolicy,
    session_id: &str,
    closed: &mut watch::Receiver<bool>,
    last_error: &mut Option<DisconnectReason>,
    mut meshsec: Option<&mut MeshSecRecv>,
    pending: &mut VecDeque<Bytes>,
) -> Option<Bytes> {
    if let Some(payload) = pending.pop_front() {
        return Some(payload);
    }
    if *closed.borrow() {
        return None;
    }
    let recv = async {
        loop {
            let mut first_payload = None;
            for inbound in packet_loop.drain_inbound() {
                let decoded = match meshsec.as_deref_mut() {
                    Some(mc) => {
                        let epoch = meshsec_epoch_number(now_unix_secs());
                        match open_mesh_frame(
                            &inbound.payload,
                            &mc.keys,
                            &mc.local_node_id,
                            epoch.saturating_sub(MESHSEC_ACCEPTED_EPOCH_SKEW_SLOTS)
                                ..=epoch + MESHSEC_ACCEPTED_EPOCH_SKEW_SLOTS,
                            &mut mc.replay,
                        ) {
                            Ok((_, frame)) => Ok(frame),
                            Err(_) => continue,
                        }
                    }
                    None => {
                        let mut frame_buf = BytesMut::from(&inbound.payload[..]);
                        decode_frame(&mut frame_buf)
                    }
                };
                match decoded {
                    Ok(MeshFrame::StreamData {
                        session_id: frame_session_id,
                        payload,
                        ..
                    }) if frame_session_id == session_id => {
                        if first_payload.is_none() {
                            first_payload = Some(payload);
                        } else {
                            pending.push_back(payload);
                        }
                    }
                    Ok(MeshFrame::StreamShutdownWrite {
                        session_id: frame_session_id,
                    })
                    | Ok(MeshFrame::StreamClose {
                        session_id: frame_session_id,
                        ..
                    }) if frame_session_id == session_id => {
                        if first_payload.is_none() && pending.is_empty() {
                            return Ok(None);
                        }
                    }
                    Ok(MeshFrame::StreamOpenReject {
                        session_id: frame_session_id,
                        close_reason,
                        ..
                    }) if frame_session_id == session_id => {
                        return Err(std::io::Error::other(format!(
                            "stream open rejected: {close_reason:?}"
                        )));
                    }
                    Ok(MeshFrame::PortOpen(mouth)) => {
                        coord.apply_port_open(&mouth);
                        continue;
                    }
                    Ok(MeshFrame::PortClose { .. }) => continue,
                    Ok(MeshFrame::AckNack(ack)) => {
                        let resend = policy.to_retransmit(&ack);
                        if !resend.is_empty() {
                            let dst = coord.addr();
                            for bytes in resend {
                                let _ = packet_loop.try_enqueue(OutboundDatagram {
                                    destination: dst,
                                    payload: Bytes::from(bytes),
                                });
                            }
                            let _ = packet_loop.flush().await;
                        }
                        continue;
                    }
                    Ok(_) => continue,
                    Err(err) => return Err(std::io::Error::other(err.to_string())),
                }
            }
            if let Some(payload) = first_payload {
                return Ok(Some(payload));
            }
            packet_loop.poll_recv().await?;
        }
    };

    tokio::select! {
        _ = closed.changed() => None,
        result = recv => match result {
            Ok(result) => result,
            Err(err) => {
                *last_error = Some(DisconnectReason::Other(err.to_string()));
                None
            }
        },
    }
}

#[allow(clippy::too_many_arguments)]
async fn send_stream_close(
    packet_loop: &UdpPacketLoop,
    coord: &DeliveryCoord,
    policy: &EgressPolicy,
    timeout: Duration,
    native_event_mode: NativeEventMode,
    session_id: &str,
    seal: Option<&MeshSecEgress>,
    close_reason: CloseReasonWire,
) -> Result<(), SendError> {
    send_mesh_frame(
        packet_loop,
        coord,
        policy,
        timeout,
        native_event_mode,
        seal,
        &MeshFrame::StreamClose {
            session_id: session_id.to_owned(),
            close_reason,
        },
    )
    .await
}

async fn send_close(
    packet_loop: &UdpPacketLoop,
    coord: &DeliveryCoord,
    policy: &EgressPolicy,
    timeout: Duration,
    native_event_mode: NativeEventMode,
    session_id: &str,
    seal: Option<&MeshSecEgress>,
) -> Result<(), SendError> {
    send_mesh_frame(
        packet_loop,
        coord,
        policy,
        timeout,
        native_event_mode,
        seal,
        &MeshFrame::DatagramClose {
            session_id: session_id.to_owned(),
            close_reason: CloseReasonWire::Normal,
        },
    )
    .await
}

fn endpoint_from_socket_addr(addr: SocketAddr) -> Endpoint {
    Endpoint::new(addr.ip().to_string(), addr.port()).expect("socket addr endpoint")
}

fn flow_semantics_wire(request: &BusSessionRequest) -> FlowSemanticsWire {
    match request.flow_semantics {
        FlowSemantics::ByteStream => FlowSemanticsWire::ByteStream,
        FlowSemantics::Datagram => FlowSemanticsWire::Datagram,
        FlowSemantics::Message => FlowSemanticsWire::Message,
        _ => FlowSemanticsWire::ByteStream,
    }
}

fn return_semantics_wire(request: &BusSessionRequest) -> ReturnSemanticsWire {
    match request.return_semantics {
        ReturnSemantics::Direct => ReturnSemanticsWire::Direct,
        ReturnSemantics::PacketDedup => ReturnSemanticsWire::PacketDedup,
        ReturnSemantics::SequenceReorder => ReturnSemanticsWire::SequenceReorder,
        _ => ReturnSemanticsWire::Direct,
    }
}

fn close_reason_wire(reason: &DisconnectReason) -> CloseReasonWire {
    match reason {
        DisconnectReason::NoUsableExit | DisconnectReason::HostUnreachable => {
            CloseReasonWire::NoUsableExit
        }
        DisconnectReason::AddressNotSupported | DisconnectReason::Other(_) => {
            CloseReasonWire::ProtocolError
        }
        _ => CloseReasonWire::Normal,
    }
}

async fn send_mesh_frame(
    packet_loop: &UdpPacketLoop,
    coord: &DeliveryCoord,
    policy: &EgressPolicy,
    timeout: Duration,
    native_event_mode: NativeEventMode,
    seal: Option<&MeshSecEgress>,
    frame: &MeshFrame,
) -> Result<(), SendError> {
    let peer = coord.addr();
    let (_, frame_seq, frame_semantic) = frame_event_meta(frame);
    let encoded = match (native_event_mode, seal) {
        (NativeEventMode::MeshFrame, Some(s)) => seal_mesh_frame(
            frame,
            &s.ctx,
            meshsec_epoch_number(now_unix_secs()),
            s.counter.fetch_add(1, Ordering::Relaxed),
        )
        .map_err(|_| SendError::Closed)?,
        (NativeEventMode::MeshFrame, None) => encode_frame(frame).map_err(|_| SendError::Closed)?,
        (NativeEventMode::SecureUdpNative, seal) => {
            let frame_clear = encode_frame(frame).map_err(|_| SendError::Closed)?;
            let (family_id, seq, semantic) = frame_event_meta(frame);
            // The policy id is delivery-coordinate metadata only; it never
            // alters family id, seq, or semantic.
            let event =
                wrap_frame_event(family_id, seq, semantic, policy.policy_id(), &frame_clear);
            let event_bytes = encode_event(&event).map_err(|_| SendError::Closed)?;
            match seal {
                Some(s) => seal_bytes(
                    &event_bytes,
                    &s.ctx,
                    meshsec_epoch_number(now_unix_secs()),
                    s.counter.fetch_add(1, Ordering::Relaxed),
                )
                .map_err(|_| SendError::Closed)?,
                None => event_bytes,
            }
        }
    };
    if encoded.len() > 65_507 {
        return Err(SendError::PayloadTooLarge);
    }
    // Repair remembers a data send so an inbound AckNack can retransmit it.
    if matches!(
        frame_semantic,
        mb_proto_mesh::EventSemantic::Datagram | mb_proto_mesh::EventSemantic::Stream
    ) {
        policy.remember(frame_seq, &encoded);
    }
    // Replicate is a bounded duplicate send to the (rotating) delivery
    // coordinate; every other mode sends exactly once. Delivery coordinates
    // only — session id, family, seq, and target are untouched.
    for _ in 0..policy.send_copies() {
        packet_loop
            .try_enqueue(OutboundDatagram {
                destination: peer,
                payload: Bytes::from(encoded.clone()),
            })
            .map_err(|_| SendError::BufferFull)?;
    }
    let outcome = tokio::time::timeout(timeout, packet_loop.flush())
        .await
        .map_err(|_| SendError::Closed)?
        .map_err(|_| SendError::Closed)?;
    if outcome.sent == 0 && outcome.pmtu_dropped > 0 {
        return Err(SendError::PayloadTooLarge);
    }
    Ok(())
}

fn send_error_to_disconnect(err: SendError) -> DisconnectReason {
    match err {
        SendError::AddressNotSupported => DisconnectReason::AddressNotSupported,
        SendError::PayloadTooLarge => {
            DisconnectReason::Other("mesh datagram open too large".into())
        }
        SendError::BufferFull | SendError::Closed => DisconnectReason::ConnectionRefused,
        _ => DisconnectReason::ConnectionRefused,
    }
}

#[cfg(test)]
mod mouth_rotation_tests {
    use super::*;

    fn mouth(addr: &str, epoch: u64) -> ReceiverMouth {
        ReceiverMouth {
            mouth_id: "mouth-1".into(),
            udp_addr: addr.into(),
            family_filter: vec!["datagram".into()],
            advertised_capacity: 4096,
            epoch,
        }
    }

    #[test]
    fn initial_mouth_addr_is_the_configured_peer() {
        let configured: SocketAddr = "127.0.0.1:7001".parse().unwrap();
        let coord = DeliveryCoord::new(configured);
        assert_eq!(coord.addr(), configured);
    }

    #[test]
    fn port_open_rotation_updates_addr_and_epoch_make_before_break() {
        let coord = DeliveryCoord::new("127.0.0.1:7001".parse().unwrap());
        assert!(coord.apply_port_open(&mouth("127.0.0.1:7009", 5)));
        // The new coordinate is live the instant apply_port_open returns true,
        // before any old-mouth close: this is make-before-break.
        assert_eq!(coord.addr(), "127.0.0.1:7009".parse().unwrap());
        assert_eq!(coord.epoch.load(Ordering::Relaxed), 5);
    }

    #[test]
    fn stale_epoch_port_open_is_rejected_and_addr_unchanged() {
        let coord = DeliveryCoord::new("127.0.0.1:7001".parse().unwrap());
        assert!(coord.apply_port_open(&mouth("127.0.0.1:7009", 5)));
        // A strictly-older epoch must not rewind the coordinate.
        assert!(!coord.apply_port_open(&mouth("127.0.0.1:6000", 4)));
        assert_eq!(coord.addr(), "127.0.0.1:7009".parse().unwrap());
        assert_eq!(coord.epoch.load(Ordering::Relaxed), 5);
        // A malformed udp_addr is rejected without touching the coordinate.
        assert!(!coord.apply_port_open(&mouth("not-an-addr", 6)));
        assert_eq!(coord.addr(), "127.0.0.1:7009".parse().unwrap());
    }

    #[test]
    fn family_seq_and_session_id_survive_two_mouth_rotation() {
        // The session's monotone family seq and identity live in fields the
        // coordinate never touches; rotating across two mouths must not reset
        // or perturb them.
        let coord = DeliveryCoord::new("127.0.0.1:7001".parse().unwrap());
        let next_seq = AtomicU64::new(1);
        let session_id = String::from("s-egress-42");

        let s1 = next_seq.fetch_add(1, Ordering::Relaxed);
        assert!(coord.apply_port_open(&mouth("127.0.0.1:7009", 1)));
        let s2 = next_seq.fetch_add(1, Ordering::Relaxed);
        assert!(coord.apply_port_open(&mouth("127.0.0.1:7010", 2)));
        let s3 = next_seq.fetch_add(1, Ordering::Relaxed);

        assert_eq!((s1, s2, s3), (1, 2, 3));
        assert_eq!(next_seq.load(Ordering::Relaxed), 4);
        assert_eq!(session_id, "s-egress-42");
        assert_eq!(coord.addr(), "127.0.0.1:7010".parse().unwrap());
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;
    use mb_proto_mesh::SeqRange;

    #[test]
    fn replicate_count_is_bounded_duplicate_send() {
        assert_eq!(replicate_count(0), 1, "0 fanout is meaningless -> 1");
        assert_eq!(replicate_count(1), 1);
        assert_eq!(replicate_count(2), 2);
        assert_eq!(replicate_count(4), 4);
        assert_eq!(
            replicate_count(255),
            4,
            "fanout is clamped, no amplification"
        );
    }

    #[test]
    fn send_copies_only_replicate_fans_out() {
        let steer = EgressPolicy::new(DeliveryMode::Steer, 3, 4);
        assert_eq!(steer.send_copies(), 1, "Steer sends exactly once");
        let rep = EgressPolicy::new(DeliveryMode::Replicate, 3, 4);
        assert_eq!(
            rep.send_copies(),
            3,
            "Replicate fans out the configured count"
        );
        let repair = EgressPolicy::new(DeliveryMode::Repair, 3, 4);
        assert_eq!(
            repair.send_copies(),
            1,
            "Repair sends once, retransmits on AckNack"
        );
    }

    #[test]
    fn stripe_index_round_robins_across_mouths_and_degrades_to_steer_at_one() {
        // One mouth: Stripe == Steer.
        for seq in 0..5u64 {
            assert_eq!(stripe_index(seq, 1), 0);
            assert_eq!(stripe_index(seq, 0), 0);
        }
        // Multiple mouths: consecutive packages spread round-robin.
        assert_eq!(stripe_index(0, 3), 0);
        assert_eq!(stripe_index(1, 3), 1);
        assert_eq!(stripe_index(2, 3), 2);
        assert_eq!(stripe_index(3, 3), 0);
    }

    #[test]
    fn repair_remembers_only_data_seqs_and_retransmits_missing_ranges() {
        let policy = EgressPolicy::new(DeliveryMode::Repair, 2, 4);
        policy.remember(0, b"control-no-seq"); // seq 0 (control) is not buffered
        policy.remember(1, b"data-seq-1");
        policy.remember(2, b"data-seq-2");
        policy.remember(3, b"data-seq-3");

        let ack = AckNack {
            family_id: "fam".into(),
            cumulative_seq: 0,
            received_bitmap: "0".repeat(32),
            missing_ranges: vec![SeqRange { start: 2, end: 3 }],
        };
        let resend = policy.to_retransmit(&ack);
        assert_eq!(
            resend,
            vec![b"data-seq-2".to_vec(), b"data-seq-3".to_vec()],
            "only the seqs the peer reports missing are retransmitted"
        );

        // Steer never buffers, so a stray AckNack retransmits nothing.
        let steer = EgressPolicy::new(DeliveryMode::Steer, 2, 4);
        steer.remember(1, b"x");
        assert!(steer.to_retransmit(&ack).is_empty());
    }

    #[test]
    fn probe_budget_caps_low_rate_samples() {
        let policy = EgressPolicy::new(DeliveryMode::Probe, 2, 3);
        assert!(policy.take_probe_token(), "1st probe within budget");
        assert!(policy.take_probe_token(), "2nd probe within budget");
        assert!(policy.take_probe_token(), "3rd probe within budget");
        assert!(
            !policy.take_probe_token(),
            "4th probe exceeds budget -> skipped"
        );
        assert!(!policy.take_probe_token(), "budget stays exhausted");
    }
}
