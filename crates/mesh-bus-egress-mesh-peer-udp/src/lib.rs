//! Raw UDP Mesh Protocol egress adapter.

mod demux;
mod meshsec;
mod policy;
mod sender;

use async_trait::async_trait;
use bytes::Bytes;
use demux::{DatagramDemuxHandle, StreamDemuxHandle, StreamEvent, control_result};
use mb_endpoint::Endpoint;
#[cfg(test)]
use mb_proto_mesh::{AckNack, ReceiverMouth};
use mb_proto_mesh::{
    CloseReasonWire, DatagramOpen, DeliveryMode, FlowSemanticsWire, MeshFrame, MeshSecSealContext,
    NativeEventMode, ReturnSemanticsWire, StreamOpen,
};
use mesh_bus_core::transport::udp_loop::UdpPacketLoop;
use mesh_bus_core::{
    BusPathInfo, BusSessionInfo, BusSessionRequest, Capabilities, DatagramEgress, DatagramRecvHalf,
    DatagramSendHalf, DatagramSession, DisconnectReason, ExitId, FlowSemantics, Measurement,
    PathState, ReturnSemantics, SendError, StreamEgress, StreamRecvHalf, StreamSendHalf,
    StreamSession,
};
use sender::MeshPeerSender;
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, watch};

pub use meshsec::meshsec_max_payload_bytes;
pub(crate) use meshsec::{
    MeshSecEgress, MeshSecRecv, STREAM_FLUSH_CHUNK_BATCH, now_unix_secs, stream_chunk_bytes,
};
pub(crate) use policy::{DeliveryCoord, EgressPolicy};
#[cfg(test)]
pub(crate) use policy::{replicate_count, stripe_index};

const MAX_MESH_DATAGRAM_PAYLOAD_BYTES: usize = 65_000;
static STREAM_OPEN_TOKEN: AtomicU64 = AtomicU64::new(1);

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
        let sender = MeshPeerSender::spawn(
            packet_loop.clone(),
            coord.clone(),
            policy.clone(),
            self.timeout,
            self.native_event_mode,
            seal.clone(),
        );
        let demux = demux::spawn_stream_driver(
            packet_loop.clone(),
            coord.clone(),
            policy.clone(),
            sender.clone(),
            self.native_event_mode,
            meshsec_recv,
            session_id.clone(),
        );

        Ok(Box::new(MeshPeerUdpStreamSession {
            exit_id: self.id.clone(),
            info,
            request: request.clone(),
            timeout: self.timeout,
            packet_loop,
            sender,
            session_id,
            next_seq: Arc::new(AtomicU64::new(1)),
            connected: false,
            closed_tx,
            closed_rx,
            last_error: None,
            seal,
            demux,
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
        let sender = MeshPeerSender::spawn(
            packet_loop.clone(),
            coord.clone(),
            policy.clone(),
            self.timeout,
            self.native_event_mode,
            seal.clone(),
        );
        let demux = demux::spawn_datagram_driver(
            packet_loop.clone(),
            coord.clone(),
            policy.clone(),
            sender.clone(),
            self.native_event_mode,
            meshsec_recv,
            session_id.clone(),
        );
        sender
            .send_frame(MeshFrame::DatagramOpen(DatagramOpen {
                session_id: session_id.clone(),
                fixed_target: Some(request.target.clone()),
                max_datagram_bytes: self.max_payload_bytes() as u64,
            }))
            .await
            .map_err(send_error_to_disconnect)?;

        Ok(Box::new(MeshPeerUdpDatagramSession {
            info,
            timeout: self.timeout,
            sender,
            session_id,
            next_seq: Arc::new(AtomicU64::new(1)),
            closed_tx,
            closed_rx,
            last_error: None,
            demux,
        }))
    }
}

struct MeshPeerUdpStreamSession {
    exit_id: ExitId,
    info: BusSessionInfo,
    request: BusSessionRequest,
    timeout: Duration,
    packet_loop: Arc<UdpPacketLoop>,
    sender: MeshPeerSender,
    session_id: String,
    next_seq: Arc<AtomicU64>,
    connected: bool,
    closed_tx: watch::Sender<bool>,
    closed_rx: watch::Receiver<bool>,
    last_error: Option<DisconnectReason>,
    seal: Option<MeshSecEgress>,
    demux: StreamDemuxHandle,
}

#[async_trait]
impl StreamSession for MeshPeerUdpStreamSession {
    async fn connect(&mut self) -> Result<&BusSessionInfo, DisconnectReason> {
        if self.connected {
            return Ok(&self.info);
        }
        let open_token = next_stream_open_token();
        self.sender
            .send_frame(MeshFrame::StreamOpen(StreamOpen {
                session_id: self.session_id.clone(),
                open_token,
                target: self.request.target.clone(),
                route_group: self.request.route_group.clone(),
                flow_semantics: flow_semantics_wire(&self.request),
                return_semantics: return_semantics_wire(&self.request),
                source_node_id: "local".into(),
                path_trace: self.info.path_trace.iter().map(|id| id.0.clone()).collect(),
            }))
            .await
            .map_err(send_error_to_disconnect)?;
        let control_inbox = &mut self.demux.control_inbox;
        tokio::time::timeout(self.timeout, async {
            loop {
                let Some(control) = control_inbox.recv().await else {
                    return Err(DisconnectReason::ConnectionReset);
                };
                if let Some(result) = control_result(control, open_token) {
                    return result;
                }
            }
        })
        .await
        .map_err(|_| DisconnectReason::TimedOut)??;

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
            sender: session.sender.clone(),
            session_id: session.session_id.clone(),
            next_seq: session.next_seq.clone(),
            closed: session.closed_tx,
            seal: session.seal,
        };
        let recv = MeshPeerUdpStreamRecvHalf {
            closed: session.closed_rx,
            last_error: session.last_error,
            data_inbox: session.demux.data_inbox,
            event_inbox: session.demux.event_inbox,
            _driver: session.demux.driver,
            pending: VecDeque::new(),
            terminal: None,
        };
        (Box::new(send), Box::new(recv))
    }

    async fn abort(&mut self, reason: DisconnectReason) {
        self.last_error = Some(reason.clone());
        let _ = send_stream_close(&self.sender, &self.session_id, close_reason_wire(&reason)).await;
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
    sender: MeshPeerSender,
    session_id: String,
    next_seq: Arc<AtomicU64>,
    closed: watch::Sender<bool>,
    seal: Option<MeshSecEgress>,
}

#[async_trait]
impl StreamSendHalf for MeshPeerUdpStreamSendHalf {
    async fn send(&mut self, payload: Bytes) -> Result<(), DisconnectReason> {
        if *self.closed.borrow() {
            return Err(DisconnectReason::SessionClosed);
        }
        let chunk_bytes = stream_chunk_bytes(self.seal.as_ref());
        let mut frames = Vec::new();
        for chunk in payload.chunks(chunk_bytes) {
            let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
            frames.push(MeshFrame::StreamData {
                session_id: self.session_id.clone(),
                seq,
                payload: Bytes::copy_from_slice(chunk),
            });
            if frames.len() >= STREAM_FLUSH_CHUNK_BATCH {
                self.sender
                    .send_data_frames(std::mem::take(&mut frames))
                    .await
                    .map_err(send_error_to_disconnect)?;
            }
        }
        self.sender
            .send_data_frames(frames)
            .await
            .map_err(send_error_to_disconnect)?;
        Ok(())
    }

    async fn shutdown_write(&mut self) {
        let _ = self
            .sender
            .send_frame(MeshFrame::StreamShutdownWrite {
                session_id: self.session_id.clone(),
            })
            .await;
    }

    async fn abort(&mut self, reason: DisconnectReason) {
        let _ = send_stream_close(&self.sender, &self.session_id, close_reason_wire(&reason)).await;
        let _ = self.closed.send(true);
    }
}

struct MeshPeerUdpStreamRecvHalf {
    closed: watch::Receiver<bool>,
    last_error: Option<DisconnectReason>,
    data_inbox: mpsc::Receiver<Bytes>,
    event_inbox: mpsc::Receiver<StreamEvent>,
    _driver: demux::DriverGuard,
    pending: VecDeque<Bytes>,
    terminal: Option<StreamEvent>,
}

#[async_trait]
impl StreamRecvHalf for MeshPeerUdpStreamRecvHalf {
    async fn recv(&mut self) -> Option<Bytes> {
        if let Some(payload) = self.pending.pop_front() {
            return Some(payload);
        }
        if let Ok(payload) = self.data_inbox.try_recv() {
            return Some(payload);
        }
        if let Some(event) = self.terminal.take() {
            return self.apply_stream_event(event);
        }
        if *self.closed.borrow() {
            return None;
        }
        tokio::select! {
            _ = self.closed.changed() => None,
            payload = self.data_inbox.recv() => payload,
            event = self.event_inbox.recv() => match event {
                Some(event) => {
                    while let Ok(payload) = self.data_inbox.try_recv() {
                        self.pending.push_back(payload);
                    }
                    if let Some(payload) = self.pending.pop_front() {
                        self.terminal = Some(event);
                        Some(payload)
                    } else {
                        self.apply_stream_event(event)
                    }
                }
                None => None,
            },
        }
    }

    fn last_error(&self) -> Option<&DisconnectReason> {
        self.last_error.as_ref()
    }
}

impl MeshPeerUdpStreamRecvHalf {
    fn apply_stream_event(&mut self, event: StreamEvent) -> Option<Bytes> {
        match event {
            StreamEvent::ShutdownWrite | StreamEvent::Close(CloseReasonWire::Normal) => None,
            StreamEvent::Close(reason) => {
                self.last_error = Some(wire_close_to_disconnect(reason));
                None
            }
            StreamEvent::QueueFull => {
                self.last_error = Some(DisconnectReason::QueueFull);
                None
            }
        }
    }
}

struct MeshPeerUdpDatagramSession {
    info: BusSessionInfo,
    timeout: Duration,
    sender: MeshPeerSender,
    session_id: String,
    next_seq: Arc<AtomicU64>,
    closed_tx: watch::Sender<bool>,
    closed_rx: watch::Receiver<bool>,
    last_error: Option<DisconnectReason>,
    demux: DatagramDemuxHandle,
}

#[async_trait]
impl DatagramSession for MeshPeerUdpDatagramSession {
    async fn send_to(&mut self, target: Endpoint, payload: Bytes) -> Result<(), SendError> {
        mesh_send_to(
            &self.sender,
            &self.session_id,
            &self.next_seq,
            &self.closed_tx,
            target,
            payload,
        )
        .await
    }

    async fn recv_from(&mut self) -> Option<(Endpoint, Bytes)> {
        mesh_recv_from(
            &mut self.closed_rx,
            Some(self.timeout),
            &mut self.last_error,
            &mut self.demux.datagram_inbox,
            &mut self.demux.error_inbox,
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
        let _ = send_close(&self.sender, &self.session_id).await;
        let _ = self.closed_tx.send(true);
    }

    fn split(self: Box<Self>) -> (Box<dyn DatagramSendHalf>, Box<dyn DatagramRecvHalf>) {
        let session = *self;
        let send = MeshPeerUdpDatagramSendHalf {
            sender: session.sender.clone(),
            session_id: session.session_id.clone(),
            next_seq: session.next_seq.clone(),
            closed: session.closed_tx,
        };
        let recv = MeshPeerUdpDatagramRecvHalf {
            closed: session.closed_rx,
            last_error: None,
            datagram_inbox: session.demux.datagram_inbox,
            error_inbox: session.demux.error_inbox,
            _driver: session.demux.driver,
        };
        (Box::new(send), Box::new(recv))
    }
}

struct MeshPeerUdpDatagramSendHalf {
    sender: MeshPeerSender,
    session_id: String,
    next_seq: Arc<AtomicU64>,
    closed: watch::Sender<bool>,
}

#[async_trait]
impl DatagramSendHalf for MeshPeerUdpDatagramSendHalf {
    async fn send_to(&mut self, target: Endpoint, payload: Bytes) -> Result<(), SendError> {
        mesh_send_to(
            &self.sender,
            &self.session_id,
            &self.next_seq,
            &self.closed,
            target,
            payload,
        )
        .await
    }

    async fn close(&mut self) {
        let _ = send_close(&self.sender, &self.session_id).await;
        let _ = self.closed.send(true);
    }
}

struct MeshPeerUdpDatagramRecvHalf {
    closed: watch::Receiver<bool>,
    last_error: Option<DisconnectReason>,
    datagram_inbox: mpsc::Receiver<(Endpoint, Bytes)>,
    error_inbox: mpsc::Receiver<DisconnectReason>,
    _driver: demux::DriverGuard,
}

#[async_trait]
impl DatagramRecvHalf for MeshPeerUdpDatagramRecvHalf {
    async fn recv_from(&mut self) -> Option<(Endpoint, Bytes)> {
        mesh_recv_from(
            &mut self.closed,
            None,
            &mut self.last_error,
            &mut self.datagram_inbox,
            &mut self.error_inbox,
        )
        .await
    }

    fn last_error(&self) -> Option<&DisconnectReason> {
        self.last_error.as_ref()
    }
}

async fn mesh_send_to(
    sender: &MeshPeerSender,
    session_id: &str,
    next_seq: &AtomicU64,
    closed: &watch::Sender<bool>,
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
    sender
        .send_frame(MeshFrame::DatagramSend {
            session_id: session_id.to_owned(),
            seq,
            target,
            payload,
        })
        .await
}

async fn mesh_recv_from(
    closed: &mut watch::Receiver<bool>,
    timeout: Option<Duration>,
    last_error: &mut Option<DisconnectReason>,
    datagram_inbox: &mut mpsc::Receiver<(Endpoint, Bytes)>,
    error_inbox: &mut mpsc::Receiver<DisconnectReason>,
) -> Option<(Endpoint, Bytes)> {
    if *closed.borrow() {
        return None;
    }
    if let Ok(reason) = error_inbox.try_recv() {
        *last_error = Some(reason);
        return None;
    }
    tokio::select! {
        biased;
        _ = closed.changed() => None,
        reason = error_inbox.recv() => {
            if let Some(reason) = reason {
                *last_error = Some(reason);
            }
            None
        },
        result = async {
            if let Some(timeout) = timeout {
                match tokio::time::timeout(timeout, datagram_inbox.recv()).await {
                    Ok(result) => result,
                    Err(_) => None,
                }
            } else {
                datagram_inbox.recv().await
            }
        } => result,
    }
}

async fn send_stream_close(
    sender: &MeshPeerSender,
    session_id: &str,
    close_reason: CloseReasonWire,
) -> Result<(), SendError> {
    sender
        .send_frame(MeshFrame::StreamClose {
            session_id: session_id.to_owned(),
            close_reason,
        })
        .await
}

async fn send_close(sender: &MeshPeerSender, session_id: &str) -> Result<(), SendError> {
    sender
        .send_frame(MeshFrame::DatagramClose {
            session_id: session_id.to_owned(),
            close_reason: CloseReasonWire::Normal,
        })
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
        DisconnectReason::AddressNotSupported
        | DisconnectReason::QueueFull
        | DisconnectReason::Other(_) => CloseReasonWire::ProtocolError,
        _ => CloseReasonWire::Normal,
    }
}

fn wire_close_to_disconnect(reason: CloseReasonWire) -> DisconnectReason {
    match reason {
        CloseReasonWire::Normal => DisconnectReason::SessionClosed,
        CloseReasonWire::Unsupported | CloseReasonWire::ProtocolError => {
            DisconnectReason::Other(format!("{reason:?}"))
        }
        CloseReasonWire::NoUsableExit => DisconnectReason::NoUsableExit,
    }
}

fn next_stream_open_token() -> u64 {
    let counter = STREAM_OPEN_TOKEN.fetch_add(1, Ordering::Relaxed);
    let time_mix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| (d.as_secs() << 32) ^ u64::from(d.subsec_nanos()))
        .unwrap_or(counter.rotate_left(17));
    let token = rand::random::<u64>() ^ time_mix.rotate_left(23) ^ counter.rotate_left(41);
    if token == 0 { counter | 1 } else { token }
}

fn send_error_to_disconnect(err: SendError) -> DisconnectReason {
    match err {
        SendError::AddressNotSupported => DisconnectReason::AddressNotSupported,
        SendError::PayloadTooLarge => {
            DisconnectReason::Other("mesh datagram open too large".into())
        }
        SendError::BufferFull => DisconnectReason::QueueFull,
        SendError::Closed => DisconnectReason::ConnectionRefused,
        _ => DisconnectReason::ConnectionRefused,
    }
}

#[cfg(test)]
mod mouth_rotation_tests;
#[cfg(test)]
mod policy_tests;
