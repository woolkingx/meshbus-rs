//! Raw UDP Mesh Protocol ingress adapter.

mod mouth_registry;
mod sender;

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use mb_endpoint::Endpoint;
#[cfg(test)]
use mb_proto_mesh::ReceiverMouth;
use mb_proto_mesh::{
    CloseReasonWire, EventSemantic, MESHSEC_ACCEPTED_EPOCH_SKEW_SLOTS, MESHSEC_REPLAY_WINDOW_BITS,
    MeshFrame, MeshSecError, MeshSecOpenKey, MeshSecReplayCache, MeshSecSealContext,
    NativeEventMode, StreamOpenRejectReason, decode_event, decode_frame, decode_mesh_frame_clear,
    event_frame_payload, meshsec_epoch_number, open_bytes,
};
use mb_reorder::{FamilyPushOutcome, FamilyReorderState};
use mesh_bus_core::transport::udp_loop::UdpPacketLoop;
use mesh_bus_core::{
    BusDatagramRecvHalf, BusDatagramSendHalf, BusError, BusPort, BusSessionRequest,
    BusStreamRecvHalf, BusStreamSendHalf, DisconnectReason, IngressPlugin,
    kernel::observation::{EventPayload, EventPayloadInner, OBS_MESHSEC_DROP, OBS_NATIVE_DROP},
};
#[cfg(test)]
use mouth_registry::MOUTH_SOFT_TTL_SECS;
use mouth_registry::{MouthEntry, MouthKey, apply_port_close, apply_port_open};
use sender::MeshPeerIngressSender;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;

const MAX_PEER_SESSIONS: usize = 1024;
const DEFAULT_PENDING_STREAM_DATA_MAX_BYTES: usize = 64 * 1024;

/// Bounded per-family reorder window for native-mode ordered families. Frames
/// beyond this distance close the family fail-closed (no bus re-entry).
const NATIVE_REORDER_WINDOW: u16 = 64;

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Native-mode (`SecureUdpNative`) Layer-2 drop classes. Fail-closed: every
/// variant drops the datagram (no bus session, no reply) but the reason stays
/// typed and observable, mirroring the MeshSec-layer `MeshSecError` trace so
/// oversize/replay/bad-epoch (MeshSec layer) and overflow/unsupported-family
/// (this layer) are all preserved as typed failures, never silent drops.
#[derive(Debug, Clone, Copy)]
enum NativeDropReason {
    EventDecode,
    ControlPayloadMissing,
    ControlFrameDecode,
    UnsupportedEventFamily,
    QueueOverflow,
    PackageFrameDecode,
    StreamDataPending,
}

fn native_drop_reason(reason: NativeDropReason) -> &'static str {
    match reason {
        NativeDropReason::EventDecode => "event_decode",
        NativeDropReason::ControlPayloadMissing => "control_payload_missing",
        NativeDropReason::ControlFrameDecode => "control_frame_decode",
        NativeDropReason::UnsupportedEventFamily => "unsupported_event_family",
        NativeDropReason::QueueOverflow => "queue_overflow",
        NativeDropReason::PackageFrameDecode => "package_frame_decode",
        NativeDropReason::StreamDataPending => "stream_data_pending",
    }
}

fn meshsec_drop_reason(err: &MeshSecError) -> &'static str {
    match err {
        MeshSecError::Auth => "auth",
        MeshSecError::Replay => "replay",
        MeshSecError::ReplayTooOld => "replay_too_old",
        MeshSecError::Truncated => "truncated",
        MeshSecError::UnsupportedVersion(_) => "unsupported_version",
        MeshSecError::PayloadTooLarge => "payload_too_large",
        MeshSecError::Serialize(_) => "serialize",
    }
}

fn drop_payload(peer: SocketAddr, reason: &'static str, secure: bool) -> EventPayload {
    EventPayload(Arc::new(EventPayloadInner {
        source_addr: Some(peer.to_string()),
        reason: Some(reason.to_string()),
        transport_mode: Some("mesh-peer-udp".to_string()),
        secure: Some(secure),
        ..EventPayloadInner::default()
    }))
}

fn drop_meshsec(port: &BusPort, peer: SocketAddr, err: &MeshSecError) {
    port.publish_observation(
        OBS_MESHSEC_DROP,
        drop_payload(peer, meshsec_drop_reason(err), true),
    );
}

fn drop_native(port: &BusPort, peer: SocketAddr, reason: NativeDropReason) {
    port.publish_observation(
        OBS_NATIVE_DROP,
        drop_payload(peer, native_drop_reason(reason), false),
    );
    tracing::trace!(
        target: "mesh_peer_udp_ingress",
        %peer,
        ?reason,
        "native secure-udp event dropped fail-closed"
    );
}

/// Receiver-side MeshSec material: the configured open keys plus the per-boot
/// boot salt used to seal reverse replies.
struct MeshSecIngress {
    local_node_id: String,
    keys: Vec<MeshSecOpenKey>,
    boot_salt: [u8; 4],
}

const MESHSEC_STREAM_CHUNK_BYTES: usize = 832;
const STREAM_FLUSH_CHUNK_BATCH: usize = 64;
const CONTROL_REPLY_BOUND: usize = 64;

/// Reverse sealing state for one matched peer so `DatagramReturn` /
/// `StreamOpenReject` replies never travel in clear. The counter is shared per
/// matched peer because `K_tx` is per static key, not per session.
#[derive(Clone)]
struct MeshSecReplySeal {
    ctx: MeshSecSealContext,
    counter: Arc<AtomicU64>,
}

fn reply_seal_for(
    ms: &MeshSecIngress,
    peer_id: &str,
    counters: &mut HashMap<String, Arc<AtomicU64>>,
) -> Option<MeshSecReplySeal> {
    let key = ms.keys.iter().find(|k| k.peer_id == peer_id)?;
    let counter = counters
        .entry(peer_id.to_string())
        .or_insert_with(|| Arc::new(AtomicU64::new(1)))
        .clone();
    Some(MeshSecReplySeal {
        ctx: MeshSecSealContext {
            local_node_id: ms.local_node_id.clone(),
            remote_node_id: key.remote_node_id.clone(),
            static_key: key.static_key,
            boot_salt: ms.boot_salt,
        },
        counter,
    })
}

pub struct MeshPeerUdpIngress {
    packet_loop: UdpPacketLoop,
    max_peer_sessions: usize,
    pending_stream_data_max_bytes: usize,
    meshsec: Option<MeshSecIngress>,
    native_event_mode: NativeEventMode,
}

impl MeshPeerUdpIngress {
    pub fn new(packet_loop: UdpPacketLoop) -> Self {
        Self {
            packet_loop,
            max_peer_sessions: MAX_PEER_SESSIONS,
            pending_stream_data_max_bytes: DEFAULT_PENDING_STREAM_DATA_MAX_BYTES,
            meshsec: None,
            native_event_mode: NativeEventMode::default(),
        }
    }

    pub fn with_max_peer_sessions(mut self, max: usize) -> Self {
        self.max_peer_sessions = max.max(1);
        self
    }

    pub fn with_pending_stream_data_max_bytes(mut self, max: usize) -> Self {
        self.pending_stream_data_max_bytes = max.max(1);
        self
    }

    /// Match the sender's wire mode. `SecureUdpNative` decodes the MeshEvent /
    /// DataPackage envelope and runs per-family reorder before bus re-entry;
    /// `MeshFrame` keeps the legacy byte-for-byte decode path.
    pub fn with_native_event_mode(mut self, mode: NativeEventMode) -> Self {
        self.native_event_mode = mode;
        self
    }

    /// Open every inbound frame with MeshSec and seal every reply. Without
    /// configured keys the adapter stays debug-clear for loopback tests.
    pub fn with_meshsec_keys(mut self, local_node_id: String, keys: Vec<MeshSecOpenKey>) -> Self {
        self.meshsec = Some(MeshSecIngress {
            local_node_id,
            keys,
            boot_salt: rand::random(),
        });
        self
    }
}

struct PeerDatagramSession {
    send: Mutex<Box<dyn BusDatagramSendHalf>>,
    pump: JoinHandle<()>,
}

impl PeerDatagramSession {
    async fn close(&self) {
        self.pump.abort();
        self.send.lock().await.close().await;
    }
}

struct PeerStreamSession {
    send: Mutex<Box<dyn BusStreamSendHalf>>,
    pump: JoinHandle<()>,
}

impl PeerStreamSession {
    async fn close(&self) {
        self.pump.abort();
        self.send
            .lock()
            .await
            .abort(DisconnectReason::SessionClosed)
            .await;
    }
}

type SessionKey = (SocketAddr, String);
type FamilyKey = (SocketAddr, String);

struct ControlReply {
    peer: SocketAddr,
    native_event_mode: NativeEventMode,
    seal: Option<MeshSecReplySeal>,
    frame: MeshFrame,
}

struct PendingStreamData {
    frames: Vec<Bytes>,
    bytes: usize,
}

impl PendingStreamData {
    fn push(&mut self, payload: Bytes) {
        self.bytes = self.bytes.saturating_add(payload.len());
        self.frames.push(payload);
    }
}

fn spawn_response_pump(
    sender: MeshPeerIngressSender,
    peer: SocketAddr,
    session_id: String,
    mut recv: Box<dyn BusDatagramRecvHalf>,
    reply_seal: Option<MeshSecReplySeal>,
    native_event_mode: NativeEventMode,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut seq = 1u64;
        while let Some((source, payload)) = recv.recv_from().await {
            let frame = MeshFrame::DatagramReturn {
                session_id: session_id.clone(),
                seq,
                source,
                payload,
            };
            seq = seq.saturating_add(1);
            if sender
                .send_frame(peer, native_event_mode, reply_seal.clone(), frame)
                .await
                .is_err()
            {
                break;
            }
        }
    })
}

fn spawn_control_reply_worker(
    sender: MeshPeerIngressSender,
    mut rx: mpsc::Receiver<ControlReply>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(reply) = rx.recv().await {
            let _ = sender
                .send_frame(reply.peer, reply.native_event_mode, reply.seal, reply.frame)
                .await;
        }
    })
}

fn spawn_stream_response_pump(
    sender: MeshPeerIngressSender,
    peer: SocketAddr,
    session_id: String,
    mut recv: Box<dyn BusStreamRecvHalf>,
    reply_seal: Option<MeshSecReplySeal>,
    native_event_mode: NativeEventMode,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut seq = 1u64;
        while let Some(payload) = recv.recv().await {
            let chunk_bytes = stream_chunk_bytes(reply_seal.as_ref());
            let mut frames = Vec::new();
            for chunk in payload.chunks(chunk_bytes) {
                frames.push(MeshFrame::StreamData {
                    session_id: session_id.clone(),
                    seq,
                    payload: Bytes::copy_from_slice(chunk),
                });
                seq = seq.saturating_add(1);
                if frames.len() >= STREAM_FLUSH_CHUNK_BATCH {
                    if sender
                        .send_data_frames(
                            peer,
                            native_event_mode,
                            reply_seal.clone(),
                            std::mem::take(&mut frames),
                        )
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
            if sender
                .send_data_frames(peer, native_event_mode, reply_seal.clone(), frames)
                .await
                .is_err()
            {
                return;
            }
        }
        let _ = sender
            .send_frame(
                peer,
                native_event_mode,
                reply_seal,
                MeshFrame::StreamShutdownWrite {
                    session_id: session_id.clone(),
                },
            )
            .await;
    })
}

fn stream_chunk_bytes(seal: Option<&MeshSecReplySeal>) -> usize {
    if seal.is_some() {
        MESHSEC_STREAM_CHUNK_BYTES
    } else {
        65_000
    }
}

async fn open_peer_datagram_session(
    port: &BusPort,
    sender: MeshPeerIngressSender,
    peer: SocketAddr,
    session_id: String,
    target: Endpoint,
    reply_seal: Option<MeshSecReplySeal>,
    native_event_mode: NativeEventMode,
) -> Option<Arc<PeerDatagramSession>> {
    let Ok(session) = port
        .open_datagram(BusSessionRequest::datagram(target))
        .await
    else {
        return None;
    };
    let (send, recv) = session.split();
    let pump = spawn_response_pump(
        sender,
        peer,
        session_id,
        recv,
        reply_seal,
        native_event_mode,
    );
    Some(Arc::new(PeerDatagramSession {
        send: Mutex::new(send),
        pump,
    }))
}

async fn open_peer_stream_session(
    port: &BusPort,
    sender: MeshPeerIngressSender,
    peer: SocketAddr,
    open: mb_proto_mesh::StreamOpen,
    reply_seal: Option<MeshSecReplySeal>,
    native_event_mode: NativeEventMode,
) -> Result<Arc<PeerStreamSession>, DisconnectReason> {
    let mut request = BusSessionRequest::stream(open.target);
    if let Some(route_group) = open.route_group {
        request = request.with_route_group(route_group);
    }
    let mut session = port.open_stream(request).await?;
    session.connect().await?;
    let (send, recv) = session.split();
    let pump = spawn_stream_response_pump(
        sender,
        peer,
        open.session_id,
        recv,
        reply_seal,
        native_event_mode,
    );
    Ok(Arc::new(PeerStreamSession {
        send: Mutex::new(send),
        pump,
    }))
}

#[async_trait]
impl IngressPlugin for MeshPeerUdpIngress {
    fn name(&self) -> &str {
        "mesh-peer-udp-ingress"
    }

    async fn run(self: Box<Self>, port: BusPort) -> Result<(), BusError> {
        let max_peer_sessions = self.max_peer_sessions;
        let pending_stream_data_max_bytes = self.pending_stream_data_max_bytes;
        let meshsec = self.meshsec;
        let native_event_mode = self.native_event_mode;
        let packet_loop = Arc::new(self.packet_loop);
        let sender = MeshPeerIngressSender::spawn(packet_loop.clone());
        let (control_reply_tx, control_reply_rx) = mpsc::channel(CONTROL_REPLY_BOUND);
        let _control_reply_worker = spawn_control_reply_worker(sender.clone(), control_reply_rx);
        let mut sessions: HashMap<SessionKey, Arc<PeerDatagramSession>> = HashMap::new();
        let mut stream_sessions: HashMap<SessionKey, Arc<PeerStreamSession>> = HashMap::new();
        let mut pending_stream_data: HashMap<SessionKey, PendingStreamData> = HashMap::new();
        let mut family_states: HashMap<FamilyKey, FamilyReorderState> = HashMap::new();
        let mut mouths: HashMap<MouthKey, MouthEntry> = HashMap::new();
        let mut replay = MeshSecReplayCache::new(MESHSEC_REPLAY_WINDOW_BITS);
        let mut reply_counters: HashMap<String, Arc<AtomicU64>> = HashMap::new();

        loop {
            packet_loop
                .poll_recv()
                .await
                .map_err(|_| BusError::ChannelClosed)?;

            for inbound in packet_loop.drain_inbound() {
                let peer = inbound.source;

                // Layer 1: MeshSec open (or clear loopback). Tampered, replayed,
                // or wrong-epoch datagrams drop here fail-closed.
                let (clear, reply_seal, sealed): (Vec<u8>, Option<MeshSecReplySeal>, bool) =
                    match &meshsec {
                        Some(ms) => {
                            let epoch = meshsec_epoch_number(now_unix_secs());
                            match open_bytes(
                                &inbound.payload,
                                &ms.keys,
                                &ms.local_node_id,
                                epoch.saturating_sub(MESHSEC_ACCEPTED_EPOCH_SKEW_SLOTS)
                                    ..=epoch + MESHSEC_ACCEPTED_EPOCH_SKEW_SLOTS,
                                &mut replay,
                            ) {
                                Ok((peer_id, clear)) => (
                                    clear,
                                    reply_seal_for(ms, &peer_id, &mut reply_counters),
                                    true,
                                ),
                                Err(err) => {
                                    drop_meshsec(&port, peer, &err);
                                    tracing::trace!(
                                        target: "mesh_peer_udp_ingress",
                                        %peer,
                                        ?err,
                                        "meshsec open failed; dropping packet"
                                    );
                                    continue;
                                }
                            }
                        }
                        None => (inbound.payload.to_vec(), None, false),
                    };

                // Layer 2: decode the wire mode into ordered `MeshFrame`s.
                // `MeshFrame` stays byte-for-byte; `SecureUdpNative` unwraps the
                // native event and runs per-family reorder so the bus only
                // re-enters legal in-order frames.
                let frames: Vec<MeshFrame> = match native_event_mode {
                    NativeEventMode::MeshFrame => {
                        // `seal_mesh_frame` seals raw `bincode::serialize(frame)`
                        // with no `encode_frame` MAGIC envelope, so the post-open
                        // clear bytes decode through `decode_mesh_frame_clear`.
                        // The unsealed clear path is `encode_frame` MAGIC-framed.
                        let decoded = if sealed {
                            decode_mesh_frame_clear(&clear)
                        } else {
                            decode_frame(&mut BytesMut::from(&clear[..]))
                        };
                        match decoded {
                            Ok(frame) => vec![frame],
                            Err(_) => continue,
                        }
                    }
                    NativeEventMode::SecureUdpNative => {
                        let event = match decode_event(&mut BytesMut::from(&clear[..])) {
                            Ok(event) => event,
                            Err(_) => {
                                drop_native(&port, peer, NativeDropReason::EventDecode);
                                continue;
                            }
                        };
                        match event.semantic {
                            EventSemantic::Control | EventSemantic::Observation => {
                                let Some(payload) = event_frame_payload(&event) else {
                                    drop_native(
                                        &port,
                                        peer,
                                        NativeDropReason::ControlPayloadMissing,
                                    );
                                    continue;
                                };
                                match decode_frame(&mut BytesMut::from(payload)) {
                                    Ok(frame) => vec![frame],
                                    Err(_) => {
                                        drop_native(
                                            &port,
                                            peer,
                                            NativeDropReason::ControlFrameDecode,
                                        );
                                        continue;
                                    }
                                }
                            }
                            EventSemantic::Stream | EventSemantic::Datagram => {
                                let Some(package) = event.package.clone() else {
                                    drop_native(
                                        &port,
                                        peer,
                                        NativeDropReason::UnsupportedEventFamily,
                                    );
                                    continue;
                                };
                                let fam_key = (peer, event.family_id.clone());
                                if !family_states.contains_key(&fam_key)
                                    && family_states.len() >= max_peer_sessions
                                {
                                    if let Some(evict) = family_states.keys().next().cloned() {
                                        family_states.remove(&evict);
                                    }
                                }
                                let outcome = family_states
                                    .entry(fam_key.clone())
                                    .or_insert_with(|| {
                                        FamilyReorderState::new(
                                            event.family_id.clone(),
                                            1,
                                            NATIVE_REORDER_WINDOW,
                                            0,
                                        )
                                    })
                                    .push_package(package);
                                match outcome {
                                    FamilyPushOutcome::Deliver(packages) => {
                                        let mut decoded = Vec::with_capacity(packages.len());
                                        for pkg in packages {
                                            match decode_frame(&mut BytesMut::from(
                                                &pkg.payload[..],
                                            )) {
                                                Ok(frame) => decoded.push(frame),
                                                Err(_) => drop_native(
                                                    &port,
                                                    peer,
                                                    NativeDropReason::PackageFrameDecode,
                                                ),
                                            }
                                        }
                                        decoded
                                    }
                                    FamilyPushOutcome::WindowOverflow(_) => {
                                        drop_native(&port, peer, NativeDropReason::QueueOverflow);
                                        if matches!(event.semantic, EventSemantic::Stream) {
                                            let _ = control_reply_tx.try_send(ControlReply {
                                                peer,
                                                native_event_mode,
                                                seal: reply_seal.clone(),
                                                frame: MeshFrame::StreamClose {
                                                    session_id: event.family_id.clone(),
                                                    close_reason: CloseReasonWire::ProtocolError,
                                                },
                                            });
                                        }
                                        family_states.remove(&fam_key);
                                        continue;
                                    }
                                    FamilyPushOutcome::Gap(ack) => {
                                        // L5 feedback: report the missing seqs
                                        // so a Repair-mode egress retransmits.
                                        // Control replies are queued to the
                                        // worker so native receive/reorder never
                                        // waits on packet-loop flush.
                                        let _ = control_reply_tx.try_send(ControlReply {
                                            peer,
                                            native_event_mode,
                                            seal: reply_seal.clone(),
                                            frame: MeshFrame::AckNack(ack),
                                        });
                                        continue;
                                    }
                                    FamilyPushOutcome::Buffered | FamilyPushOutcome::Duplicate => {
                                        continue;
                                    }
                                }
                            }
                        }
                    }
                };

                for frame in frames {
                    let reply_seal = reply_seal.clone();
                    match frame {
                        MeshFrame::DatagramOpen(open) => {
                            let Some(target) = open.fixed_target else {
                                continue;
                            };
                            let key = (peer, open.session_id.clone());
                            if sessions.contains_key(&key) {
                                continue;
                            }
                            if let Some(session) = open_peer_datagram_session(
                                &port,
                                sender.clone(),
                                peer,
                                open.session_id,
                                target,
                                reply_seal,
                                native_event_mode,
                            )
                            .await
                            {
                                if sessions.len() >= max_peer_sessions {
                                    if let Some(evict) = sessions.keys().next().cloned() {
                                        if let Some(evicted) = sessions.remove(&evict) {
                                            evicted.close().await;
                                        }
                                    }
                                }
                                sessions.insert(key, session);
                            }
                        }
                        MeshFrame::DatagramSend {
                            session_id,
                            target,
                            payload,
                            ..
                        } => {
                            let key = (peer, session_id.clone());
                            let session = if let Some(session) = sessions.get(&key) {
                                session.clone()
                            } else {
                                let Some(session) = open_peer_datagram_session(
                                    &port,
                                    sender.clone(),
                                    peer,
                                    session_id.clone(),
                                    target.clone(),
                                    reply_seal,
                                    native_event_mode,
                                )
                                .await
                                else {
                                    continue;
                                };
                                if sessions.len() >= max_peer_sessions {
                                    if let Some(evict) = sessions.keys().next().cloned() {
                                        if let Some(evicted) = sessions.remove(&evict) {
                                            evicted.close().await;
                                        }
                                    }
                                }
                                sessions.insert(key, session.clone());
                                session
                            };
                            let _ = session.send.lock().await.send_to(target, payload).await;
                        }
                        MeshFrame::DatagramClose { session_id, .. } => {
                            family_states.remove(&(peer, session_id.clone()));
                            if let Some(session) = sessions.remove(&(peer, session_id)) {
                                session.close().await;
                            }
                        }
                        MeshFrame::StreamOpen(open) => {
                            let key = (peer, open.session_id.clone());
                            if stream_sessions.contains_key(&key) {
                                continue;
                            }
                            let session_id = open.session_id.clone();
                            let open_token = open.open_token;
                            match open_peer_stream_session(
                                &port,
                                sender.clone(),
                                peer,
                                open,
                                reply_seal.clone(),
                                native_event_mode,
                            )
                            .await
                            {
                                Ok(session) => {
                                    let accepted = MeshFrame::StreamOpenAccepted {
                                        session_id: session_id.clone(),
                                        open_token,
                                    };
                                    let _ = sender
                                        .send_frame(
                                            peer,
                                            native_event_mode,
                                            reply_seal.clone(),
                                            accepted,
                                        )
                                        .await;
                                    if stream_sessions.len() >= max_peer_sessions {
                                        if let Some(evict) = stream_sessions.keys().next().cloned()
                                        {
                                            if let Some(evicted) = stream_sessions.remove(&evict) {
                                                evicted.close().await;
                                            }
                                        }
                                    }
                                    stream_sessions.insert(key.clone(), session.clone());
                                    if let Some(pending) = pending_stream_data.remove(&key) {
                                        for payload in pending.frames {
                                            if session
                                                .send
                                                .lock()
                                                .await
                                                .send(payload)
                                                .await
                                                .is_err()
                                            {
                                                if let Some(session) = stream_sessions.remove(&key)
                                                {
                                                    session.close().await;
                                                }
                                                break;
                                            }
                                        }
                                    }
                                }
                                Err(reason) => {
                                    let reject = MeshFrame::StreamOpenReject {
                                        session_id,
                                        open_token,
                                        reason: reject_reason(&reason),
                                        close_reason: close_reason_wire(&reason),
                                    };
                                    let _ = sender
                                        .send_frame(peer, native_event_mode, reply_seal, reject)
                                        .await;
                                }
                            }
                        }
                        MeshFrame::StreamData {
                            session_id,
                            payload,
                            ..
                        } => {
                            let key = (peer, session_id.clone());
                            if let Some(session) = stream_sessions.get(&key) {
                                if session.send.lock().await.send(payload).await.is_err() {
                                    if let Some(session) = stream_sessions.remove(&key) {
                                        session.close().await;
                                    }
                                }
                            } else {
                                let pending = pending_stream_data.entry(key).or_insert_with(|| {
                                    PendingStreamData {
                                        frames: Vec::new(),
                                        bytes: 0,
                                    }
                                });
                                if pending.bytes.saturating_add(payload.len())
                                    > pending_stream_data_max_bytes
                                {
                                    drop_native(&port, peer, NativeDropReason::StreamDataPending);
                                    continue;
                                }
                                pending.push(payload);
                            }
                        }
                        MeshFrame::StreamOpenAccepted { .. } => {}
                        MeshFrame::StreamShutdownWrite { session_id } => {
                            let key = (peer, session_id);
                            if let Some(session) = stream_sessions.get(&key) {
                                session.send.lock().await.shutdown_write().await;
                            }
                        }
                        MeshFrame::StreamClose { session_id, .. } => {
                            family_states.remove(&(peer, session_id.clone()));
                            pending_stream_data.remove(&(peer, session_id.clone()));
                            if let Some(session) = stream_sessions.remove(&(peer, session_id)) {
                                session.close().await;
                            }
                        }
                        MeshFrame::PortOpen(mouth) => {
                            apply_port_open(&mut mouths, peer, &mouth, now_unix_secs());
                        }
                        MeshFrame::PortClose { mouth_id, epoch } => {
                            apply_port_close(&mut mouths, peer, &mouth_id, epoch);
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

fn reject_reason(reason: &DisconnectReason) -> StreamOpenRejectReason {
    match reason {
        DisconnectReason::NoUsableExit | DisconnectReason::HostUnreachable => {
            StreamOpenRejectReason::NoUsableExit
        }
        DisconnectReason::ConnectionRefused
        | DisconnectReason::NetworkUnreachable
        | DisconnectReason::TimedOut => StreamOpenRejectReason::NoUsableExit,
        _ => StreamOpenRejectReason::ProtocolError,
    }
}

fn close_reason_wire(reason: &DisconnectReason) -> CloseReasonWire {
    match reason {
        DisconnectReason::NoUsableExit | DisconnectReason::HostUnreachable => {
            CloseReasonWire::NoUsableExit
        }
        DisconnectReason::ConnectionRefused
        | DisconnectReason::NetworkUnreachable
        | DisconnectReason::TimedOut => CloseReasonWire::NoUsableExit,
        DisconnectReason::AddressNotSupported | DisconnectReason::Other(_) => {
            CloseReasonWire::ProtocolError
        }
        _ => CloseReasonWire::Normal,
    }
}

#[cfg(test)]
mod mouth_registry_tests;
