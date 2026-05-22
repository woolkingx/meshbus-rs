//! Raw UDP Mesh Protocol ingress adapter.

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use mb_endpoint::Endpoint;
use mb_proto_mesh::{
    CloseReasonWire, EventSemantic, MESHSEC_ACCEPTED_EPOCH_SKEW_SLOTS, MESHSEC_REPLAY_WINDOW_BITS,
    MeshFrame, MeshSecError, MeshSecOpenKey, MeshSecReplayCache, MeshSecSealContext,
    NativeEventMode, ReceiverMouth, StreamOpenRejectReason, decode_event, decode_frame,
    decode_mesh_frame_clear, encode_frame, event_frame_payload, meshsec_epoch_number, open_bytes,
    seal_mesh_frame,
};
use mb_reorder::{FamilyPushOutcome, FamilyReorderState};
use mesh_bus_core::transport::udp_loop::{OutboundDatagram, UdpPacketLoop};
use mesh_bus_core::{
    BusDatagramRecvHalf, BusDatagramSendHalf, BusError, BusPort, BusSessionRequest,
    BusStreamRecvHalf, BusStreamSendHalf, DisconnectReason, IngressPlugin,
    kernel::observation::{EventPayload, EventPayloadInner, OBS_MESHSEC_DROP, OBS_NATIVE_DROP},
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

const MAX_PEER_SESSIONS: usize = 1024;

/// Bounded per-family reorder window for native-mode ordered families. Frames
/// beyond this distance close the family fail-closed (no bus re-entry).
const NATIVE_REORDER_WINDOW: u16 = 64;

/// Soft TTL for a receiver mouth entry. A mouth not re-advertised within this
/// window is pruned on the next PortOpen for its peer. The registry holds
/// delivery coordinates only; expiry never tears down a bus session.
const MOUTH_SOFT_TTL_SECS: u64 = 30;

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
}

fn native_drop_reason(reason: NativeDropReason) -> &'static str {
    match reason {
        NativeDropReason::EventDecode => "event_decode",
        NativeDropReason::ControlPayloadMissing => "control_payload_missing",
        NativeDropReason::ControlFrameDecode => "control_frame_decode",
        NativeDropReason::UnsupportedEventFamily => "unsupported_event_family",
        NativeDropReason::QueueOverflow => "queue_overflow",
        NativeDropReason::PackageFrameDecode => "package_frame_decode",
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
    meshsec: Option<MeshSecIngress>,
    native_event_mode: NativeEventMode,
}

impl MeshPeerUdpIngress {
    pub fn new(packet_loop: UdpPacketLoop) -> Self {
        Self {
            packet_loop,
            max_peer_sessions: MAX_PEER_SESSIONS,
            meshsec: None,
            native_event_mode: NativeEventMode::default(),
        }
    }

    pub fn with_max_peer_sessions(mut self, max: usize) -> Self {
        self.max_peer_sessions = max.max(1);
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
type MouthKey = (SocketAddr, String);

/// One receiver-mouth registry entry. Delivery coordinate only — it carries no
/// session, route, or channel truth and never owns a bus session. `epoch` and
/// `last_seen` drive rotation/TTL; the remaining fields are the recorded
/// delivery-coordinate evidence consumed by M6 LinkEvidence / M7 DeliveryPolicy.
struct MouthEntry {
    epoch: u64,
    #[allow(dead_code)]
    udp_addr: String,
    #[allow(dead_code)]
    family_filter: Vec<String>,
    #[allow(dead_code)]
    advertised_capacity: u32,
    last_seen: u64,
}

/// Apply a PortOpen advertisement to the receiver-mouth registry. Pure
/// delivery-coordinate bookkeeping: it never opens, closes, or mutates a bus
/// session, family-reorder state, or route. Soft-TTL-expired entries for the
/// peer are pruned first. A stale-epoch advertisement (older than the recorded
/// epoch for the same mouth) is ignored. Make-before-break: a fresh or rotated
/// mouth is eligible immediately on upsert. Returns true when the registry now
/// reflects this mouth, false when the advertisement was ignored as stale.
fn apply_port_open(
    mouths: &mut HashMap<MouthKey, MouthEntry>,
    peer: SocketAddr,
    mouth: &ReceiverMouth,
    now: u64,
) -> bool {
    mouths.retain(|(p, _), e| *p != peer || now.saturating_sub(e.last_seen) <= MOUTH_SOFT_TTL_SECS);
    let key = (peer, mouth.mouth_id.clone());
    if let Some(existing) = mouths.get(&key) {
        if existing.epoch > mouth.epoch {
            return false;
        }
    }
    mouths.insert(
        key,
        MouthEntry {
            epoch: mouth.epoch,
            udp_addr: mouth.udp_addr.clone(),
            family_filter: mouth.family_filter.clone(),
            advertised_capacity: mouth.advertised_capacity,
            last_seen: now,
        },
    );
    true
}

/// Apply a PortClose to the registry. A stale-epoch close (older than the
/// recorded epoch) is ignored so a late close cannot retract a rotated mouth.
/// Pure registry bookkeeping — never touches a bus session. Returns true when
/// an entry was removed.
fn apply_port_close(
    mouths: &mut HashMap<MouthKey, MouthEntry>,
    peer: SocketAddr,
    mouth_id: &str,
    epoch: u64,
) -> bool {
    let key = (peer, mouth_id.to_string());
    match mouths.get(&key) {
        Some(existing) if existing.epoch > epoch => false,
        Some(_) => mouths.remove(&key).is_some(),
        None => false,
    }
}

fn spawn_response_pump(
    packet_loop: Arc<UdpPacketLoop>,
    peer: SocketAddr,
    session_id: String,
    mut recv: Box<dyn BusDatagramRecvHalf>,
    reply_seal: Option<MeshSecReplySeal>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some((source, payload)) = recv.recv_from().await {
            let frame = MeshFrame::DatagramReturn {
                session_id: session_id.clone(),
                seq: 0,
                source,
                payload,
            };
            if send_mesh_frame(&packet_loop, peer, reply_seal.as_ref(), &frame)
                .await
                .is_err()
            {
                break;
            }
        }
    })
}

fn spawn_stream_response_pump(
    packet_loop: Arc<UdpPacketLoop>,
    peer: SocketAddr,
    session_id: String,
    mut recv: Box<dyn BusStreamRecvHalf>,
    reply_seal: Option<MeshSecReplySeal>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut seq = 1u64;
        while let Some(payload) = recv.recv().await {
            let chunk_bytes = stream_chunk_bytes(reply_seal.as_ref());
            for chunk in payload.chunks(chunk_bytes) {
                let frame = MeshFrame::StreamData {
                    session_id: session_id.clone(),
                    seq,
                    payload: Bytes::copy_from_slice(chunk),
                };
                seq = seq.saturating_add(1);
                if send_mesh_frame(&packet_loop, peer, reply_seal.as_ref(), &frame)
                    .await
                    .is_err()
                {
                    return;
                }
                if reply_seal.is_some() {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            }
        }
        let _ = send_mesh_frame(
            &packet_loop,
            peer,
            reply_seal.as_ref(),
            &MeshFrame::StreamShutdownWrite {
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
    packet_loop: Arc<UdpPacketLoop>,
    peer: SocketAddr,
    session_id: String,
    target: Endpoint,
    reply_seal: Option<MeshSecReplySeal>,
) -> Option<Arc<PeerDatagramSession>> {
    let Ok(session) = port
        .open_datagram(BusSessionRequest::datagram(target))
        .await
    else {
        return None;
    };
    let (send, recv) = session.split();
    let pump = spawn_response_pump(packet_loop, peer, session_id, recv, reply_seal);
    Some(Arc::new(PeerDatagramSession {
        send: Mutex::new(send),
        pump,
    }))
}

async fn open_peer_stream_session(
    port: &BusPort,
    packet_loop: Arc<UdpPacketLoop>,
    peer: SocketAddr,
    open: mb_proto_mesh::StreamOpen,
    reply_seal: Option<MeshSecReplySeal>,
) -> Result<Arc<PeerStreamSession>, DisconnectReason> {
    let mut request = BusSessionRequest::stream(open.target);
    if let Some(route_group) = open.route_group {
        request = request.with_route_group(route_group);
    }
    let mut session = port.open_stream(request).await?;
    session.connect().await?;
    let (send, recv) = session.split();
    let pump = spawn_stream_response_pump(packet_loop, peer, open.session_id, recv, reply_seal);
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
        let meshsec = self.meshsec;
        let native_event_mode = self.native_event_mode;
        let packet_loop = Arc::new(self.packet_loop);
        let mut sessions: HashMap<SessionKey, Arc<PeerDatagramSession>> = HashMap::new();
        let mut stream_sessions: HashMap<SessionKey, Arc<PeerStreamSession>> = HashMap::new();
        let mut pending_stream_data: HashMap<SessionKey, Vec<Bytes>> = HashMap::new();
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
                                        family_states.remove(&fam_key);
                                        continue;
                                    }
                                    FamilyPushOutcome::Gap(ack) => {
                                        // L5 feedback: report the missing seqs
                                        // so a Repair-mode egress retransmits.
                                        // Best-effort; the AckNack carries no
                                        // route/session truth and a failed
                                        // send-back just waits for the next
                                        // gap. Replicate dedup needs nothing
                                        // here — a duplicate seq already lands
                                        // as Duplicate below.
                                        let _ = send_mesh_frame(
                                            &packet_loop,
                                            peer,
                                            reply_seal.as_ref(),
                                            &MeshFrame::AckNack(ack),
                                        )
                                        .await;
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
                                packet_loop.clone(),
                                peer,
                                open.session_id,
                                target,
                                reply_seal,
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
                                    packet_loop.clone(),
                                    peer,
                                    session_id.clone(),
                                    target.clone(),
                                    reply_seal,
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
                            match open_peer_stream_session(
                                &port,
                                packet_loop.clone(),
                                peer,
                                open,
                                reply_seal.clone(),
                            )
                            .await
                            {
                                Ok(session) => {
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
                                        for payload in pending {
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
                                        reason: reject_reason(&reason),
                                        close_reason: close_reason_wire(&reason),
                                    };
                                    let _ = send_mesh_frame(
                                        &packet_loop,
                                        peer,
                                        reply_seal.as_ref(),
                                        &reject,
                                    )
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
                                pending_stream_data.entry(key).or_default().push(payload);
                            }
                        }
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

async fn send_mesh_frame(
    packet_loop: &UdpPacketLoop,
    peer: SocketAddr,
    seal: Option<&MeshSecReplySeal>,
    frame: &MeshFrame,
) -> Result<(), std::io::Error> {
    let encoded = match seal {
        Some(s) => seal_mesh_frame(
            frame,
            &s.ctx,
            meshsec_epoch_number(now_unix_secs()),
            s.counter.fetch_add(1, Ordering::Relaxed),
        )
        .map_err(|err| std::io::Error::other(err.to_string()))?,
        None => encode_frame(frame).map_err(|err| std::io::Error::other(err.to_string()))?,
    };
    packet_loop.enqueue(OutboundDatagram {
        destination: peer,
        payload: Bytes::from(encoded),
    });
    packet_loop.flush().await?;
    Ok(())
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
mod mouth_registry_tests {
    use super::*;

    fn mouth(id: &str, addr: &str, epoch: u64) -> ReceiverMouth {
        ReceiverMouth {
            mouth_id: id.into(),
            udp_addr: addr.into(),
            family_filter: vec!["datagram".into()],
            advertised_capacity: 1024,
            epoch,
        }
    }

    fn peer() -> SocketAddr {
        "127.0.0.1:9100".parse().unwrap()
    }

    #[test]
    fn initial_mouth_is_recorded() {
        let mut mouths: HashMap<MouthKey, MouthEntry> = HashMap::new();
        assert!(apply_port_open(
            &mut mouths,
            peer(),
            &mouth("m1", "10.0.0.1:7001", 1),
            100
        ));
        let e = mouths.get(&(peer(), "m1".into())).unwrap();
        assert_eq!(e.epoch, 1);
        assert_eq!(e.udp_addr, "10.0.0.1:7001");
        assert_eq!(e.last_seen, 100);
    }

    #[test]
    fn mouth_rotation_make_before_break_keeps_old_until_close() {
        let mut mouths: HashMap<MouthKey, MouthEntry> = HashMap::new();
        apply_port_open(&mut mouths, peer(), &mouth("m1", "10.0.0.1:7001", 1), 100);
        // New mouth becomes eligible immediately; old mouth still present.
        assert!(apply_port_open(
            &mut mouths,
            peer(),
            &mouth("m2", "10.0.0.1:7002", 2),
            101
        ));
        assert!(mouths.contains_key(&(peer(), "m1".into())));
        assert!(mouths.contains_key(&(peer(), "m2".into())));
        // Old mouth closes only after the new one is live (break).
        assert!(apply_port_close(&mut mouths, peer(), "m1", 1));
        assert!(!mouths.contains_key(&(peer(), "m1".into())));
        assert!(mouths.contains_key(&(peer(), "m2".into())));
    }

    #[test]
    fn stale_epoch_mouth_open_and_close_are_ignored() {
        let mut mouths: HashMap<MouthKey, MouthEntry> = HashMap::new();
        apply_port_open(&mut mouths, peer(), &mouth("m1", "10.0.0.1:7002", 5), 100);
        // Stale-epoch re-open does not regress the coordinate.
        assert!(!apply_port_open(
            &mut mouths,
            peer(),
            &mouth("m1", "10.0.0.1:7001", 3),
            101
        ));
        assert_eq!(
            mouths.get(&(peer(), "m1".into())).unwrap().udp_addr,
            "10.0.0.1:7002"
        );
        // Stale-epoch close cannot retract a rotated mouth.
        assert!(!apply_port_close(&mut mouths, peer(), "m1", 4));
        assert!(mouths.contains_key(&(peer(), "m1".into())));
        // Current-or-newer-epoch close removes it.
        assert!(apply_port_close(&mut mouths, peer(), "m1", 5));
        assert!(!mouths.contains_key(&(peer(), "m1".into())));
    }

    #[test]
    fn soft_ttl_expired_mouth_is_pruned_on_next_open() {
        let mut mouths: HashMap<MouthKey, MouthEntry> = HashMap::new();
        apply_port_open(&mut mouths, peer(), &mouth("m1", "10.0.0.1:7001", 1), 100);
        // A later PortOpen for a different mouth, past the soft TTL, prunes m1.
        apply_port_open(
            &mut mouths,
            peer(),
            &mouth("m2", "10.0.0.1:7002", 1),
            100 + MOUTH_SOFT_TTL_SECS + 1,
        );
        assert!(!mouths.contains_key(&(peer(), "m1".into())));
        assert!(mouths.contains_key(&(peer(), "m2".into())));
    }
}
