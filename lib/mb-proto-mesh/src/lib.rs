//! Pure Mesh Protocol wire codec. No I/O.

pub mod meshsec;
pub mod replay;

pub use meshsec::*;
pub use replay::MeshSecReplayCache;

use bytes::{Buf, Bytes, BytesMut};
use mb_endpoint::Endpoint;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MAGIC: u16 = 0x4d42;
pub const PROTOCOL_VERSION: u8 = 1;
const HEADER_LEN: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BindingKind {
    RawUdp,
    Quic,
    TcpReference,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowSemanticsWire {
    ByteStream,
    Datagram,
    Message,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReturnSemanticsWire {
    Direct,
    PacketDedup,
    SequenceReorder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CloseReasonWire {
    Normal,
    Unsupported,
    NoUsableExit,
    ProtocolError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamOpenRejectReason {
    ReliableStreamUnsupported,
    NoUsableExit,
    PolicyRejected,
    ProtocolError,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub node_id: String,
    pub binding: BindingKind,
    pub nonce: u64,
    pub spki_pin_sha256: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamOpen {
    pub session_id: String,
    pub open_token: u64,
    #[serde(with = "endpoint_serde")]
    pub target: Endpoint,
    pub route_group: Option<String>,
    pub flow_semantics: FlowSemanticsWire,
    pub return_semantics: ReturnSemanticsWire,
    pub source_node_id: String,
    pub path_trace: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatagramOpen {
    pub session_id: String,
    #[serde(with = "option_endpoint_serde")]
    pub fixed_target: Option<Endpoint>,
    pub max_datagram_bytes: u64,
}

/// L4 receiver mouth advertisement. Mirrors `receiver_mouth_v1`: it is a
/// delivery coordinate only and never carries session, route, or channel truth.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiverMouth {
    pub mouth_id: String,
    pub udp_addr: String,
    pub family_filter: Vec<String>,
    pub advertised_capacity: u32,
    pub epoch: u64,
}

/// Best-effort scheduling evidence for one sender-to-mouth relation. Mirrors
/// the handbook Control-Plane `LinkSample`: it reports observed delivery health
/// and is never route or registry truth. Receivers fold it into local
/// `LinkEvidence`; they must not treat it as a session, route, or channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkSample {
    pub source_node_id: String,
    pub mouth_id: String,
    pub epoch: u64,
    pub seq: u64,
    pub observed_at_ms: u64,
    pub rtt_us: u32,
    /// Observed loss ratio in per-mille (0..=1000); integer keeps the wire
    /// shape stable across endianness and serde backends.
    pub loss_permille: u16,
    pub goodput_bps: u64,
    pub queue_delay_us: u32,
    pub close_count: u32,
    pub saturated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MeshFrame {
    Hello(Hello),
    StreamOpen(StreamOpen),
    StreamOpenReject {
        session_id: String,
        open_token: u64,
        reason: StreamOpenRejectReason,
        close_reason: CloseReasonWire,
    },
    StreamData {
        session_id: String,
        seq: u64,
        #[serde(with = "bytes_serde")]
        payload: Bytes,
    },
    StreamShutdownWrite {
        session_id: String,
    },
    StreamClose {
        session_id: String,
        close_reason: CloseReasonWire,
    },
    DatagramOpen(DatagramOpen),
    DatagramSend {
        session_id: String,
        seq: u64,
        #[serde(with = "endpoint_serde")]
        target: Endpoint,
        #[serde(with = "bytes_serde")]
        payload: Bytes,
    },
    DatagramReturn {
        session_id: String,
        seq: u64,
        #[serde(with = "endpoint_serde")]
        source: Endpoint,
        #[serde(with = "bytes_serde")]
        payload: Bytes,
    },
    DatagramClose {
        session_id: String,
        close_reason: CloseReasonWire,
    },
    PortOpen(ReceiverMouth),
    PortClose {
        mouth_id: String,
        epoch: u64,
    },
    LinkSample(LinkSample),
    AckNack(AckNack),
    /// Positive L5 control acknowledgement for `StreamOpen`. This variant is
    /// intentionally appended to preserve existing bincode discriminants for
    /// all previously-defined mesh frames.
    StreamOpenAccepted {
        session_id: String,
        open_token: u64,
    },
}

impl MeshFrame {
    fn msg_type(&self) -> u8 {
        match self {
            MeshFrame::Hello(_) => 1,
            MeshFrame::StreamOpen(_) => 16,
            MeshFrame::StreamOpenReject { .. } => 17,
            MeshFrame::StreamData { .. } => 18,
            MeshFrame::StreamShutdownWrite { .. } => 19,
            MeshFrame::StreamClose { .. } => 20,
            MeshFrame::DatagramOpen(_) => 31,
            MeshFrame::DatagramSend { .. } => 32,
            MeshFrame::DatagramReturn { .. } => 33,
            MeshFrame::DatagramClose { .. } => 34,
            MeshFrame::PortOpen(_) => 48,
            MeshFrame::PortClose { .. } => 49,
            MeshFrame::LinkSample(_) => 50,
            MeshFrame::AckNack(_) => 51,
            MeshFrame::StreamOpenAccepted { .. } => 52,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Error)]
pub enum CodecError {
    #[error("incomplete frame")]
    Incomplete,
    #[error("bad magic: {0:#06x}")]
    BadMagic(u16),
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u8),
    #[error("encode failed: {0}")]
    Encode(String),
    #[error("decode failed: {0}")]
    Decode(String),
}

pub fn encode_frame(frame: &MeshFrame) -> Result<Vec<u8>, CodecError> {
    let payload = bincode::serialize(frame).map_err(|err| CodecError::Encode(err.to_string()))?;
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(&MAGIC.to_be_bytes());
    out.push(PROTOCOL_VERSION);
    out.push(frame.msg_type());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

pub fn decode_frame(buf: &mut BytesMut) -> Result<MeshFrame, CodecError> {
    if buf.len() < HEADER_LEN {
        return Err(CodecError::Incomplete);
    }

    let magic = u16::from_be_bytes([buf[0], buf[1]]);
    if magic != MAGIC {
        return Err(CodecError::BadMagic(magic));
    }

    let version = buf[2];
    if version != PROTOCOL_VERSION {
        return Err(CodecError::UnsupportedVersion(version));
    }

    let payload_len = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
    if buf.len() < HEADER_LEN + payload_len {
        return Err(CodecError::Incomplete);
    }

    let payload = buf[HEADER_LEN..HEADER_LEN + payload_len].to_vec();
    buf.advance(HEADER_LEN + payload_len);
    bincode::deserialize(&payload).map_err(|err| CodecError::Decode(err.to_string()))
}

/// Decode a `MeshFrame` from MeshSec clear SDU bytes. This is the inverse of
/// the inner `bincode::serialize` performed by `seal_mesh_frame`: the legacy
/// sealed wire carries the raw bincode frame with no `encode_frame` envelope,
/// so callers that already ran `open_bytes` decode it here instead of
/// `decode_frame`.
pub fn decode_mesh_frame_clear(clear: &[u8]) -> Result<MeshFrame, CodecError> {
    bincode::deserialize(clear).map_err(|err| CodecError::Decode(err.to_string()))
}

pub type EventId = String;
pub type FamilyId = String;
pub type DeliveryPolicyId = String;
pub type PackageId = String;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventSemantic {
    Stream,
    Datagram,
    Control,
    Observation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReliabilityClass {
    BestEffort,
    Reliable,
    Repairable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderingClass {
    Unordered,
    OrderedWithinFamily,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryMode {
    Steer,
    Stripe,
    Replicate,
    Repair,
    Probe,
}

impl DeliveryMode {
    /// Stable wire policy id stamped onto `MeshEvent.delivery_policy_id`. The
    /// id is delivery-coordinate metadata only; it never alters family id,
    /// seq, or semantic.
    pub fn policy_id(self) -> &'static str {
        match self {
            DeliveryMode::Steer => STEER_DELIVERY_POLICY_ID,
            DeliveryMode::Stripe => "stripe",
            DeliveryMode::Replicate => "replicate",
            DeliveryMode::Repair => "repair",
            DeliveryMode::Probe => "probe",
        }
    }

    /// Inverse of [`DeliveryMode::policy_id`]. Unknown ids fall back to
    /// `Steer` (the default, never-route-truth policy).
    pub fn from_policy_id(id: &str) -> DeliveryMode {
        match id {
            "stripe" => DeliveryMode::Stripe,
            "replicate" => DeliveryMode::Replicate,
            "repair" => DeliveryMode::Repair,
            "probe" => DeliveryMode::Probe,
            _ => DeliveryMode::Steer,
        }
    }
}

/// One-XOR-parity over a generation of equal-or-padded data chunks. The parity
/// is the byte-wise XOR of every chunk, zero-padded to the longest chunk. It
/// reconstructs exactly one lost chunk per generation and is observation-grade
/// repair data, never route truth.
pub fn xor_parity(chunks: &[&[u8]]) -> Vec<u8> {
    let width = chunks.iter().map(|c| c.len()).max().unwrap_or(0);
    let mut parity = vec![0u8; width];
    for chunk in chunks {
        for (p, b) in parity.iter_mut().zip(chunk.iter()) {
            *p ^= *b;
        }
    }
    parity
}

/// Recover the single missing chunk of a generation from the surviving chunks
/// and the parity. `present` holds every chunk slot; exactly one `None` slot
/// is the loss. Returns `None` when zero or more than one slot is missing.
pub fn reconstruct_missing(present: &[Option<&[u8]>], parity: &[u8]) -> Option<Vec<u8>> {
    let mut missing = None;
    for (idx, slot) in present.iter().enumerate() {
        if slot.is_none() {
            if missing.is_some() {
                return None;
            }
            missing = Some(idx);
        }
    }
    missing?;
    let mut out = parity.to_vec();
    for slot in present.iter().flatten() {
        if slot.len() > out.len() {
            out.resize(slot.len(), 0);
        }
        for (o, b) in out.iter_mut().zip(slot.iter()) {
            *o ^= *b;
        }
    }
    Some(out)
}

/// Wire envelope a mesh-peer UDP adapter speaks. `SecureUdpNative` carries
/// frame bytes inside a native `MeshEvent`/`DataPackage`; `MeshFrame` keeps the
/// legacy bincode `MeshFrame` path. Selector only — it does not change the
/// `MeshFrame` clear bytes that get wrapped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum NativeEventMode {
    #[default]
    SecureUdpNative,
    MeshFrame,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventPci {
    pub checksum: Option<String>,
    pub compression: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataPackage {
    pub package_id: PackageId,
    pub seq: u64,
    pub offset: u64,
    pub len: u32,
    pub fragment_id: u16,
    pub fragment_count: u16,
    #[serde(with = "bytes_serde")]
    pub payload: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshEvent {
    pub event_id: EventId,
    pub family_id: FamilyId,
    pub semantic: EventSemantic,
    pub reliability: ReliabilityClass,
    pub ordering: OrderingClass,
    pub delivery_policy_id: DeliveryPolicyId,
    pub path_epoch: u64,
    pub ttl: u8,
    pub pci: EventPci,
    pub package: Option<DataPackage>,
}

/// Inclusive sequence range of missing DataPackages within a family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeqRange {
    pub start: u64,
    pub end: u64,
}

/// L5 family feedback. Confirms or requests DataPackages, not transport
/// streams. Mirrors schema `ack_nack_v1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AckNack {
    pub family_id: FamilyId,
    pub cumulative_seq: u64,
    pub received_bitmap: String,
    pub missing_ranges: Vec<SeqRange>,
}

pub const EVENT_MSG_TYPE: u8 = 64;

pub fn encode_event(event: &MeshEvent) -> Result<Vec<u8>, CodecError> {
    let payload = bincode::serialize(event).map_err(|err| CodecError::Encode(err.to_string()))?;
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(&MAGIC.to_be_bytes());
    out.push(PROTOCOL_VERSION);
    out.push(EVENT_MSG_TYPE);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

pub fn decode_event(buf: &mut BytesMut) -> Result<MeshEvent, CodecError> {
    if buf.len() < HEADER_LEN {
        return Err(CodecError::Incomplete);
    }

    let magic = u16::from_be_bytes([buf[0], buf[1]]);
    if magic != MAGIC {
        return Err(CodecError::BadMagic(magic));
    }

    let version = buf[2];
    if version != PROTOCOL_VERSION {
        return Err(CodecError::UnsupportedVersion(version));
    }

    if buf[3] != EVENT_MSG_TYPE {
        return Err(CodecError::Decode(format!(
            "not a mesh event: msg_type {}",
            buf[3]
        )));
    }

    let payload_len = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
    if buf.len() < HEADER_LEN + payload_len {
        return Err(CodecError::Incomplete);
    }

    let payload = buf[HEADER_LEN..HEADER_LEN + payload_len].to_vec();
    buf.advance(HEADER_LEN + payload_len);
    bincode::deserialize(&payload).map_err(|err| CodecError::Decode(err.to_string()))
}

/// Delivery policy id stamped on native steer-path events in M4.
pub const STEER_DELIVERY_POLICY_ID: &str = "steer";

/// Canonical (reliability, ordering) for a native-mode wrapped frame, keyed by
/// semantic. `Control` bypasses the family reorder gate (Unordered); ordered
/// data families are `Reliable` + `OrderedWithinFamily`.
fn native_frame_classes(semantic: EventSemantic) -> (ReliabilityClass, OrderingClass) {
    match semantic {
        EventSemantic::Control | EventSemantic::Observation => {
            (ReliabilityClass::BestEffort, OrderingClass::Unordered)
        }
        EventSemantic::Stream | EventSemantic::Datagram => (
            ReliabilityClass::Reliable,
            OrderingClass::OrderedWithinFamily,
        ),
    }
}

/// Wrap already-encoded `MeshFrame` clear bytes as a single-package native
/// `MeshEvent`. Egress build and ingress parse must both go through this and
/// [`event_frame_payload`] so the two ends cannot drift.
pub fn wrap_frame_event(
    family_id: &str,
    seq: u64,
    semantic: EventSemantic,
    delivery_policy_id: &str,
    frame_clear: &[u8],
) -> MeshEvent {
    let (reliability, ordering) = native_frame_classes(semantic);
    let id = format!("{family_id}:{seq}");
    MeshEvent {
        event_id: id.clone(),
        family_id: family_id.to_string(),
        semantic,
        reliability,
        ordering,
        delivery_policy_id: delivery_policy_id.to_string(),
        path_epoch: 0,
        ttl: 64,
        pci: EventPci::default(),
        package: Some(DataPackage {
            package_id: id,
            seq,
            offset: 0,
            len: frame_clear.len() as u32,
            fragment_id: 0,
            fragment_count: 1,
            payload: Bytes::copy_from_slice(frame_clear),
        }),
    }
}

/// Borrow the wrapped `MeshFrame` clear bytes from a native event built by
/// [`wrap_frame_event`].
pub fn event_frame_payload(event: &MeshEvent) -> Option<&[u8]> {
    event.package.as_ref().map(|p| p.payload.as_ref())
}

/// Canonical `(family_id, seq, semantic)` a native-mode adapter stamps when it
/// wraps a `MeshFrame`. Session control (`DatagramOpen`/`Close`,
/// `StreamOpen`/reject/shutdown/close, `Hello`) is `Control` so the receiver
/// processes it ahead of the ordered family; data frames carry their own seq.
pub fn frame_event_meta(frame: &MeshFrame) -> (&str, u64, EventSemantic) {
    match frame {
        MeshFrame::DatagramOpen(d) => (&d.session_id, 0, EventSemantic::Control),
        MeshFrame::DatagramSend {
            session_id, seq, ..
        } => (session_id, *seq, EventSemantic::Datagram),
        MeshFrame::DatagramReturn {
            session_id, seq, ..
        } => (session_id, *seq, EventSemantic::Datagram),
        MeshFrame::DatagramClose { session_id, .. } => (session_id, 0, EventSemantic::Control),
        MeshFrame::StreamOpen(s) => (&s.session_id, 0, EventSemantic::Control),
        MeshFrame::StreamData {
            session_id, seq, ..
        } => (session_id, *seq, EventSemantic::Stream),
        MeshFrame::StreamOpenAccepted { session_id, .. }
        | MeshFrame::StreamOpenReject { session_id, .. }
        | MeshFrame::StreamShutdownWrite { session_id }
        | MeshFrame::StreamClose { session_id, .. } => (session_id, 0, EventSemantic::Control),
        MeshFrame::Hello(_) => ("", 0, EventSemantic::Control),
        MeshFrame::PortOpen(m) => (&m.mouth_id, 0, EventSemantic::Control),
        MeshFrame::PortClose { mouth_id, .. } => (mouth_id, 0, EventSemantic::Control),
        MeshFrame::LinkSample(s) => (&s.mouth_id, s.seq, EventSemantic::Observation),
        MeshFrame::AckNack(a) => (&a.family_id, 0, EventSemantic::Control),
    }
}

mod endpoint_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(endpoint: &Endpoint, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (endpoint.host(), endpoint.port()).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Endpoint, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (host, port) = <(String, u16)>::deserialize(deserializer)?;
        Endpoint::new(host, port).map_err(serde::de::Error::custom)
    }
}

mod option_endpoint_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(endpoint: &Option<Endpoint>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        endpoint
            .as_ref()
            .map(|ep| (ep.host(), ep.port()))
            .serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Endpoint>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let endpoint = <Option<(String, u16)>>::deserialize(deserializer)?;
        endpoint
            .map(|(host, port)| Endpoint::new(host, port).map_err(serde::de::Error::custom))
            .transpose()
    }
}

mod bytes_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Bytes, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        bytes.as_ref().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Bytes, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<u8>::deserialize(deserializer).map(Bytes::from)
    }
}
