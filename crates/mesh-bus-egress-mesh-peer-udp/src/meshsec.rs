//! MeshSec egress sealing helpers and payload budgets.

use mb_proto_mesh::{
    MESHSEC_REPLAY_WINDOW_BITS, MeshSecOpenKey, MeshSecReplayCache, MeshSecSealContext,
};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_MESH_DATAGRAM_PAYLOAD_BYTES: usize = 65_000;
/// Upper bound on bincode MeshFrame::DatagramSend framing minus the payload
/// (enum tag + session_id string + Endpoint + seq). Conservative; sealed clear
/// = framing + payload must fit MESHSEC_MAX_CLEAR_LEN.
const MESH_DATAGRAM_FRAME_OVERHEAD: usize = 256;
const MESHSEC_STREAM_CHUNK_BYTES: usize = 832;
pub(crate) const STREAM_FLUSH_CHUNK_BATCH: usize = 64;

/// Advertised datagram payload budget when the configured peer carries MeshSec:
/// the sealed clear (encoded frame) must fit the 1024 padding bucket.
pub fn meshsec_max_payload_bytes() -> usize {
    mb_proto_mesh::meshsec::MESHSEC_MAX_CLEAR_LEN - MESH_DATAGRAM_FRAME_OVERHEAD
}

pub(crate) fn stream_chunk_bytes(seal: Option<&MeshSecEgress>) -> usize {
    if seal.is_some() {
        MESHSEC_STREAM_CHUNK_BYTES
    } else {
        MAX_MESH_DATAGRAM_PAYLOAD_BYTES
    }
}

pub(crate) fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Sender-side MeshSec state for one datagram session: the sealing context plus
/// a session-monotonic counter shared by every outbound frame.
#[derive(Clone)]
pub(crate) struct MeshSecEgress {
    pub(crate) ctx: MeshSecSealContext,
    pub(crate) counter: Arc<AtomicU64>,
}

impl MeshSecEgress {
    /// Reverse-direction open key so the egress can authenticate the peer's
    /// sealed `DatagramReturn` / `DatagramClose` replies.
    pub(crate) fn reply_recv(&self) -> MeshSecRecv {
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
pub(crate) struct MeshSecRecv {
    pub(crate) local_node_id: String,
    pub(crate) keys: Vec<MeshSecOpenKey>,
    pub(crate) replay: MeshSecReplayCache,
}
