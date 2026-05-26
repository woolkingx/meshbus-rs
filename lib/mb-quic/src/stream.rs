//! RFC 9000 §2-§3 stream model: identifier algebra, an ordered receive
//! reassembler, a send buffer, and the per-connection stream table.
//!
//! Flow-control credit lives in [`crate::flow_control`]; this module owns only
//! stream data buffering and lifecycle.

use std::collections::{BTreeMap, HashMap};

use crate::Side;

/// Low two bits of a stream ID (RFC 9000 §2.1).
const INITIATOR_BIT: u64 = 0x1;
const UNI_BIT: u64 = 0x2;

/// Most concurrently tracked streams before a peer-initiated new stream is
/// refused (defense against peer-driven implicit-create blow-up).
pub const MAX_CONCURRENT_STREAMS: usize = 256;

/// Stream-ID helpers (RFC 9000 §2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamId(pub u64);

impl StreamId {
    /// Side that opened this stream.
    pub fn initiator(self) -> Side {
        if self.0 & INITIATOR_BIT == 0 {
            Side::Client
        } else {
            Side::Server
        }
    }

    /// True for a bidirectional stream.
    pub fn is_bidi(self) -> bool {
        self.0 & UNI_BIT == 0
    }

    /// True if `side` opened this stream.
    pub fn is_locally_initiated(self, side: Side) -> bool {
        self.initiator() == side
    }

    /// The nth stream of the given kind for `side`.
    pub fn nth(side: Side, bidi: bool, index: u64) -> StreamId {
        let mut v = index << 2;
        if side == Side::Server {
            v |= INITIATOR_BIT;
        }
        if !bidi {
            v |= UNI_BIT;
        }
        StreamId(v)
    }
}

/// Ordered receive reassembler (RFC 9000 §2.2): absorbs out-of-order STREAM
/// data and yields a contiguous prefix.
#[derive(Default)]
pub struct RecvStream {
    chunks: BTreeMap<u64, Vec<u8>>,
    read_off: u64,
    final_size: Option<u64>,
    stopped: bool,
}

impl RecvStream {
    /// Absorb a STREAM data chunk at `offset`. Later duplicate/overlapping
    /// bytes are ignored; the contiguous prefix is what `read` returns.
    pub fn ingest(&mut self, offset: u64, data: &[u8], fin: bool) {
        if fin {
            self.final_size = Some(offset + data.len() as u64);
        }
        let end = offset + data.len() as u64;
        if end <= self.read_off || data.is_empty() {
            return;
        }
        let start = offset.max(self.read_off);
        let slice = &data[(start - offset) as usize..];
        self.chunks.entry(start).or_insert_with(|| slice.to_vec());
    }

    /// Pop the in-order prefix accumulated so far.
    pub fn read(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        while let Some((&off, _)) = self.chunks.iter().next() {
            if off > self.read_off {
                break;
            }
            let data = self.chunks.remove(&off).unwrap();
            let skip = (self.read_off - off) as usize;
            if skip < data.len() {
                out.extend_from_slice(&data[skip..]);
                self.read_off += (data.len() - skip) as u64;
            }
        }
        out
    }

    /// True once every byte through the peer's FIN has been read.
    pub fn is_finished(&self) -> bool {
        matches!(self.final_size, Some(fs) if self.read_off >= fs)
    }

    /// Mark that the application asked to stop reading (STOP_SENDING).
    pub fn stop(&mut self) {
        self.stopped = true;
    }

    /// Whether STOP_SENDING was requested.
    pub fn is_stopped(&self) -> bool {
        self.stopped
    }

    /// True when in-order bytes are buffered or an unconsumed FIN is pending.
    pub fn has_readable(&self) -> bool {
        if let Some((&off, _)) = self.chunks.iter().next() {
            if off <= self.read_off {
                return true;
            }
        }
        matches!(self.final_size, Some(fs) if self.read_off < fs)
    }
}

/// Send-side stream buffer (RFC 9000 §2.3/§3.1).
#[derive(Default)]
pub struct SendStream {
    queued: Vec<u8>,
    send_off: u64,
    fin: bool,
    fin_sent: bool,
}

impl SendStream {
    /// Append application bytes; `fin` finalises the stream.
    pub fn write(&mut self, data: &[u8], fin: bool) {
        self.queued.extend_from_slice(data);
        if fin {
            self.fin = true;
        }
    }

    /// True if there are bytes or a FIN still to put on the wire.
    pub fn has_pending(&self) -> bool {
        !self.queued.is_empty() || (self.fin && !self.fin_sent)
    }

    /// Take up to `max` bytes for one STREAM frame. Returns
    /// `(offset, data, fin)` or `None` when nothing is pending.
    pub fn take(&mut self, max: usize) -> Option<(u64, Vec<u8>, bool)> {
        if !self.has_pending() {
            return None;
        }
        let n = self.queued.len().min(max);
        let chunk: Vec<u8> = self.queued.drain(..n).collect();
        let off = self.send_off;
        self.send_off += n as u64;
        let fin = self.fin && self.queued.is_empty();
        if fin {
            self.fin_sent = true;
        }
        Some((off, chunk, fin))
    }
}

/// One open stream's send and receive halves.
#[derive(Default)]
pub struct Stream {
    /// Outbound buffer.
    pub send: SendStream,
    /// Inbound reassembler.
    pub recv: RecvStream,
}

/// Per-connection stream table (RFC 9000 §2.1 allocation, §4.6 limits).
pub struct StreamMap {
    side: Side,
    streams: HashMap<u64, Stream>,
    next_bidi: u64,
    next_uni: u64,
    peer_max_bidi: u64,
    peer_max_uni: u64,
}

impl StreamMap {
    /// New table for `side` with the peer's advertised stream limits.
    pub fn new(side: Side, peer_max_bidi: u64, peer_max_uni: u64) -> Self {
        Self {
            side,
            streams: HashMap::new(),
            next_bidi: 0,
            next_uni: 0,
            peer_max_bidi,
            peer_max_uni,
        }
    }

    /// Raise a peer stream limit (MAX_STREAMS); never decreases.
    pub fn set_peer_max(&mut self, bidi: bool, value: u64) {
        let slot = if bidi {
            &mut self.peer_max_bidi
        } else {
            &mut self.peer_max_uni
        };
        if value > *slot {
            *slot = value;
        }
    }

    /// Open the next locally initiated stream, or `None` if the peer's limit
    /// is exhausted.
    pub fn open(&mut self, bidi: bool) -> Option<StreamId> {
        let (next, max) = if bidi {
            (&mut self.next_bidi, self.peer_max_bidi)
        } else {
            (&mut self.next_uni, self.peer_max_uni)
        };
        if *next >= max {
            return None;
        }
        let idx = *next;
        *next += 1;
        let id = StreamId::nth(self.side, bidi, idx);
        self.streams.insert(id.0, Stream::default());
        Some(id)
    }

    /// Get or implicitly create a stream by ID (peer-initiated streams are
    /// created on first reference, RFC 9000 §3.2).
    pub fn entry(&mut self, id: u64) -> &mut Stream {
        self.streams.entry(id).or_default()
    }

    /// True when `id` is not yet tracked and the table is already at the
    /// concurrent-stream cap, so implicitly creating it would blow the bound.
    pub fn would_exceed_cap(&self, id: u64) -> bool {
        !self.streams.contains_key(&id) && self.streams.len() >= MAX_CONCURRENT_STREAMS
    }

    /// Borrow a stream if it exists.
    pub fn get(&self, id: u64) -> Option<&Stream> {
        self.streams.get(&id)
    }

    /// Number of currently tracked streams.
    pub fn len(&self) -> usize {
        self.streams.len()
    }

    /// True when no streams are tracked.
    pub fn is_empty(&self) -> bool {
        self.streams.is_empty()
    }

    /// IDs that currently have outbound data or a pending FIN.
    pub fn sendable(&self) -> Vec<u64> {
        let mut ids: Vec<u64> = self
            .streams
            .iter()
            .filter(|(_, s)| s.send.has_pending())
            .map(|(&id, _)| id)
            .collect();
        ids.sort_unstable();
        ids
    }

    /// IDs that currently have in-order inbound data or an unconsumed FIN.
    pub fn readable(&self) -> Vec<u64> {
        let mut ids: Vec<u64> = self
            .streams
            .iter()
            .filter(|(_, s)| s.recv.has_readable())
            .map(|(&id, _)| id)
            .collect();
        ids.sort_unstable();
        ids
    }
}

#[cfg(test)]
#[path = "stream_tests.rs"]
mod stream_tests;
