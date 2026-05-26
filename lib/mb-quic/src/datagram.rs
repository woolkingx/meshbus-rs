//! RFC 9221 unreliable DATAGRAM frames.
//!
//! Datagrams are best-effort: they are subject to congestion control and flow
//! is bounded by a fixed-size local queue, but a lost DATAGRAM frame is never
//! retransmitted. This module owns only the send/receive queues; framing lives
//! in [`crate::frame`].

use std::collections::VecDeque;

/// Best-effort datagram send/receive queues (RFC 9221 §5).
pub struct DatagramQueue {
    outgoing: VecDeque<Vec<u8>>,
    incoming: VecDeque<Vec<u8>>,
    max_queued: usize,
    max_recv: usize,
}

impl Default for DatagramQueue {
    fn default() -> Self {
        Self::new(64)
    }
}

impl DatagramQueue {
    /// New queue holding at most `depth` datagrams per direction.
    pub fn new(depth: usize) -> Self {
        Self {
            outgoing: VecDeque::new(),
            incoming: VecDeque::new(),
            max_queued: depth,
            max_recv: depth,
        }
    }

    /// Queue an application datagram for transmission. Returns `false` (and
    /// drops the datagram) when the send queue is full — best-effort, no
    /// backpressure (RFC 9221 §5).
    pub fn queue_outgoing(&mut self, data: Vec<u8>) -> bool {
        if self.outgoing.len() >= self.max_queued {
            return false;
        }
        self.outgoing.push_back(data);
        true
    }

    /// True if a DATAGRAM frame is waiting to go on the wire.
    pub fn has_outgoing(&self) -> bool {
        !self.outgoing.is_empty()
    }

    /// Pop the next datagram that fits in `max_len` bytes. Datagrams larger
    /// than any frame budget are dropped rather than fragmented (RFC 9221
    /// forbids fragmenting a DATAGRAM frame).
    pub fn take_outgoing(&mut self, max_len: usize) -> Option<Vec<u8>> {
        while let Some(front) = self.outgoing.front() {
            if front.len() <= max_len {
                return self.outgoing.pop_front();
            }
            self.outgoing.pop_front();
        }
        None
    }

    /// Absorb a received DATAGRAM payload. The oldest is evicted when the
    /// receive queue is full (best-effort delivery).
    pub fn ingest(&mut self, data: Vec<u8>) {
        if self.incoming.len() >= self.max_recv {
            self.incoming.pop_front();
        }
        self.incoming.push_back(data);
    }

    /// Pop the next received datagram in arrival order.
    pub fn recv(&mut self) -> Option<Vec<u8>> {
        self.incoming.pop_front()
    }
}

#[cfg(test)]
#[path = "datagram_tests.rs"]
mod datagram_tests;
