//! In/out datagram queues for the UDP packet loop. Payload-opaque: the queue
//! never inspects datagram bodies.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::Instant;

use bytes::Bytes;

/// One opaque datagram queued for transmission to a destination endpoint.
#[derive(Clone, Debug)]
pub struct OutboundDatagram {
    pub destination: SocketAddr,
    pub payload: Bytes,
}

/// One opaque datagram received from the socket, with its source endpoint and
/// arrival timestamp preserved.
#[derive(Clone, Debug)]
pub struct InboundDatagram {
    pub source: SocketAddr,
    pub payload: Bytes,
    pub received_at: Instant,
}

/// Maximum number of datagrams the outbound queue holds before it back-pressures
/// instead of growing without bound.
pub const OUTBOUND_QUEUE_CAPACITY: usize = 1024;

/// Returned when the bounded outbound queue is at capacity. The caller decides
/// whether to drop, retry, or surface backpressure; the substrate never grows
/// the queue without bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("udp outbound queue is full ({capacity} datagrams)")]
pub struct QueueFull {
    pub capacity: usize,
}

/// Bounded FIFO pair. Outbound byte accounting feeds the path-stats
/// send-buffer projection without parsing payloads.
#[derive(Default)]
pub(crate) struct DatagramQueues {
    outbound: VecDeque<OutboundDatagram>,
    inbound: VecDeque<InboundDatagram>,
    outbound_bytes: usize,
}

impl DatagramQueues {
    pub(crate) fn enqueue_outbound(&mut self, dgram: OutboundDatagram) -> Result<(), QueueFull> {
        if self.outbound.len() >= OUTBOUND_QUEUE_CAPACITY {
            return Err(QueueFull {
                capacity: OUTBOUND_QUEUE_CAPACITY,
            });
        }
        self.outbound_bytes = self.outbound_bytes.saturating_add(dgram.payload.len());
        self.outbound.push_back(dgram);
        Ok(())
    }

    /// Take the whole outbound run at once for a batched send. Byte accounting
    /// resets because the queue is now empty; boundaries are preserved one
    /// `OutboundDatagram` per logical datagram.
    pub(crate) fn drain_outbound(&mut self) -> Vec<OutboundDatagram> {
        self.outbound_bytes = 0;
        self.outbound.drain(..).collect()
    }

    pub(crate) fn push_inbound(&mut self, dgram: InboundDatagram) {
        self.inbound.push_back(dgram);
    }

    pub(crate) fn drain_inbound(&mut self) -> Vec<InboundDatagram> {
        self.inbound.drain(..).collect()
    }

    pub(crate) fn outbound_len(&self) -> usize {
        self.outbound.len()
    }

    pub(crate) fn outbound_bytes(&self) -> usize {
        self.outbound_bytes
    }

    pub(crate) fn inbound_len(&self) -> usize {
        self.inbound.len()
    }
}
