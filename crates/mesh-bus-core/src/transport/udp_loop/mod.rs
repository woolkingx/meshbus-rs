//! L4 UDP delivery substrate.
//!
//! `UdpPacketLoop` owns one tokio `UdpSocket`, an outbound and an inbound
//! datagram queue, packet timestamps, an optional fixed peer endpoint, and the
//! path-stats projection. Payload bytes are opaque: this module never parses,
//! encodes, or decodes any application wire structure. MeshFrame encode/decode
//! stays in the peer crates.
//!
//! `flush` drains the whole outbound run once under a short queue-mutex hold
//! and hands it to the endpoint, which selects the L4 send plan: per-message
//! UDP GSO for legal homogeneous prefixes, `sendmmsg` for normal Linux batches,
//! and per-datagram send elsewhere. `poll_recv` drains with `recvmmsg` on Linux.
//! One queue entry always maps to one logical datagram; GSO only changes syscall
//! shape, not protocol ownership or receive boundaries.
//!
//! Methods take `&self` with interior mutability so the loop can be shared
//! across tasks via `Arc` (e.g. a receive loop and a response pump). The
//! internal locks are `std::sync::Mutex` held only for queue/stat bookkeeping
//! and never across socket await points.

#[cfg(target_os = "linux")]
mod batch_linux;
#[cfg(target_os = "linux")]
mod gso_gro_linux;
pub mod pacing;
pub mod pmtu;
mod queue;
mod socket;

use std::io;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;

use crate::transport::path_stats::PathStats;

pub use queue::{InboundDatagram, OUTBOUND_QUEUE_CAPACITY, OutboundDatagram, QueueFull};
pub use socket::BatchIoStats;

use pacing::Pacer;
use pmtu::CONSERVATIVE_PMTU;
use queue::DatagramQueues;
use socket::UdpEndpoint;

/// Outcome of one `flush`: how many datagrams left the socket and how many the
/// conservative PMTU guard dropped before send. `sent == 0` with a nonzero
/// `pmtu_dropped` means the caller's datagram never went out.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FlushOutcome {
    pub sent: usize,
    pub pmtu_dropped: usize,
}

pub struct UdpPacketLoop {
    endpoint: UdpEndpoint,
    queues: Mutex<DatagramQueues>,
    peer: Option<SocketAddr>,
    pacer: Pacer,
    stats: Mutex<PathStats>,
}

impl UdpPacketLoop {
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        let endpoint = UdpEndpoint::bind(addr).await?;
        let caps = endpoint.offload_caps();
        let stats = PathStats {
            gso_segment_size: caps.gso_segment_size,
            pmtu: caps.pmtu,
            ..Default::default()
        };
        Ok(Self {
            endpoint,
            queues: Mutex::new(DatagramQueues::default()),
            peer: None,
            pacer: Pacer::new(0),
            stats: Mutex::new(stats),
        })
    }

    /// Pin a fixed adjacent peer endpoint. This is path evidence only; it is
    /// never route truth or session truth.
    pub fn with_peer(mut self, peer: SocketAddr) -> Self {
        self.peer = Some(peer);
        self
    }

    /// Set the software release pacing rate in bytes per second. Rate `0`
    /// (the default) is unpaced and adds zero delay.
    pub fn with_pacing(mut self, rate_bytes_per_sec: u64) -> Self {
        self.pacer = Pacer::new(rate_bytes_per_sec);
        self
    }

    pub fn peer(&self) -> Option<SocketAddr> {
        self.peer
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    /// Queue one datagram for the next `flush`, dropping it (and counting the
    /// drop in `PathStats.queue_full_drops`) if the bounded queue is full. Use
    /// `try_enqueue` when the caller needs to observe the backpressure.
    pub fn enqueue(&self, datagram: OutboundDatagram) {
        let _ = self.try_enqueue(datagram);
    }

    /// Queue one datagram for the next `flush`, or return a typed `QueueFull`
    /// when the bounded outbound queue is at capacity. A refusal is also folded
    /// into `PathStats.queue_full_drops` so backpressure stays observable.
    pub fn try_enqueue(&self, datagram: OutboundDatagram) -> Result<(), QueueFull> {
        let result = self
            .queues
            .lock()
            .expect("udp loop queue mutex")
            .enqueue_outbound(datagram);
        if result.is_err() {
            let mut s = self.stats.lock().expect("udp loop stats mutex");
            s.queue_full_drops = s.queue_full_drops.saturating_add(1);
        }
        self.refresh_send_buf_stats();
        result
    }

    pub fn pending_outbound(&self) -> usize {
        self.queues
            .lock()
            .expect("udp loop queue mutex")
            .outbound_len()
    }

    pub fn pending_inbound(&self) -> usize {
        self.queues
            .lock()
            .expect("udp loop queue mutex")
            .inbound_len()
    }

    /// Send every queued outbound datagram. The whole run is drained under one
    /// short queue-mutex hold (never across the socket await), then handed to
    /// the endpoint which selects a legal L4 send plan (GSO super-buffer,
    /// `sendmmsg`, or per-datagram fallback). Each batch entry stays one
    /// logical datagram. Returns how many datagrams were sent and how many the
    /// PMTU guard dropped, so the caller can surface an oversize drop instead
    /// of mistaking it for success.
    pub async fn flush(&self) -> io::Result<FlushOutcome> {
        let mut batch = self
            .queues
            .lock()
            .expect("udp loop queue mutex")
            .drain_outbound();
        if batch.is_empty() {
            return Ok(FlushOutcome::default());
        }
        // Conservative PMTU guard: a datagram past the floor would be
        // fragmented or rejected by the kernel, breaking the 1:1 contract — so
        // drop it rather than corrupt the run.
        let before = batch.len();
        batch.retain(|d| d.payload.len() <= CONSERVATIVE_PMTU as usize);
        let pmtu_dropped = before - batch.len();
        if pmtu_dropped > 0 {
            tracing::warn!(
                target: "mesh_bus.udp_loop",
                pmtu = CONSERVATIVE_PMTU,
                pmtu_dropped,
                "udp_datagram_dropped_pmtu"
            );
        }
        if batch.is_empty() {
            self.record_release(0, pmtu_dropped as u32);
            return Ok(FlushOutcome {
                sent: 0,
                pmtu_dropped,
            });
        }
        let bytes: usize = batch.iter().map(|d| d.payload.len()).sum();
        let delay = self.pacer.delay_for(bytes);
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        let sent = self.endpoint.send_batch(&batch).await?;
        self.record_release(
            delay.as_micros().min(u32::MAX as u128) as u32,
            pmtu_dropped as u32,
        );
        self.refresh_send_buf_stats();
        self.sample_now();
        Ok(FlushOutcome { sent, pmtu_dropped })
    }

    /// Await socket readability, then move every currently available datagram
    /// into the inbound queue. Returns the count received.
    pub async fn poll_recv(&self) -> io::Result<usize> {
        let datagrams = self.endpoint.recv_ready().await?;
        let count = datagrams.len();
        if count > 0 {
            let now = Instant::now();
            {
                let mut q = self.queues.lock().expect("udp loop queue mutex");
                for (src, bytes) in datagrams {
                    q.push_inbound(InboundDatagram {
                        source: src,
                        payload: Bytes::from(bytes),
                        received_at: now,
                    });
                }
            }
            self.stats
                .lock()
                .expect("udp loop stats mutex")
                .recv_batch_size = Some(count.min(u32::MAX as usize) as u32);
            self.sample_now();
        }
        Ok(count)
    }

    pub fn drain_inbound(&self) -> Vec<InboundDatagram> {
        self.queues
            .lock()
            .expect("udp loop queue mutex")
            .drain_inbound()
    }

    pub fn path_stats(&self) -> PathStats {
        self.stats.lock().expect("udp loop stats mutex").clone()
    }

    /// Batch-I/O instrumentation snapshot: syscall/datagram accounting and
    /// whether this build compiled the `sendmmsg`/`recvmmsg` path. Distinct
    /// from `path_stats`, which reports path quality.
    pub fn batch_io_stats(&self) -> BatchIoStats {
        self.endpoint.batch_io_stats()
    }

    fn refresh_send_buf_stats(&self) {
        let used = {
            let q = self.queues.lock().expect("udp loop queue mutex");
            q.outbound_bytes().min(u32::MAX as usize) as u32
        };
        self.stats
            .lock()
            .expect("udp loop stats mutex")
            .send_buf_used_bytes = Some(used);
    }

    /// Fold one release outcome into PathStats: the pacing delay just applied,
    /// the cumulative drop count, and the endpoint's cumulative send errors.
    fn record_release(&self, pacing_delay_us: u32, dropped: u32) {
        let send_errors = self.endpoint.send_errors().min(u32::MAX as u64) as u32;
        let caps = self.endpoint.offload_caps();
        let mut s = self.stats.lock().expect("udp loop stats mutex");
        s.pacing_delay_us = Some(pacing_delay_us);
        s.gso_segment_size = caps.gso_segment_size;
        s.pmtu = caps.pmtu;
        s.drops = s.drops.saturating_add(dropped);
        s.send_errors = send_errors;
    }

    fn sample_now(&self) {
        self.stats
            .lock()
            .expect("udp loop stats mutex")
            .sampled_at_ms = now_ms();
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
