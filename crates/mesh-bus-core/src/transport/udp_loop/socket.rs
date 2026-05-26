//! Thin async UDP endpoint. Owns one socket and performs datagram I/O.
//!
//! On Linux the send path first tries a data-shaped GSO plan for a homogeneous
//! same-destination prefix, then falls back to `sendmmsg`; the receive path uses
//! `recvmmsg`. Elsewhere it loops single `send_to`/`try_recv_from`. Payload bytes
//! stay opaque and one queue entry remains one logical datagram.
//!
//! The socket is held behind `Arc` so a send task and a receive task can drive
//! it concurrently (tokio `UdpSocket` tracks read and write readiness
//! independently). Methods take `&self`.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};

use tokio::net::UdpSocket;

use super::pmtu::CONSERVATIVE_PMTU;
use super::queue::OutboundDatagram;

/// Offload capability snapshot. `pmtu` is resolved once because the
/// conservative guard is a pure-software clamp that applies on every platform.
/// `gso_segment_size` is dynamic: it is `Some(size)` only after a real
/// per-message UDP_SEGMENT send succeeds, and returns to `None` after a GSO
/// fallback.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct OffloadCaps {
    pub gso_segment_size: Option<u16>,
    pub pmtu: Option<u16>,
}

/// Largest UDP payload the loop will accept off the wire in one datagram.
/// Linux receives through `batch_linux` (own buffer sizing), so this is only
/// the single-recv fallback's buffer.
#[cfg(not(target_os = "linux"))]
const MAX_UDP_DATAGRAM_BYTES: usize = 65_535;

/// Whether this build compiled the `sendmmsg`/`recvmmsg` batch path.
#[cfg(target_os = "linux")]
const BATCH_SUPPORTED: bool = true;
#[cfg(not(target_os = "linux"))]
const BATCH_SUPPORTED: bool = false;

/// Snapshot of batch-I/O instrumentation. Separate from `PathStats`: this
/// reports syscall/datagram accounting and platform support, not path quality.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BatchIoStats {
    pub send_syscalls: u64,
    pub send_datagrams: u64,
    pub recv_syscalls: u64,
    pub recv_datagrams: u64,
    pub gso_send_syscalls: u64,
    pub gso_send_datagrams: u64,
    pub gso_fallbacks: u64,
    pub batch_send_supported: bool,
    pub batch_recv_supported: bool,
}

#[derive(Default)]
struct BatchCounters {
    send_syscalls: AtomicU64,
    send_datagrams: AtomicU64,
    recv_syscalls: AtomicU64,
    recv_datagrams: AtomicU64,
    gso_send_syscalls: AtomicU64,
    gso_send_datagrams: AtomicU64,
    gso_fallbacks: AtomicU64,
    send_errors: AtomicU64,
}

pub(crate) struct UdpEndpoint {
    socket: Arc<UdpSocket>,
    counters: BatchCounters,
    offload: OffloadCaps,
    gso_disabled: AtomicBool,
    last_gso_segment_size: AtomicU16,
    #[cfg(target_os = "linux")]
    recv_scratch: Mutex<super::batch_linux::RecvBatchScratch>,
}

impl UdpEndpoint {
    pub(crate) async fn bind(addr: SocketAddr) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        let offload = Self::apply_offload(&socket);
        Ok(Self {
            socket: Arc::new(socket),
            counters: BatchCounters::default(),
            offload,
            gso_disabled: AtomicBool::new(false),
            last_gso_segment_size: AtomicU16::new(0),
            #[cfg(target_os = "linux")]
            recv_scratch: Mutex::new(super::batch_linux::RecvBatchScratch::new()),
        })
    }

    /// Resolve offload capabilities once at bind. The PMTU guard is a software
    /// clamp so it is always reported; GSO is Linux-only and best effort.
    #[cfg(target_os = "linux")]
    fn apply_offload(socket: &UdpSocket) -> OffloadCaps {
        use std::os::unix::io::AsRawFd;
        let fd = socket.as_raw_fd();
        super::gso_gro_linux::clear_socket_gso(fd);
        super::gso_gro_linux::probe_gro(fd);
        super::pmtu::enable_pmtu_probe(fd);
        OffloadCaps {
            gso_segment_size: None,
            pmtu: Some(CONSERVATIVE_PMTU),
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn apply_offload(_socket: &UdpSocket) -> OffloadCaps {
        OffloadCaps {
            gso_segment_size: None,
            pmtu: Some(CONSERVATIVE_PMTU),
        }
    }

    pub(crate) fn offload_caps(&self) -> OffloadCaps {
        OffloadCaps {
            gso_segment_size: self.current_gso_segment_size(),
            pmtu: self.offload.pmtu,
        }
    }

    pub(crate) fn send_errors(&self) -> u64 {
        self.counters.send_errors.load(Ordering::Relaxed)
    }

    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub(crate) fn batch_io_stats(&self) -> BatchIoStats {
        BatchIoStats {
            send_syscalls: self.counters.send_syscalls.load(Ordering::Relaxed),
            send_datagrams: self.counters.send_datagrams.load(Ordering::Relaxed),
            recv_syscalls: self.counters.recv_syscalls.load(Ordering::Relaxed),
            recv_datagrams: self.counters.recv_datagrams.load(Ordering::Relaxed),
            gso_send_syscalls: self.counters.gso_send_syscalls.load(Ordering::Relaxed),
            gso_send_datagrams: self.counters.gso_send_datagrams.load(Ordering::Relaxed),
            gso_fallbacks: self.counters.gso_fallbacks.load(Ordering::Relaxed),
            batch_send_supported: BATCH_SUPPORTED,
            batch_recv_supported: BATCH_SUPPORTED,
        }
    }

    fn current_gso_segment_size(&self) -> Option<u16> {
        match self.last_gso_segment_size.load(Ordering::Relaxed) {
            0 => None,
            size => Some(size),
        }
    }

    /// Send a whole outbound run. One logical datagram per batch entry; the
    /// destination endpoint of each entry is preserved. Returns the count the
    /// kernel accepted (always the full batch on success).
    #[cfg(target_os = "linux")]
    pub(crate) async fn send_batch(&self, batch: &[OutboundDatagram]) -> io::Result<usize> {
        use std::os::unix::io::AsRawFd;
        use tokio::io::Interest;

        let mut sent = 0usize;
        while sent < batch.len() {
            self.socket.writable().await?;
            let remaining = &batch[sent..];
            if !self.gso_disabled.load(Ordering::Relaxed) {
                match self.socket.try_io(Interest::WRITABLE, || {
                    super::batch_linux::sendmsg_gso(self.socket.as_raw_fd(), remaining)
                }) {
                    Ok(Some(plan)) => {
                        self.counters.send_syscalls.fetch_add(1, Ordering::Relaxed);
                        self.counters
                            .send_datagrams
                            .fetch_add(plan.segments as u64, Ordering::Relaxed);
                        self.counters
                            .gso_send_syscalls
                            .fetch_add(1, Ordering::Relaxed);
                        self.counters
                            .gso_send_datagrams
                            .fetch_add(plan.segments as u64, Ordering::Relaxed);
                        self.last_gso_segment_size
                            .store(plan.segment_size, Ordering::Relaxed);
                        sent += plan.segments;
                        continue;
                    }
                    Ok(None) => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(e) if is_gso_fallback_error(&e) => {
                        self.counters.gso_fallbacks.fetch_add(1, Ordering::Relaxed);
                        self.gso_disabled.store(true, Ordering::Relaxed);
                        self.last_gso_segment_size.store(0, Ordering::Relaxed);
                    }
                    Err(e) => {
                        self.counters.send_errors.fetch_add(1, Ordering::Relaxed);
                        return Err(e);
                    }
                }
            }
            match self.socket.try_io(Interest::WRITABLE, || {
                super::batch_linux::sendmmsg(self.socket.as_raw_fd(), remaining)
            }) {
                Ok(0) => break,
                Ok(n) => {
                    self.counters.send_syscalls.fetch_add(1, Ordering::Relaxed);
                    self.counters
                        .send_datagrams
                        .fetch_add(n as u64, Ordering::Relaxed);
                    sent += n;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => {
                    self.counters.send_errors.fetch_add(1, Ordering::Relaxed);
                    return Err(e);
                }
            }
        }
        Ok(sent)
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) async fn send_batch(&self, batch: &[OutboundDatagram]) -> io::Result<usize> {
        let mut sent = 0usize;
        for dgram in batch {
            if let Err(e) = self.socket.send_to(&dgram.payload, dgram.destination).await {
                self.counters.send_errors.fetch_add(1, Ordering::Relaxed);
                return Err(e);
            }
            self.counters.send_syscalls.fetch_add(1, Ordering::Relaxed);
            self.counters.send_datagrams.fetch_add(1, Ordering::Relaxed);
            sent += 1;
        }
        Ok(sent)
    }

    /// Await readability, then drain every datagram currently buffered on the
    /// socket. One vector entry per logical datagram; boundaries are kept.
    #[cfg(target_os = "linux")]
    pub(crate) async fn recv_ready(&self) -> io::Result<Vec<(SocketAddr, Vec<u8>)>> {
        use std::os::unix::io::AsRawFd;
        use tokio::io::Interest;

        self.socket.readable().await?;
        let mut out = Vec::new();
        loop {
            match self.socket.try_io(Interest::READABLE, || {
                let mut scratch = self.recv_scratch.lock().expect("udp recv scratch mutex");
                super::batch_linux::recvmmsg(self.socket.as_raw_fd(), &mut scratch)
            }) {
                Ok(batch) => {
                    self.counters.recv_syscalls.fetch_add(1, Ordering::Relaxed);
                    self.counters
                        .recv_datagrams
                        .fetch_add(batch.len() as u64, Ordering::Relaxed);
                    let full = batch.len() == super::batch_linux::MAX_MMSG;
                    out.extend(batch);
                    if !full {
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) async fn recv_ready(&self) -> io::Result<Vec<(SocketAddr, Vec<u8>)>> {
        self.socket.readable().await?;
        let mut buf = vec![0u8; MAX_UDP_DATAGRAM_BYTES];
        let mut out = Vec::new();
        loop {
            match self.socket.try_recv_from(&mut buf) {
                Ok((n, src)) => {
                    self.counters.recv_syscalls.fetch_add(1, Ordering::Relaxed);
                    self.counters.recv_datagrams.fetch_add(1, Ordering::Relaxed);
                    out.push((src, buf[..n].to_vec()));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }
}

#[cfg(target_os = "linux")]
fn is_gso_fallback_error(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::EINVAL) | Some(libc::EIO) | Some(libc::EMSGSIZE)
    )
}
