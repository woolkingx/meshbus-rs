//! Linux splice(2) relay for TCP socket pairs.

use mesh_bus_core::{CloseReason, TcpSpliceDirection, TcpSpliceSession};
use std::io;
use std::net::{Shutdown, TcpStream as StdTcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use tokio::net::TcpStream;

const SPLICE_CHUNK_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SpliceStats {
    pub bytes_up: u64,
    pub bytes_down: u64,
}

#[cfg(target_os = "linux")]
pub async fn splice_tcp_streams(
    client: TcpStream,
    upstream: TcpSpliceSession,
) -> io::Result<SpliceStats> {
    let accounting = upstream.accounting();
    let client = client.into_std()?;
    let upstream = upstream.into_std();
    client.set_nonblocking(false)?;
    upstream.set_nonblocking(false)?;

    let up_src = client.try_clone()?;
    let up_dst = upstream.try_clone()?;
    let down_src = upstream;
    let down_dst = client;

    let up_accounting = accounting.clone();
    let down_accounting = accounting.clone();
    let up = tokio::task::spawn_blocking(move || {
        splice_direction(up_src, up_dst, TcpSpliceDirection::Up, up_accounting)
    });
    let down = tokio::task::spawn_blocking(move || {
        splice_direction(
            down_src,
            down_dst,
            TcpSpliceDirection::Down,
            down_accounting,
        )
    });

    let (up, down) = tokio::join!(up, down);
    let result = match (up, down) {
        (Ok(Ok(bytes_up)), Ok(Ok(bytes_down))) => Ok(SpliceStats {
            bytes_up,
            bytes_down,
        }),
        (Ok(Err(err)), _) | (_, Ok(Err(err))) => Err(err),
        (Err(err), _) | (_, Err(err)) => {
            Err(io::Error::other(format!("splice task failed: {err}")))
        }
    };

    if let Some(accounting) = accounting {
        accounting.close_once(CloseReason::UpstreamEof).await;
    }

    result
}

#[cfg(not(target_os = "linux"))]
pub async fn splice_tcp_streams(
    _client: TcpStream,
    _upstream: TcpSpliceSession,
) -> io::Result<SpliceStats> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "splice is only supported on Linux",
    ))
}

#[cfg(target_os = "linux")]
fn splice_direction(
    src: StdTcpStream,
    dst: StdTcpStream,
    direction: TcpSpliceDirection,
    accounting: Option<std::sync::Arc<dyn mesh_bus_core::TcpSpliceAccounting>>,
) -> io::Result<u64> {
    let pipe = Pipe::new()?;
    let mut total = 0u64;
    loop {
        let n = splice_fd(src.as_raw_fd(), pipe.write.as_raw_fd(), SPLICE_CHUNK_BYTES)?;
        if n == 0 {
            let _ = dst.shutdown(Shutdown::Write);
            return Ok(total);
        }
        let mut remaining = n;
        while remaining > 0 {
            let written = splice_fd(pipe.read.as_raw_fd(), dst.as_raw_fd(), remaining)?;
            if written == 0 {
                let _ = dst.shutdown(Shutdown::Write);
                return Ok(total);
            }
            remaining -= written;
        }
        total += n as u64;
        if let Some(accounting) = &accounting {
            accounting.add_bytes(direction, n as u64);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn splice_direction(
    _src: StdTcpStream,
    _dst: StdTcpStream,
    _direction: TcpSpliceDirection,
    _accounting: Option<std::sync::Arc<dyn mesh_bus_core::TcpSpliceAccounting>>,
) -> io::Result<u64> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "splice is only supported on Linux",
    ))
}

#[cfg(target_os = "linux")]
struct Pipe {
    read: OwnedFd,
    write: OwnedFd,
}

#[cfg(target_os = "linux")]
impl Pipe {
    fn new() -> io::Result<Self> {
        let mut fds = [0; 2];
        let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        // 256 KiB: best for single-flow (fits L2 cache), neutral for 8-conn.
        // Silently ignored on EPERM (unprivileged containers); falls back to 64 KiB default.
        let _ = unsafe { libc::fcntl(fds[1], libc::F_SETPIPE_SZ, 256 * 1024i32) };
        Ok(Self { read, write })
    }
}

#[cfg(target_os = "linux")]
fn splice_fd(src: RawFd, dst: RawFd, len: usize) -> io::Result<usize> {
    loop {
        let n = unsafe {
            libc::splice(
                src,
                std::ptr::null_mut(),
                dst,
                std::ptr::null_mut(),
                len,
                libc::SPLICE_F_MOVE,
            )
        };
        if n >= 0 {
            return Ok(n as usize);
        }
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(err);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn splices_bidirectional_tcp_streams() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = upstream.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            loop {
                let n = sock.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                sock.write_all(&buf[..n]).await.unwrap();
            }
        });

        let ingress = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ingress_addr = ingress.local_addr().unwrap();
        let relay = tokio::spawn(async move {
            let (client_side, _) = ingress.accept().await.unwrap();
            let upstream_side = TcpStream::connect(upstream_addr).await.unwrap();
            let splice = TcpSpliceSession::new(upstream_side.into_std().unwrap())
                .with_accounting(Arc::new(TestAccounting::default()));
            splice_tcp_streams(client_side, splice).await.unwrap()
        });

        let mut client = TcpStream::connect(ingress_addr).await.unwrap();
        client.write_all(b"splice-me").await.unwrap();
        client.shutdown().await.unwrap();
        let mut echoed = Vec::new();
        client.read_to_end(&mut echoed).await.unwrap();

        let stats = relay.await.unwrap();
        assert_eq!(echoed, b"splice-me");
        assert_eq!(stats.bytes_up, 9);
        assert_eq!(stats.bytes_down, 9);
    }

    #[tokio::test]
    async fn close_once_runs_when_splice_errors_or_exits_early() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            let (sock, _) = upstream.accept().await.unwrap();
            drop(sock);
        });

        let ingress = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ingress_addr = ingress.local_addr().unwrap();
        let accounting = Arc::new(TestAccounting::default());
        let relay_accounting = accounting.clone();
        let relay = tokio::spawn(async move {
            let (client_side, _) = ingress.accept().await.unwrap();
            let upstream_side = TcpStream::connect(upstream_addr).await.unwrap();
            let splice = TcpSpliceSession::new(upstream_side.into_std().unwrap())
                .with_accounting(relay_accounting);
            let _ = splice_tcp_streams(client_side, splice).await;
        });

        let mut client = TcpStream::connect(ingress_addr).await.unwrap();
        let _ = client.write_all(b"force-close").await;
        let _ = client.shutdown().await;
        relay.await.unwrap();

        assert_eq!(accounting.closes.load(Ordering::Relaxed), 1);
    }

    #[derive(Default)]
    struct TestAccounting {
        up: AtomicU64,
        down: AtomicU64,
        closes: AtomicU64,
    }

    #[async_trait::async_trait]
    impl mesh_bus_core::TcpSpliceAccounting for TestAccounting {
        fn add_bytes(&self, direction: TcpSpliceDirection, bytes: u64) {
            match direction {
                TcpSpliceDirection::Up => self.up.fetch_add(bytes, Ordering::Relaxed),
                TcpSpliceDirection::Down => self.down.fetch_add(bytes, Ordering::Relaxed),
            };
        }

        async fn close_once(&self, _reason: CloseReason) {
            self.closes.fetch_add(1, Ordering::Relaxed);
        }
    }
}
