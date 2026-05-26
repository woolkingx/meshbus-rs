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
