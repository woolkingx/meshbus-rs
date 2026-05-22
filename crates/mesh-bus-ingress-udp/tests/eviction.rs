//! Eviction cleanup: when the per-peer session map is full, the evicted
//! datagram session must be closed and its response pump must stop. The
//! recording egress signals send-half `close()` and recv-half `Drop` by
//! session ordinal so the test can prove both happened for the evicted entry.

use async_trait::async_trait;
use bytes::Bytes;
use mb_endpoint::Endpoint;
use mesh_bus_core::{
    BusBuilder, BusSessionInfo, BusSessionRequest, Capabilities, DatagramEgress, DatagramRecvHalf,
    DatagramSendHalf, DatagramSession, DisconnectReason, ExitId, ExitResult, IngressPlugin,
    RankContext, ScheduleDecision, SchedulerPlugin, SendError,
};
use mesh_bus_ingress_udp::UdpIngress;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

struct First;
impl SchedulerPlugin for First {
    fn schedule(&self, c: &[ExitId], _ctx: &RankContext) -> ScheduleDecision {
        ScheduleDecision::ordered((0..c.len()).collect())
    }
    fn feedback(&self, _r: &ExitResult, _payload_bytes: u64, _at_ms: u64) {}
}

struct RecordingEgress {
    id: ExitId,
    caps: Capabilities,
    next_ordinal: Arc<AtomicUsize>,
    accepted_tx: mpsc::UnboundedSender<usize>,
    close_tx: mpsc::UnboundedSender<usize>,
    drop_tx: mpsc::UnboundedSender<usize>,
}

impl RecordingEgress {
    fn new(
        accepted_tx: mpsc::UnboundedSender<usize>,
        close_tx: mpsc::UnboundedSender<usize>,
        drop_tx: mpsc::UnboundedSender<usize>,
    ) -> Self {
        Self {
            id: ExitId("recording".into()),
            caps: Capabilities {
                protocol: "udp".into(),
                supports_stream: false,
                supports_datagram: true,
                max_payload_bytes: Some(65_507),
                groups: Vec::new(),
            },
            next_ordinal: Arc::new(AtomicUsize::new(0)),
            accepted_tx,
            close_tx,
            drop_tx,
        }
    }
}

#[async_trait]
impl DatagramEgress for RecordingEgress {
    fn id(&self) -> &ExitId {
        &self.id
    }
    fn capabilities(&self) -> &Capabilities {
        &self.caps
    }
    fn max_payload_bytes(&self) -> usize {
        65_507
    }
    async fn open_datagram(
        &self,
        _request: &BusSessionRequest,
        info: BusSessionInfo,
    ) -> Result<Box<dyn DatagramSession>, DisconnectReason> {
        let ordinal = self.next_ordinal.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(RecordingSession {
            info,
            ordinal,
            accepted_tx: self.accepted_tx.clone(),
            close_tx: self.close_tx.clone(),
            drop_tx: self.drop_tx.clone(),
        }))
    }
}

struct RecordingSession {
    info: BusSessionInfo,
    ordinal: usize,
    accepted_tx: mpsc::UnboundedSender<usize>,
    close_tx: mpsc::UnboundedSender<usize>,
    drop_tx: mpsc::UnboundedSender<usize>,
}

#[async_trait]
impl DatagramSession for RecordingSession {
    async fn send_to(&mut self, _target: Endpoint, _payload: Bytes) -> Result<(), SendError> {
        let _ = self.accepted_tx.send(self.ordinal);
        Ok(())
    }
    async fn recv_from(&mut self) -> Option<(Endpoint, Bytes)> {
        std::future::pending().await
    }
    fn info(&self) -> &BusSessionInfo {
        &self.info
    }
    fn max_payload_bytes(&self) -> usize {
        65_507
    }
    async fn close(&mut self) {
        let _ = self.close_tx.send(self.ordinal);
    }
    fn split(self: Box<Self>) -> (Box<dyn DatagramSendHalf>, Box<dyn DatagramRecvHalf>) {
        (
            Box::new(RecordingSendHalf {
                ordinal: self.ordinal,
                accepted_tx: self.accepted_tx.clone(),
                close_tx: self.close_tx.clone(),
            }),
            Box::new(RecordingRecvHalf {
                ordinal: self.ordinal,
                drop_tx: self.drop_tx.clone(),
            }),
        )
    }
}

struct RecordingSendHalf {
    ordinal: usize,
    accepted_tx: mpsc::UnboundedSender<usize>,
    close_tx: mpsc::UnboundedSender<usize>,
}

#[async_trait]
impl DatagramSendHalf for RecordingSendHalf {
    async fn send_to(&mut self, _target: Endpoint, _payload: Bytes) -> Result<(), SendError> {
        let _ = self.accepted_tx.send(self.ordinal);
        Ok(())
    }
    async fn close(&mut self) {
        let _ = self.close_tx.send(self.ordinal);
    }
}

struct RecordingRecvHalf {
    ordinal: usize,
    drop_tx: mpsc::UnboundedSender<usize>,
}

#[async_trait]
impl DatagramRecvHalf for RecordingRecvHalf {
    async fn recv_from(&mut self) -> Option<(Endpoint, Bytes)> {
        std::future::pending().await
    }
    fn last_error(&self) -> Option<&DisconnectReason> {
        None
    }
}

impl Drop for RecordingRecvHalf {
    fn drop(&mut self) {
        let _ = self.drop_tx.send(self.ordinal);
    }
}

/// With a one-session cap, the first peer's session is evicted when the second
/// peer arrives. The evicted session must be closed (send-half `close()`) and
/// its response pump must stop (recv-half `Drop`), both for ordinal 0.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn eviction_closes_udp_peer_session_and_stops_pump() {
    let (accepted_tx, mut accepted_rx) = mpsc::unbounded_channel::<usize>();
    let (close_tx, mut close_rx) = mpsc::unbounded_channel::<usize>();
    let (drop_tx, mut drop_rx) = mpsc::unbounded_channel::<usize>();

    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_datagram_egress(Box::new(RecordingEgress::new(
            accepted_tx,
            close_tx,
            drop_tx,
        )))
        .build()
        .await;
    let port = bus.port();
    let _bh = bus.spawn();

    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind ingress");
    let bind_port = sock.local_addr().expect("ingress addr").port();
    let target = Endpoint::new("127.0.0.1", 9999).expect("endpoint");
    let ingress = UdpIngress::new(sock, target).with_max_peer_sessions(1);
    tokio::spawn(async move {
        let _ = Box::new(ingress).run(port).await;
    });

    let addr = format!("127.0.0.1:{bind_port}");

    // Peer A: opens session ordinal 0.
    let client_a = UdpSocket::bind("127.0.0.1:0").await.expect("bind client a");
    client_a.send_to(b"a", &addr).await.expect("send a");
    let first = tokio::time::timeout(Duration::from_secs(2), accepted_rx.recv())
        .await
        .expect("timeout waiting for session 0 open")
        .expect("accepted channel closed");
    assert_eq!(first, 0, "first opened session must be ordinal 0");

    // Peer B: a distinct source address opens ordinal 1 and evicts ordinal 0.
    let client_b = UdpSocket::bind("127.0.0.1:0").await.expect("bind client b");
    client_b.send_to(b"b", &addr).await.expect("send b");

    let closed = tokio::time::timeout(Duration::from_secs(2), close_rx.recv())
        .await
        .expect("timeout: evicted session 0 was never closed")
        .expect("close channel closed");
    assert_eq!(closed, 0, "evicted session ordinal 0 must be closed");

    let dropped = tokio::time::timeout(Duration::from_secs(2), drop_rx.recv())
        .await
        .expect("timeout: evicted session 0 response pump never stopped")
        .expect("drop channel closed");
    assert_eq!(dropped, 0, "evicted session 0 recv half must be dropped");
}
