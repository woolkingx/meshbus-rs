use async_trait::async_trait;
use bytes::Bytes;
use mb_endpoint::Endpoint;
use mesh_bus_core::{
    BusBuilder, BusSessionInfo, BusSessionRequest, Capabilities, DatagramEgress, DatagramRecvHalf,
    DatagramSendHalf, DatagramSession, DisconnectReason, ExitId, ExitResult, IngressPlugin,
    RankContext, ScheduleDecision, SchedulerPlugin, SendError,
};
use mesh_bus_egress_udp::UdpEgress;
use mesh_bus_ingress_udp::UdpIngress;
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

// ── Fake egress: send_to notifies a counter, recv_from blocks forever ────────
// The egress's DatagramSession::send_to writes to a shared Sender so tests can
// observe when the ingress has forwarded a datagram to the egress layer, without
// relying on any response coming back.

struct CountingEgress {
    id: ExitId,
    caps: Capabilities,
    // Channel where each accepted datagram's payload is forwarded.
    accepted_tx: mpsc::Sender<Bytes>,
}

impl CountingEgress {
    fn new(accepted_tx: mpsc::Sender<Bytes>) -> Self {
        Self {
            id: ExitId("counting".into()),
            caps: Capabilities {
                protocol: "udp".into(),
                supports_stream: false,
                supports_datagram: true,
                max_payload_bytes: Some(65_507),
                groups: Vec::new(),
            },
            accepted_tx,
        }
    }
}

#[async_trait]
impl DatagramEgress for CountingEgress {
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
        Ok(Box::new(CountingSession {
            info,
            accepted_tx: self.accepted_tx.clone(),
        }))
    }
}

struct CountingSession {
    info: BusSessionInfo,
    accepted_tx: mpsc::Sender<Bytes>,
}

#[async_trait]
impl DatagramSession for CountingSession {
    async fn send_to(&mut self, _target: Endpoint, payload: Bytes) -> Result<(), SendError> {
        let _ = self.accepted_tx.send(payload).await;
        Ok(())
    }
    async fn recv_from(&mut self) -> Option<(Endpoint, Bytes)> {
        // Never return a response — forces ingress to be non-lockstep to pass.
        std::future::pending().await
    }
    fn info(&self) -> &BusSessionInfo {
        &self.info
    }
    fn max_payload_bytes(&self) -> usize {
        65_507
    }
    async fn close(&mut self) {}
    fn split(self: Box<Self>) -> (Box<dyn DatagramSendHalf>, Box<dyn DatagramRecvHalf>) {
        let tx = self.accepted_tx.clone();
        (Box::new(CountingSendHalf { tx }), Box::new(NeverRecvHalf))
    }
}

struct CountingSendHalf {
    tx: mpsc::Sender<Bytes>,
}
#[async_trait]
impl DatagramSendHalf for CountingSendHalf {
    async fn send_to(&mut self, _target: Endpoint, payload: Bytes) -> Result<(), SendError> {
        let _ = self.tx.send(payload).await;
        Ok(())
    }
    async fn close(&mut self) {}
}

struct NeverRecvHalf;
#[async_trait]
impl DatagramRecvHalf for NeverRecvHalf {
    async fn recv_from(&mut self) -> Option<(Endpoint, Bytes)> {
        std::future::pending().await
    }
    fn last_error(&self) -> Option<&DisconnectReason> {
        None
    }
}

async fn spawn_udp_echo() -> u16 {
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp echo");
    let port = sock.local_addr().expect("udp echo addr").port();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            let (n, peer) = sock.recv_from(&mut buf).await.expect("recv udp");
            sock.send_to(&buf[..n], peer).await.expect("send udp");
        }
    });
    port
}

/// Two datagrams from the same client must both reach the ingress without blocking
/// on a response from the egress. The egress recv half never returns, so a lockstep
/// implementation would hang after the first datagram and never accept the second.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ingress_accepts_two_datagrams_without_waiting_for_response() {
    // Channel capacity 2: both accepted datagrams can land without blocking.
    let (accepted_tx, mut accepted_rx) = mpsc::channel::<Bytes>(2);

    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_datagram_egress(Box::new(CountingEgress::new(accepted_tx)))
        .build()
        .await;
    let port = bus.port();
    let _bh = bus.spawn();

    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind ingress");
    let bind_port = sock.local_addr().expect("ingress addr").port();
    let target = mb_endpoint::Endpoint::new("127.0.0.1", 9999).expect("endpoint");
    let ingress = UdpIngress::new(sock, target);
    tokio::spawn(async move {
        let _ = Box::new(ingress).run(port).await;
    });

    let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
    let addr = format!("127.0.0.1:{bind_port}");

    // Send two datagrams; lockstep ingress would block on recv_from after first.
    client.send_to(b"first", &addr).await.expect("send first");
    client.send_to(b"second", &addr).await.expect("send second");

    // Both datagrams must reach the egress send_to within 500ms.
    let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
    let first = tokio::time::timeout_at(deadline, accepted_rx.recv())
        .await
        .expect("timeout waiting for first datagram")
        .expect("channel closed");
    let second = tokio::time::timeout_at(deadline, accepted_rx.recv())
        .await
        .expect("timeout waiting for second datagram — ingress is lockstep (blocked on recv)")
        .expect("channel closed");

    let payloads: std::collections::HashSet<&[u8]> =
        [first.as_ref(), second.as_ref()].into_iter().collect();
    assert!(payloads.contains(b"first".as_ref()));
    assert!(payloads.contains(b"second".as_ref()));
}

#[tokio::test]
async fn ingress_pipes_udp_datagram_to_egress() {
    let echo_port = spawn_udp_echo().await;
    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_datagram_egress(Box::new(UdpEgress::new(
            ExitId("udp".into()),
            Duration::from_millis(500),
        )))
        .build()
        .await;
    let port = bus.port();
    let _bh = bus.spawn();

    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind ingress");
    let bind_port = sock.local_addr().expect("ingress addr").port();
    let target = mb_endpoint::Endpoint::new("127.0.0.1", echo_port).expect("endpoint");
    let ingress = UdpIngress::new(sock, target);
    tokio::spawn(async move { Box::new(ingress).run(port).await.expect("ingress run") });

    let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
    client
        .send_to(b"hello", format!("127.0.0.1:{bind_port}"))
        .await
        .expect("client send");
    let mut buf = vec![0u8; 32];
    let (n, _) = client.recv_from(&mut buf).await.expect("client recv");
    assert_eq!(&buf[..n], b"hello");
}
