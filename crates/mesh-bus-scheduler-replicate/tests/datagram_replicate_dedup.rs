use bytes::Bytes;
use mb_endpoint::Endpoint;
use mesh_bus_core::{
    BusBuilder, BusDatagramRecvHalf, BusDatagramSendHalf, BusSessionInfo, BusSessionRequest,
    Capabilities, DatagramEgress, DatagramSession, DisconnectReason, ExitId, ScheduleHint,
    SendError,
};
use mesh_bus_scheduler_replicate::ReplicateScheduler;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

async fn spawn_udp_echo(delay: Duration, response: &'static [u8]) -> (u16, Arc<AtomicU32>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp echo");
    let port = sock.local_addr().expect("udp echo addr").port();
    let seen = Arc::new(AtomicU32::new(0));
    let seen_task = seen.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            let (_n, peer) = sock.recv_from(&mut buf).await.expect("recv udp");
            seen_task.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(delay).await;
            sock.send_to(response, peer).await.expect("send udp");
        }
    });
    (port, seen)
}

struct FixedUdpExit {
    id: ExitId,
    caps: Capabilities,
    target: Endpoint,
    timeout: Duration,
}

impl FixedUdpExit {
    fn new(id: &str, port: u16) -> Self {
        Self {
            id: ExitId(id.into()),
            caps: Capabilities {
                protocol: "udp-test-exit".into(),
                supports_stream: false,
                supports_datagram: true,
                max_payload_bytes: None,
                groups: Vec::new(),
            },
            target: Endpoint::new("127.0.0.1", port).expect("endpoint"),
            timeout: Duration::from_millis(500),
        }
    }
}

#[async_trait::async_trait]
impl DatagramEgress for FixedUdpExit {
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
        Ok(Box::new(FixedUdpSession {
            target: self.target.clone(),
            timeout: self.timeout,
            info,
            pending: None,
        }))
    }
}

struct FixedUdpSession {
    target: Endpoint,
    timeout: Duration,
    info: BusSessionInfo,
    pending: Option<(Endpoint, Bytes)>,
}

#[async_trait::async_trait]
impl DatagramSession for FixedUdpSession {
    async fn send_to(&mut self, _target: Endpoint, payload: Bytes) -> Result<(), SendError> {
        let sock = UdpSocket::bind("127.0.0.1:0")
            .await
            .map_err(|_| SendError::Closed)?;
        let target = format!("{}:{}", self.target.host(), self.target.port());
        tokio::time::timeout(self.timeout, sock.send_to(&payload, target))
            .await
            .map_err(|_| SendError::Closed)?
            .map_err(|_| SendError::Closed)?;
        let mut buf = vec![0u8; 2048];
        let (n, _) = tokio::time::timeout(self.timeout, sock.recv_from(&mut buf))
            .await
            .map_err(|_| SendError::Closed)?
            .map_err(|_| SendError::Closed)?;
        buf.truncate(n);
        self.pending = Some((self.target.clone(), Bytes::from(buf)));
        Ok(())
    }

    async fn recv_from(&mut self) -> Option<(Endpoint, Bytes)> {
        self.pending.take()
    }

    fn info(&self) -> &BusSessionInfo {
        &self.info
    }

    fn max_payload_bytes(&self) -> usize {
        65_507
    }

    async fn close(&mut self) {}

    fn split(self: Box<Self>) -> (Box<dyn BusDatagramSendHalf>, Box<dyn BusDatagramRecvHalf>) {
        let (reply_tx, reply_rx) = mpsc::unbounded_channel();
        (
            Box::new(FixedUdpSendHalf {
                target: self.target.clone(),
                timeout: self.timeout,
                reply_tx,
            }),
            Box::new(FixedUdpRecvHalf { reply_rx }),
        )
    }
}

struct FixedUdpSendHalf {
    target: Endpoint,
    timeout: Duration,
    reply_tx: mpsc::UnboundedSender<(Endpoint, Bytes)>,
}

#[async_trait::async_trait]
impl BusDatagramSendHalf for FixedUdpSendHalf {
    async fn send_to(&mut self, _target: Endpoint, payload: Bytes) -> Result<(), SendError> {
        let sock = UdpSocket::bind("127.0.0.1:0")
            .await
            .map_err(|_| SendError::Closed)?;
        let target = format!("{}:{}", self.target.host(), self.target.port());
        tokio::time::timeout(self.timeout, sock.send_to(&payload, target))
            .await
            .map_err(|_| SendError::Closed)?
            .map_err(|_| SendError::Closed)?;
        let reply_tx = self.reply_tx.clone();
        let source = self.target.clone();
        let timeout = self.timeout;
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            let Ok(Ok((n, _))) = tokio::time::timeout(timeout, sock.recv_from(&mut buf)).await
            else {
                return;
            };
            buf.truncate(n);
            let _ = reply_tx.send((source, Bytes::from(buf)));
        });
        Ok(())
    }

    async fn close(&mut self) {}
}

struct FixedUdpRecvHalf {
    reply_rx: mpsc::UnboundedReceiver<(Endpoint, Bytes)>,
}

#[async_trait::async_trait]
impl BusDatagramRecvHalf for FixedUdpRecvHalf {
    async fn recv_from(&mut self) -> Option<(Endpoint, Bytes)> {
        self.reply_rx.recv().await
    }

    fn last_error(&self) -> Option<&DisconnectReason> {
        None
    }
}

#[tokio::test]
async fn datagram_replicate_returns_fast_reply_once_and_hits_slow_exit() {
    let (fast_port, fast_seen) = spawn_udp_echo(Duration::from_millis(5), b"fast").await;
    let (slow_port, slow_seen) = spawn_udp_echo(Duration::from_millis(100), b"slow").await;
    let bus = BusBuilder::new()
        .scheduler(Box::new(ReplicateScheduler::new()))
        .add_datagram_egress(Box::new(FixedUdpExit::new("fast", fast_port)))
        .add_datagram_egress(Box::new(FixedUdpExit::new("slow", slow_port)))
        .build()
        .await;
    let port = bus.port();
    let handle = bus.spawn();
    let target = Endpoint::new("127.0.0.1", fast_port).expect("endpoint");
    let mut request = BusSessionRequest::datagram(target.clone());
    request.schedule_hint = ScheduleHint::FanOut { k: 2 };
    let mut session = port.open_datagram(request).await.expect("open datagram");
    session
        .send_to(target, Bytes::from_static(b"query"))
        .await
        .expect("send datagram");
    let (_source, payload) = session.recv_from().await.expect("first return");
    assert_eq!(&payload[..], b"fast");
    tokio::time::sleep(Duration::from_millis(130)).await;
    assert_eq!(fast_seen.load(Ordering::SeqCst), 1);
    assert_eq!(slow_seen.load(Ordering::SeqCst), 1);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), session.recv_from())
            .await
            .is_err(),
        "replicated datagram returned more than once"
    );
    handle.shutdown().await;
}
