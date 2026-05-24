//! Eviction cleanup for the raw-UDP mesh-peer ingress. When the
//! `(peer, session_id)` map is full, the evicted bus datagram session must be
//! closed and its response pump must stop. The recording egress signals
//! send-half `close()` and recv-half `Drop` by session ordinal.

use async_trait::async_trait;
use bytes::Bytes;
use mb_endpoint::Endpoint;
use mb_proto_mesh::{
    FlowSemanticsWire, MeshFrame, NativeEventMode, ReturnSemanticsWire, StreamOpen, encode_frame,
};
use mesh_bus_core::transport::udp_loop::UdpPacketLoop;
use mesh_bus_core::{
    BusBuilder, BusSessionInfo, BusSessionRequest, Capabilities, DatagramEgress, DatagramRecvHalf,
    DatagramSendHalf, DatagramSession, DisconnectReason, ExitId, ExitResult, IngressPlugin,
    RankContext, ScheduleDecision, SchedulerPlugin, SendError, StreamEgress, StreamRecvHalf,
    StreamSendHalf, StreamSession,
};
use mesh_bus_ingress_mesh_peer_udp::MeshPeerUdpIngress;
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

struct RecordingStreamEgress {
    id: ExitId,
    caps: Capabilities,
    next_ordinal: Arc<AtomicUsize>,
    accepted_tx: mpsc::UnboundedSender<usize>,
    close_tx: mpsc::UnboundedSender<usize>,
    drop_tx: mpsc::UnboundedSender<usize>,
}

impl RecordingStreamEgress {
    fn new(
        accepted_tx: mpsc::UnboundedSender<usize>,
        close_tx: mpsc::UnboundedSender<usize>,
        drop_tx: mpsc::UnboundedSender<usize>,
    ) -> Self {
        Self {
            id: ExitId("recording-stream".into()),
            caps: Capabilities {
                protocol: "tcp".into(),
                supports_stream: true,
                supports_datagram: false,
                max_payload_bytes: None,
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
impl StreamEgress for RecordingStreamEgress {
    fn id(&self) -> &ExitId {
        &self.id
    }

    fn capabilities(&self) -> &Capabilities {
        &self.caps
    }

    async fn open_stream(
        &self,
        _request: &BusSessionRequest,
        info: BusSessionInfo,
    ) -> Result<Box<dyn StreamSession>, DisconnectReason> {
        let ordinal = self.next_ordinal.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(RecordingStreamSession {
            info,
            ordinal,
            accepted_tx: self.accepted_tx.clone(),
            close_tx: self.close_tx.clone(),
            drop_tx: self.drop_tx.clone(),
        }))
    }
}

struct RecordingStreamSession {
    info: BusSessionInfo,
    ordinal: usize,
    accepted_tx: mpsc::UnboundedSender<usize>,
    close_tx: mpsc::UnboundedSender<usize>,
    drop_tx: mpsc::UnboundedSender<usize>,
}

#[async_trait]
impl StreamSession for RecordingStreamSession {
    async fn connect(&mut self) -> Result<&BusSessionInfo, DisconnectReason> {
        let _ = self.accepted_tx.send(self.ordinal);
        Ok(&self.info)
    }

    fn into_tcp_splice(
        self: Box<Self>,
    ) -> Result<mesh_bus_core::TcpSpliceSession, Box<dyn StreamSession>> {
        Err(self)
    }

    fn split(self: Box<Self>) -> (Box<dyn StreamSendHalf>, Box<dyn StreamRecvHalf>) {
        (
            Box::new(RecordingStreamSendHalf {
                ordinal: self.ordinal,
                close_tx: self.close_tx.clone(),
            }),
            Box::new(RecordingStreamRecvHalf {
                ordinal: self.ordinal,
                drop_tx: self.drop_tx.clone(),
            }),
        )
    }

    async fn abort(&mut self, _reason: DisconnectReason) {
        let _ = self.close_tx.send(self.ordinal);
    }

    fn info(&self) -> &BusSessionInfo {
        &self.info
    }

    fn last_error(&self) -> Option<&DisconnectReason> {
        None
    }
}

struct RecordingStreamSendHalf {
    ordinal: usize,
    close_tx: mpsc::UnboundedSender<usize>,
}

#[async_trait]
impl StreamSendHalf for RecordingStreamSendHalf {
    async fn send(&mut self, _payload: Bytes) -> Result<(), DisconnectReason> {
        Ok(())
    }

    async fn shutdown_write(&mut self) {}

    async fn abort(&mut self, _reason: DisconnectReason) {
        let _ = self.close_tx.send(self.ordinal);
    }
}

struct RecordingStreamRecvHalf {
    ordinal: usize,
    drop_tx: mpsc::UnboundedSender<usize>,
}

#[async_trait]
impl StreamRecvHalf for RecordingStreamRecvHalf {
    async fn recv(&mut self) -> Option<Bytes> {
        std::future::pending().await
    }

    fn last_error(&self) -> Option<&DisconnectReason> {
        None
    }
}

impl Drop for RecordingStreamRecvHalf {
    fn drop(&mut self) {
        let _ = self.drop_tx.send(self.ordinal);
    }
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

fn datagram_send(session_id: &str, target: &Endpoint, body: &'static [u8]) -> Vec<u8> {
    encode_frame(&MeshFrame::DatagramSend {
        session_id: session_id.into(),
        seq: 1,
        target: target.clone(),
        payload: Bytes::from_static(body),
    })
    .expect("encode datagram send")
}

fn stream_open(session_id: &str, target: &Endpoint) -> Vec<u8> {
    encode_frame(&MeshFrame::StreamOpen(StreamOpen {
        session_id: session_id.into(),
        open_token: 1,
        target: target.clone(),
        route_group: None,
        flow_semantics: FlowSemanticsWire::ByteStream,
        return_semantics: ReturnSemanticsWire::Direct,
        source_node_id: "node-a".into(),
        path_trace: vec!["node-a".into()],
    }))
    .expect("encode stream open")
}

/// With a one-session cap, the first `(peer, session_id)` is evicted when a
/// second distinct session id arrives from the same peer. The evicted bus
/// datagram session (ordinal 0) must be closed and its pump stopped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn datagram_eviction_still_closes_datagram_session() {
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

    let ingress_loop = UdpPacketLoop::bind("127.0.0.1:0".parse().expect("ingress bind addr"))
        .await
        .expect("bind mesh ingress");
    let ingress_addr = ingress_loop.local_addr().expect("ingress addr");
    let ingress = MeshPeerUdpIngress::new(ingress_loop)
        .with_max_peer_sessions(1)
        .with_native_event_mode(NativeEventMode::MeshFrame);
    tokio::spawn(async move {
        let _ = Box::new(ingress).run(port).await;
    });

    let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
    let target = Endpoint::new("127.0.0.1", 9999).expect("endpoint");

    // Session "a": opens bus datagram session ordinal 0.
    peer.send_to(&datagram_send("a", &target, b"a"), ingress_addr)
        .await
        .expect("send a");
    let first = tokio::time::timeout(Duration::from_secs(2), accepted_rx.recv())
        .await
        .expect("timeout waiting for session 0 open")
        .expect("accepted channel closed");
    assert_eq!(first, 0, "first opened session must be ordinal 0");

    // Session "b": same peer, distinct id — evicts (peer, "a") = ordinal 0.
    peer.send_to(&datagram_send("b", &target, b"b"), ingress_addr)
        .await
        .expect("send b");

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn evicted_stream_session_aborts_recv_pump() {
    let (accepted_tx, mut accepted_rx) = mpsc::unbounded_channel::<usize>();
    let (close_tx, mut close_rx) = mpsc::unbounded_channel::<usize>();
    let (drop_tx, mut drop_rx) = mpsc::unbounded_channel::<usize>();

    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_stream_egress(Box::new(RecordingStreamEgress::new(
            accepted_tx,
            close_tx,
            drop_tx,
        )))
        .build()
        .await;
    let port = bus.port();
    let _bh = bus.spawn();

    let ingress_loop = UdpPacketLoop::bind("127.0.0.1:0".parse().expect("ingress bind addr"))
        .await
        .expect("bind mesh ingress");
    let ingress_addr = ingress_loop.local_addr().expect("ingress addr");
    let ingress = MeshPeerUdpIngress::new(ingress_loop)
        .with_max_peer_sessions(1)
        .with_native_event_mode(NativeEventMode::MeshFrame);
    tokio::spawn(async move {
        let _ = Box::new(ingress).run(port).await;
    });

    let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
    let target = Endpoint::new("127.0.0.1", 9999).expect("endpoint");

    peer.send_to(&stream_open("a", &target), ingress_addr)
        .await
        .expect("send stream a");
    let first = tokio::time::timeout(Duration::from_secs(2), accepted_rx.recv())
        .await
        .expect("timeout waiting for stream session 0 open")
        .expect("accepted channel closed");
    assert_eq!(first, 0, "first opened stream must be ordinal 0");

    peer.send_to(&stream_open("b", &target), ingress_addr)
        .await
        .expect("send stream b");

    let closed = tokio::time::timeout(Duration::from_secs(2), close_rx.recv())
        .await
        .expect("timeout: evicted stream session 0 was never aborted")
        .expect("close channel closed");
    assert_eq!(closed, 0, "evicted stream ordinal 0 must be aborted");

    let dropped = tokio::time::timeout(Duration::from_secs(2), drop_rx.recv())
        .await
        .expect("timeout: evicted stream session 0 pump never stopped")
        .expect("drop channel closed");
    assert_eq!(dropped, 0, "evicted stream recv half must be dropped");
}
