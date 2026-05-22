use crate::{
    BusBuilder, BusEvent, BusSessionInfo, BusSessionRequest, Capabilities, DisconnectReason,
    EgressPlugin, ExitId, ExitResult, Frame, FrameKind, Measurement, ObserverPlugin, PathState,
    RankContext, ReturnEvent, ScheduleDecision, SchedulerPlugin, SessionId, StreamEgress,
    StreamRecvHalf, StreamSendHalf, StreamSession,
};
use async_trait::async_trait;
use bytes::Bytes;
use mb_endpoint::Endpoint;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

struct First;

impl SchedulerPlugin for First {
    fn schedule(&self, candidates: &[ExitId], _ctx: &RankContext) -> ScheduleDecision {
        ScheduleDecision::ordered((0..candidates.len()).collect())
    }

    fn feedback(&self, _result: &ExitResult, _payload_bytes: u64, _at_ms: u64) {}
}

struct ScriptedStream {
    id: ExitId,
}

struct DirectLoopbackEgress {
    id: ExitId,
    sends: Arc<AtomicU64>,
}

struct DirectLoopbackSession {
    info: BusSessionInfo,
    sends: Arc<AtomicU64>,
}

struct DirectLoopbackSend {
    tx: tokio::sync::mpsc::Sender<Bytes>,
    sends: Arc<AtomicU64>,
}

struct DirectLoopbackRecv {
    rx: tokio::sync::mpsc::Receiver<Bytes>,
    last_error: Option<DisconnectReason>,
}

#[async_trait]
impl EgressPlugin for ScriptedStream {
    fn id(&self) -> &ExitId {
        &self.id
    }

    fn capabilities(&self) -> &Capabilities {
        static CAPS: std::sync::OnceLock<Capabilities> = std::sync::OnceLock::new();
        CAPS.get_or_init(|| Capabilities {
            protocol: "test".into(),
            supports_stream: true,
            supports_datagram: false,
            max_payload_bytes: None,
            groups: Vec::new(),
        })
    }

    async fn send(&self, frame: Frame) -> ExitResult {
        let return_event = if matches!(frame.kind, FrameKind::Open) {
            ReturnEvent::Idle
        } else {
            ReturnEvent::Data {
                seq: frame.seq,
                payload: frame.payload,
            }
        };
        ExitResult {
            exit_id: self.id.clone(),
            success: true,
            rtt_ms: 1,
            local_endpoint: Some(Endpoint::new("127.0.0.1", 49152).expect("local endpoint")),
            return_event,
        }
    }

    async fn poll(&self, _session_id: &SessionId) -> ReturnEvent {
        ReturnEvent::Idle
    }

    async fn probe(&self, _target: &Endpoint) -> Measurement {
        Measurement {
            exit_id: self.id.clone(),
            at_ms: 0,
            rtt_ms: 1,
            payload_bytes: 0,
            jitter_ms: None,
            throughput_bps: None,
            success: true,
        }
    }

    async fn close(&self, _session_id: &SessionId) {}
}

#[async_trait]
impl StreamEgress for DirectLoopbackEgress {
    fn id(&self) -> &ExitId {
        &self.id
    }

    fn capabilities(&self) -> &Capabilities {
        static CAPS: std::sync::OnceLock<Capabilities> = std::sync::OnceLock::new();
        CAPS.get_or_init(|| Capabilities {
            protocol: "direct-loopback".into(),
            supports_stream: true,
            supports_datagram: false,
            max_payload_bytes: None,
            groups: Vec::new(),
        })
    }

    async fn open_stream(
        &self,
        _request: &BusSessionRequest,
        info: BusSessionInfo,
    ) -> Result<Box<dyn StreamSession>, DisconnectReason> {
        Ok(Box::new(DirectLoopbackSession {
            info,
            sends: self.sends.clone(),
        }))
    }
}

#[async_trait]
impl StreamSession for DirectLoopbackSession {
    async fn connect(&mut self) -> Result<&BusSessionInfo, DisconnectReason> {
        Ok(&self.info)
    }

    fn into_tcp_splice(self: Box<Self>) -> Result<crate::TcpSpliceSession, Box<dyn StreamSession>> {
        Err(self)
    }

    fn split(self: Box<Self>) -> (Box<dyn StreamSendHalf>, Box<dyn StreamRecvHalf>) {
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        (
            Box::new(DirectLoopbackSend {
                tx,
                sends: self.sends,
            }),
            Box::new(DirectLoopbackRecv {
                rx,
                last_error: None,
            }),
        )
    }

    async fn abort(&mut self, reason: DisconnectReason) {
        let _ = reason;
        self.info.paths[0].state = PathState::Closed;
    }

    fn info(&self) -> &BusSessionInfo {
        &self.info
    }

    fn last_error(&self) -> Option<&DisconnectReason> {
        None
    }
}

#[async_trait]
impl StreamSendHalf for DirectLoopbackSend {
    async fn send(&mut self, payload: Bytes) -> Result<(), DisconnectReason> {
        self.sends.fetch_add(1, Ordering::Relaxed);
        self.tx
            .send(payload)
            .await
            .map_err(|_| DisconnectReason::ReaderClosed)
    }

    async fn shutdown_write(&mut self) {}

    async fn abort(&mut self, _reason: DisconnectReason) {}
}

#[async_trait]
impl StreamRecvHalf for DirectLoopbackRecv {
    async fn recv(&mut self) -> Option<Bytes> {
        let item = self.rx.recv().await;
        if item.is_none() {
            self.last_error = Some(DisconnectReason::UpstreamEof);
        }
        item
    }

    fn last_error(&self) -> Option<&DisconnectReason> {
        self.last_error.as_ref()
    }
}

#[tokio::test]
async fn stream_session_connect_send_recv_uses_existing_bus_routing() {
    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_egress(Box::new(ScriptedStream {
            id: ExitId("test".into()),
        }))
        .build()
        .await;
    let port = bus.port();
    let handle = bus.spawn();

    let mut session = port
        .open_stream(BusSessionRequest::stream(
            Endpoint::new("example.com", 443).expect("endpoint"),
        ))
        .await
        .expect("open stream");
    session.connect().await.expect("connect");
    let (mut send_half, mut recv_half) = session.split();
    send_half
        .send(Bytes::from_static(b"hello"))
        .await
        .expect("send");
    let payload = recv_half.recv().await.expect("recv");
    assert_eq!(&payload[..], b"hello");
    handle.shutdown().await;
}

#[tokio::test]
async fn stream_session_connect_populates_primary_path_local_endpoint() {
    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_egress(Box::new(ScriptedStream {
            id: ExitId("tcp-a".into()),
        }))
        .build()
        .await;
    let port = bus.port();
    let handle = bus.spawn();

    let mut session = port
        .open_stream(BusSessionRequest::stream(
            Endpoint::new("example.com", 443).expect("endpoint"),
        ))
        .await
        .expect("open stream");
    let info = session.connect().await.expect("connect");
    let path = info
        .paths
        .get(info.primary)
        .expect("primary path should be populated after connect");

    assert_eq!(path.exit_id, ExitId("tcp-a".into()));
    assert_eq!(
        path.local,
        Endpoint::new("127.0.0.1", 49152).expect("local endpoint")
    );
    assert_eq!(
        path.remote,
        Endpoint::new("example.com", 443).expect("remote")
    );
    handle.shutdown().await;
}

#[tokio::test]
async fn forwarder_stream_data_bypasses_dispatch_after_open() {
    let sends = Arc::new(AtomicU64::new(0));
    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_stream_egress(Box::new(DirectLoopbackEgress {
            id: ExitId("direct".into()),
            sends: sends.clone(),
        }))
        .build()
        .await;
    let port = bus.port();
    let handle = bus.spawn();

    let mut session = port
        .open_stream(BusSessionRequest::stream(
            Endpoint::new("example.com", 443).expect("endpoint"),
        ))
        .await
        .expect("open stream");
    let flow_id = session.connect().await.expect("connect").flow_id.clone();
    let (mut send_half, mut recv_half) = session.split();

    send_half
        .send(Bytes::from_static(b"hello"))
        .await
        .expect("send 1");
    send_half
        .send(Bytes::from_static(b"!"))
        .await
        .expect("send 2");
    assert_eq!(&recv_half.recv().await.expect("recv 1")[..], b"hello");
    assert_eq!(&recv_half.recv().await.expect("recv 2")[..], b"!");

    let snapshot = handle.snapshot().await;
    let exit = snapshot
        .exits
        .iter()
        .find(|exit| exit.exit_id.0 == "direct")
        .expect("exit snapshot");
    assert_eq!(exit.send_count, 1, "only Open may enter dispatch");
    assert_eq!(sends.load(Ordering::Relaxed), 2);
    let counters = snapshot
        .flows
        .iter()
        .find(|(id, _)| id == &flow_id)
        .map(|(_, counters)| counters)
        .expect("flow counters");
    assert_eq!(counters.bytes_out, 6);
    assert_eq!(counters.bytes_in, 6);

    handle.shutdown().await;
}

struct RecordingObserver {
    events: Arc<std::sync::Mutex<Vec<BusEvent>>>,
}

impl ObserverPlugin for RecordingObserver {
    fn on_event(&self, event: &BusEvent) {
        self.events
            .lock()
            .expect("recorder mutex")
            .push(event.clone());
    }
}

fn flow_closed_count(events: &[BusEvent], flow_id: &crate::FlowId) -> usize {
    events
        .iter()
        .filter(|e| {
            matches!(
                e,
                BusEvent::Core(env)
                    if env.type_id
                        == crate::kernel::observation::EventTypeId::Core(
                            crate::kernel::observation::CoreEventId::FlowClosed
                        )
                    && env.payload.0.flow_id_text.as_deref() == Some(flow_id.0.as_str())
            )
        })
        .count()
}

#[tokio::test]
async fn direct_stream_forwarder_close_cleans_flow_state() {
    let sends = Arc::new(AtomicU64::new(0));
    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_stream_egress(Box::new(DirectLoopbackEgress {
            id: ExitId("direct".into()),
            sends: sends.clone(),
        }))
        .build()
        .await;
    let port = bus.port();
    let handle = bus.spawn();

    let mut session = port
        .open_stream(BusSessionRequest::stream(
            Endpoint::new("example.com", 443).expect("endpoint"),
        ))
        .await
        .expect("open stream");
    let flow_id = session.connect().await.expect("connect").flow_id.clone();
    let (send_half, mut recv_half) = session.split();

    // Drive EOF from the recv half: dropping the send half drops the egress
    // loopback tx, so the egress recv returns None and the forwarder closes.
    drop(send_half);
    assert!(recv_half.recv().await.is_none(), "loopback EOF after drop");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let snapshot = handle.snapshot().await;
    assert!(
        !snapshot.flows.iter().any(|(id, _)| id == &flow_id),
        "closed forwarder flow must not leak a counter entry: {:?}",
        snapshot.flows
    );

    // No stale pin: a fresh stream still routes and establishes its own flow.
    let mut session2 = port
        .open_stream(BusSessionRequest::stream(
            Endpoint::new("example.com", 443).expect("endpoint"),
        ))
        .await
        .expect("open stream 2");
    let flow_id2 = session2.connect().await.expect("connect 2").flow_id.clone();
    let (mut send2, mut recv2) = session2.split();
    send2
        .send(Bytes::from_static(b"again"))
        .await
        .expect("send 2");
    assert_eq!(&recv2.recv().await.expect("recv 2")[..], b"again");
    let snapshot2 = handle.snapshot().await;
    assert!(
        snapshot2.flows.iter().any(|(id, _)| id == &flow_id2),
        "second flow must be tracked"
    );

    handle.shutdown().await;
}

#[tokio::test]
async fn direct_stream_forwarder_abort_cleans_flow_state_once() {
    let events = Arc::new(std::sync::Mutex::new(Vec::<BusEvent>::new()));
    let sends = Arc::new(AtomicU64::new(0));
    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_stream_egress(Box::new(DirectLoopbackEgress {
            id: ExitId("direct".into()),
            sends: sends.clone(),
        }))
        .add_observer(Box::new(RecordingObserver {
            events: events.clone(),
        }))
        .build()
        .await;
    let port = bus.port();
    let handle = bus.spawn();

    let mut session = port
        .open_stream(BusSessionRequest::stream(
            Endpoint::new("example.com", 443).expect("endpoint"),
        ))
        .await
        .expect("open stream");
    let flow_id = session.connect().await.expect("connect").flow_id.clone();
    let (mut send_half, mut recv_half) = session.split();

    // Abort the send half and also drive the recv EOF: both call close_once,
    // but the close guard must publish exactly one FlowClosed.
    send_half.abort(DisconnectReason::ConnectionReset).await;
    drop(send_half);
    let _ = recv_half.recv().await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let snapshot = handle.snapshot().await;
    assert!(
        !snapshot.flows.iter().any(|(id, _)| id == &flow_id),
        "aborted forwarder flow must not leak a counter entry"
    );
    handle.shutdown().await;

    let evs = events.lock().expect("recorder mutex");
    assert_eq!(
        flow_closed_count(&evs, &flow_id),
        1,
        "exactly one FlowClosed lifecycle event, got: {evs:?}"
    );
}
