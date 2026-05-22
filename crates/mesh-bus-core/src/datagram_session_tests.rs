use crate::{
    BusBuilder, BusDatagramRecvHalf, BusDatagramSendHalf, BusDatagramSession, BusSessionInfo,
    BusSessionRequest, Capabilities, DatagramEgress, DisconnectReason, EgressPlugin, ExitId,
    ExitResult, FlowSemantics, Frame, Measurement, RankContext, ReturnEvent, ReturnSemantics,
    ScheduleDecision, ScheduleHint, SchedulerPlugin, SendError, SessionId,
    egress_adapter::DatagramEgressAdapter,
};
use async_trait::async_trait;
use bytes::Bytes;
use mb_endpoint::Endpoint;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};

struct First;

impl SchedulerPlugin for First {
    fn schedule(&self, candidates: &[ExitId], _ctx: &RankContext) -> ScheduleDecision {
        ScheduleDecision::ordered((0..candidates.len()).collect())
    }

    fn feedback(&self, _result: &ExitResult, _payload_bytes: u64, _at_ms: u64) {}
}

/// Minimal DatagramEgress for tests where the egress is never actually called
/// (e.g. request-validation rejection tests). Cause (c) fix: replaces
/// EchoDatagram: EgressPlugin (add_egress backdoor) with the public DatagramEgress API.
struct NeverCalledDatagramEgress;

#[async_trait]
impl DatagramEgress for NeverCalledDatagramEgress {
    fn id(&self) -> &ExitId {
        static ID: std::sync::OnceLock<ExitId> = std::sync::OnceLock::new();
        ID.get_or_init(|| ExitId("never-called".into()))
    }
    fn capabilities(&self) -> &Capabilities {
        static CAPS: std::sync::OnceLock<Capabilities> = std::sync::OnceLock::new();
        CAPS.get_or_init(|| Capabilities {
            protocol: "never-called".into(),
            supports_stream: false,
            supports_datagram: true,
            max_payload_bytes: Some(65_507),
            groups: Vec::new(),
        })
    }
    fn max_payload_bytes(&self) -> usize {
        65_507
    }
    async fn open_datagram(
        &self,
        _request: &BusSessionRequest,
        _info: BusSessionInfo,
    ) -> Result<Box<dyn BusDatagramSession>, DisconnectReason> {
        panic!("NeverCalledDatagramEgress::open_datagram must not be called in rejection tests")
    }
}

// datagram_session_preserves_one_call_one_datagram and
// datagram_session_reports_source_from_send_to_target have been moved to
// crates/mesh-bus-core/tests/dispatch_datagram.rs (dispatch owner-contract, D-M7.2).

/// Local EgressPlugin echo helper for fanout timing invariant.
/// datagram_fanout_hint_replicates_to_multiple_egresses_and_dedups_return is a
/// timing/concurrency invariant (dedup across fan-out replicate path); it stays inline.
struct EchoDatagram {
    id: ExitId,
    seen: Option<Arc<Mutex<Vec<ExitId>>>>,
}

#[async_trait]
impl EgressPlugin for EchoDatagram {
    fn id(&self) -> &ExitId {
        &self.id
    }
    fn capabilities(&self) -> &Capabilities {
        static CAPS: std::sync::OnceLock<Capabilities> = std::sync::OnceLock::new();
        CAPS.get_or_init(|| Capabilities {
            protocol: "udp-echo".into(),
            supports_stream: false,
            supports_datagram: true,
            max_payload_bytes: Some(1200),
            groups: Vec::new(),
        })
    }
    async fn send(&self, frame: Frame) -> ExitResult {
        if let Some(seen) = &self.seen {
            seen.lock().await.push(self.id.clone());
        }
        ExitResult {
            exit_id: self.id.clone(),
            success: true,
            rtt_ms: 1,
            local_endpoint: None,
            return_event: ReturnEvent::Data {
                seq: frame.seq,
                payload: frame.payload,
            },
        }
    }
    async fn poll(&self, _: &SessionId) -> ReturnEvent {
        ReturnEvent::Idle
    }
    async fn probe(&self, _: &mb_endpoint::Endpoint) -> Measurement {
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
    async fn close(&self, _: &SessionId) {}
}

#[tokio::test]
async fn datagram_fanout_hint_replicates_to_multiple_egresses_and_dedups_return() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_egress(Box::new(EchoDatagram {
            id: ExitId("wan-a".into()),
            seen: Some(seen.clone()),
        }))
        .add_egress(Box::new(EchoDatagram {
            id: ExitId("wan-b".into()),
            seen: Some(seen.clone()),
        }))
        .build()
        .await;
    let port = bus.port();
    let handle = bus.spawn();
    let target = Endpoint::new("127.0.0.1", 9000).expect("target");
    let mut request = BusSessionRequest::datagram(target.clone());
    request.schedule_hint = ScheduleHint::FanOut { k: 2 };
    let mut session = port.open_datagram(request).await.expect("open datagram");

    session
        .send_to(target, Bytes::from_static(b"pkt"))
        .await
        .expect("send");
    let (_source, payload) = session.recv_from().await.expect("recv");

    assert_eq!(&payload[..], b"pkt");
    assert_eq!(
        *seen.lock().await,
        vec![ExitId("wan-a".into()), ExitId("wan-b".into())]
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), session.recv_from())
            .await
            .is_err(),
        "fanout must dedup duplicate returns for one packet"
    );
    handle.shutdown().await;
}

// data-owner-fixture (cause c — wrong API corrected): validates that
// open_datagram() rejects FanOut k=0 at the BusSessionRequest validation gate
// before any egress is consulted. Owner: mesh-bus-core session validation.
// Schema: schemas/session.schema.json (schedule_hint field).
// Uses public DatagramEgress API (NeverCalledDatagramEgress) instead of
// EgressPlugin backdoor; egress is never reached because rejection fires first.
#[tokio::test]
async fn datagram_fanout_zero_is_rejected_at_open() {
    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_datagram_egress(Box::new(NeverCalledDatagramEgress))
        .build()
        .await;
    let port = bus.port();
    let handle = bus.spawn();
    let target = Endpoint::new("127.0.0.1", 9000).expect("target");
    let mut request = BusSessionRequest::datagram(target);
    request.schedule_hint = ScheduleHint::FanOut { k: 0 };

    let err = match port.open_datagram(request).await {
        Ok(_) => panic!("FanOut k=0 must be rejected"),
        Err(err) => err,
    };

    assert_eq!(err, DisconnectReason::AddressNotSupported);
    handle.shutdown().await;
}

// --- persistent datagram egress session test ---

struct NotifyingSend {
    notify: Arc<tokio::sync::Notify>,
    count: Arc<Mutex<u32>>,
}

struct BlockingRecv {
    _park: tokio::sync::oneshot::Receiver<()>,
}

#[async_trait]
impl crate::BusDatagramSendHalf for NotifyingSend {
    async fn send_to(&mut self, _target: Endpoint, _payload: Bytes) -> Result<(), SendError> {
        *self.count.lock().await += 1;
        self.notify.notify_one();
        Ok(())
    }
    async fn close(&mut self) {}
}

#[async_trait]
impl crate::BusDatagramRecvHalf for BlockingRecv {
    async fn recv_from(&mut self) -> Option<(Endpoint, Bytes)> {
        let _ = (&mut self._park).await;
        None
    }
    fn last_error(&self) -> Option<&DisconnectReason> {
        None
    }
}

struct BlockingEgress {
    id: ExitId,
    send_count: Arc<Mutex<u32>>,
    notify: Arc<tokio::sync::Notify>,
}

#[async_trait]
impl DatagramEgress for BlockingEgress {
    fn id(&self) -> &ExitId {
        &self.id
    }

    fn capabilities(&self) -> &Capabilities {
        static CAPS: std::sync::OnceLock<Capabilities> = std::sync::OnceLock::new();
        CAPS.get_or_init(|| Capabilities {
            protocol: "block-udp".into(),
            supports_stream: false,
            supports_datagram: true,
            max_payload_bytes: Some(65_507),
            groups: Vec::new(),
        })
    }

    fn max_payload_bytes(&self) -> usize {
        65_507
    }

    async fn open_datagram(
        &self,
        _request: &BusSessionRequest,
        _info: BusSessionInfo,
    ) -> Result<Box<dyn BusDatagramSession>, DisconnectReason> {
        let (_tx, rx) = tokio::sync::oneshot::channel::<()>();
        let send_half = NotifyingSend {
            notify: self.notify.clone(),
            count: self.send_count.clone(),
        };
        let recv_half = BlockingRecv { _park: rx };

        // We can't easily return a "pre-split" session here, so we wrap in a custom session.
        // Actually we need to return a BusDatagramSession that when split() gives our halves.
        struct ReadySession {
            send: Option<NotifyingSend>,
            recv: Option<BlockingRecv>,
        }

        #[async_trait]
        impl crate::BusDatagramSession for ReadySession {
            async fn send_to(&mut self, _t: Endpoint, _p: Bytes) -> Result<(), SendError> {
                if let Some(s) = &mut self.send {
                    s.send_to(_t, _p).await
                } else {
                    Err(SendError::Closed)
                }
            }
            async fn recv_from(&mut self) -> Option<(Endpoint, Bytes)> {
                if let Some(r) = &mut self.recv {
                    r.recv_from().await
                } else {
                    None
                }
            }
            fn info(&self) -> &BusSessionInfo {
                static I: std::sync::OnceLock<BusSessionInfo> = std::sync::OnceLock::new();
                I.get_or_init(|| BusSessionInfo {
                    session_id: SessionId("ready".into()),
                    flow_id: crate::FlowId("ready".into()),
                    schedule_mode: crate::ScheduleMode::Ordered,
                    paths: Vec::new(),
                    primary: 0,
                    path_trace: Vec::new(),
                    started_at_ms: 0,
                })
            }
            fn max_payload_bytes(&self) -> usize {
                65_507
            }
            async fn close(&mut self) {}
            fn split(
                mut self: Box<Self>,
            ) -> (
                Box<dyn crate::BusDatagramSendHalf>,
                Box<dyn crate::BusDatagramRecvHalf>,
            ) {
                (
                    Box::new(
                        self.send
                            .take()
                            .expect("split called twice: send half missing"),
                    ),
                    Box::new(
                        self.recv
                            .take()
                            .expect("split called twice: recv half missing"),
                    ),
                )
            }
        }

        Ok(Box::new(ReadySession {
            send: Some(send_half),
            recv: Some(recv_half),
        }))
    }
}

#[tokio::test]
async fn datagram_send_does_not_wait_for_response() {
    // BlockingEgress: recv_from never returns, but send_to succeeds immediately.
    // Without persistent sessions, dispatch blocks on recv_from after the first frame,
    // so the second send_to never reaches the egress.
    // With persistent sessions + async pump, both sends reach the egress quickly.
    let send_count = Arc::new(Mutex::new(0u32));
    let notify = Arc::new(tokio::sync::Notify::new());
    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_datagram_egress(Box::new(BlockingEgress {
            id: ExitId("blocking-udp".into()),
            send_count: send_count.clone(),
            notify: notify.clone(),
        }))
        .build()
        .await;
    let port = bus.port();
    let handle = bus.spawn();
    let target = Endpoint::new("127.0.0.1", 9000).expect("endpoint");
    let mut session = port
        .open_datagram(BusSessionRequest::datagram(target.clone()))
        .await
        .expect("open datagram");

    session
        .send_to(target.clone(), Bytes::from_static(b"pkt1"))
        .await
        .expect("send 1");
    session
        .send_to(target.clone(), Bytes::from_static(b"pkt2"))
        .await
        .expect("send 2");

    // Wait for both sends to reach the egress (with 500ms timeout).
    let received = tokio::time::timeout(std::time::Duration::from_millis(500), async {
        loop {
            if *send_count.lock().await >= 2 {
                break;
            }
            notify.notified().await;
        }
    })
    .await;

    assert!(
        received.is_ok(),
        "both packets must reach egress within timeout"
    );
    assert_eq!(*send_count.lock().await, 2, "send_count must be exactly 2");
    handle.shutdown().await;
}

struct ControlledDatagramEgress {
    id: ExitId,
    sent: mpsc::UnboundedSender<(Endpoint, Bytes)>,
    responses: Mutex<Option<mpsc::UnboundedReceiver<(Endpoint, Bytes)>>>,
}

struct ControlledDatagramSession {
    info: BusSessionInfo,
    sent: mpsc::UnboundedSender<(Endpoint, Bytes)>,
    responses: Option<mpsc::UnboundedReceiver<(Endpoint, Bytes)>>,
}

struct ControlledSendHalf {
    sent: mpsc::UnboundedSender<(Endpoint, Bytes)>,
}

struct ControlledRecvHalf {
    responses: mpsc::UnboundedReceiver<(Endpoint, Bytes)>,
}

#[async_trait]
impl DatagramEgress for ControlledDatagramEgress {
    fn id(&self) -> &ExitId {
        &self.id
    }

    fn capabilities(&self) -> &Capabilities {
        static CAPS: std::sync::OnceLock<Capabilities> = std::sync::OnceLock::new();
        CAPS.get_or_init(|| Capabilities {
            protocol: "controlled-udp".into(),
            supports_stream: false,
            supports_datagram: true,
            max_payload_bytes: Some(65_507),
            groups: Vec::new(),
        })
    }

    fn max_payload_bytes(&self) -> usize {
        65_507
    }

    async fn open_datagram(
        &self,
        _request: &BusSessionRequest,
        info: BusSessionInfo,
    ) -> Result<Box<dyn BusDatagramSession>, DisconnectReason> {
        let responses = self
            .responses
            .lock()
            .await
            .take()
            .ok_or(DisconnectReason::SessionClosed)?;
        Ok(Box::new(ControlledDatagramSession {
            info,
            sent: self.sent.clone(),
            responses: Some(responses),
        }))
    }
}

#[async_trait]
impl BusDatagramSession for ControlledDatagramSession {
    async fn send_to(&mut self, target: Endpoint, payload: Bytes) -> Result<(), SendError> {
        self.sent
            .send((target, payload))
            .map_err(|_| SendError::Closed)
    }

    async fn recv_from(&mut self) -> Option<(Endpoint, Bytes)> {
        self.responses.as_mut()?.recv().await
    }

    fn info(&self) -> &BusSessionInfo {
        &self.info
    }

    fn max_payload_bytes(&self) -> usize {
        65_507
    }

    async fn close(&mut self) {}

    fn split(
        mut self: Box<Self>,
    ) -> (
        Box<dyn crate::BusDatagramSendHalf>,
        Box<dyn crate::BusDatagramRecvHalf>,
    ) {
        (
            Box::new(ControlledSendHalf {
                sent: self.sent.clone(),
            }),
            Box::new(ControlledRecvHalf {
                responses: self.responses.take().expect("response receiver present"),
            }),
        )
    }
}

#[async_trait]
impl crate::BusDatagramSendHalf for ControlledSendHalf {
    async fn send_to(&mut self, target: Endpoint, payload: Bytes) -> Result<(), SendError> {
        self.sent
            .send((target, payload))
            .map_err(|_| SendError::Closed)
    }

    async fn close(&mut self) {}
}

#[async_trait]
impl crate::BusDatagramRecvHalf for ControlledRecvHalf {
    async fn recv_from(&mut self) -> Option<(Endpoint, Bytes)> {
        self.responses.recv().await
    }

    fn last_error(&self) -> Option<&DisconnectReason> {
        None
    }
}

#[tokio::test]
async fn datagram_adapter_preserves_response_seq_by_return_source() {
    let (sent_tx, mut sent_rx) = mpsc::unbounded_channel();
    let (response_tx, response_rx) = mpsc::unbounded_channel();
    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_datagram_egress(Box::new(ControlledDatagramEgress {
            id: ExitId("controlled".into()),
            sent: sent_tx,
            responses: Mutex::new(Some(response_rx)),
        }))
        .build()
        .await;
    let port = bus.port();
    let handle = bus.spawn();
    let session_target = Endpoint::new("127.0.0.1", 9000).expect("session target");
    let target_a = Endpoint::new("127.0.0.1", 9001).expect("target a");
    let target_b = Endpoint::new("127.0.0.1", 9002).expect("target b");
    let mut session = port
        .open_datagram(BusSessionRequest::datagram(session_target))
        .await
        .expect("open datagram");

    session
        .send_to(target_a.clone(), Bytes::from_static(b"a"))
        .await
        .expect("send a");
    session
        .send_to(target_b.clone(), Bytes::from_static(b"b"))
        .await
        .expect("send b");

    assert_eq!(sent_rx.recv().await.expect("first sent").0, target_a);
    assert_eq!(sent_rx.recv().await.expect("second sent").0, target_b);

    response_tx
        .send((target_b.clone(), Bytes::from_static(b"reply-b")))
        .expect("response b");
    response_tx
        .send((target_a.clone(), Bytes::from_static(b"reply-a")))
        .expect("response a");

    let (source_b, payload_b) = session.recv_from().await.expect("recv b");
    let (source_a, payload_a) = session.recv_from().await.expect("recv a");

    assert_eq!(source_b, target_b);
    assert_eq!(payload_b, Bytes::from_static(b"reply-b"));
    assert_eq!(source_a, target_a);
    assert_eq!(payload_a, Bytes::from_static(b"reply-a"));
    handle.shutdown().await;
}

// ── Task 4: direct datagram forwarder half tests ──────────────────────────────

#[tokio::test]
async fn datagram_forwarder_recv_preserves_source_endpoint() {
    use crate::FlowId;
    use crate::kernel::forwarder::{
        DataplaneShape, FlowCounters, ForwarderClose, ForwarderDatagramState,
        ForwarderDatagramTransport, noop_forwarder_close_cleanup,
    };
    use crate::kernel::observation::ObservationBus;
    use crate::transport::session::datagram_halves::make_direct_datagram_forwarder_halves;

    let target_a = Endpoint::new("127.0.0.1", 9011).unwrap();
    let target_b = Endpoint::new("127.0.0.1", 9012).unwrap();

    let (sent_tx, _sent_rx) = mpsc::unbounded_channel::<(Endpoint, bytes::Bytes)>();
    let (response_tx, response_rx) = mpsc::unbounded_channel::<(Endpoint, bytes::Bytes)>();
    response_tx
        .send((target_b.clone(), bytes::Bytes::from_static(b"reply")))
        .unwrap();

    let close = Arc::new(ForwarderClose::new(
        Arc::new(ObservationBus::default()),
        FlowId("f-recv".into()),
        SessionId("s-recv".into()),
        ExitId("e-recv".into()),
        Arc::new(|| 0),
        noop_forwarder_close_cleanup(),
        DataplaneShape::DatagramForwarder,
    ));
    let state = ForwarderDatagramState {
        transport: ForwarderDatagramTransport {
            send: Mutex::new(Box::new(ControlledSendHalf { sent: sent_tx })),
            recv: Mutex::new(Box::new(ControlledRecvHalf {
                responses: response_rx,
            })),
        },
        counters: Arc::new(FlowCounters::new()),
        close,
        fixed_target: target_a,
    };

    let (_send, mut recv) = make_direct_datagram_forwarder_halves(state);
    let (source, payload) = recv.recv_from().await.expect("must receive");
    assert_eq!(source, target_b, "source endpoint preserved from inner");
    assert_eq!(&payload[..], b"reply");
}

#[tokio::test]
async fn datagram_forwarder_rejects_second_target() {
    use crate::FlowId;
    use crate::kernel::forwarder::{
        DataplaneShape, FlowCounters, ForwarderClose, ForwarderDatagramState,
        ForwarderDatagramTransport, noop_forwarder_close_cleanup,
    };
    use crate::kernel::observation::ObservationBus;
    use crate::transport::session::datagram_halves::make_direct_datagram_forwarder_halves;

    let target_a = Endpoint::new("127.0.0.1", 9013).unwrap();
    let target_b = Endpoint::new("127.0.0.1", 9014).unwrap();

    let (sent_tx, _sent_rx) = mpsc::unbounded_channel::<(Endpoint, bytes::Bytes)>();
    let (_response_tx, response_rx) = mpsc::unbounded_channel::<(Endpoint, bytes::Bytes)>();

    let close = Arc::new(ForwarderClose::new(
        Arc::new(ObservationBus::default()),
        FlowId("f-rej".into()),
        SessionId("s-rej".into()),
        ExitId("e-rej".into()),
        Arc::new(|| 0),
        noop_forwarder_close_cleanup(),
        DataplaneShape::DatagramForwarder,
    ));
    let state = ForwarderDatagramState {
        transport: ForwarderDatagramTransport {
            send: Mutex::new(Box::new(ControlledSendHalf { sent: sent_tx })),
            recv: Mutex::new(Box::new(ControlledRecvHalf {
                responses: response_rx,
            })),
        },
        counters: Arc::new(FlowCounters::new()),
        close,
        fixed_target: target_a,
    };

    let (mut send, _recv) = make_direct_datagram_forwarder_halves(state);
    let result = send
        .send_to(target_b, bytes::Bytes::from_static(b"wrong"))
        .await;
    assert_eq!(result, Err(SendError::AddressNotSupported));
}

// ── Task 3: open_forwarder_datagram adapter test ──────────────────────────────

struct MockDatagramSendHalf {
    send_count: Arc<std::sync::atomic::AtomicUsize>,
}
struct MockDatagramRecvHalf;

#[async_trait]
impl BusDatagramSendHalf for MockDatagramSendHalf {
    async fn send_to(&mut self, _: Endpoint, _: Bytes) -> Result<(), SendError> {
        self.send_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
    async fn close(&mut self) {}
}

#[async_trait]
impl BusDatagramRecvHalf for MockDatagramRecvHalf {
    async fn recv_from(&mut self) -> Option<(Endpoint, Bytes)> {
        None
    }
    fn last_error(&self) -> Option<&DisconnectReason> {
        None
    }
}

struct MockDatagramSession {
    info: BusSessionInfo,
    send_count: Arc<std::sync::atomic::AtomicUsize>,
}

#[async_trait]
impl BusDatagramSession for MockDatagramSession {
    async fn send_to(&mut self, target: Endpoint, payload: Bytes) -> Result<(), SendError> {
        self.send_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let _ = (target, payload);
        Ok(())
    }
    async fn recv_from(&mut self) -> Option<(Endpoint, Bytes)> {
        None
    }
    fn info(&self) -> &BusSessionInfo {
        &self.info
    }
    fn max_payload_bytes(&self) -> usize {
        65_507
    }
    async fn close(&mut self) {}
    fn split(self: Box<Self>) -> (Box<dyn BusDatagramSendHalf>, Box<dyn BusDatagramRecvHalf>) {
        (
            Box::new(MockDatagramSendHalf {
                send_count: self.send_count,
            }),
            Box::new(MockDatagramRecvHalf),
        )
    }
}

struct MockDatagramEgress {
    id: ExitId,
    open_count: Arc<std::sync::atomic::AtomicUsize>,
    send_count: Arc<std::sync::atomic::AtomicUsize>,
}

#[async_trait]
impl DatagramEgress for MockDatagramEgress {
    fn id(&self) -> &ExitId {
        &self.id
    }
    fn capabilities(&self) -> &Capabilities {
        static CAPS: std::sync::OnceLock<Capabilities> = std::sync::OnceLock::new();
        CAPS.get_or_init(|| Capabilities {
            protocol: "mock-udp".into(),
            supports_stream: false,
            supports_datagram: true,
            max_payload_bytes: Some(65_507),
            groups: Vec::new(),
        })
    }
    fn max_payload_bytes(&self) -> usize {
        65_507
    }
    async fn open_datagram(
        &self,
        _request: &BusSessionRequest,
        info: BusSessionInfo,
    ) -> Result<Box<dyn BusDatagramSession>, DisconnectReason> {
        self.open_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(Box::new(MockDatagramSession {
            info,
            send_count: self.send_count.clone(),
        }))
    }
}

#[tokio::test]
async fn datagram_forwarder_probe_uses_open_datagram_without_empty_send() {
    let open_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let send_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let adapter = DatagramEgressAdapter::new(Box::new(MockDatagramEgress {
        id: ExitId("mock".into()),
        open_count: open_count.clone(),
        send_count: send_count.clone(),
    }));

    let mut frame = Frame::open(
        SessionId("s-1".into()),
        Endpoint::new("127.0.0.1", 9000).unwrap(),
    );
    frame.flow_semantics = FlowSemantics::Datagram;

    let result = adapter.open_forwarder_datagram(&frame).await;

    assert!(result.is_some(), "open_forwarder_datagram must return Some");
    assert!(result.unwrap().is_ok(), "must succeed");
    assert_eq!(
        open_count.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "open_datagram called once"
    );
    assert_eq!(
        send_count.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "no empty send"
    );
}

// datagram_forwarder_unsupported_probe_falls_back_without_empty_send and
// datagram_forwarder_fixed_target_skips_scheduler_after_open and
// datagram_forwarder_replicate_stays_frame_router and
// datagram_forwarder_closed_shape_matches_opened_shape have been moved to
// crates/mesh-bus-core/tests/dispatch_datagram.rs (dispatch owner-contract, D-M7.2).

// ── M2: datagram return-semantics gate ────────────────────────────────────────

/// Data-owner-fixture: validate_datagram_request rejects SequenceReorder before
/// any egress is consulted. Owner: mesh-bus-core transport/session (validate_datagram_request).
/// Cause (c) fix: DatagramEgress public API replaces EgressPlugin backdoor.
/// Egress never called — NeverCalledDatagramEgress panics on open_datagram.
#[tokio::test]
async fn datagram_forwarder_rejects_sequence_reorder_return_semantics() {
    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_datagram_egress(Box::new(NeverCalledDatagramEgress))
        .build()
        .await;
    let port = bus.port();
    let handle = bus.spawn();
    let target = Endpoint::new("127.0.0.1", 9030).expect("target");
    let mut request = BusSessionRequest::datagram(target);
    request.return_semantics = ReturnSemantics::SequenceReorder;

    let err = match port.open_datagram(request).await {
        Ok(_) => panic!("SequenceReorder datagram must be rejected before direct open"),
        Err(err) => err,
    };

    assert_eq!(err, DisconnectReason::AddressNotSupported);
    handle.shutdown().await;
}
