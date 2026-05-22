use crate::{
    BusBuilder, Capabilities, DisconnectReason, EgressPlugin, ExitId, ExitResult, Frame, FrameKind,
    Measurement, RankContext, ReturnEvent, ScheduleDecision, ScheduleHint, SchedulerPlugin,
    SessionId, transport::session::types::BusSessionRequest,
};
use async_trait::async_trait;
use bytes::Bytes;
use mb_endpoint::Endpoint;
use std::sync::Arc;
use tokio::sync::Mutex;

// ── Shared test helpers ───────────────────────────────────────────────────────

struct First;

impl SchedulerPlugin for First {
    fn schedule(&self, candidates: &[ExitId], _ctx: &RankContext) -> ScheduleDecision {
        ScheduleDecision::ordered((0..candidates.len()).collect())
    }
    fn feedback(&self, _result: &ExitResult, _payload_bytes: u64, _at_ms: u64) {}
}

struct EchoStream {
    id: ExitId,
}

#[async_trait]
impl EgressPlugin for EchoStream {
    fn id(&self) -> &ExitId {
        &self.id
    }
    fn capabilities(&self) -> &Capabilities {
        static CAPS: std::sync::OnceLock<Capabilities> = std::sync::OnceLock::new();
        CAPS.get_or_init(|| Capabilities {
            protocol: "test-stream".into(),
            supports_stream: true,
            supports_datagram: false,
            max_payload_bytes: None,
            groups: Vec::new(),
        })
    }
    async fn send(&self, frame: Frame) -> ExitResult {
        ExitResult {
            exit_id: self.id.clone(),
            success: true,
            rtt_ms: 1,
            local_endpoint: Some(Endpoint::new("127.0.0.1", 49200).expect("local")),
            return_event: if matches!(frame.kind, FrameKind::Open) {
                ReturnEvent::Idle
            } else {
                ReturnEvent::Data {
                    seq: frame.seq,
                    payload: frame.payload,
                }
            },
        }
    }
    async fn poll(&self, _: &SessionId) -> ReturnEvent {
        ReturnEvent::Idle
    }
    async fn probe(&self, _: &Endpoint) -> Measurement {
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
            protocol: "test-udp".into(),
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
    async fn probe(&self, _: &Endpoint) -> Measurement {
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

// ── stream connect returns path info ─────────────────────────────────────────

#[tokio::test]
async fn stream_connect_returns_path_info() {
    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_egress(Box::new(EchoStream {
            id: ExitId("e0".into()),
        }))
        .build()
        .await;
    let port = bus.port();
    let handle = bus.spawn();

    let mut session = port
        .open_stream(BusSessionRequest::stream(
            Endpoint::new("example.com", 443).expect("target"),
        ))
        .await
        .expect("open stream");
    let info = session.connect().await.expect("connect");
    assert!(
        !info.paths.is_empty(),
        "paths must be populated after connect"
    );
    assert_eq!(info.paths[info.primary].exit_id, ExitId("e0".into()));
    assert_eq!(info.paths[info.primary].local.port(), 49200);

    handle.shutdown().await;
}

// ── stream half-close keeps read side open ────────────────────────────────────

#[tokio::test]
async fn stream_half_close_keeps_read_side_open() {
    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_egress(Box::new(EchoStream {
            id: ExitId("e1".into()),
        }))
        .build()
        .await;
    let port = bus.port();
    let handle = bus.spawn();

    let mut session = port
        .open_stream(BusSessionRequest::stream(
            Endpoint::new("example.com", 80).expect("target"),
        ))
        .await
        .expect("open stream");
    session.connect().await.expect("connect");
    let (mut send, mut recv) = session.split();

    send.send(Bytes::from_static(b"ping")).await.expect("send");
    let payload = recv.recv().await.expect("recv after send");
    assert_eq!(&payload[..], b"ping");

    // shutdown_write flushes a ShutdownWrite frame; the recv half stays alive
    send.shutdown_write().await;
    drop(recv);

    handle.shutdown().await;
}

// ── datagram send_to preserves packet target as recv source ───────────────────

#[tokio::test]
async fn datagram_send_to_preserves_packet_target_as_recv_source() {
    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_egress(Box::new(EchoDatagram {
            id: ExitId("udp0".into()),
            seen: None,
        }))
        .build()
        .await;
    let port = bus.port();
    let handle = bus.spawn();

    let session_target = Endpoint::new("127.0.0.1", 9000).expect("session target");
    let packet_target = Endpoint::new("127.0.0.2", 9001).expect("packet target");
    let mut session = port
        .open_datagram(BusSessionRequest::datagram(session_target))
        .await
        .expect("open datagram");

    session
        .send_to(packet_target.clone(), Bytes::from_static(b"query"))
        .await
        .expect("send_to");
    let (source, payload) = session.recv_from().await.expect("recv_from");

    assert_eq!(
        source, packet_target,
        "recv source must match send_to target"
    );
    assert_eq!(&payload[..], b"query");

    handle.shutdown().await;
}

// ── datagram split: seq-keyed source map survives out-of-order returns ────────

#[tokio::test]
async fn datagram_split_maps_out_of_order_returns_by_seq() {
    let target_a = Endpoint::new("127.0.0.1", 10001).expect("target_a");
    let target_b = Endpoint::new("127.0.0.1", 10002).expect("target_b");

    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_egress(Box::new(EchoDatagram {
            id: ExitId("udp-split".into()),
            seen: None,
        }))
        .build()
        .await;
    let port = bus.port();
    let handle = bus.spawn();

    let session_target = Endpoint::new("127.0.0.1", 9999).expect("session target");
    let session = port
        .open_datagram(BusSessionRequest::datagram(session_target))
        .await
        .expect("open datagram");

    let (mut send_half, mut recv_half) = session.split();

    // send target_a first (seq=0), then target_b (seq=1)
    send_half
        .send_to(target_a.clone(), Bytes::from_static(b"from-a"))
        .await
        .expect("send_a");
    send_half
        .send_to(target_b.clone(), Bytes::from_static(b"from-b"))
        .await
        .expect("send_b");

    // EchoDatagram echoes in send order; recv_from should map seq→source correctly
    let (src0, pay0) = recv_half.recv_from().await.expect("recv 0");
    let (src1, pay1) = recv_half.recv_from().await.expect("recv 1");

    assert_eq!(src0, target_a, "first recv source must be target_a");
    assert_eq!(&pay0[..], b"from-a");
    assert_eq!(src1, target_b, "second recv source must be target_b");
    assert_eq!(&pay1[..], b"from-b");

    handle.shutdown().await;
}

// ── route_group default and builder ──────────────────────────────────────────

#[test]
fn route_group_default_none_and_builder_sets() {
    let target = Endpoint::parse("1.2.3.4:80").expect("endpoint");
    let req = BusSessionRequest::stream(target.clone());
    assert!(req.route_group.is_none());
    let req2 = BusSessionRequest::stream(target).with_route_group("cn");
    assert_eq!(req2.route_group.as_deref(), Some("cn"));
}

// ── FanOut k=0 is rejected ────────────────────────────────────────────────────

#[tokio::test]
async fn datagram_fanout_zero_is_rejected() {
    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_egress(Box::new(EchoDatagram {
            id: ExitId("udp1".into()),
            seen: None,
        }))
        .build()
        .await;
    let port = bus.port();
    let handle = bus.spawn();

    let mut request =
        BusSessionRequest::datagram(Endpoint::new("127.0.0.1", 9000).expect("target"));
    request.schedule_hint = ScheduleHint::FanOut { k: 0 };

    match port.open_datagram(request).await {
        Ok(_) => panic!("FanOut k=0 must be rejected"),
        Err(e) => assert_eq!(e, DisconnectReason::AddressNotSupported),
    }

    handle.shutdown().await;
}

#[tokio::test]
async fn probe_submit_failure_reclaims_probe_channel() {
    use crate::kernel::forwarder::{
        DatagramForwarderProbeOutcome, ForwarderDatagramState, ForwarderStreamState,
    };
    use crate::kernel::session_handle::SessionHandle;
    use crate::transport::forwarding::types::ScheduleMode;
    use crate::transport::session::datagram_halves::InternalDatagramSession;
    use crate::transport::session::types::{BusDatagramSession, BusSessionInfo, SendError};
    use dashmap::DashMap;
    use tokio::sync::{mpsc, oneshot};

    let target = Endpoint::new("example.com", 9000).expect("valid endpoint");
    let (submit_tx, submit_rx) = mpsc::channel::<Frame>(4);
    let (_ret_tx, ret_rx) = mpsc::channel::<ReturnEvent>(4);
    let probe_channels: Arc<DashMap<SessionId, oneshot::Sender<DatagramForwarderProbeOutcome>>> =
        Arc::new(DashMap::new());
    let probe_obs = probe_channels.clone();
    let handle = SessionHandle {
        id: SessionId("leak-test".into()),
        submit: submit_tx,
        returns: ret_rx,
        forwarder_streams: Arc::new(DashMap::<SessionId, ForwarderStreamState>::new()),
        forwarder_datagrams: Arc::new(DashMap::<SessionId, ForwarderDatagramState>::new()),
        probe_channels,
    };
    // Force the probe submit to fail by dropping the Frame receiver.
    drop(submit_rx);

    let request = BusSessionRequest::datagram(target.clone());
    let info = BusSessionInfo::empty_for_test(ScheduleMode::Ordered);
    let mut session = InternalDatagramSession::new(handle, request, info, 1500);

    let result = session.send_to(target, Bytes::from_static(b"x")).await;
    assert!(
        matches!(result, Err(SendError::Closed)),
        "probe submit failure must report Closed, got {result:?}"
    );
    assert!(
        probe_obs.is_empty(),
        "probe_channels entry leaked after submit failure"
    );
}
