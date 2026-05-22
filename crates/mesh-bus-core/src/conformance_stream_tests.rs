use crate::{
    BusBuilder, BusSessionRequest, Capabilities, EgressPlugin, ExitId, ExitResult, Frame,
    FrameKind, Measurement, RankContext, ReturnEvent, ScheduleDecision, SchedulerPlugin, SessionId,
};
use async_trait::async_trait;
use bytes::Bytes;
use mb_endpoint::Endpoint;

struct Ordered;

impl SchedulerPlugin for Ordered {
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
            protocol: "conformance-stream".into(),
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
            local_endpoint: Some(Endpoint::new("127.0.0.1", 49152).expect("local endpoint")),
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

#[tokio::test]
async fn stream_session_conformance_connect_send_recv_and_path_info() {
    let bus = BusBuilder::new()
        .scheduler(Box::new(Ordered))
        .add_egress(Box::new(EchoStream {
            id: ExitId("stream-a".into()),
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
    assert_eq!(info.paths[info.primary].exit_id, ExitId("stream-a".into()));
    assert_eq!(info.paths[info.primary].local.port(), 49152);

    let (mut send, mut recv) = session.split();
    send.send(Bytes::from_static(b"hello")).await.expect("send");
    let payload = recv.recv().await.expect("recv");
    assert_eq!(&payload[..], b"hello");

    handle.shutdown().await;
}
