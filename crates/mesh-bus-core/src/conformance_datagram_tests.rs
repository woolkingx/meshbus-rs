use crate::{
    BusBuilder, BusSessionRequest, Capabilities, EgressPlugin, ExitId, ExitResult, Frame,
    Measurement, RankContext, ReturnEvent, ScheduleDecision, ScheduleHint, SchedulerPlugin,
    SessionId,
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

struct EchoDatagram {
    id: ExitId,
}

#[async_trait]
impl EgressPlugin for EchoDatagram {
    fn id(&self) -> &ExitId {
        &self.id
    }

    fn capabilities(&self) -> &Capabilities {
        static CAPS: std::sync::OnceLock<Capabilities> = std::sync::OnceLock::new();
        CAPS.get_or_init(|| Capabilities {
            protocol: "conformance-datagram".into(),
            supports_stream: false,
            supports_datagram: true,
            max_payload_bytes: Some(65_507),
            groups: Vec::new(),
        })
    }

    async fn send(&self, frame: Frame) -> ExitResult {
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
async fn datagram_session_conformance_preserves_boundary_and_source() {
    let bus = BusBuilder::new()
        .scheduler(Box::new(Ordered))
        .add_egress(Box::new(EchoDatagram {
            id: ExitId("udp-a".into()),
        }))
        .build()
        .await;
    let port = bus.port();
    let handle = bus.spawn();

    let default_target = Endpoint::new("example.com", 53).expect("default target");
    let target = Endpoint::new("1.1.1.1", 53).expect("target");
    let mut session = port
        .open_datagram(BusSessionRequest::datagram(default_target))
        .await
        .expect("open datagram");
    session
        .send_to(target.clone(), Bytes::from_static(b"question"))
        .await
        .expect("send datagram");
    let (source, payload) = session.recv_from().await.expect("recv datagram");
    assert_eq!(source, target);
    assert_eq!(&payload[..], b"question");

    handle.shutdown().await;
}

#[tokio::test]
async fn datagram_session_conformance_rejects_fanout_zero() {
    let bus = BusBuilder::new()
        .scheduler(Box::new(Ordered))
        .add_egress(Box::new(EchoDatagram {
            id: ExitId("udp-a".into()),
        }))
        .build()
        .await;
    let port = bus.port();
    let handle = bus.spawn();

    let mut request = BusSessionRequest::datagram(Endpoint::new("1.1.1.1", 53).expect("target"));
    request.schedule_hint = ScheduleHint::FanOut { k: 0 };
    assert!(port.open_datagram(request).await.is_err());

    handle.shutdown().await;
}
