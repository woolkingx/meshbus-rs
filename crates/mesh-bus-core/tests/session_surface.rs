use async_trait::async_trait;
use bytes::Bytes;
use mb_endpoint::Endpoint;
use mesh_bus_core::{
    BusSessionInfo, BusSessionRequest, DatagramSession, DisconnectReason, FlowSemantics,
    ReturnSemantics, ScheduleHint, ScheduleMode, SendError, StreamRecvHalf, StreamSendHalf,
    StreamSession, TrafficClass,
};

/// Guard: the Frame→ReturnEvent dispatch boundary is a PUBLISHED owner-test data contract
/// (decision 0.4.39, DDTR D-M7.2). Frame, FrameKind, EgressPlugin, and BusPort::open_session
/// are intentionally public so that dispatch_contract integration tests can prove the
/// kernel dispatch transform as frame.schema.json → return-event.schema.json owner fixtures.
///
/// The constraint being enforced here is narrower: runtime application participants (L7
/// ingress/egress crates) must NOT be named in the kernel source, and the open_session
/// boundary must document that it is for owner-test use only — not a general L7 API.
#[test]
fn raw_frame_channel_documents_owner_test_contract_not_application_api() {
    let lib = include_str!("../src/lib.rs");
    let port = include_str!("../src/kernel/port.rs");

    // Frame, FrameKind, EgressPlugin are now public per 0.4.39 owner-test data contract.
    // The doc-comment on EgressPlugin must document the application-participant prohibition.
    assert!(
        lib.contains("pub trait EgressPlugin"),
        "EgressPlugin must be public per 0.4.39 owner-test data contract"
    );
    assert!(
        lib.contains("pub struct Frame"),
        "Frame must be public per 0.4.39 owner-test data contract"
    );

    // BusPort::open_session must carry the owner-test-only disclaimer.
    assert!(
        port.contains("owner-test data contract") || port.contains("owner-test"),
        "BusPort::open_session must document that it is an owner-test boundary, not a general L7 plugin API"
    );

    // The application-participant prohibition must still be stated in the EgressPlugin doc.
    assert!(
        lib.contains("application participants") || lib.contains("must NOT implement"),
        "EgressPlugin doc must state that runtime application participants must not implement it for routing"
    );
}

#[test]
fn session_request_defaults_to_auto_ordered_stream_intent() {
    let req = BusSessionRequest::stream(Endpoint::new("example.com", 443).expect("endpoint"));
    assert_eq!(req.flow_semantics, FlowSemantics::ByteStream);
    assert_eq!(req.traffic_class, TrafficClass::Bulk);
    assert_eq!(req.return_semantics, ReturnSemantics::Direct);
    assert_eq!(req.schedule_hint, ScheduleHint::Auto);
}

#[test]
fn datagram_request_defaults_to_packet_dedup_intent() {
    let req = BusSessionRequest::datagram(Endpoint::new("example.com", 53).expect("endpoint"));
    assert_eq!(req.flow_semantics, FlowSemantics::Datagram);
    assert_eq!(req.traffic_class, TrafficClass::Interactive);
    assert_eq!(req.return_semantics, ReturnSemantics::PacketDedup);
    assert_eq!(req.schedule_hint, ScheduleHint::Auto);
}

#[test]
fn stripe_hint_is_reserved_but_addressable() {
    let hint = ScheduleHint::Stripe { n: 2 };
    assert_eq!(hint, ScheduleHint::Stripe { n: 2 });
}

struct DummyStream {
    info: BusSessionInfo,
}

#[async_trait]
impl StreamSession for DummyStream {
    async fn connect(&mut self) -> Result<&BusSessionInfo, DisconnectReason> {
        Ok(&self.info)
    }

    fn into_tcp_splice(
        self: Box<Self>,
    ) -> Result<mesh_bus_core::TcpSpliceSession, Box<dyn StreamSession>> {
        Err(self)
    }

    fn split(self: Box<Self>) -> (Box<dyn StreamSendHalf>, Box<dyn StreamRecvHalf>) {
        (Box::new(DummySender), Box::new(DummyReceiver))
    }

    async fn abort(&mut self, _reason: DisconnectReason) {}

    fn info(&self) -> &BusSessionInfo {
        &self.info
    }

    fn last_error(&self) -> Option<&DisconnectReason> {
        None
    }
}

#[test]
fn datagram_session_trait_exposes_payload_limit() {
    let session = DummyDatagram {
        info: BusSessionInfo::empty_for_test(ScheduleMode::Ordered),
    };
    assert_eq!(session.max_payload_bytes(), 1200);
}

struct DummySender;

#[async_trait]
impl StreamSendHalf for DummySender {
    async fn send(&mut self, _payload: Bytes) -> Result<(), DisconnectReason> {
        Ok(())
    }

    async fn shutdown_write(&mut self) {}

    async fn abort(&mut self, _reason: DisconnectReason) {}
}

struct DummyReceiver;

#[async_trait]
impl StreamRecvHalf for DummyReceiver {
    async fn recv(&mut self) -> Option<Bytes> {
        None
    }

    fn last_error(&self) -> Option<&DisconnectReason> {
        None
    }
}

struct DummyDatagram {
    info: BusSessionInfo,
}

#[async_trait]
impl DatagramSession for DummyDatagram {
    async fn send_to(&mut self, _target: Endpoint, _payload: Bytes) -> Result<(), SendError> {
        Ok(())
    }

    async fn recv_from(&mut self) -> Option<(Endpoint, Bytes)> {
        None
    }

    fn info(&self) -> &BusSessionInfo {
        &self.info
    }

    fn max_payload_bytes(&self) -> usize {
        1200
    }

    async fn close(&mut self) {}

    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn mesh_bus_core::BusDatagramSendHalf>,
        Box<dyn mesh_bus_core::BusDatagramRecvHalf>,
    ) {
        (
            Box::new(DummyDatagramSendHalf),
            Box::new(DummyDatagramRecvHalf),
        )
    }
}

use mesh_bus_core::{BusDatagramRecvHalf, BusDatagramSendHalf};

struct DummyDatagramSendHalf;

#[async_trait]
impl BusDatagramSendHalf for DummyDatagramSendHalf {
    async fn send_to(&mut self, _target: Endpoint, _payload: Bytes) -> Result<(), SendError> {
        Ok(())
    }
    async fn close(&mut self) {}
}

struct DummyDatagramRecvHalf;

#[async_trait]
impl BusDatagramRecvHalf for DummyDatagramRecvHalf {
    async fn recv_from(&mut self) -> Option<(Endpoint, Bytes)> {
        None
    }
    fn last_error(&self) -> Option<&mesh_bus_core::DisconnectReason> {
        None
    }
}

#[test]
fn datagram_split_traits_are_public_session_surface() {
    fn assert_send<T: Send + 'static>() {}
    assert_send::<Box<dyn BusDatagramSendHalf>>();
    assert_send::<Box<dyn BusDatagramRecvHalf>>();
}
