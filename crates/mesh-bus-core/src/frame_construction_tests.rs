//! Data-owner fixture: Frame construction + FlowId contract.
//! Owner: mesh-bus-core lib (Frame struct, FlowId::mint_for).
//! Schema: schemas/frame.schema.json.
//! No BusBuilder, no EgressPlugin, no SchedulerPlugin.

use crate::{FlowId, Frame, FrameKind, ReturnSemantics, SessionId};
use mb_endpoint::Endpoint;

#[test]
fn packet_header_classifies_flow_from_session_and_target() {
    // Temporal-free Frame construction: proves FlowId is deterministic over
    // (session, target) and does not embed the L7 host naming atom in cleartext
    // (data-ontology F2 invariant, schemas/frame.schema.json: flow_id field).
    let session = SessionId("s-1".into());
    let target = Endpoint::new("example.com", 443).expect("valid endpoint");
    let first = Frame::data(
        session.clone(),
        7,
        target.clone(),
        bytes::Bytes::from_static(b"a"),
    );
    let second = Frame::data(session, 8, target, bytes::Bytes::from_static(b"b"));

    assert_eq!(first.packet_id.0, 7);
    assert_eq!(second.packet_id.0, 8);
    assert_eq!(first.flow_id, second.flow_id);
    assert!(
        !first.flow_id.0.contains("example.com"),
        "FlowId leaks L7 host: {}",
        first.flow_id.0
    );
    assert_eq!(
        first.flow_id,
        FlowId::mint_for(
            &SessionId("s-1".into()),
            &Endpoint::new("example.com", 443).unwrap()
        )
    );
    assert_eq!(first.return_semantics, ReturnSemantics::Direct);
    assert_eq!(second.return_semantics, ReturnSemantics::Direct);
}

#[test]
fn datagram_frame_uses_packet_dedup_return_semantics() {
    // Frame::datagram() sets PacketDedup return semantics per schema/frame contract.
    // Owner: mesh-bus-core lib; schema: schemas/frame.schema.json (return_semantics field).
    let session = SessionId("s-1".into());
    let target = Endpoint::new("example.com", 53).expect("valid endpoint");
    let frame = Frame::datagram(session, 3, target, bytes::Bytes::from_static(b"dgram"));

    assert_eq!(frame.kind, FrameKind::Datagram);
    assert_eq!(frame.return_semantics, ReturnSemantics::PacketDedup);
}
