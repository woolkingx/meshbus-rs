use crate::transport::forwarding::data_handle::capability_matches_flow;
use crate::transport::forwarding::types::{Capabilities, FlowSemantics};
use crate::{Frame, RankContext, SessionId};
use mb_endpoint::Endpoint;

#[test]
fn capability_filter_rejects_wrong_flow_semantics() {
    let stream_only = Capabilities {
        protocol: "tcp".into(),
        supports_stream: true,
        supports_datagram: false,
        max_payload_bytes: None,
        groups: Vec::new(),
    };
    let datagram_only = Capabilities {
        protocol: "udp".into(),
        supports_stream: false,
        supports_datagram: true,
        max_payload_bytes: None,
        groups: Vec::new(),
    };

    assert!(capability_matches_flow(
        &stream_only,
        FlowSemantics::ByteStream
    ));
    assert!(!capability_matches_flow(
        &stream_only,
        FlowSemantics::Datagram
    ));
    assert!(capability_matches_flow(
        &stream_only,
        FlowSemantics::Message
    ));

    assert!(!capability_matches_flow(
        &datagram_only,
        FlowSemantics::ByteStream
    ));
    assert!(capability_matches_flow(
        &datagram_only,
        FlowSemantics::Datagram
    ));
    assert!(capability_matches_flow(
        &datagram_only,
        FlowSemantics::Message
    ));
}

#[test]
fn rank_context_preserves_source_and_target_keys() {
    let target = Endpoint::new("example.com", 443).expect("valid endpoint");
    let session_id = SessionId("sess-1".into());
    let mut frame = Frame::open(session_id.clone(), target.clone());
    frame.source_key = Some("203.0.113.7".into());
    frame.target_key = Some("example.com".into());

    let ctx = RankContext::from(&frame);

    assert_eq!(ctx.source_key.as_deref(), Some("203.0.113.7"));
    assert_eq!(ctx.target_key.as_deref(), Some("example.com"));
    assert_eq!(ctx.packet_id, frame.packet_id);
    assert_eq!(ctx.flow_id, frame.flow_id);
    assert_eq!(ctx.session_id, session_id);
    assert_eq!(ctx.target, target);
    assert_eq!(ctx.traffic_class, frame.traffic_class);
    assert_eq!(ctx.flow_semantics, frame.flow_semantics);
    assert_eq!(ctx.return_semantics, frame.return_semantics);
    assert_eq!(ctx.schedule_hint, frame.schedule_hint);
}

#[test]
fn capabilities_groups_field_round_trip() {
    let caps = Capabilities {
        protocol: "tcp".into(),
        supports_stream: true,
        supports_datagram: false,
        max_payload_bytes: None,
        groups: vec!["cn".into(), "wan20".into()],
    };
    assert_eq!(caps.groups, vec!["cn".to_string(), "wan20".to_string()]);
    // Cloning preserves groups (Capabilities derives Clone).
    let cloned = caps.clone();
    assert_eq!(cloned.groups.len(), 2);
}
