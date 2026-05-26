use crate::{
    Frame,
    transport::forwarding::types::{Capabilities, FlowSemantics, RankContext},
};

impl From<&Frame> for RankContext {
    fn from(frame: &Frame) -> Self {
        RankContext {
            packet_id: frame.packet_id,
            flow_id: frame.flow_id.clone(),
            session_id: frame.session_id.clone(),
            target: frame.target.clone(),
            traffic_class: frame.traffic_class,
            policy_ref: frame.policy_ref.clone(),
            deadline_ms: frame.deadline_ms,
            schedule_hint: frame.schedule_hint,
            flow_semantics: frame.flow_semantics,
            return_semantics: frame.return_semantics,
            source_key: frame.source_key.clone(),
            target_key: frame.target_key.clone(),
            source_activity: None,
        }
    }
}

/// Message-shaped flows can ride on stream or datagram egress; pure stream or
/// datagram caps must reject the opposite semantics.
pub(crate) fn capability_matches_flow(cap: &Capabilities, semantics: FlowSemantics) -> bool {
    match semantics {
        FlowSemantics::ByteStream => cap.supports_stream,
        FlowSemantics::Datagram => cap.supports_datagram,
        FlowSemantics::Message => cap.supports_stream || cap.supports_datagram,
    }
}
