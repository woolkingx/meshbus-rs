use super::*;
use mb_endpoint::Endpoint;

#[test]
fn packetizer_classifies_control_and_data_frames() {
    assert!(is_control_frame(&MeshFrame::StreamOpenAccepted {
        session_id: "s".into(),
        open_token: 7,
    }));
    assert!(!is_control_frame(&MeshFrame::DatagramReturn {
        session_id: "s".into(),
        seq: 1,
        source: Endpoint::new("127.0.0.1", 53).unwrap(),
        payload: Bytes::from_static(b"x"),
    }));
}
