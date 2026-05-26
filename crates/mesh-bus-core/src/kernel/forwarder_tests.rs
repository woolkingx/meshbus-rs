use super::*;

fn stream_caps() -> Capabilities {
    Capabilities {
        protocol: "tcp".into(),
        supports_stream: true,
        supports_datagram: false,
        max_payload_bytes: None,
        groups: vec![],
    }
}

fn datagram_caps() -> Capabilities {
    Capabilities {
        protocol: "udp".into(),
        supports_stream: false,
        supports_datagram: true,
        max_payload_bytes: None,
        groups: vec![],
    }
}

#[test]
fn flow_counters_per_direction_fetch_add() {
    let c = FlowCounters::new();
    c.field(Direction::Up)
        .fetch_add(64 * 1024, Ordering::Relaxed);
    c.field(Direction::Down)
        .fetch_add(32 * 1024, Ordering::Relaxed);
    let s = c.snapshot();
    assert_eq!(s.bytes_in, 32 * 1024);
    assert_eq!(s.bytes_out, 64 * 1024);
}

#[tokio::test]
async fn forwarder_close_runs_async_cleanup() {
    use std::collections::HashMap;
    use tokio::sync::Mutex;

    let flow_id = FlowId("flow-cleanup".into());
    let pins = Arc::new(Mutex::new(HashMap::from([(flow_id.clone(), 7usize)])));
    let pins_c = pins.clone();
    let flow_id_c = flow_id.clone();
    let close = ForwarderClose::new(
        Arc::new(ObservationBus::default()),
        flow_id.clone(),
        SessionId("session-cleanup".into()),
        ExitId("exit-cleanup".into()),
        Arc::new(|| 0),
        Arc::new(move || {
            let pins_c = pins_c.clone();
            let flow_id_c = flow_id_c.clone();
            Box::pin(async move {
                pins_c.lock().await.remove(&flow_id_c);
            })
        }),
        DataplaneShape::Forwarder,
    );

    close.close_once(CloseReason::SessionClosed).await;

    assert!(
        !pins.lock().await.contains_key(&flow_id),
        "close cleanup must be able to remove mutex-protected flow pins"
    );
}

#[test]
fn derive_truth_table() {
    let stream = stream_caps();
    let datagram = datagram_caps();
    let empty = TransformRequirements::default();
    let one_transform = TransformRequirements::with("encrypt");

    assert_eq!(
        DataplaneShape::derive(
            FlowSemantics::ByteStream,
            ReturnSemantics::Direct,
            1,
            &stream,
            &empty
        ),
        DataplaneShape::Forwarder
    );
    assert_eq!(
        DataplaneShape::derive(
            FlowSemantics::Datagram,
            ReturnSemantics::Direct,
            1,
            &datagram,
            &empty
        ),
        DataplaneShape::DatagramForwarder
    );
    assert_eq!(
        DataplaneShape::derive(
            FlowSemantics::Datagram,
            ReturnSemantics::PacketDedup,
            1,
            &datagram,
            &empty
        ),
        DataplaneShape::DatagramForwarder
    );
    assert_eq!(
        DataplaneShape::derive(
            FlowSemantics::Datagram,
            ReturnSemantics::SequenceReorder,
            1,
            &datagram,
            &empty,
        ),
        DataplaneShape::FrameRouter
    );
    assert_eq!(
        DataplaneShape::derive(
            FlowSemantics::Datagram,
            ReturnSemantics::PacketDedup,
            2,
            &datagram,
            &empty,
        ),
        DataplaneShape::FrameRouter
    );
    assert_eq!(
        DataplaneShape::derive(
            FlowSemantics::Datagram,
            ReturnSemantics::PacketDedup,
            1,
            &datagram,
            &one_transform,
        ),
        DataplaneShape::FrameRouter
    );
    assert_eq!(
        DataplaneShape::derive(
            FlowSemantics::ByteStream,
            ReturnSemantics::Direct,
            2,
            &stream,
            &empty
        ),
        DataplaneShape::FrameRouter
    );
    assert_eq!(
        DataplaneShape::derive(
            FlowSemantics::ByteStream,
            ReturnSemantics::Direct,
            1,
            &stream,
            &one_transform
        ),
        DataplaneShape::FrameRouter
    );
    assert_eq!(
        DataplaneShape::derive(
            FlowSemantics::ByteStream,
            ReturnSemantics::Direct,
            1,
            &datagram,
            &empty
        ),
        DataplaneShape::FrameRouter
    );
}
