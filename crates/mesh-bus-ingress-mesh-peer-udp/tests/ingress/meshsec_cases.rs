use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn meshsec_sealed_datagram_reenters_bus_and_seals_return() {
    let echo_port = spawn_udp_echo().await;
    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_datagram_egress(Box::new(UdpEgress::new(
            ExitId("udp".into()),
            Duration::from_millis(500),
        )))
        .build()
        .await;
    let port = bus.port();
    let _handle = bus.spawn();
    let ingress_addr = spawn_keyed_ingress(port).await;

    let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
    let target = endpoint("127.0.0.1", echo_port);

    let open = seal_as_node_a(
        &MeshFrame::DatagramOpen(mb_proto_mesh::DatagramOpen {
            session_id: "sec-d-1".into(),
            fixed_target: Some(target.clone()),
            max_datagram_bytes: 1200,
        }),
        TEST_KEY,
        1,
    );
    peer.send_to(&open, ingress_addr).await.expect("send open");

    let send = seal_as_node_a(
        &MeshFrame::DatagramSend {
            session_id: "sec-d-1".into(),
            seq: 7,
            target: target.clone(),
            payload: Bytes::from_static(b"hello"),
        },
        TEST_KEY,
        2,
    );
    peer.send_to(&send, ingress_addr)
        .await
        .expect("send datagram");

    let mut buf = vec![0u8; 2048];
    let (n, _) = peer.recv_from(&mut buf).await.expect("recv sealed return");
    // The wire bytes must not be a clear Mesh frame.
    assert!(
        decode_frame(&mut BytesMut::from(&buf[..n])).is_err(),
        "DatagramReturn must travel sealed, not in clear"
    );
    let returned = open_reverse_reply(&buf[..n]);
    assert_eq!(
        returned,
        MeshFrame::DatagramReturn {
            session_id: "sec-d-1".into(),
            seq: 1,
            source: target,
            payload: Bytes::from_static(b"hello"),
        }
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn meshsec_native_datagram_return_uses_ordered_seq() {
    let echo_port = spawn_udp_echo().await;
    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_datagram_egress(Box::new(mesh_bus_egress_udp::UdpEgress::new(
            ExitId("udp".into()),
            Duration::from_millis(500),
        )))
        .build()
        .await;
    let port = bus.port();
    let _handle = bus.spawn();
    let ingress_addr = spawn_keyed_native_ingress(port).await;
    let target = Endpoint::new("127.0.0.1", echo_port).expect("target");
    let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");

    let open = seal_native_as_node_a(
        &MeshFrame::DatagramOpen(mb_proto_mesh::DatagramOpen {
            session_id: "sec-native-d-1".into(),
            fixed_target: Some(target.clone()),
            max_datagram_bytes: 1200,
        }),
        TEST_KEY,
        1,
    );
    peer.send_to(&open, ingress_addr)
        .await
        .expect("send native open");

    let send = seal_native_as_node_a(
        &MeshFrame::DatagramSend {
            session_id: "sec-native-d-1".into(),
            seq: 1,
            target: target.clone(),
            payload: Bytes::from_static(b"native-hello"),
        },
        TEST_KEY,
        2,
    );
    peer.send_to(&send, ingress_addr)
        .await
        .expect("send native datagram");

    let mut buf = vec![0u8; 2048];
    let (n, _) = peer
        .recv_from(&mut buf)
        .await
        .expect("recv native sealed return");
    let returned = open_reverse_native_reply(&buf[..n]);
    assert_eq!(
        returned,
        MeshFrame::DatagramReturn {
            session_id: "sec-native-d-1".into(),
            seq: 1,
            source: target,
            payload: Bytes::from_static(b"native-hello"),
        }
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn meshsec_stream_response_pump_has_no_artificial_per_chunk_delay() {
    let payload = Bytes::from(vec![9u8; 40_000]);
    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_stream_egress(Box::new(BurstStreamEgress::new(payload.clone())))
        .build()
        .await;
    let port = bus.port();
    let _handle = bus.spawn();
    let ingress_addr = spawn_keyed_ingress(port).await;

    let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
    let open = seal_as_node_a(
        &MeshFrame::StreamOpen(StreamOpen {
            session_id: "sec-s-fast".into(),
            open_token: 44,
            target: endpoint("example.com", 443),
            route_group: None,
            flow_semantics: FlowSemanticsWire::ByteStream,
            return_semantics: ReturnSemanticsWire::Direct,
            source_node_id: "node-a".into(),
            path_trace: vec!["node-a".into()],
        }),
        TEST_KEY,
        1,
    );
    peer.send_to(&open, ingress_addr)
        .await
        .expect("send stream open");

    let collect = async {
        let mut received = Vec::new();
        loop {
            let mut buf = vec![0u8; 2048];
            let (n, _) = peer
                .recv_from(&mut buf)
                .await
                .expect("recv sealed stream reply");
            match open_reverse_reply(&buf[..n]) {
                MeshFrame::StreamOpenAccepted { .. } => {}
                MeshFrame::StreamData { payload, .. } => {
                    received.extend_from_slice(&payload);
                    if received.len() >= 40_000 {
                        return received;
                    }
                }
                other => panic!("unexpected stream reply {other:?}"),
            }
        }
    };

    let received = tokio::time::timeout(Duration::from_millis(500), collect)
        .await
        .expect("sealed response pump must not sleep once per small chunk");
    assert_eq!(received, payload);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn meshsec_clear_and_wrong_key_packets_are_dropped() {
    let echo_port = spawn_udp_echo().await;
    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_datagram_egress(Box::new(UdpEgress::new(
            ExitId("udp".into()),
            Duration::from_millis(500),
        )))
        .build()
        .await;
    let port = bus.port();
    let _handle = bus.spawn();
    let ingress_addr = spawn_keyed_ingress(port).await;

    let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
    let target = endpoint("127.0.0.1", echo_port);

    // Clear (unsealed) frames must be dropped when MeshSec keys are configured.
    let clear_open = encode_frame(&MeshFrame::DatagramOpen(mb_proto_mesh::DatagramOpen {
        session_id: "clear-1".into(),
        fixed_target: Some(target.clone()),
        max_datagram_bytes: 1200,
    }))
    .expect("encode clear open");
    peer.send_to(&clear_open, ingress_addr)
        .await
        .expect("send clear open");
    let clear_send = encode_frame(&MeshFrame::DatagramSend {
        session_id: "clear-1".into(),
        seq: 1,
        target: target.clone(),
        payload: Bytes::from_static(b"clear"),
    })
    .expect("encode clear send");
    peer.send_to(&clear_send, ingress_addr)
        .await
        .expect("send clear send");

    // Wrong-key sealed frames must never open a bus session.
    let wrong = seal_as_node_a(
        &MeshFrame::DatagramOpen(mb_proto_mesh::DatagramOpen {
            session_id: "wrong-1".into(),
            fixed_target: Some(target.clone()),
            max_datagram_bytes: 1200,
        }),
        [1u8; 32],
        1,
    );
    peer.send_to(&wrong, ingress_addr)
        .await
        .expect("send wrong-key open");

    let mut buf = vec![0u8; 2048];
    let quiet = tokio::time::timeout(Duration::from_millis(300), peer.recv_from(&mut buf)).await;
    assert!(
        quiet.is_err(),
        "clear and wrong-key packets must not produce any datagram return"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn meshsec_wrong_key_and_replay_publish_drop_events_without_sessions() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_datagram_egress(Box::new(UdpEgress::new(
            ExitId("udp".into()),
            Duration::from_millis(500),
        )))
        .add_observer(Box::new(DropRecorder {
            events: events.clone(),
        }))
        .build()
        .await;
    let port = bus.port();
    let handle = bus.spawn();
    let ingress_addr = spawn_keyed_ingress(port).await;

    let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
    let target = endpoint("127.0.0.1", spawn_udp_echo().await);
    let wrong = seal_as_node_a(
        &MeshFrame::DatagramOpen(mb_proto_mesh::DatagramOpen {
            session_id: "wrong-obs".into(),
            fixed_target: Some(target),
            max_datagram_bytes: 1200,
        }),
        [1u8; 32],
        44,
    );
    peer.send_to(&wrong, ingress_addr)
        .await
        .expect("send wrong-key open");
    let auth = wait_for_drop_reason(&events, OBS_MESHSEC_DROP, "auth").await;
    assert_eq!(auth.payload.0.secure, Some(true));

    let port_open = seal_as_node_a(
        &MeshFrame::PortOpen(mb_proto_mesh::ReceiverMouth {
            mouth_id: "mouth-a".into(),
            udp_addr: "127.0.0.1:19000".into(),
            family_filter: vec!["control".into()],
            advertised_capacity: 1,
            epoch: 1,
        }),
        TEST_KEY,
        45,
    );
    peer.send_to(&port_open, ingress_addr)
        .await
        .expect("send port open");
    peer.send_to(&port_open, ingress_addr)
        .await
        .expect("send replayed port open");
    let replay = wait_for_drop_reason(&events, OBS_MESHSEC_DROP, "replay").await;
    assert_eq!(replay.payload.0.source_addr.is_some(), true);

    let snapshot = handle.snapshot().await;
    assert_eq!(snapshot.dispatch_success, 0);
    assert_eq!(snapshot.dispatch_failure, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_native_packet_publishes_native_drop_without_session() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_datagram_egress(Box::new(UdpEgress::new(
            ExitId("udp".into()),
            Duration::from_millis(500),
        )))
        .add_observer(Box::new(DropRecorder {
            events: events.clone(),
        }))
        .build()
        .await;
    let port = bus.port();
    let handle = bus.spawn();

    let ingress_loop = UdpPacketLoop::bind("127.0.0.1:0".parse().expect("ingress bind addr"))
        .await
        .expect("bind mesh ingress");
    let ingress_addr = ingress_loop.local_addr().expect("ingress addr");
    let ingress = MeshPeerUdpIngress::new(ingress_loop)
        .with_native_event_mode(NativeEventMode::SecureUdpNative);
    tokio::spawn(async move {
        let _ = Box::new(ingress).run(port).await;
    });

    let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
    peer.send_to(b"not-a-native-event", ingress_addr)
        .await
        .expect("send malformed native packet");
    let event = wait_for_drop_reason(&events, OBS_NATIVE_DROP, "event_decode").await;
    assert_eq!(event.payload.0.secure, Some(false));

    let snapshot = handle.snapshot().await;
    assert_eq!(snapshot.dispatch_success, 0);
    assert_eq!(snapshot.dispatch_failure, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_data_before_open_is_bounded_and_observable() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_datagram_egress(Box::new(UdpEgress::new(
            ExitId("udp".into()),
            Duration::from_millis(500),
        )))
        .add_observer(Box::new(DropRecorder {
            events: events.clone(),
        }))
        .build()
        .await;
    let port = bus.port();
    let handle = bus.spawn();

    let ingress_loop = UdpPacketLoop::bind("127.0.0.1:0".parse().expect("ingress bind addr"))
        .await
        .expect("bind mesh ingress");
    let ingress_addr = ingress_loop.local_addr().expect("ingress addr");
    let ingress = MeshPeerUdpIngress::new(ingress_loop)
        .with_native_event_mode(NativeEventMode::MeshFrame)
        .with_pending_stream_data_max_bytes(8);
    tokio::spawn(async move {
        let _ = Box::new(ingress).run(port).await;
    });

    let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
    for seq in 1..=3 {
        let data = encode_frame(&MeshFrame::StreamData {
            session_id: "missing-open".into(),
            seq,
            payload: Bytes::from_static(b"abcdef"),
        })
        .expect("encode stream data");
        peer.send_to(&data, ingress_addr)
            .await
            .expect("send stream data");
    }

    let event = wait_for_drop_reason(&events, OBS_NATIVE_DROP, "stream_data_pending").await;
    assert_eq!(event.payload.0.secure, Some(false));

    let snapshot = handle.snapshot().await;
    assert_eq!(snapshot.dispatch_success, 0);
    assert_eq!(snapshot.dispatch_failure, 0);
}
