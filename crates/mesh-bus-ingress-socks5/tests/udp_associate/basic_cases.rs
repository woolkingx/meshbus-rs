use super::*;

#[tokio::test]
async fn udp_associate_relays_datagram_through_bus() {
    let echo = UdpSocket::bind("127.0.0.1:0").await.expect("bind echo");
    let echo_addr = echo.local_addr().expect("echo addr");
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1024];
        loop {
            let (n, peer) = echo.recv_from(&mut buf).await.expect("recv echo");
            echo.send_to(&buf[..n], peer).await.expect("send echo");
        }
    });

    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_datagram_egress(Box::new(UdpEgress::new(
            ExitId("udp".into()),
            Duration::from_millis(500),
        )))
        .build()
        .await;
    let port = bus.port();
    let _bh = bus.spawn();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ingress");
    let bind_port = listener.local_addr().expect("ingress addr").port();
    let ingress = Socks5Ingress::new(listener);
    tokio::spawn(async move { Box::new(ingress).run(port).await.expect("ingress run") });

    let mut control = TcpStream::connect(format!("127.0.0.1:{bind_port}"))
        .await
        .expect("control connect");
    control
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("write greeting");
    let mut auth = [0u8; 2];
    control.read_exact(&mut auth).await.expect("read auth");
    assert_eq!(auth, [0x05, 0x00]);

    let udp = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind client udp");
    let udp_addr = udp.local_addr().expect("client udp addr");
    let bind = Endpoint::new(udp_addr.ip().to_string(), udp_addr.port()).expect("valid bind");
    control
        .write_all(&encode_udp_associate_request(&bind))
        .await
        .expect("write udp associate");
    let mut reply = [0u8; 10];
    control.read_exact(&mut reply).await.expect("read reply");
    assert_eq!(reply[1], 0x00, "SOCKS5 reply must be Succeeded");
    let relay_addr = parse_ipv4_reply_addr(&reply);

    let target = Endpoint::new(echo_addr.ip().to_string(), echo_addr.port()).expect("target");
    let request = encode_udp_datagram(&target, b"udp-hi");
    udp.send_to(&request, relay_addr)
        .await
        .expect("send relay packet");

    let mut buf = vec![0u8; 1024];
    let (n, _) = tokio::time::timeout(Duration::from_secs(1), udp.recv_from(&mut buf))
        .await
        .expect("recv timeout")
        .expect("recv relay response");
    let mut response = BytesMut::from(&buf[..n]);
    let datagram = decode_udp_datagram(&mut response).expect("valid relay response");
    assert_eq!(datagram.target.host(), target.host());
    assert_eq!(datagram.target.port(), target.port());
    assert_eq!(&datagram.payload[..], b"udp-hi");
}

#[tokio::test]
async fn udp_associate_with_pipeline_defers_forward_decision_until_packet_target() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_datagram_egress(Box::new(EchoEgress::new(seen.clone())))
        .build()
        .await;
    let port = bus.port();
    let _bh = bus.spawn();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ingress");
    let control_addr = listener.local_addr().expect("ingress addr");
    let ingress = Socks5Ingress::new(listener).with_pipeline(udp_packet_pipeline_runtime());
    tokio::spawn(async move { Box::new(ingress).run(port).await.expect("ingress run") });

    let udp = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind client udp");
    let udp_addr = udp.local_addr().expect("client udp addr");
    let mut control = TcpStream::connect(control_addr)
        .await
        .expect("control connect");
    let relay = negotiate_udp_associate(&mut control, udp_addr)
        .await
        .expect("associate must succeed before packet target exists");

    let target = Endpoint::new("127.0.0.1", 53).expect("target");
    let request = encode_udp_datagram(&target, b"packet-policy");
    udp.send_to(&request, relay)
        .await
        .expect("send relay packet");

    let mut buf = vec![0u8; 1024];
    let (n, _) = tokio::time::timeout(Duration::from_secs(1), udp.recv_from(&mut buf))
        .await
        .expect("recv timeout")
        .expect("recv");
    let mut response = BytesMut::from(&buf[..n]);
    let datagram = decode_udp_datagram(&mut response).expect("valid relay response");
    assert_eq!(datagram.target.host(), target.host());
    assert_eq!(datagram.target.port(), target.port());
    assert_eq!(&datagram.payload[..], b"packet-policy");
    assert_eq!(seen.lock().await.len(), 1);
}

#[tokio::test]
async fn udp_associate_rejects_datagrams_from_undeclared_peer() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let control_addr = start_socks5_udp_association(seen.clone()).await;
    let target = Endpoint::new("127.0.0.1", 53).expect("target");

    let owner = UdpSocket::bind("127.0.0.1:0").await.expect("bind owner");
    let owner_addr = owner.local_addr().expect("owner addr");
    let rogue = UdpSocket::bind("127.0.0.1:0").await.expect("bind rogue");

    let mut control = TcpStream::connect(control_addr)
        .await
        .expect("control connect");
    let relay = negotiate_udp_associate(&mut control, owner_addr)
        .await
        .expect("associate");

    let request = encode_udp_datagram(&target, b"rogue");
    rogue.send_to(&request, relay).await.expect("rogue send");

    let mut buf = vec![0u8; 1024];
    let rejected = tokio::time::timeout(Duration::from_millis(100), rogue.recv_from(&mut buf))
        .await
        .is_err();
    assert!(rejected, "rogue UDP peer must not receive a relay response");
    assert!(
        seen.lock().await.is_empty(),
        "rogue datagram must not enter the bus"
    );

    let request = encode_udp_datagram(&target, b"owner");
    owner.send_to(&request, relay).await.expect("owner send");
    let (n, _) = tokio::time::timeout(Duration::from_secs(1), owner.recv_from(&mut buf))
        .await
        .expect("owner recv timeout")
        .expect("owner recv");
    let mut response = BytesMut::from(&buf[..n]);
    let datagram = decode_udp_datagram(&mut response).expect("valid relay response");
    assert_eq!(&datagram.payload[..], b"owner");
    assert_eq!(seen.lock().await.len(), 1);
}

#[tokio::test]
async fn udp_associate_reuses_session_for_same_client_and_target() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let control_addr = start_socks5_udp_association(seen.clone()).await;
    let target = Endpoint::new("127.0.0.1", 53).expect("target");

    let udp = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
    let owner_addr = udp.local_addr().expect("owner addr");
    let mut control = TcpStream::connect(control_addr)
        .await
        .expect("control connect");
    let relay = negotiate_udp_associate(&mut control, owner_addr)
        .await
        .expect("associate");

    for payload in [b"one".as_slice(), b"two".as_slice()] {
        let request = encode_udp_datagram(&target, payload);
        udp.send_to(&request, relay).await.expect("send");
        let mut buf = vec![0u8; 1024];
        let _ = tokio::time::timeout(Duration::from_secs(1), udp.recv_from(&mut buf))
            .await
            .expect("recv timeout")
            .expect("recv");
    }

    let seen = seen.lock().await;
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].0, seen[1].0, "same target must reuse session");
    assert_eq!(seen[0].1, seen[1].1, "same target must preserve flow_id");
}

#[tokio::test]
async fn udp_associate_fails_before_success_when_bus_has_no_datagram_egress() {
    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_stream_egress(Box::new(mesh_bus_egress_tcp::TcpEgress::new(
            ExitId("tcp-only".into()),
            Duration::from_millis(100),
        )))
        .build()
        .await;
    let port = bus.port();
    let _bh = bus.spawn();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ingress");
    let control_addr = listener.local_addr().expect("ingress addr");
    let ingress = Socks5Ingress::new(listener);
    tokio::spawn(async move { Box::new(ingress).run(port).await.expect("ingress run") });

    let udp = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
    let mut control = TcpStream::connect(control_addr)
        .await
        .expect("control connect");
    control
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("write greeting");
    let mut auth = [0u8; 2];
    control.read_exact(&mut auth).await.expect("read auth");
    assert_eq!(auth, [0x05, 0x00]);

    let udp_addr = udp.local_addr().expect("udp addr");
    let bind = Endpoint::new(udp_addr.ip().to_string(), udp_addr.port()).expect("valid bind");
    control
        .write_all(&encode_udp_associate_request(&bind))
        .await
        .expect("write udp associate");
    let mut reply = [0u8; 10];
    control.read_exact(&mut reply).await.expect("read reply");
    assert_eq!(
        reply[1], 0x04,
        "missing datagram egress should be HostUnreachable"
    );
}

#[tokio::test]
async fn udp_associate_per_packet_rule_drops_denied_target() {
    // Two UDP echo sockets: "allow" + "deny". A chain that denies a specific
    // dst_port at packet evaluation time must let ASSOCIATE succeed (because
    // the declared peer port — the client's UDP source — does not match the
    // denied port) but drop relay packets aimed at the denied port. Packets to
    // the allowed port still round-trip through the bus.
    use mb_rule::{Action, MatchExpr, Predicate, Rule, RuleChain, RuleSetRegistry};
    use mesh_bus_ingress_socks5::{RulePolicy, Socks5Ingress};

    let allow_echo = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind allow echo");
    let allow_addr = allow_echo.local_addr().expect("allow addr");
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1024];
        loop {
            let (n, peer) = allow_echo
                .recv_from(&mut buf)
                .await
                .expect("recv allow echo");
            allow_echo
                .send_to(&buf[..n], peer)
                .await
                .expect("send allow echo");
        }
    });

    let deny_echo = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind deny echo");
    let deny_addr = deny_echo.local_addr().expect("deny addr");
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1024];
        loop {
            let (n, peer) = deny_echo.recv_from(&mut buf).await.expect("recv deny echo");
            deny_echo
                .send_to(&buf[..n], peer)
                .await
                .expect("send deny echo");
        }
    });

    let chain = RuleChain {
        rules: vec![Rule {
            id: Some("deny-by-port".into()),
            r#match: MatchExpr::Term(Predicate::DstPortEq(deny_addr.port())),
            action: Action::Deny,
        }],
        default: Action::Allow,
    };
    let policy = RulePolicy::new(chain, RuleSetRegistry::empty());

    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_datagram_egress(Box::new(mesh_bus_egress_udp::UdpEgress::new(
            ExitId("udp".into()),
            Duration::from_millis(500),
        )))
        .build()
        .await;
    let port = bus.port();
    let _bh = bus.spawn();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ingress");
    let control_addr = listener.local_addr().expect("ingress addr");
    let ingress = Socks5Ingress::new(listener).with_rule_policy(policy);
    tokio::spawn(async move { Box::new(ingress).run(port).await.expect("ingress run") });

    // Open a control connection + UDP socket and run ASSOCIATE.
    let mut control = TcpStream::connect(control_addr)
        .await
        .expect("control connect");
    let udp = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind client udp");
    let udp_addr = udp.local_addr().expect("client udp addr");
    // Sanity: the client's UDP port must differ from the denied target port
    // so ASSOCIATE evaluation against declared peer does not match the rule.
    assert_ne!(udp_addr.port(), deny_addr.port());

    let relay_addr = negotiate_udp_associate(&mut control, udp_addr)
        .await
        .expect("udp associate ok");

    // Packet to the DENIED port: must be dropped silently.
    let deny_target =
        Endpoint::new(deny_addr.ip().to_string(), deny_addr.port()).expect("deny target");
    udp.send_to(
        &encode_udp_datagram(&deny_target, b"denied-pkt"),
        relay_addr,
    )
    .await
    .expect("send deny relay packet");
    let mut buf = vec![0u8; 1024];
    let denied = tokio::time::timeout(Duration::from_millis(400), udp.recv_from(&mut buf)).await;
    assert!(
        denied.is_err(),
        "per-packet rule deny must drop the datagram (got {denied:?})"
    );

    // Packet to the ALLOWED port: must round-trip through the bus.
    let allow_target =
        Endpoint::new(allow_addr.ip().to_string(), allow_addr.port()).expect("allow target");
    udp.send_to(&encode_udp_datagram(&allow_target, b"ok-pkt"), relay_addr)
        .await
        .expect("send allow relay packet");
    let (n, _) = tokio::time::timeout(Duration::from_secs(1), udp.recv_from(&mut buf))
        .await
        .expect("recv allow timeout")
        .expect("recv allow response");
    let mut response = BytesMut::from(&buf[..n]);
    let datagram = decode_udp_datagram(&mut response).expect("decode allow response");
    assert_eq!(datagram.target.port(), allow_addr.port());
    assert_eq!(&datagram.payload[..], b"ok-pkt");
}
