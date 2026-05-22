use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use mb_endpoint::Endpoint;
use mb_proto_socks5::{decode_udp_datagram, encode_udp_associate_request, encode_udp_datagram};
use mb_rule::RuleSetRegistry;
use mesh_bus_core::kernel::{
    Event, HookId, HookKind, HookSpec, KernelCtx, KernelRegistry, Pipeline, PipelineId, SinkId,
    SinkSpec, SourceId, SourceSpec, Verdict, Wiring,
};
use mesh_bus_core::{
    BusBuilder, BusDatagramRecvHalf, BusDatagramSendHalf, BusSessionInfo, BusSessionRequest,
    Capabilities, DatagramEgress, DatagramSession, DisconnectReason, ExitId, ExitResult, FlowId,
    IngressPlugin, RankContext, ScheduleDecision, SchedulerPlugin, SendError, SessionId,
};
use mesh_bus_egress_udp::UdpEgress;
use mesh_bus_ingress_socks5::{PipelineRuntime, Socks5Ingress};
use mesh_bus_pipeline_hooks::context::SharedHookCtx;
use mesh_bus_resolver::cache::DnsCache;
use mesh_bus_resolver::data_handle::ResolverHandle;
use mesh_bus_resolver::types::{ResolutionSignals, ResolveAnswer, ResolveError, ResolveRequest};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;

struct First;
impl SchedulerPlugin for First {
    fn schedule(&self, c: &[ExitId], _ctx: &RankContext) -> ScheduleDecision {
        ScheduleDecision::ordered((0..c.len()).collect())
    }
    fn feedback(&self, _r: &ExitResult, _payload_bytes: u64, _at_ms: u64) {}
}

struct UnreachableResolver;

#[async_trait]
impl ResolverHandle for UnreachableResolver {
    async fn resolve(
        &self,
        _req: ResolveRequest,
    ) -> Result<(ResolveAnswer, ResolutionSignals), (ResolveError, ResolutionSignals)> {
        panic!("test hook must not invoke resolver");
    }
}

struct EchoEgress {
    id: ExitId,
    seen: Arc<Mutex<Vec<(SessionId, FlowId)>>>,
    caps: Capabilities,
}

impl EchoEgress {
    fn new(seen: Arc<Mutex<Vec<(SessionId, FlowId)>>>) -> Self {
        Self {
            id: ExitId("echo".into()),
            seen,
            caps: Capabilities {
                protocol: "test-udp".into(),
                supports_stream: false,
                supports_datagram: true,
                max_payload_bytes: None,
                groups: Vec::new(),
            },
        }
    }
}

#[async_trait]
impl DatagramEgress for EchoEgress {
    fn id(&self) -> &ExitId {
        &self.id
    }

    fn capabilities(&self) -> &Capabilities {
        &self.caps
    }

    fn max_payload_bytes(&self) -> usize {
        65_507
    }

    async fn open_datagram(
        &self,
        _request: &BusSessionRequest,
        info: BusSessionInfo,
    ) -> Result<Box<dyn DatagramSession>, DisconnectReason> {
        Ok(Box::new(EchoDatagramSession {
            seen: self.seen.clone(),
            info,
            pending: None,
        }))
    }
}

struct EchoDatagramSession {
    seen: Arc<Mutex<Vec<(SessionId, FlowId)>>>,
    info: BusSessionInfo,
    pending: Option<(Endpoint, Bytes)>,
}

// Split halves for EchoDatagramSession: send stores to a channel, recv reads from it.
struct EchoSendHalf {
    seen: Arc<Mutex<Vec<(SessionId, FlowId)>>>,
    session_id: SessionId,
    flow_id: FlowId,
    tx: tokio::sync::mpsc::UnboundedSender<(Endpoint, Bytes)>,
}

struct EchoRecvHalf {
    rx: tokio::sync::mpsc::UnboundedReceiver<(Endpoint, Bytes)>,
}

#[async_trait]
impl BusDatagramSendHalf for EchoSendHalf {
    async fn send_to(&mut self, target: Endpoint, payload: Bytes) -> Result<(), SendError> {
        self.seen
            .lock()
            .await
            .push((self.session_id.clone(), self.flow_id.clone()));
        // echo: send the packet back through the channel
        let _ = self.tx.send((target, payload));
        Ok(())
    }

    async fn close(&mut self) {}
}

#[async_trait]
impl BusDatagramRecvHalf for EchoRecvHalf {
    async fn recv_from(&mut self) -> Option<(Endpoint, Bytes)> {
        self.rx.recv().await
    }

    fn last_error(&self) -> Option<&DisconnectReason> {
        None
    }
}

#[async_trait]
impl DatagramSession for EchoDatagramSession {
    async fn send_to(&mut self, target: Endpoint, payload: Bytes) -> Result<(), SendError> {
        self.seen
            .lock()
            .await
            .push((self.info.session_id.clone(), self.info.flow_id.clone()));
        self.pending = Some((target, payload));
        Ok(())
    }

    async fn recv_from(&mut self) -> Option<(Endpoint, Bytes)> {
        self.pending.take()
    }

    fn info(&self) -> &BusSessionInfo {
        &self.info
    }

    fn max_payload_bytes(&self) -> usize {
        65_507
    }

    async fn close(&mut self) {}

    fn split(self: Box<Self>) -> (Box<dyn BusDatagramSendHalf>, Box<dyn BusDatagramRecvHalf>) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let send = Box::new(EchoSendHalf {
            seen: self.seen,
            session_id: self.info.session_id.clone(),
            flow_id: self.info.flow_id.clone(),
            tx,
        });
        let recv = Box::new(EchoRecvHalf { rx });
        (send, recv)
    }
}

fn accept_only_targeted_udp_packet(event: &mut Event, _ctx: &mut KernelCtx) -> Verdict {
    if event.meta.net.dst_port.is_none() {
        return Verdict::Reject(mesh_bus_core::kernel::Reason::code(
            "udp_control_must_not_run_forward_pipeline",
        ));
    }
    Verdict::Accept(SinkId::new("echo"))
}

fn udp_packet_pipeline_runtime() -> PipelineRuntime {
    let source = SourceId::new("ingress:0");
    let pipeline = PipelineId::new("forward");
    let hook = HookId::new("policy.udp_packet_gate");
    let sink = SinkId::new("echo");
    let mut reg = KernelRegistry::default();
    reg.sources.insert(
        source.clone(),
        SourceSpec {
            id: source.clone(),
            kind: "application/source".into(),
            initial_writes: vec![
                "net.dst_port".into(),
                "net.protocol".into(),
                "net.src_ip".into(),
                "trace.flow_id".into(),
                "ext.operation".into(),
            ],
        },
    );
    reg.sinks.insert(
        sink.clone(),
        SinkSpec {
            id: sink.clone(),
            kind: "datagram_egress".into(),
        },
    );
    reg.hooks.insert(
        hook.clone(),
        HookSpec {
            id: hook.clone(),
            kind: HookKind::Policy,
            allowed_namespaces: vec!["net.*".into()],
            reads: vec!["net.dst_port".into()],
            writes: vec![],
            may_terminate: true,
            may_jump: false,
            may_jump_to: vec![],
            may_accept_to: vec![sink],
            side_effect_only: false,
        },
    );
    reg.fns
        .insert(hook.clone(), accept_only_targeted_udp_packet);
    reg.pipelines.insert(
        pipeline.clone(),
        Pipeline {
            id: pipeline.clone(),
            hooks: vec![hook],
        },
    );
    reg.wirings.push(Wiring {
        source: source.clone(),
        pipeline,
    });

    let shared = SharedHookCtx {
        resolver: Arc::new(UnreachableResolver),
        cache: Arc::new(DnsCache::new()),
        geoip: Arc::new(mb_geoip::GeoIpDb::empty()),
        geosite: Arc::new(mb_geosite::GeositeDb::empty()),
        rule_chain: Arc::new(mb_rule::RuleChain {
            rules: vec![],
            default: mb_rule::Action::Allow,
        }),
        rule_sets: Arc::new(RuleSetRegistry::empty()),
        candidates: Arc::new(vec![]),
        tokio: tokio::runtime::Handle::current(),
    };
    PipelineRuntime::new(shared, Arc::new(reg), source).expect("pipeline runtime")
}

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

async fn start_socks5_udp_association(seen: Arc<Mutex<Vec<(SessionId, FlowId)>>>) -> SocketAddr {
    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_datagram_egress(Box::new(EchoEgress::new(seen)))
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

    control_addr
}

async fn negotiate_udp_associate(
    control: &mut TcpStream,
    declared_peer: SocketAddr,
) -> Result<SocketAddr, std::io::Error> {
    control.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut auth = [0u8; 2];
    control.read_exact(&mut auth).await?;
    assert_eq!(auth, [0x05, 0x00]);

    let bind = Endpoint::new(declared_peer.ip().to_string(), declared_peer.port())
        .expect("declared peer endpoint");
    control
        .write_all(&encode_udp_associate_request(&bind))
        .await?;
    let mut reply = [0u8; 10];
    control.read_exact(&mut reply).await?;
    assert_eq!(reply[1], 0x00, "SOCKS5 reply must be Succeeded");
    Ok(parse_ipv4_reply_addr(&reply))
}

fn parse_ipv4_reply_addr(reply: &[u8; 10]) -> SocketAddr {
    assert_eq!(reply[0], 0x05);
    assert_eq!(reply[3], 0x01);
    let ip = IpAddr::V4(Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]));
    let port = u16::from_be_bytes([reply[8], reply[9]]);
    SocketAddr::new(ip, port)
}

// Session whose recv_from blocks indefinitely — used to prove send does not lockstep.
struct SlowRecvSession {
    send_count: Arc<std::sync::atomic::AtomicU32>,
    info: BusSessionInfo,
}

struct SlowRecvSendHalf {
    send_count: Arc<std::sync::atomic::AtomicU32>,
}

struct SlowRecvRecvHalf;

#[async_trait]
impl BusDatagramSendHalf for SlowRecvSendHalf {
    async fn send_to(&mut self, _target: Endpoint, _payload: Bytes) -> Result<(), SendError> {
        self.send_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    async fn close(&mut self) {}
}

#[async_trait]
impl BusDatagramRecvHalf for SlowRecvRecvHalf {
    async fn recv_from(&mut self) -> Option<(Endpoint, Bytes)> {
        // Block forever — simulates a slow / never-responding upstream.
        std::future::pending::<Option<(Endpoint, Bytes)>>().await
    }

    fn last_error(&self) -> Option<&DisconnectReason> {
        None
    }
}

#[async_trait]
impl DatagramSession for SlowRecvSession {
    async fn send_to(&mut self, _target: Endpoint, _payload: Bytes) -> Result<(), SendError> {
        self.send_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    async fn recv_from(&mut self) -> Option<(Endpoint, Bytes)> {
        std::future::pending::<Option<(Endpoint, Bytes)>>().await
    }

    fn info(&self) -> &BusSessionInfo {
        &self.info
    }

    fn max_payload_bytes(&self) -> usize {
        65_507
    }

    async fn close(&mut self) {}

    fn split(self: Box<Self>) -> (Box<dyn BusDatagramSendHalf>, Box<dyn BusDatagramRecvHalf>) {
        (
            Box::new(SlowRecvSendHalf {
                send_count: self.send_count,
            }),
            Box::new(SlowRecvRecvHalf),
        )
    }
}

#[tokio::test]
async fn udp_associate_same_target_sends_do_not_wait_for_first_response() {
    // Two UDP datagrams to the same target with a never-responding upstream.
    // With lockstep send/recv, the second send would hang waiting for recv_from.
    // With split pump, both sends must complete within the timeout.
    let send_count = Arc::new(std::sync::atomic::AtomicU32::new(0));

    struct SlowEgress {
        id: ExitId,
        send_count: Arc<std::sync::atomic::AtomicU32>,
        caps: Capabilities,
    }

    #[async_trait]
    impl DatagramEgress for SlowEgress {
        fn id(&self) -> &ExitId {
            &self.id
        }
        fn capabilities(&self) -> &Capabilities {
            &self.caps
        }
        fn max_payload_bytes(&self) -> usize {
            65_507
        }
        async fn open_datagram(
            &self,
            _request: &BusSessionRequest,
            info: BusSessionInfo,
        ) -> Result<Box<dyn DatagramSession>, DisconnectReason> {
            Ok(Box::new(SlowRecvSession {
                send_count: self.send_count.clone(),
                info,
            }))
        }
    }

    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_datagram_egress(Box::new(SlowEgress {
            id: ExitId("slow".into()),
            send_count: send_count.clone(),
            caps: Capabilities {
                protocol: "test-slow".into(),
                supports_stream: false,
                supports_datagram: true,
                max_payload_bytes: None,
                groups: Vec::new(),
            },
        }))
        .build()
        .await;
    let port = bus.port();
    let _bh = bus.spawn();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let control_addr = listener.local_addr().expect("addr");
    let ingress = Socks5Ingress::new(listener);
    tokio::spawn(async move { Box::new(ingress).run(port).await.expect("ingress run") });

    let udp = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
    let udp_addr = udp.local_addr().expect("udp addr");
    let mut control = TcpStream::connect(control_addr).await.expect("connect");
    let relay = negotiate_udp_associate(&mut control, udp_addr)
        .await
        .expect("associate");

    let target = Endpoint::new("127.0.0.1", 5353).expect("target");

    // Send two packets to the same target without waiting for a response.
    // Both must reach the egress (send_count == 2) within the timeout.
    tokio::time::timeout(Duration::from_secs(2), async {
        let pkt1 = encode_udp_datagram(&target, b"first");
        udp.send_to(&pkt1, relay).await.expect("send first");
        let pkt2 = encode_udp_datagram(&target, b"second");
        udp.send_to(&pkt2, relay).await.expect("send second");

        // Poll until both sends arrive at the egress (with backoff).
        loop {
            if send_count.load(std::sync::atomic::Ordering::SeqCst) >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("both sends must reach egress without waiting for recv");

    assert_eq!(
        send_count.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "both datagrams must be forwarded to the egress"
    );
}

/// Build a raw SOCKS5 UDP relay header with a non-zero FRAG field (fragmented datagram).
/// Format: RSV(2) FRAG(1) ATYP(1) ADDR(4) PORT(2) DATA
fn build_fragmented_udp_packet(
    frag: u8,
    target_ip: [u8; 4],
    target_port: u16,
    data: &[u8],
) -> Vec<u8> {
    let mut pkt = vec![0x00, 0x00, frag, 0x01];
    pkt.extend_from_slice(&target_ip);
    pkt.extend_from_slice(&target_port.to_be_bytes());
    pkt.extend_from_slice(data);
    pkt
}

#[tokio::test]
async fn udp_associate_discards_fragmented_datagrams() {
    // SOCKS5 UDP relay packets with FRAG != 0 must be silently discarded.
    // The codec returns CodecError::UnsupportedFragment, forward_udp_packet drops it.
    let seen = Arc::new(Mutex::new(Vec::new()));
    let control_addr = start_socks5_udp_association(seen.clone()).await;

    let udp = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
    let owner_addr = udp.local_addr().expect("owner addr");
    let mut control = TcpStream::connect(control_addr)
        .await
        .expect("control connect");
    let relay = negotiate_udp_associate(&mut control, owner_addr)
        .await
        .expect("associate");

    // Send a fragmented packet (FRAG=1) — must be discarded.
    let frag_pkt = build_fragmented_udp_packet(1, [127, 0, 0, 1], 53, b"fragmented");
    udp.send_to(&frag_pkt, relay)
        .await
        .expect("send fragmented packet");

    // No response expected within timeout.
    let mut buf = vec![0u8; 1024];
    let discarded = tokio::time::timeout(Duration::from_millis(200), udp.recv_from(&mut buf))
        .await
        .is_err();
    assert!(
        discarded,
        "fragmented UDP datagram must be silently discarded"
    );
    assert!(
        seen.lock().await.is_empty(),
        "fragmented datagram must not reach the bus"
    );

    // Session must still work: send a valid FRAG=0 packet and get it echoed.
    let target = Endpoint::new("127.0.0.1", 53).expect("target");
    let ok_pkt = encode_udp_datagram(&target, b"ok");
    udp.send_to(&ok_pkt, relay).await.expect("send ok packet");
    let (n, _) = tokio::time::timeout(Duration::from_secs(1), udp.recv_from(&mut buf))
        .await
        .expect("recv ok timeout")
        .expect("recv ok");
    let mut response = BytesMut::from(&buf[..n]);
    let datagram = decode_udp_datagram(&mut response).expect("decode ok response");
    assert_eq!(&datagram.payload[..], b"ok");
    assert_eq!(
        seen.lock().await.len(),
        1,
        "valid packet must reach the bus"
    );
}

#[tokio::test]
async fn udp_relay_cleaned_up_when_control_tcp_closes() {
    // After the control TCP connection closes, the relay UDP task must be aborted.
    // Subsequent UDP packets to the relay address must not get a response.
    let seen = Arc::new(Mutex::new(Vec::new()));
    let control_addr = start_socks5_udp_association(seen.clone()).await;

    let udp = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
    let owner_addr = udp.local_addr().expect("owner addr");
    let mut control = TcpStream::connect(control_addr)
        .await
        .expect("control connect");
    let relay = negotiate_udp_associate(&mut control, owner_addr)
        .await
        .expect("associate");

    // Confirm relay works before closing control.
    let target = Endpoint::new("127.0.0.1", 53).expect("target");
    udp.send_to(&encode_udp_datagram(&target, b"before"), relay)
        .await
        .expect("send before");
    let mut buf = vec![0u8; 1024];
    let (n, _) = tokio::time::timeout(Duration::from_secs(1), udp.recv_from(&mut buf))
        .await
        .expect("recv before timeout")
        .expect("recv before");
    let mut response = BytesMut::from(&buf[..n]);
    let datagram = decode_udp_datagram(&mut response).expect("decode before");
    assert_eq!(&datagram.payload[..], b"before");

    // Close control TCP.
    drop(control);

    // Give the ingress a moment to detect the TCP close and abort the relay task.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Further UDP packets must not get responses (relay is gone).
    udp.send_to(&encode_udp_datagram(&target, b"after"), relay)
        .await
        .expect("send after");
    let no_response = tokio::time::timeout(Duration::from_millis(300), udp.recv_from(&mut buf))
        .await
        .is_err();
    assert!(
        no_response,
        "relay must not respond after control TCP closes"
    );
}

#[tokio::test]
async fn udp_associate_multi_target_remains_framerouter_safe() {
    // Two independent UDP echo servers on distinct ports.
    let echo1 = UdpSocket::bind("127.0.0.1:0").await.expect("bind echo1");
    let port1 = echo1.local_addr().expect("echo1 addr").port();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            let (n, peer) = echo1.recv_from(&mut buf).await.expect("recv echo1");
            echo1.send_to(&buf[..n], peer).await.expect("send echo1");
        }
    });

    let echo2 = UdpSocket::bind("127.0.0.1:0").await.expect("bind echo2");
    let port2 = echo2.local_addr().expect("echo2 addr").port();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            let (n, peer) = echo2.recv_from(&mut buf).await.expect("recv echo2");
            echo2.send_to(&buf[..n], peer).await.expect("send echo2");
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
    let control_addr = listener.local_addr().expect("ingress addr");
    let ingress = Socks5Ingress::new(listener);
    tokio::spawn(async move { Box::new(ingress).run(port).await.expect("ingress run") });

    let udp = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
    let udp_addr = udp.local_addr().expect("client addr");
    let mut control = TcpStream::connect(control_addr)
        .await
        .expect("control connect");
    let relay = negotiate_udp_associate(&mut control, udp_addr)
        .await
        .expect("associate");

    let target1 = Endpoint::new("127.0.0.1", port1).expect("target1");
    let target2 = Endpoint::new("127.0.0.1", port2).expect("target2");
    let mut buf = vec![0u8; 1024];

    udp.send_to(&encode_udp_datagram(&target1, b"pkt-a"), relay)
        .await
        .expect("send to target1");
    let (n, _) = tokio::time::timeout(Duration::from_secs(1), udp.recv_from(&mut buf))
        .await
        .expect("recv target1 timeout")
        .expect("recv target1");
    let datagram = decode_udp_datagram(&mut BytesMut::from(&buf[..n])).expect("decode target1");
    assert_eq!(&datagram.payload[..], b"pkt-a");
    assert_eq!(datagram.target.port(), port1);

    udp.send_to(&encode_udp_datagram(&target2, b"pkt-b"), relay)
        .await
        .expect("send to target2");
    let (n, _) = tokio::time::timeout(Duration::from_secs(1), udp.recv_from(&mut buf))
        .await
        .expect("recv target2 timeout")
        .expect("recv target2");
    let datagram = decode_udp_datagram(&mut BytesMut::from(&buf[..n])).expect("decode target2");
    assert_eq!(&datagram.payload[..], b"pkt-b");
    assert_eq!(datagram.target.port(), port2);
}

#[tokio::test]
async fn evicted_udp_target_pump_is_aborted() {
    // Drive more than MAX_UDP_TARGET_SESSIONS (256) distinct targets through
    // one association. Each evicted target's response pump owns its own
    // recv-half clone, so Arc-drop alone never stops it; eviction must
    // explicitly abort it. Functional proxy: every distinct-target roundtrip
    // still completes within a bounded time and returns its own payload — a
    // leaked/abandoned pump or a deadlock under eviction churn would hang or
    // corrupt one of the later roundtrips.
    let seen = Arc::new(Mutex::new(Vec::new()));
    let control_addr = start_socks5_udp_association(seen.clone()).await;

    let udp = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
    let owner_addr = udp.local_addr().expect("owner addr");
    let mut control = TcpStream::connect(control_addr)
        .await
        .expect("control connect");
    let relay = negotiate_udp_associate(&mut control, owner_addr)
        .await
        .expect("associate");

    // 300 > MAX_UDP_TARGET_SESSIONS (256): forces ~44 evictions.
    const N: u16 = 300;
    let mut buf = vec![0u8; 1024];
    for i in 1..=N {
        let target = Endpoint::new("127.0.0.1", i).expect("target");
        let payload = format!("pkt-{i}");
        udp.send_to(&encode_udp_datagram(&target, payload.as_bytes()), relay)
            .await
            .expect("send relay packet");
        let (n, _) = tokio::time::timeout(Duration::from_secs(1), udp.recv_from(&mut buf))
            .await
            .expect("roundtrip must not hang under eviction churn")
            .expect("recv relay response");
        let datagram =
            decode_udp_datagram(&mut BytesMut::from(&buf[..n])).expect("valid relay response");
        assert_eq!(datagram.target.port(), i, "roundtrip {i} target port");
        assert_eq!(
            &datagram.payload[..],
            payload.as_bytes(),
            "roundtrip {i} payload"
        );
    }
}
