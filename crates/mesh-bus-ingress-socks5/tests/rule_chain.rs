//! Integration test: SOCKS5 ingress + mb-rule chain.
//! Verifies REP 0x02 ConnectionNotAllowed on Deny (CONNECT and UDP ASSOCIATE),
//! allowed traffic still completes the SOCKS5 handshake, and
//! `SetRouteGroup` projection actually pins dispatch to a group-tagged egress.

use mb_endpoint::Endpoint;
use mb_proto_socks5::{
    Command, Method, encode_connect_request, encode_greeting, encode_udp_associate_request,
};
use mb_rule::{Action, MatchExpr, Predicate, Rule, RuleChain, RuleSetRegistry, RuleSocks5Command};
use mesh_bus_core::{
    BusBuilder, BusSessionInfo, BusSessionRequest, Capabilities, DisconnectReason, ExitId,
    ExitResult, IngressPlugin, RankContext, ScheduleDecision, SchedulerPlugin, StreamEgress,
    StreamRecvHalf, StreamSendHalf, StreamSession,
};
use mesh_bus_ingress_socks5::{AuthConfig, RulePolicy, Socks5Ingress};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// ── First-exit scheduler ─────────────────────────────────────────────────────

struct First;
impl SchedulerPlugin for First {
    fn schedule(&self, c: &[ExitId], _ctx: &RankContext) -> ScheduleDecision {
        ScheduleDecision::ordered((0..c.len()).collect())
    }
    fn feedback(&self, _r: &ExitResult, _payload_bytes: u64, _at_ms: u64) {}
}

// ── Inert StreamEgress that opens but produces no upstream bytes ──────────────

struct InertEgress {
    id: ExitId,
    caps: Capabilities,
    opens: Arc<AtomicUsize>,
}

impl InertEgress {
    fn new(id: &str, groups: Vec<String>) -> (Self, Arc<AtomicUsize>) {
        let opens = Arc::new(AtomicUsize::new(0));
        let caps = Capabilities {
            protocol: "test".into(),
            supports_stream: true,
            supports_datagram: false,
            max_payload_bytes: None,
            groups,
        };
        (
            Self {
                id: ExitId(id.into()),
                caps,
                opens: opens.clone(),
            },
            opens,
        )
    }
}

#[async_trait::async_trait]
impl StreamEgress for InertEgress {
    fn id(&self) -> &ExitId {
        &self.id
    }
    fn capabilities(&self) -> &Capabilities {
        &self.caps
    }
    async fn open_stream(
        &self,
        _request: &BusSessionRequest,
        info: BusSessionInfo,
    ) -> Result<Box<dyn StreamSession>, DisconnectReason> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(InertSession { info, last: None }))
    }
}

struct InertSession {
    info: BusSessionInfo,
    last: Option<DisconnectReason>,
}

#[async_trait::async_trait]
impl StreamSession for InertSession {
    async fn connect(&mut self) -> Result<&BusSessionInfo, DisconnectReason> {
        Ok(&self.info)
    }
    fn into_tcp_splice(
        self: Box<Self>,
    ) -> Result<mesh_bus_core::TcpSpliceSession, Box<dyn StreamSession>> {
        Err(self)
    }
    fn split(self: Box<Self>) -> (Box<dyn StreamSendHalf>, Box<dyn StreamRecvHalf>) {
        (Box::new(InertSend), Box::new(InertRecv { last: self.last }))
    }
    async fn abort(&mut self, reason: DisconnectReason) {
        self.last = Some(reason);
    }
    fn info(&self) -> &BusSessionInfo {
        &self.info
    }
    fn last_error(&self) -> Option<&DisconnectReason> {
        self.last.as_ref()
    }
}

struct InertSend;
#[async_trait::async_trait]
impl StreamSendHalf for InertSend {
    async fn send(&mut self, _payload: bytes::Bytes) -> Result<(), DisconnectReason> {
        Ok(())
    }
    async fn shutdown_write(&mut self) {}
    async fn abort(&mut self, _reason: DisconnectReason) {}
}

struct InertRecv {
    last: Option<DisconnectReason>,
}
#[async_trait::async_trait]
impl StreamRecvHalf for InertRecv {
    async fn recv(&mut self) -> Option<bytes::Bytes> {
        None
    }
    fn last_error(&self) -> Option<&DisconnectReason> {
        self.last.as_ref()
    }
}

// ── Rule chains under test ───────────────────────────────────────────────────

fn block_chain() -> RuleChain {
    RuleChain {
        rules: vec![Rule {
            id: None,
            r#match: MatchExpr::Term(Predicate::HostnameExact("blocked.example.com".into())),
            action: Action::Deny,
        }],
        default: Action::Allow,
    }
}

fn block_udp_chain() -> RuleChain {
    RuleChain {
        rules: vec![Rule {
            id: None,
            r#match: MatchExpr::Term(Predicate::Socks5CommandEq(RuleSocks5Command::UdpAssociate)),
            action: Action::Deny,
        }],
        default: Action::Allow,
    }
}

fn auth_user_chain() -> RuleChain {
    RuleChain {
        rules: vec![Rule {
            id: Some("vip-by-auth".into()),
            r#match: MatchExpr::Term(Predicate::AuthenticatedUserEq("alice".into())),
            action: Action::SetRouteGroup("vip".into()),
        }],
        default: Action::Allow,
    }
}

fn cn_route_chain() -> RuleChain {
    RuleChain {
        rules: vec![Rule {
            id: None,
            r#match: MatchExpr::Term(Predicate::HostnameSuffix(".cn".into())),
            action: Action::SetRouteGroup("cn".into()),
        }],
        default: Action::Allow,
    }
}

// ── Spawn helpers ────────────────────────────────────────────────────────────

async fn spawn_with_single_inert(chain: RuleChain) -> u16 {
    let (egress, _opens) = InertEgress::new("e", Vec::new());
    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_stream_egress(Box::new(egress))
        .build()
        .await;
    let port = bus.port();
    let _bh = bus.spawn();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let bind_port = listener.local_addr().expect("addr").port();
    let policy = RulePolicy::new(chain, RuleSetRegistry::default());
    let ingress = Socks5Ingress::new(listener).with_rule_policy(policy);
    tokio::spawn(async move {
        Box::new(ingress).run(port).await.expect("run");
    });
    bind_port
}

struct MultiEgressHandle {
    bind_port: u16,
    cn_opens: Arc<AtomicUsize>,
    default_opens: Arc<AtomicUsize>,
}

async fn spawn_with_cn_and_default(chain: RuleChain) -> MultiEgressHandle {
    let (cn_egress, cn_opens) = InertEgress::new("cn-exit", vec!["cn".into()]);
    let (default_egress, default_opens) = InertEgress::new("default-exit", Vec::new());
    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_stream_egress(Box::new(default_egress))
        .add_stream_egress(Box::new(cn_egress))
        .build()
        .await;
    let port = bus.port();
    let _bh = bus.spawn();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let bind_port = listener.local_addr().expect("addr").port();
    let policy = RulePolicy::new(chain, RuleSetRegistry::default());
    let ingress = Socks5Ingress::new(listener).with_rule_policy(policy);
    tokio::spawn(async move {
        Box::new(ingress).run(port).await.expect("run");
    });
    MultiEgressHandle {
        bind_port,
        cn_opens,
        default_opens,
    }
}

async fn spawn_with_auth_and_chain(chain: RuleChain, auth: AuthConfig) -> MultiEgressHandle {
    let (vip_egress, vip_opens) = InertEgress::new("vip-exit", vec!["vip".into()]);
    let (default_egress, default_opens) = InertEgress::new("default-exit", Vec::new());
    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_stream_egress(Box::new(default_egress))
        .add_stream_egress(Box::new(vip_egress))
        .build()
        .await;
    let port = bus.port();
    let _bh = bus.spawn();
    std::mem::forget(_bh);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let bind_port = listener.local_addr().expect("addr").port();
    let policy = RulePolicy::new(chain, RuleSetRegistry::default());
    let ingress = Socks5Ingress::new(listener)
        .with_rule_policy(policy)
        .with_auth(auth);
    tokio::spawn(async move {
        Box::new(ingress).run(port).await.expect("run");
    });
    MultiEgressHandle {
        bind_port,
        cn_opens: vip_opens,
        default_opens,
    }
}

async fn handshake_connect_with_auth(
    bind_port: u16,
    target: &Endpoint,
    user: &str,
    pass: &str,
) -> [u8; 2] {
    let mut client = TcpStream::connect(format!("127.0.0.1:{bind_port}"))
        .await
        .expect("client connect");
    client
        .write_all(&[0x05, 0x01, 0x02])
        .await
        .expect("write greeting");
    let mut method = [0u8; 2];
    client
        .read_exact(&mut method)
        .await
        .expect("read method reply");
    assert_eq!(method, [0x05, 0x02], "server must select UserPass");
    let ub = user.as_bytes();
    let pb = pass.as_bytes();
    let mut subneg = Vec::with_capacity(3 + ub.len() + pb.len());
    subneg.push(0x01);
    subneg.push(ub.len() as u8);
    subneg.extend_from_slice(ub);
    subneg.push(pb.len() as u8);
    subneg.extend_from_slice(pb);
    client.write_all(&subneg).await.expect("write subneg");
    let mut sub_reply = [0u8; 2];
    client
        .read_exact(&mut sub_reply)
        .await
        .expect("read subneg reply");
    assert_eq!(sub_reply, [0x01, 0x00], "subneg must succeed");

    let req = encode_connect_request(target);
    client.write_all(&req).await.expect("write connect");
    let mut reply = [0u8; 10];
    client
        .read_exact(&mut reply)
        .await
        .expect("read connect reply");
    [reply[0], reply[1]]
}

async fn handshake_connect(bind_port: u16, target: &Endpoint) -> [u8; 2] {
    let mut client = TcpStream::connect(format!("127.0.0.1:{bind_port}"))
        .await
        .expect("client connect");
    client
        .write_all(&encode_greeting(&[Method::NoAuth]))
        .await
        .expect("write greeting");
    let mut auth = [0u8; 2];
    client.read_exact(&mut auth).await.expect("read auth");
    assert_eq!(auth, [0x05, 0x00]);
    client
        .write_all(&encode_connect_request(target))
        .await
        .expect("write connect");
    let mut head = [0u8; 2];
    client.read_exact(&mut head).await.expect("read reply head");
    head
}

async fn handshake_udp_associate(bind_port: u16, bind: &Endpoint) -> [u8; 2] {
    let mut client = TcpStream::connect(format!("127.0.0.1:{bind_port}"))
        .await
        .expect("client connect");
    client
        .write_all(&encode_greeting(&[Method::NoAuth]))
        .await
        .expect("write greeting");
    let mut auth = [0u8; 2];
    client.read_exact(&mut auth).await.expect("read auth");
    assert_eq!(auth, [0x05, 0x00]);
    client
        .write_all(&encode_udp_associate_request(bind))
        .await
        .expect("write udp associate");
    let mut head = [0u8; 2];
    client.read_exact(&mut head).await.expect("read reply head");
    head
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn connect_denied_by_rule_returns_connection_not_allowed() {
    let bind_port = spawn_with_single_inert(block_chain()).await;
    let target = Endpoint::new("blocked.example.com", 443).expect("ep");
    let head = handshake_connect(bind_port, &target).await;
    assert_eq!(head[0], 0x05);
    assert_eq!(head[1], 0x02, "expected ConnectionNotAllowed REP");
}

#[tokio::test]
async fn connect_allowed_by_rule_completes_handshake() {
    let bind_port = spawn_with_single_inert(block_chain()).await;
    let target = Endpoint::new("allowed.example.com", 443).expect("ep");
    let head = handshake_connect(bind_port, &target).await;
    assert_eq!(head[0], 0x05);
    assert_eq!(head[1], 0x00, "expected Succeeded REP");
}

#[tokio::test]
async fn udp_associate_denied_by_rule_returns_connection_not_allowed() {
    let bind_port = spawn_with_single_inert(block_udp_chain()).await;
    let bind = Endpoint::new("127.0.0.1", 1).expect("ep");
    let head = handshake_udp_associate(bind_port, &bind).await;
    assert_eq!(head[0], 0x05);
    assert_eq!(
        head[1], 0x02,
        "UDP ASSOCIATE deny must short-circuit to ConnectionNotAllowed before relay bind"
    );
}

#[tokio::test]
async fn connect_to_cn_suffix_pins_to_cn_route_group() {
    let handle = spawn_with_cn_and_default(cn_route_chain()).await;
    let target = Endpoint::new("foo.cn", 443).expect("ep");
    let head = handshake_connect(handle.bind_port, &target).await;
    assert_eq!(head[0], 0x05);
    assert_eq!(head[1], 0x00, "expected Succeeded REP");

    // Give dispatch a beat to settle; open_stream runs on the bus task.
    for _ in 0..50 {
        if handle.cn_opens.load(Ordering::SeqCst) > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(
        handle.cn_opens.load(Ordering::SeqCst),
        1,
        "cn-tagged egress should serve foo.cn"
    );
    assert_eq!(
        handle.default_opens.load(Ordering::SeqCst),
        0,
        "default egress must be filtered out by route_group=cn"
    );
}

#[tokio::test]
async fn connect_without_group_match_falls_through_to_default_egress() {
    let handle = spawn_with_cn_and_default(cn_route_chain()).await;
    let target = Endpoint::new("foo.us", 443).expect("ep");
    let head = handshake_connect(handle.bind_port, &target).await;
    assert_eq!(head[0], 0x05);
    assert_eq!(head[1], 0x00, "expected Succeeded REP");

    for _ in 0..50 {
        if handle.default_opens.load(Ordering::SeqCst) > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    // Without route_group, scheduler ordered() picks index 0 (default-exit registered first).
    assert_eq!(
        handle.default_opens.load(Ordering::SeqCst),
        1,
        "default egress should serve foo.us"
    );
    assert_eq!(
        handle.cn_opens.load(Ordering::SeqCst),
        0,
        "cn-tagged egress must not serve non-cn host"
    );
}

#[tokio::test]
async fn authenticated_user_pins_to_vip_route_group() {
    let auth = AuthConfig::new().with_user("alice", "s3cret");
    let handle = spawn_with_auth_and_chain(auth_user_chain(), auth).await;
    let target = Endpoint::new("example.com", 443).expect("ep");
    let head = handshake_connect_with_auth(handle.bind_port, &target, "alice", "s3cret").await;
    assert_eq!(head[0], 0x05);
    assert_eq!(head[1], 0x00, "expected Succeeded REP");

    for _ in 0..50 {
        if handle.cn_opens.load(Ordering::SeqCst) > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(
        handle.cn_opens.load(Ordering::SeqCst),
        1,
        "vip-tagged egress should serve alice"
    );
    assert_eq!(
        handle.default_opens.load(Ordering::SeqCst),
        0,
        "default egress must be filtered out by route_group=vip"
    );
}

#[allow(dead_code)]
fn _force_command_use() {
    let _ = Command::Connect;
}
