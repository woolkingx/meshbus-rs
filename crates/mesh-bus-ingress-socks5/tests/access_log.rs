//! Decision-trace assertion: after a CONNECT, the SOCKS5 ingress emits a
//! "connect_open" log line carrying matched_rule_id, matched_rule_index,
//! default_used, action, route_group, schedule_hint.
//!
//! Uses a JSON tracing subscriber routed to an in-memory buffer, then parses
//! each line as JSON and looks up the connect_open record.

use mb_endpoint::Endpoint;
use mb_proto_socks5::{Command, Method, encode_connect_request, encode_greeting};
use mb_rule::{Action, MatchExpr, Predicate, Rule, RuleChain, RuleSetRegistry};
use mesh_bus_core::{
    BusBuilder, BusSessionInfo, BusSessionRequest, Capabilities, DisconnectReason, ExitId,
    ExitResult, IngressPlugin, RankContext, ScheduleDecision, SchedulerPlugin, StreamEgress,
    StreamRecvHalf, StreamSendHalf, StreamSession,
};
use mesh_bus_ingress_socks5::{RulePolicy, Socks5Ingress};
use std::io;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing_subscriber::fmt::MakeWriter;

// ── Shared in-memory log buffer + MakeWriter ─────────────────────────────────

#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl Buffer {
    fn snapshot_lines(&self) -> Vec<serde_json::Value> {
        let bytes = self.0.lock().expect("buffer lock").clone();
        let text = String::from_utf8_lossy(&bytes).into_owned();
        text.lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .collect()
    }
}

impl io::Write for Buffer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().expect("buffer lock").extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Buffer {
    type Writer = Buffer;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

// ── Inert StreamEgress (copied; isolated to keep test self-contained) ────────

struct First;
impl SchedulerPlugin for First {
    fn schedule(&self, c: &[ExitId], _ctx: &RankContext) -> ScheduleDecision {
        ScheduleDecision::ordered((0..c.len()).collect())
    }
    fn feedback(&self, _r: &ExitResult, _payload_bytes: u64, _at_ms: u64) {}
}

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

// ── Rule chain: cn-suffix → cn route_group; default deny ─────────────────────

fn cn_chain() -> RuleChain {
    RuleChain {
        rules: vec![Rule {
            id: Some("cn-traffic".into()),
            r#match: MatchExpr::Term(Predicate::HostnameSuffix(".cn".into())),
            action: Action::SetRouteGroup("cn".into()),
        }],
        default: Action::Allow,
    }
}

fn deny_blocked_chain() -> RuleChain {
    RuleChain {
        rules: vec![Rule {
            id: Some("block-bad".into()),
            r#match: MatchExpr::Term(Predicate::HostnameExact("blocked.example.com".into())),
            action: Action::Deny,
        }],
        default: Action::Allow,
    }
}

fn default_deny_chain() -> RuleChain {
    RuleChain {
        rules: Vec::new(),
        default: Action::Deny,
    }
}

// ── Test ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn connect_open_log_carries_decision_trace_fields() {
    // Wire a process-local subscriber. set_default returns a DefaultGuard;
    // keep it alive across the whole CONNECT to capture spawned-task logs too.
    let buffer = Buffer::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_writer(buffer.clone())
        .with_target(true)
        .with_ansi(false)
        .with_level(true)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let (cn_egress, _cn_opens) = InertEgress::new("cn-exit", vec!["cn".into()]);
    let (default_egress, _default_opens) = InertEgress::new("default-exit", Vec::new());
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
    let policy = RulePolicy::new(cn_chain(), RuleSetRegistry::default());
    let ingress = Socks5Ingress::new(listener).with_rule_policy(policy);
    tokio::spawn(async move {
        Box::new(ingress).run(port).await.expect("run");
    });

    let target = Endpoint::new("example.cn", 443).expect("ep");
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
        .write_all(&encode_connect_request(&target))
        .await
        .expect("write connect");
    // Read the full 10-byte reply so the server has definitely executed log_connect_open.
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.expect("read reply");
    assert_eq!(reply[0], 0x05);
    assert_eq!(reply[1], 0x00, "CONNECT should succeed");

    let lines = buffer.snapshot_lines();
    let open = lines
        .iter()
        .find(|v| {
            v.get("fields")
                .and_then(|f| f.get("message"))
                .and_then(|m| m.as_str())
                == Some("connect_open")
        })
        .unwrap_or_else(|| panic!("no connect_open log line; got {} lines", lines.len()));

    let fields = open.get("fields").expect("fields");
    assert_eq!(
        fields.get("matched_rule_id").and_then(|v| v.as_str()),
        Some("cn-traffic")
    );
    assert_eq!(
        fields.get("matched_rule_index").and_then(|v| v.as_str()),
        Some("0")
    );
    assert_eq!(
        fields.get("default_used").and_then(|v| v.as_bool()),
        Some(false)
    );
    assert_eq!(
        fields.get("action").and_then(|v| v.as_str()),
        Some("set_route_group:cn")
    );
    assert_eq!(
        fields.get("route_group").and_then(|v| v.as_str()),
        Some("cn")
    );
    assert_eq!(
        fields.get("schedule_hint").and_then(|v| v.as_str()),
        Some("auto")
    );
}

#[tokio::test]
async fn flow_opened_log_carries_dispatch_trace_fields() {
    let buffer = Buffer::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_writer(buffer.clone())
        .with_target(true)
        .with_ansi(false)
        .with_level(true)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let (cn_egress, _cn_opens) = InertEgress::new("cn-exit", vec!["cn".into()]);
    let (default_egress, _default_opens) = InertEgress::new("default-exit", Vec::new());
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
    let policy = RulePolicy::new(cn_chain(), RuleSetRegistry::default());
    let ingress = Socks5Ingress::new(listener).with_rule_policy(policy);
    tokio::spawn(async move {
        Box::new(ingress).run(port).await.expect("run");
    });

    let target = Endpoint::new("example.cn", 443).expect("ep");
    let mut client = TcpStream::connect(format!("127.0.0.1:{bind_port}"))
        .await
        .expect("client connect");
    client
        .write_all(&encode_greeting(&[Method::NoAuth]))
        .await
        .expect("write greeting");
    let mut auth = [0u8; 2];
    client.read_exact(&mut auth).await.expect("read auth");
    client
        .write_all(&encode_connect_request(&target))
        .await
        .expect("write connect");
    // Read the full 10-byte reply to ensure the server has executed log_flow_opened.
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.expect("read reply");

    let lines = buffer.snapshot_lines();
    let dispatch = lines
        .iter()
        .find(|v| {
            v.get("fields")
                .and_then(|f| f.get("message"))
                .and_then(|m| m.as_str())
                == Some("flow_opened")
        })
        .unwrap_or_else(|| panic!("no flow_opened log line; got {} lines", lines.len()));

    let fields = dispatch.get("fields").expect("fields");
    // exit_id and selected_exit must both be present and identical (mirror by design).
    let exit_id = fields
        .get("exit_id")
        .and_then(|v| v.as_str())
        .expect("exit_id");
    let selected = fields
        .get("selected_exit")
        .and_then(|v| v.as_str())
        .expect("selected_exit");
    assert_eq!(exit_id, selected);
    assert_eq!(
        selected, "cn-exit",
        "route_group should pin to the cn-tagged exit"
    );

    assert!(
        fields.get("flow_id").and_then(|v| v.as_str()).is_some(),
        "flow_id missing"
    );
    assert!(fields.get("packet_id").is_some(), "packet_id missing");
    assert_eq!(
        fields.get("route_group").and_then(|v| v.as_str()),
        Some("cn")
    );
    assert_eq!(
        fields.get("schedule_hint").and_then(|v| v.as_str()),
        Some("auto")
    );
    assert!(
        fields
            .get("candidate_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
            >= 1,
        "candidate_count should be >= 1"
    );
    assert_eq!(fields.get("success").and_then(|v| v.as_bool()), Some(true));
}

#[tokio::test]
async fn connect_denied_log_carries_matched_rule_and_action_deny() {
    let buffer = Buffer::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_writer(buffer.clone())
        .with_target(true)
        .with_ansi(false)
        .with_level(true)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

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
    let policy = RulePolicy::new(deny_blocked_chain(), RuleSetRegistry::default());
    let ingress = Socks5Ingress::new(listener).with_rule_policy(policy);
    tokio::spawn(async move {
        Box::new(ingress).run(port).await.expect("run");
    });

    let target = Endpoint::new("blocked.example.com", 443).expect("ep");
    let mut client = TcpStream::connect(format!("127.0.0.1:{bind_port}"))
        .await
        .expect("client connect");
    client
        .write_all(&encode_greeting(&[Method::NoAuth]))
        .await
        .expect("write greeting");
    let mut auth = [0u8; 2];
    client.read_exact(&mut auth).await.expect("read auth");
    client
        .write_all(&encode_connect_request(&target))
        .await
        .expect("write connect");
    // Read full 10-byte reply so the server has definitely executed the deny log.
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.expect("read reply");
    assert_eq!(reply[1], 0x02, "expected ConnectionNotAllowed REP");

    let lines = buffer.snapshot_lines();
    let denied = lines
        .iter()
        .find(|v| {
            v.get("fields")
                .and_then(|f| f.get("message"))
                .and_then(|m| m.as_str())
                == Some("connect_denied_by_rule")
        })
        .unwrap_or_else(|| panic!("no connect_denied_by_rule log line"));

    let fields = denied.get("fields").expect("fields");
    assert_eq!(
        fields.get("matched_rule_id").and_then(|v| v.as_str()),
        Some("block-bad")
    );
    assert_eq!(
        fields.get("matched_rule_index").and_then(|v| v.as_str()),
        Some("0")
    );
    assert_eq!(
        fields.get("default_used").and_then(|v| v.as_bool()),
        Some(false)
    );
    assert_eq!(fields.get("action").and_then(|v| v.as_str()), Some("deny"));
}

#[tokio::test]
async fn connect_default_deny_log_marks_default_used_true() {
    let buffer = Buffer::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_writer(buffer.clone())
        .with_target(true)
        .with_ansi(false)
        .with_level(true)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

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
    let policy = RulePolicy::new(default_deny_chain(), RuleSetRegistry::default());
    let ingress = Socks5Ingress::new(listener).with_rule_policy(policy);
    tokio::spawn(async move {
        Box::new(ingress).run(port).await.expect("run");
    });

    let target = Endpoint::new("anything.example.com", 443).expect("ep");
    let mut client = TcpStream::connect(format!("127.0.0.1:{bind_port}"))
        .await
        .expect("client connect");
    client
        .write_all(&encode_greeting(&[Method::NoAuth]))
        .await
        .expect("write greeting");
    let mut auth = [0u8; 2];
    client.read_exact(&mut auth).await.expect("read auth");
    client
        .write_all(&encode_connect_request(&target))
        .await
        .expect("write connect");
    // Read full 10-byte reply so the server has definitely executed the deny log.
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.expect("read reply");
    assert_eq!(
        reply[1], 0x02,
        "default deny should map to ConnectionNotAllowed"
    );

    let lines = buffer.snapshot_lines();
    let denied = lines
        .iter()
        .find(|v| {
            v.get("fields")
                .and_then(|f| f.get("message"))
                .and_then(|m| m.as_str())
                == Some("connect_denied_by_rule")
        })
        .unwrap_or_else(|| panic!("no connect_denied_by_rule log line"));

    let fields = denied.get("fields").expect("fields");
    assert_eq!(
        fields.get("matched_rule_id").and_then(|v| v.as_str()),
        Some("-")
    );
    assert_eq!(
        fields.get("matched_rule_index").and_then(|v| v.as_str()),
        Some("-")
    );
    assert_eq!(
        fields.get("default_used").and_then(|v| v.as_bool()),
        Some(true)
    );
    assert_eq!(fields.get("action").and_then(|v| v.as_str()), Some("deny"));
}

// Silence unused-import lint for Command (kept in case future tests need it).
#[allow(dead_code)]
fn _unused() {
    let _ = Command::Connect;
}
