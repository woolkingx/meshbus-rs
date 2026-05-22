//! Integration test: SOCKS5 ingress drives `run_pipeline_with_registry`
//! directly through `Socks5Ingress::with_pipeline(PipelineRuntime)`.
//!
//! Uses a minimal one-hook pipeline that returns `Verdict::Accept(SinkId)`.
//! `verdict_apply` projects the accepted sink and any post-run metadata onto
//! the BusSessionRequest, and the bus must dispatch to the selected egress.

use bytes::Bytes;
use mb_endpoint::Endpoint;
use mb_proto_socks5::{Method, encode_connect_request, encode_greeting};
use mb_rule::RuleSetRegistry;
use mesh_bus_core::kernel::{
    Event, HookId, HookKind, HookSpec, KernelCtx, KernelRegistry, Pipeline, PipelineId, SinkId,
    SinkSpec, SourceId, SourceSpec, Verdict, Wiring,
};
use mesh_bus_core::{
    BusBuilder, BusSessionInfo, BusSessionRequest, Capabilities, DisconnectReason, ExitId,
    ExitResult, IngressPlugin, RankContext, ScheduleDecision, SchedulerPlugin, StreamEgress,
    StreamRecvHalf, StreamSendHalf, StreamSession,
};
use mesh_bus_ingress_socks5::{PipelineRuntime, Socks5Ingress};
use mesh_bus_pipeline_hooks::context::SharedHookCtx;
use mesh_bus_resolver::cache::DnsCache;
use mesh_bus_resolver::data_handle::ResolverHandle;
use mesh_bus_resolver::types::{ResolutionSignals, ResolveAnswer, ResolveError, ResolveRequest};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const TEST_SOURCE_ID: &str = "ingress:0";
const TEST_SOURCE_KIND: &str = "application/source";
const TEST_STREAM_SINK_KIND: &str = "stream_egress";

// ── First-exit scheduler ─────────────────────────────────────────────────────

struct First;
impl SchedulerPlugin for First {
    fn schedule(&self, c: &[ExitId], _ctx: &RankContext) -> ScheduleDecision {
        ScheduleDecision::ordered((0..c.len()).collect())
    }
    fn feedback(&self, _r: &ExitResult, _payload_bytes: u64, _at_ms: u64) {}
}

// ── Inert StreamEgress ───────────────────────────────────────────────────────

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
    async fn send(&mut self, _payload: Bytes) -> Result<(), DisconnectReason> {
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
    async fn recv(&mut self) -> Option<Bytes> {
        None
    }
    fn last_error(&self) -> Option<&DisconnectReason> {
        self.last.as_ref()
    }
}

// ── Stub resolver: the test hook never resolves, so this is unreachable ─────

struct UnreachableResolver;

#[async_trait::async_trait]
impl ResolverHandle for UnreachableResolver {
    async fn resolve(
        &self,
        _req: ResolveRequest,
    ) -> Result<(ResolveAnswer, ResolutionSignals), (ResolveError, ResolutionSignals)> {
        panic!("test hook must not invoke the resolver");
    }
}

// ── Test hook: tag `.cn` suffix with route_group="cn", else pass ────────────

fn cn_tag_hook(event: &mut Event, _kctx: &mut KernelCtx) -> Verdict {
    if let Some(host) = &event.meta.net.dst_host {
        if host.ends_with(".cn") {
            event.meta.policy.route_group = Some("cn".into());
            return Verdict::Accept(SinkId::new("cn-exit"));
        }
    }
    Verdict::Accept(SinkId::new("default-exit"))
}

// Pin-only hook: never writes policy.route_group; only emits Verdict::Accept(SinkId).
// Used to prove `target_sink` alone is sufficient to bind dispatch to the named exit
// even when the scheduler would otherwise prefer the first ordered candidate.
fn pin_cn_only_hook(_event: &mut Event, _kctx: &mut KernelCtx) -> Verdict {
    Verdict::Accept(SinkId::new("cn-exit"))
}

fn drop_hook(_event: &mut Event, _kctx: &mut KernelCtx) -> Verdict {
    Verdict::Drop
}

fn build_runtime() -> PipelineRuntime {
    build_runtime_with(cn_tag_hook, vec!["policy.route_group".into()])
}

fn build_runtime_pin_only() -> PipelineRuntime {
    build_runtime_with(pin_cn_only_hook, vec![])
}

fn build_runtime_drop() -> PipelineRuntime {
    build_runtime_with(drop_hook, vec![])
}

fn build_runtime_with(
    hook_fn: mesh_bus_core::kernel::HookFn,
    writes: Vec<String>,
) -> PipelineRuntime {
    let pid = PipelineId::new("forward");
    let hid = HookId::new("test.cn_tag");

    let mut reg = KernelRegistry::default();
    reg.sources.insert(
        SourceId::new(TEST_SOURCE_ID),
        SourceSpec {
            id: SourceId::new(TEST_SOURCE_ID),
            kind: TEST_SOURCE_KIND.into(),
            initial_writes: vec![
                "net.dst_host".into(),
                "net.dst_port".into(),
                "net.protocol".into(),
                "net.src_ip".into(),
                "auth.user".into(),
                "trace.flow_id".into(),
                "ext.operation".into(),
                "ext.dst_ip_primary".into(),
            ],
        },
    );
    reg.sinks.insert(
        SinkId::new("default-exit"),
        SinkSpec {
            id: SinkId::new("default-exit"),
            kind: TEST_STREAM_SINK_KIND.into(),
        },
    );
    reg.sinks.insert(
        SinkId::new("cn-exit"),
        SinkSpec {
            id: SinkId::new("cn-exit"),
            kind: TEST_STREAM_SINK_KIND.into(),
        },
    );
    reg.hooks.insert(
        hid.clone(),
        HookSpec {
            id: hid.clone(),
            kind: HookKind::Policy,
            allowed_namespaces: vec!["policy.*".into(), "net.*".into()],
            reads: vec!["net.dst_host".into()],
            writes,
            may_terminate: true,
            may_jump: false,
            may_jump_to: vec![],
            may_accept_to: vec![SinkId::new("default-exit"), SinkId::new("cn-exit")],
            side_effect_only: false,
        },
    );
    reg.fns.insert(hid.clone(), hook_fn);
    reg.pipelines.insert(
        pid.clone(),
        Pipeline {
            id: pid.clone(),
            hooks: vec![hid],
        },
    );
    reg.wirings.push(Wiring {
        source: SourceId::new(TEST_SOURCE_ID),
        pipeline: pid.clone(),
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

    PipelineRuntime::new(shared, Arc::new(reg), SourceId::new(TEST_SOURCE_ID))
        .expect("pipeline runtime")
}

async fn spawn_pipeline_with_cn_and_default() -> (u16, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    spawn_with_runtime(build_runtime()).await
}

async fn spawn_pipeline_pin_only() -> (u16, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    spawn_with_runtime(build_runtime_pin_only()).await
}

async fn spawn_pipeline_drop() -> (u16, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    spawn_with_runtime(build_runtime_drop()).await
}

async fn spawn_with_runtime(runtime: PipelineRuntime) -> (u16, Arc<AtomicUsize>, Arc<AtomicUsize>) {
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
    std::mem::forget(_bh);

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let bind_port = listener.local_addr().expect("addr").port();
    let ingress = Socks5Ingress::new(listener).with_pipeline(runtime);
    tokio::spawn(async move {
        Box::new(ingress).run(port).await.expect("run");
    });
    (bind_port, cn_opens, default_opens)
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

async fn handshake_connect_expect_close(bind_port: u16, target: &Endpoint) {
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

    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        client.read(&mut byte),
    )
    .await
    .expect("drop verdict should close instead of hanging")
    .expect("read close");
    assert_eq!(read, 0, "drop verdict must not send a SOCKS5 reply byte");
}

#[tokio::test]
async fn pipeline_route_group_pins_dispatch_to_cn_egress() {
    let (bind_port, cn_opens, default_opens) = spawn_pipeline_with_cn_and_default().await;

    let target = Endpoint::new("foo.cn", 443).expect("ep");
    let head = handshake_connect(bind_port, &target).await;
    assert_eq!(head[0], 0x05);
    assert_eq!(head[1], 0x00, "expected Succeeded REP");

    for _ in 0..50 {
        if cn_opens.load(Ordering::SeqCst) > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(
        cn_opens.load(Ordering::SeqCst),
        1,
        "cn-tagged egress should serve foo.cn via pipeline route_group projection"
    );
    assert_eq!(
        default_opens.load(Ordering::SeqCst),
        0,
        "default egress must be filtered out by route_group=cn"
    );
}

#[tokio::test]
async fn pipeline_without_group_match_falls_through_to_default() {
    let (bind_port, cn_opens, default_opens) = spawn_pipeline_with_cn_and_default().await;

    let target = Endpoint::new("foo.us", 443).expect("ep");
    let head = handshake_connect(bind_port, &target).await;
    assert_eq!(head[0], 0x05);
    assert_eq!(head[1], 0x00, "expected Succeeded REP");

    for _ in 0..50 {
        if default_opens.load(Ordering::SeqCst) > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(
        default_opens.load(Ordering::SeqCst),
        1,
        "default egress should serve foo.us (no route_group set)"
    );
    assert_eq!(
        cn_opens.load(Ordering::SeqCst),
        0,
        "cn-tagged egress must not serve non-cn host"
    );
}

// `Verdict::Accept(SinkId)` alone must pin dispatch to the named exit even when
// no `route_group` is set. The scheduler is `First` and the default-exit is
// registered before cn-exit, so without target_sink dispatch would land on
// default-exit. With target_sink="cn-exit", `healthy_candidates` filters down
// to cn-exit exactly.
#[tokio::test]
async fn pipeline_accept_sink_pins_dispatch_without_route_group() {
    let (bind_port, cn_opens, default_opens) = spawn_pipeline_pin_only().await;

    let target = Endpoint::new("anywhere.example", 443).expect("ep");
    let head = handshake_connect(bind_port, &target).await;
    assert_eq!(head[0], 0x05);
    assert_eq!(head[1], 0x00, "expected Succeeded REP");

    for _ in 0..50 {
        if cn_opens.load(Ordering::SeqCst) > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(
        cn_opens.load(Ordering::SeqCst),
        1,
        "Verdict::Accept(cn-exit) must pin dispatch to cn-exit via target_sink"
    );
    assert_eq!(
        default_opens.load(Ordering::SeqCst),
        0,
        "default-exit must not serve when target_sink=cn-exit pins dispatch"
    );
}

#[tokio::test]
async fn pipeline_drop_closes_connect_without_socks5_reply() {
    let (bind_port, cn_opens, default_opens) = spawn_pipeline_drop().await;

    let target = Endpoint::new("drop.example", 443).expect("ep");
    handshake_connect_expect_close(bind_port, &target).await;

    assert_eq!(
        default_opens.load(Ordering::SeqCst),
        0,
        "drop verdict must not open the default egress"
    );
    assert_eq!(
        cn_opens.load(Ordering::SeqCst),
        0,
        "drop verdict must not open the cn egress"
    );
}
