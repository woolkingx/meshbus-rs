//! Integration test: plain TCP ingress drives a `PipelineRuntime` decision
//! before opening the L4 stream session.
//!
//! Direct TCP has no protocol reply surface: a deny verdict simply closes the
//! accepted client socket without opening any egress. An accept verdict with
//! `policy.route_group` projects onto the BusSessionRequest so dispatch pins
//! to the group-tagged exit.

use bytes::Bytes;
use mb_endpoint::Endpoint;
use mb_rule::RuleSetRegistry;
use mesh_bus_core::kernel::{
    Event, HookId, HookKind, HookSpec, KernelCtx, KernelRegistry, Pipeline, PipelineId, Reason,
    SinkId, SinkSpec, SourceId, SourceSpec, Verdict, Wiring,
};
use mesh_bus_core::{
    BusBuilder, BusSessionInfo, BusSessionRequest, Capabilities, DisconnectReason, ExitId,
    ExitResult, IngressPlugin, RankContext, ScheduleDecision, SchedulerPlugin, StreamEgress,
    StreamRecvHalf, StreamSendHalf, StreamSession,
};
use mesh_bus_ingress_tcp::{PipelineRuntime, TcpIngress};
use mesh_bus_pipeline_hooks::context::SharedHookCtx;
use mesh_bus_resolver::cache::DnsCache;
use mesh_bus_resolver::data_handle::ResolverHandle;
use mesh_bus_resolver::types::{ResolutionSignals, ResolveAnswer, ResolveError, ResolveRequest};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

const TEST_SOURCE_ID: &str = "ingress:0";
const TEST_SOURCE_KIND: &str = "application/source";
const TEST_STREAM_SINK_KIND: &str = "stream_egress";

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

fn reject_hook(_event: &mut Event, _kctx: &mut KernelCtx) -> Verdict {
    Verdict::Reject(Reason::code("denied"))
}

fn cn_pin_hook(event: &mut Event, _kctx: &mut KernelCtx) -> Verdict {
    event.meta.policy.route_group = Some("cn".into());
    Verdict::Accept(SinkId::new("cn-exit"))
}

fn build_runtime_with(
    hook_fn: mesh_bus_core::kernel::HookFn,
    writes: Vec<String>,
) -> PipelineRuntime {
    let pid = PipelineId::new("forward");
    let hid = HookId::new("test.direct");

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
            reads: vec![],
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

async fn spawn_with_runtime(
    runtime: PipelineRuntime,
    target: Endpoint,
) -> (u16, Arc<AtomicUsize>, Arc<AtomicUsize>) {
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
    let ingress = TcpIngress::new(listener, target).with_pipeline(runtime);
    tokio::spawn(async move {
        Box::new(ingress).run(port).await.expect("run");
    });
    (bind_port, cn_opens, default_opens)
}

#[tokio::test]
async fn direct_tcp_pipeline_deny_closes_client() {
    let target = Endpoint::new("blocked.example", 80).expect("ep");
    let (bind_port, cn_opens, default_opens) =
        spawn_with_runtime(build_runtime_with(reject_hook, vec![]), target).await;

    let mut client = TcpStream::connect(format!("127.0.0.1:{bind_port}"))
        .await
        .expect("client connect");

    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        client.read(&mut byte),
    )
    .await
    .expect("deny verdict must close instead of hanging")
    .expect("read close");
    assert_eq!(read, 0, "deny verdict must close the client with no bytes");

    assert_eq!(
        default_opens.load(Ordering::SeqCst),
        0,
        "deny verdict must not open the default egress"
    );
    assert_eq!(
        cn_opens.load(Ordering::SeqCst),
        0,
        "deny verdict must not open the cn egress"
    );
}

#[tokio::test]
async fn direct_tcp_pipeline_accept_pins_route_group() {
    let target = Endpoint::new("anywhere.example", 80).expect("ep");
    let (bind_port, cn_opens, default_opens) = spawn_with_runtime(
        build_runtime_with(cn_pin_hook, vec!["policy.route_group".into()]),
        target,
    )
    .await;

    let _client = TcpStream::connect(format!("127.0.0.1:{bind_port}"))
        .await
        .expect("client connect");

    for _ in 0..50 {
        if cn_opens.load(Ordering::SeqCst) > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(
        cn_opens.load(Ordering::SeqCst),
        1,
        "Accept(cn-exit) + route_group=cn must pin dispatch to cn-exit"
    );
    assert_eq!(
        default_opens.load(Ordering::SeqCst),
        0,
        "default egress must be filtered out by route_group=cn"
    );
}
