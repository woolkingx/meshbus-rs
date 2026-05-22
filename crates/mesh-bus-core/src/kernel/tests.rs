use super::data_handle::Registry;
use super::dispatch_forwarder::apply_pin_with_hysteresis;
use crate::{
    BusBuilder, BusEvent, Capabilities, EgressPlugin, ExitId, ExitResult, Frame, Measurement,
    ObserverPlugin, RankContext, ReturnEvent, ScheduleDecision, SchedulerPlugin, SessionId,
};
use async_trait::async_trait;
use bytes::Bytes;
use mb_endpoint::Endpoint;
use std::sync::Arc;
use std::sync::atomic::Ordering;

#[test]
fn registry_starts_empty() {
    let r = Registry::new();
    assert!(r.egresses.is_empty());
    assert!(r.observers.is_empty());
    assert!(r.scheduler.is_none());
}

struct NoopScheduler;
impl SchedulerPlugin for NoopScheduler {
    fn schedule(&self, candidates: &[ExitId], _ctx: &RankContext) -> ScheduleDecision {
        ScheduleDecision::ordered((0..candidates.len()).collect())
    }
    fn feedback(&self, _r: &ExitResult, _payload_bytes: u64, _at_ms: u64) {}
}

struct DevNullEgress {
    id: ExitId,
    caps: Capabilities,
}

#[async_trait]
impl EgressPlugin for DevNullEgress {
    fn id(&self) -> &ExitId {
        &self.id
    }
    fn capabilities(&self) -> &Capabilities {
        &self.caps
    }
    async fn send(&self, _frame: Frame) -> ExitResult {
        ExitResult {
            exit_id: self.id.clone(),
            success: false,
            rtt_ms: 0,
            local_endpoint: None,
            return_event: ReturnEvent::Idle,
        }
    }
    async fn poll(&self, _s: &SessionId) -> ReturnEvent {
        ReturnEvent::Idle
    }
    async fn probe(&self, _t: &Endpoint) -> Measurement {
        Measurement {
            exit_id: self.id.clone(),
            at_ms: 0,
            rtt_ms: 0,
            payload_bytes: 0,
            jitter_ms: None,
            throughput_bps: None,
            success: true,
        }
    }
    async fn close(&self, _s: &SessionId) {}
}

#[tokio::test]
async fn shutdown_with_timeout_clean_drain_returns_ok() {
    let bus = BusBuilder::new()
        .scheduler(Box::new(NoopScheduler))
        .add_egress(Box::new(DevNullEgress {
            id: ExitId("dev-null".into()),
            caps: Capabilities {
                protocol: "tcp".into(),
                supports_stream: true,
                supports_datagram: false,
                max_payload_bytes: None,
                groups: vec![],
            },
        }))
        .build()
        .await;
    let handle = bus.spawn();
    // No frames in flight — drain should complete immediately within the timeout.
    let result = handle
        .shutdown_with_timeout(std::time::Duration::from_secs(2))
        .await;
    assert!(result.is_ok(), "clean drain must return Ok; got {result:?}");
}

// ── observer routed fan-out: core events emitted ───────────────────────────────

struct RecordingObserver {
    events: Arc<std::sync::Mutex<Vec<BusEvent>>>,
}

impl ObserverPlugin for RecordingObserver {
    fn on_event(&self, event: &BusEvent) {
        self.events
            .lock()
            .expect("recorder mutex")
            .push(event.clone());
    }
}

struct FlappingEgress {
    id: ExitId,
    caps: Capabilities,
    fail_first: std::sync::atomic::AtomicBool,
}

#[async_trait]
impl EgressPlugin for FlappingEgress {
    fn id(&self) -> &ExitId {
        &self.id
    }
    fn capabilities(&self) -> &Capabilities {
        &self.caps
    }
    async fn send(&self, frame: Frame) -> ExitResult {
        let fail = self.fail_first.swap(false, Ordering::SeqCst);
        if fail {
            ExitResult {
                exit_id: self.id.clone(),
                success: false,
                rtt_ms: 0,
                local_endpoint: None,
                return_event: ReturnEvent::Closed {
                    reason: crate::CloseReason::Other("upstream".into()),
                },
            }
        } else {
            ExitResult {
                exit_id: self.id.clone(),
                success: true,
                rtt_ms: 1,
                local_endpoint: None,
                return_event: ReturnEvent::Data {
                    seq: frame.seq,
                    payload: frame.payload,
                },
            }
        }
    }
    async fn poll(&self, _s: &SessionId) -> ReturnEvent {
        ReturnEvent::Idle
    }
    async fn probe(&self, _t: &Endpoint) -> Measurement {
        Measurement {
            exit_id: self.id.clone(),
            at_ms: 0,
            rtt_ms: 0,
            payload_bytes: 0,
            jitter_ms: None,
            throughput_bps: None,
            success: true,
        }
    }
    async fn close(&self, _s: &SessionId) {}
}

#[tokio::test]
async fn dispatch_emits_core_events_via_observation_bus() {
    let events = Arc::new(std::sync::Mutex::new(Vec::<BusEvent>::new()));
    let spy = RecordingObserver {
        events: events.clone(),
    };

    let bus = BusBuilder::new()
        .scheduler(Box::new(NoopScheduler))
        .add_egress(Box::new(FlappingEgress {
            id: ExitId("flap".into()),
            caps: Capabilities {
                protocol: "test".into(),
                supports_stream: true,
                supports_datagram: false,
                max_payload_bytes: None,
                groups: vec![],
            },
            fail_first: std::sync::atomic::AtomicBool::new(true),
        }))
        .add_observer(Box::new(spy))
        .build()
        .await;

    let port = bus.port();
    let handle = bus.spawn();
    let target = Endpoint::new("x", 1).expect("valid endpoint");

    // Frame 1: fail_first=true -> send fails -> core.path.io_error emitted.
    // dispatch_ordered sends ReturnEvent::Closed back.
    let mut s1 = port.open_session(target.clone()).await;
    s1.submit
        .send(Frame::data(
            s1.id.clone(),
            0,
            target.clone(),
            Bytes::from_static(b"fail"),
        ))
        .await
        .expect("send frame 1");
    let _ = s1.returns.recv().await; // Closed(Other("upstream"))

    // Frame 2: fail_first now false -> open succeeds -> core.flow.opened emitted.
    let mut s2 = port.open_session(target.clone()).await;
    s2.submit
        .send(Frame::open(s2.id.clone(), target.clone()))
        .await
        .expect("send frame 2");
    let _ = s2.returns.recv().await; // Connected { .. }

    // Let observer drainers process.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    handle.shutdown().await;

    let evs = events.lock().expect("recorder mutex");
    assert!(
        evs.iter().any(|e| matches!(
            e,
            BusEvent::Core(env)
                if env.type_id
                    == crate::kernel::observation::EventTypeId::Core(
                        crate::kernel::observation::CoreEventId::PathIoError
                    )
        )),
        "expected at least one core.path.io_error, got: {evs:?}"
    );
    assert!(
        evs.iter().any(|e| matches!(
            e,
            BusEvent::Core(env)
                if env.type_id
                    == crate::kernel::observation::EventTypeId::Core(
                        crate::kernel::observation::CoreEventId::FlowOpened
                    )
        )),
        "expected at least one core.flow.opened, got: {evs:?}"
    );
}

#[tokio::test]
async fn path_io_error_increments_metrics_failure_snapshot() {
    // A failing first send emits ONLY core.path.io_error: the flow never opens,
    // so close_flow_if_open is a no-op and no FlowClosed is published. The runtime
    // MetricsObserver must be wired to PathIoError, otherwise dispatch_failure
    // stays 0 even though a dispatch attempt failed.
    let bus = BusBuilder::new()
        .scheduler(Box::new(NoopScheduler))
        .add_egress(Box::new(FlappingEgress {
            id: ExitId("flap".into()),
            caps: Capabilities {
                protocol: "test".into(),
                supports_stream: true,
                supports_datagram: false,
                max_payload_bytes: None,
                groups: vec![],
            },
            fail_first: std::sync::atomic::AtomicBool::new(true),
        }))
        .build()
        .await;

    let port = bus.port();
    let handle = bus.spawn();
    let target = Endpoint::new("x", 1).expect("valid endpoint");

    let mut s1 = port.open_session(target.clone()).await;
    s1.submit
        .send(Frame::data(
            s1.id.clone(),
            0,
            target.clone(),
            Bytes::from_static(b"fail"),
        ))
        .await
        .expect("send failing frame");
    let _ = s1.returns.recv().await; // Closed(Other("upstream"))

    // Let the core observer drainer process the PathIoError envelope.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let snap = handle.snapshot().await;
    handle.shutdown().await;

    assert!(
        snap.dispatch_failure >= 1,
        "PathIoError must increment dispatch_failure via runtime wiring, got {snap:?}"
    );
}

#[tokio::test]
async fn user_observer_receives_only_declared_core_event_types() {
    use crate::kernel::observation::{CoreEventId, EventTypeId};
    let events = Arc::new(std::sync::Mutex::new(Vec::<BusEvent>::new()));
    let spy = RecordingObserver {
        events: events.clone(),
    };

    let bus = BusBuilder::new()
        .scheduler(Box::new(NoopScheduler))
        .add_egress(Box::new(FlappingEgress {
            id: ExitId("flap".into()),
            caps: Capabilities {
                protocol: "test".into(),
                supports_stream: true,
                supports_datagram: false,
                max_payload_bytes: None,
                groups: vec![],
            },
            fail_first: std::sync::atomic::AtomicBool::new(true),
        }))
        .add_observer(Box::new(spy))
        .build()
        .await;

    let port = bus.port();
    let handle = bus.spawn();
    let target = Endpoint::new("x", 1).expect("valid endpoint");

    let mut s1 = port.open_session(target.clone()).await;
    s1.submit
        .send(Frame::data(
            s1.id.clone(),
            0,
            target.clone(),
            Bytes::from_static(b"fail"),
        ))
        .await
        .expect("send failing frame");
    let _ = s1.returns.recv().await;

    let mut s2 = port.open_session(target.clone()).await;
    s2.submit
        .send(Frame::open(s2.id.clone(), target.clone()))
        .await
        .expect("send open frame");
    let _ = s2.returns.recv().await;

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    handle.shutdown().await;

    let evs = events.lock().expect("recorder mutex");
    assert!(!evs.is_empty(), "expected at least one routed core event");
    for e in evs.iter() {
        let BusEvent::Core(env) = e else {
            panic!("user observer received a non-core event: {e:?}");
        };
        assert!(
            matches!(
                env.type_id,
                EventTypeId::Core(CoreEventId::FlowOpened)
                    | EventTypeId::Core(CoreEventId::FlowClosed)
                    | EventTypeId::Core(CoreEventId::PathIoError)
            ),
            "user observer received an undeclared event type: {:?}",
            env.type_id
        );
    }
}

struct NarrowObserver {
    which: &'static [crate::kernel::observation::CoreEventId],
    events: Arc<std::sync::Mutex<Vec<BusEvent>>>,
}

impl ObserverPlugin for NarrowObserver {
    fn on_event(&self, event: &BusEvent) {
        self.events
            .lock()
            .expect("recorder mutex")
            .push(event.clone());
    }
    fn subscribed_core_events(&self) -> &'static [crate::kernel::observation::CoreEventId] {
        self.which
    }
}

#[tokio::test]
async fn observer_receives_only_declared_event_types() {
    use crate::kernel::observation::{CoreEventId, EventTypeId};
    let opened_evs = Arc::new(std::sync::Mutex::new(Vec::<BusEvent>::new()));
    let ioerr_evs = Arc::new(std::sync::Mutex::new(Vec::<BusEvent>::new()));

    let bus = BusBuilder::new()
        .scheduler(Box::new(NoopScheduler))
        .add_egress(Box::new(FlappingEgress {
            id: ExitId("flap".into()),
            caps: Capabilities {
                protocol: "test".into(),
                supports_stream: true,
                supports_datagram: false,
                max_payload_bytes: None,
                groups: vec![],
            },
            fail_first: std::sync::atomic::AtomicBool::new(true),
        }))
        .add_observer(Box::new(NarrowObserver {
            which: &[CoreEventId::FlowOpened],
            events: opened_evs.clone(),
        }))
        .add_observer(Box::new(NarrowObserver {
            which: &[CoreEventId::PathIoError],
            events: ioerr_evs.clone(),
        }))
        .build()
        .await;

    let port = bus.port();
    let handle = bus.spawn();
    let target = Endpoint::new("x", 1).expect("valid endpoint");

    // Frame 1: send fails -> core.path.io_error.
    let mut s1 = port.open_session(target.clone()).await;
    s1.submit
        .send(Frame::data(
            s1.id.clone(),
            0,
            target.clone(),
            Bytes::from_static(b"fail"),
        ))
        .await
        .expect("send failing frame");
    let _ = s1.returns.recv().await;

    // Frame 2: open succeeds -> core.flow.opened.
    let mut s2 = port.open_session(target.clone()).await;
    s2.submit
        .send(Frame::open(s2.id.clone(), target.clone()))
        .await
        .expect("send open frame");
    let _ = s2.returns.recv().await;

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    handle.shutdown().await;

    let opened = opened_evs.lock().expect("recorder mutex");
    assert!(
        !opened.is_empty(),
        "FlowOpened-only observer expected at least one event"
    );
    for e in opened.iter() {
        let BusEvent::Core(env) = e else {
            panic!("unexpected non-core event: {e:?}");
        };
        assert_eq!(
            env.type_id,
            EventTypeId::Core(CoreEventId::FlowOpened),
            "FlowOpened-only observer received undeclared type: {:?}",
            env.type_id
        );
    }

    let ioerr = ioerr_evs.lock().expect("recorder mutex");
    assert!(
        !ioerr.is_empty(),
        "PathIoError-only observer expected at least one event"
    );
    for e in ioerr.iter() {
        let BusEvent::Core(env) = e else {
            panic!("unexpected non-core event: {e:?}");
        };
        assert_eq!(
            env.type_id,
            EventTypeId::Core(CoreEventId::PathIoError),
            "PathIoError-only observer received undeclared type: {:?}",
            env.type_id
        );
    }
}

#[test]
fn observer_registry_rejects_undeclared_publish() {
    use crate::kernel::observation::{
        EventTypeId, ObsEventId, ObservationRegistry, ObserverId, ObserverSpec, PluginId, ScopeId,
    };
    let mut reg = ObservationRegistry::new();
    // Observer declares a write to an obs.* event type that was never
    // registered. verify() must fail closed before any runtime build.
    reg.register_observer(ObserverSpec {
        id: ObserverId(1),
        owner: PluginId(1),
        scope: ScopeId(1),
        reads: vec![],
        writes: vec![EventTypeId::Obs(ObsEventId(0))],
        pulls: vec![],
    })
    .expect("register observer");
    assert!(
        reg.verify().is_err(),
        "registry must reject an undeclared obs.* publish before runtime build"
    );
}

// ── apply_pin_with_hysteresis pure-function tests ─────────────────────────────

const HYSTERESIS_TAU: f64 = 0.20;

/// Scheduler that returns per-exit scores injected at construction.
struct ScoredScheduler {
    scores: std::collections::HashMap<String, u64>,
}

impl SchedulerPlugin for ScoredScheduler {
    fn schedule(&self, candidates: &[ExitId], _ctx: &RankContext) -> ScheduleDecision {
        ScheduleDecision::ordered((0..candidates.len()).collect())
    }
    fn feedback(&self, _r: &ExitResult, _payload_bytes: u64, _at_ms: u64) {}
    fn score_for(&self, exit_id: &ExitId, _candidates: &[ExitId], _ctx: &RankContext) -> u64 {
        self.scores.get(&exit_id.0).copied().unwrap_or(0)
    }
}

fn mk_egress(id: &str) -> Box<dyn EgressPlugin> {
    Box::new(DevNullEgress {
        id: ExitId(id.into()),
        caps: Capabilities {
            protocol: "test".into(),
            supports_stream: true,
            supports_datagram: false,
            max_payload_bytes: None,
            groups: vec![],
        },
    })
}

fn mk_ctx() -> RankContext {
    use crate::{FlowSemantics, PacketId, ReturnSemantics, ScheduleHint, TrafficClass};
    RankContext {
        packet_id: PacketId(0),
        flow_id: crate::FlowId("f".into()),
        session_id: SessionId("s".into()),
        target: mb_endpoint::Endpoint::new("127.0.0.1", 1).unwrap(),
        traffic_class: TrafficClass::Bulk,
        policy_ref: None,
        deadline_ms: None,
        schedule_hint: ScheduleHint::Auto,
        flow_semantics: FlowSemantics::ByteStream,
        return_semantics: ReturnSemantics::Direct,
        source_key: None,
        target_key: None,
    }
}

#[test]
fn pinned_exit_retained_under_marginal_alternative() {
    // A=100, B=110.  threshold = 100*(1+0.20)=120.  110 < 120 -> retained.
    let egresses: Vec<Box<dyn EgressPlugin>> = vec![mk_egress("a"), mk_egress("b")];
    let mut scores = std::collections::HashMap::new();
    scores.insert("a".into(), 100u64);
    scores.insert("b".into(), 110u64);
    let sched = ScoredScheduler { scores };
    let candidates = vec![ExitId("a".into()), ExitId("b".into())];
    let ctx = mk_ctx();
    // order from scheduler: [1 (b), 0 (a)]; pinned=0 (a)
    let mut order = vec![1usize, 0usize];
    apply_pin_with_hysteresis(
        &mut order,
        0,
        &egresses,
        &sched,
        &candidates,
        &ctx,
        HYSTERESIS_TAU,
    );
    assert_eq!(order[0], 0, "pin A should be promoted to front");
}

#[test]
fn pinned_exit_migrates_under_persistent_degradation() {
    // A=200, B=100.  threshold = 200*(1+0.20)=240.  100 < 240? yes, but check formula:
    // retain = pin_score < (1+tau)*alt_score => 200 < 1.20*100=120 => false -> not retained.
    let egresses: Vec<Box<dyn EgressPlugin>> = vec![mk_egress("a"), mk_egress("b")];
    let mut scores = std::collections::HashMap::new();
    scores.insert("a".into(), 200u64);
    scores.insert("b".into(), 100u64);
    let sched = ScoredScheduler { scores };
    let candidates = vec![ExitId("a".into()), ExitId("b".into())];
    let ctx = mk_ctx();
    // order from scheduler: [1 (b), 0 (a)]; pinned=0 (a)
    let mut order = vec![1usize, 0usize];
    apply_pin_with_hysteresis(
        &mut order,
        0,
        &egresses,
        &sched,
        &candidates,
        &ctx,
        HYSTERESIS_TAU,
    );
    assert_eq!(order[0], 1, "pin A should NOT be promoted; B should lead");
}

#[test]
fn hysteresis_single_candidate_always_promotes() {
    // With only one exit, pin is always retained (no alt to compare against).
    let egresses: Vec<Box<dyn EgressPlugin>> = vec![mk_egress("a")];
    let sched = ScoredScheduler {
        scores: Default::default(),
    };
    let candidates = vec![ExitId("a".into())];
    let ctx = mk_ctx();
    let mut order = vec![0usize];
    apply_pin_with_hysteresis(
        &mut order,
        0,
        &egresses,
        &sched,
        &candidates,
        &ctx,
        HYSTERESIS_TAU,
    );
    assert_eq!(order[0], 0);
}

// ── M1: compiled registry slot interning ─────────────────────────────────────

mod compiled_m1 {
    use crate::kernel::compiled::CompiledKernel;
    use crate::kernel::event::types::Event;
    use crate::kernel::kernel_registry::types::{
        HookKind, HookSpec, KernelCtx, KernelRegistry, SinkSpec, SourceSpec,
    };
    use crate::kernel::kernel_registry::verify_error::VerifyError;
    use crate::kernel::pipeline::types::{Pipeline, Wiring};
    use crate::kernel::verdict::types::{HookId, PipelineId, SinkId, SourceId, Verdict};

    fn terminal_spec(id: &str) -> HookSpec {
        HookSpec {
            id: HookId::new(id),
            kind: HookKind::Net,
            allowed_namespaces: vec![],
            reads: vec![],
            writes: vec![],
            may_terminate: true,
            may_jump: false,
            may_jump_to: vec![],
            may_accept_to: vec![],
            side_effect_only: false,
        }
    }

    fn continue_fn(_event: &mut Event, _ctx: &mut KernelCtx) -> Verdict {
        Verdict::Continue
    }

    fn valid_registry() -> KernelRegistry {
        let mut r = KernelRegistry::default();
        r.sources.insert(
            SourceId::new("src"),
            SourceSpec {
                id: SourceId::new("src"),
                kind: "application/source".into(),
                initial_writes: vec![],
            },
        );
        r.sinks.insert(
            SinkId::new("direct"),
            SinkSpec {
                id: SinkId::new("direct"),
                kind: "stream_egress".into(),
            },
        );
        r.hooks.insert(HookId::new("allow"), terminal_spec("allow"));
        r.fns.insert(HookId::new("allow"), continue_fn);
        r.pipelines.insert(
            PipelineId::new("main"),
            Pipeline {
                id: PipelineId::new("main"),
                hooks: vec![HookId::new("allow")],
            },
        );
        r.wirings.push(Wiring {
            source: SourceId::new("src"),
            pipeline: PipelineId::new("main"),
        });
        r
    }

    #[test]
    fn compiles_valid_registry_and_round_trips_slots() {
        let reg = valid_registry();
        let ck = CompiledKernel::from_registry(&reg).expect("valid registry compiles");

        let src = ck.source_slot(&SourceId::new("src")).expect("source slot");
        assert_eq!(ck.source_id(src), Some(&SourceId::new("src")));
        let sink = ck.sink_slot(&SinkId::new("direct")).expect("sink slot");
        assert_eq!(ck.sink_id(sink), Some(&SinkId::new("direct")));
        let hook = ck.hook_slot(&HookId::new("allow")).expect("hook slot");
        assert_eq!(ck.hook_id(hook), Some(&HookId::new("allow")));
        let pipe = ck
            .pipeline_slot(&PipelineId::new("main"))
            .expect("pipeline slot");
        assert_eq!(ck.pipeline_id(pipe), Some(&PipelineId::new("main")));

        assert!(ck.source_slot(&SourceId::new("absent")).is_none());
    }

    #[test]
    fn identity_mismatch_still_fails_closed() {
        let mut reg = valid_registry();
        // Key disagrees with embedded HookSpec.id.
        reg.hooks
            .insert(HookId::new("ghost"), terminal_spec("allow"));
        let err = CompiledKernel::from_registry(&reg)
            .expect_err("identity mismatch must fail before interning");
        assert!(
            matches!(err, VerifyError::RegistryIdentityMismatch { .. }),
            "expected RegistryIdentityMismatch, got {err:?}"
        );
    }

    #[test]
    fn unknown_hook_still_fails_closed() {
        let mut reg = valid_registry();
        reg.pipelines.insert(
            PipelineId::new("main"),
            Pipeline {
                id: PipelineId::new("main"),
                hooks: vec![HookId::new("missing")],
            },
        );
        let err = CompiledKernel::from_registry(&reg)
            .expect_err("unknown hook must fail before interning");
        assert!(
            matches!(err, VerifyError::UnknownHook(_, _)),
            "expected UnknownHook, got {err:?}"
        );
    }

    #[test]
    fn invalid_wiring_still_fails_closed() {
        let mut reg = valid_registry();
        reg.wirings.clear();
        reg.wirings.push(Wiring {
            source: SourceId::new("src"),
            pipeline: PipelineId::new("nope"),
        });
        let err = CompiledKernel::from_registry(&reg)
            .expect_err("invalid wiring must fail before interning");
        assert!(
            matches!(err, VerifyError::UnknownWiringPipeline { .. }),
            "expected UnknownWiringPipeline, got {err:?}"
        );
    }
}

// ── M2: compiled pipeline graph equivalence ──────────────────────────────────

mod compiled_m2 {
    use crate::kernel::compiled::CompiledPipelineSet;
    use crate::kernel::event::types::Event;
    use crate::kernel::kernel_registry::types::{
        HookKind, HookSpec, KernelCtx, KernelRegistry, SinkSpec, SourceSpec,
    };
    use crate::kernel::pipeline::data_handle::{PipelineRunError, run_pipeline_with_registry};
    use crate::kernel::pipeline::types::{Pipeline, Wiring};
    use crate::kernel::verdict::types::{HookId, PipelineId, SinkId, SourceId, Verdict};

    fn spec(
        id: &str,
        may_terminate: bool,
        may_accept_to: &[&str],
        may_jump: bool,
        may_jump_to: &[&str],
    ) -> HookSpec {
        HookSpec {
            id: HookId::new(id),
            kind: HookKind::Net,
            allowed_namespaces: vec![],
            reads: vec![],
            writes: vec![],
            may_terminate,
            may_jump,
            may_jump_to: may_jump_to.iter().map(|p| PipelineId::new(*p)).collect(),
            may_accept_to: may_accept_to.iter().map(|s| SinkId::new(*s)).collect(),
            side_effect_only: false,
        }
    }

    fn continue_fn(_e: &mut Event, _c: &mut KernelCtx) -> Verdict {
        Verdict::Continue
    }
    fn accept_direct_fn(_e: &mut Event, _c: &mut KernelCtx) -> Verdict {
        Verdict::Accept(SinkId::new("direct"))
    }
    fn accept_ghost_fn(_e: &mut Event, _c: &mut KernelCtx) -> Verdict {
        Verdict::Accept(SinkId::new("ghost"))
    }
    fn jump_other_fn(_e: &mut Event, _c: &mut KernelCtx) -> Verdict {
        Verdict::Jump(PipelineId::new("other"))
    }
    fn jump_nowhere_fn(_e: &mut Event, _c: &mut KernelCtx) -> Verdict {
        Verdict::Jump(PipelineId::new("nowhere"))
    }
    /// Jumps to the next pipeline in a linear chain. `hook_trace.len()` equals
    /// the count of hooks already executed (one per chain step), so step `i`
    /// jumps to `p{i+1}`, matching that hook's single declared `may_jump_to`.
    fn dyn_jump_fn(_e: &mut Event, c: &mut KernelCtx) -> Verdict {
        Verdict::Jump(PipelineId::new(format!("p{}", c.hook_trace.len() + 1)))
    }

    fn base() -> KernelRegistry {
        let mut r = KernelRegistry::default();
        r.sources.insert(
            SourceId::new("src"),
            SourceSpec {
                id: SourceId::new("src"),
                kind: "application/source".into(),
                initial_writes: vec![],
            },
        );
        r.sinks.insert(
            SinkId::new("direct"),
            SinkSpec {
                id: SinkId::new("direct"),
                kind: "stream_egress".into(),
            },
        );
        r
    }

    fn wire(r: &mut KernelRegistry, pipeline: &str) {
        r.wirings.push(Wiring {
            source: SourceId::new("src"),
            pipeline: PipelineId::new(pipeline),
        });
    }

    fn outcome(r: &Result<Verdict, PipelineRunError>) -> String {
        match r {
            Ok(v) => format!("OK {v:?}"),
            Err(e) => format!("ERR {e}"),
        }
    }

    /// Runs `entry` through the registry executor and the compiled graph over
    /// the same verify-passing registry, asserting identical outcome string
    /// and identical `HookTrace` sequence.
    fn assert_equivalent(reg: &KernelRegistry, entry: &str) {
        let pid = PipelineId::new(entry);

        let mut ev_r = Event::default();
        let mut ctx_r = KernelCtx::default();
        let res_r = run_pipeline_with_registry(reg, &pid, &mut ev_r, &mut ctx_r);

        let compiled = CompiledPipelineSet::compile(reg).expect("registry compiles");
        let mut ev_c = Event::default();
        let mut ctx_c = KernelCtx::default();
        let res_c = compiled.run_pipeline(&pid, &mut ev_c, &mut ctx_c);

        assert_eq!(
            outcome(&res_r),
            outcome(&res_c),
            "verdict/error string diverged for entry `{entry}`"
        );
        assert_eq!(
            format!("{:?}", ctx_r.hook_trace),
            format!("{:?}", ctx_c.hook_trace),
            "HookTrace sequence diverged for entry `{entry}`"
        );
    }

    #[test]
    fn accept_terminal_equivalence() {
        let mut r = base();
        for h in ["r1", "r2", "r3"] {
            r.hooks
                .insert(HookId::new(h), spec(h, false, &[], false, &[]));
            r.fns.insert(HookId::new(h), continue_fn);
        }
        r.hooks
            .insert(HookId::new("r4"), spec("r4", true, &["direct"], false, &[]));
        r.fns.insert(HookId::new("r4"), accept_direct_fn);
        r.pipelines.insert(
            PipelineId::new("main"),
            Pipeline {
                id: PipelineId::new("main"),
                hooks: ["r1", "r2", "r3", "r4"]
                    .iter()
                    .map(|h| HookId::new(*h))
                    .collect(),
            },
        );
        wire(&mut r, "main");
        assert_equivalent(&r, "main");
    }

    #[test]
    fn fell_off_end_equivalence() {
        let mut r = base();
        r.hooks
            .insert(HookId::new("t"), spec("t", true, &[], false, &[]));
        r.fns.insert(HookId::new("t"), continue_fn);
        r.pipelines.insert(
            PipelineId::new("main"),
            Pipeline {
                id: PipelineId::new("main"),
                hooks: vec![HookId::new("t")],
            },
        );
        wire(&mut r, "main");
        assert_equivalent(&r, "main");
    }

    #[test]
    fn jump_across_pipelines_equivalence() {
        let mut r = base();
        r.hooks
            .insert(HookId::new("j"), spec("j", false, &[], true, &["other"]));
        r.fns.insert(HookId::new("j"), jump_other_fn);
        r.hooks
            .insert(HookId::new("a"), spec("a", true, &["direct"], false, &[]));
        r.fns.insert(HookId::new("a"), accept_direct_fn);
        r.pipelines.insert(
            PipelineId::new("main"),
            Pipeline {
                id: PipelineId::new("main"),
                hooks: vec![HookId::new("j")],
            },
        );
        r.pipelines.insert(
            PipelineId::new("other"),
            Pipeline {
                id: PipelineId::new("other"),
                hooks: vec![HookId::new("a")],
            },
        );
        wire(&mut r, "main");
        assert_equivalent(&r, "main");
    }

    #[test]
    fn undeclared_accept_target_equivalence() {
        let mut r = base();
        r.hooks.insert(
            HookId::new("bad"),
            spec("bad", true, &["direct"], false, &[]),
        );
        r.fns.insert(HookId::new("bad"), accept_ghost_fn);
        r.pipelines.insert(
            PipelineId::new("main"),
            Pipeline {
                id: PipelineId::new("main"),
                hooks: vec![HookId::new("bad")],
            },
        );
        wire(&mut r, "main");
        assert_equivalent(&r, "main");
    }

    #[test]
    fn undeclared_jump_target_equivalence() {
        let mut r = base();
        r.hooks.insert(
            HookId::new("bj"),
            spec("bj", false, &[], true, &["sink_pipe"]),
        );
        r.fns.insert(HookId::new("bj"), jump_nowhere_fn);
        r.hooks
            .insert(HookId::new("a"), spec("a", true, &["direct"], false, &[]));
        r.fns.insert(HookId::new("a"), accept_direct_fn);
        r.pipelines.insert(
            PipelineId::new("main"),
            Pipeline {
                id: PipelineId::new("main"),
                hooks: vec![HookId::new("bj")],
            },
        );
        r.pipelines.insert(
            PipelineId::new("sink_pipe"),
            Pipeline {
                id: PipelineId::new("sink_pipe"),
                hooks: vec![HookId::new("a")],
            },
        );
        wire(&mut r, "main");
        assert_equivalent(&r, "main");
    }

    #[test]
    fn unknown_pipeline_equivalence() {
        let mut r = base();
        r.hooks
            .insert(HookId::new("a"), spec("a", true, &["direct"], false, &[]));
        r.fns.insert(HookId::new("a"), accept_direct_fn);
        r.pipelines.insert(
            PipelineId::new("main"),
            Pipeline {
                id: PipelineId::new("main"),
                hooks: vec![HookId::new("a")],
            },
        );
        wire(&mut r, "main");
        assert_equivalent(&r, "ghost-pipe");
    }

    #[test]
    fn jump_depth_exceeded_equivalence() {
        // verify() rejects jump cycles, so the only verify-passing way to reach
        // the runtime depth guard is an acyclic chain longer than
        // MAX_JUMP_DEPTH (32). Chain p0→…→p33: hooks h0..h32 each jump to the
        // next; h33 is a terminal accept so p33 verifies as terminating (it is
        // never reached at runtime — jumps>32 errors at p33's lookup).
        let mut r = base();
        let chain = 34usize;
        for i in 0..chain {
            let h = format!("h{i}");
            let p = format!("p{i}");
            if i + 1 < chain {
                let next = format!("p{}", i + 1);
                r.hooks.insert(
                    HookId::new(&h),
                    spec(&h, false, &[], true, &[next.as_str()]),
                );
                r.fns.insert(HookId::new(&h), dyn_jump_fn);
            } else {
                r.hooks
                    .insert(HookId::new(&h), spec(&h, true, &["direct"], false, &[]));
                r.fns.insert(HookId::new(&h), accept_direct_fn);
            }
            r.pipelines.insert(
                PipelineId::new(&p),
                Pipeline {
                    id: PipelineId::new(&p),
                    hooks: vec![HookId::new(&h)],
                },
            );
        }
        wire(&mut r, "p0");
        assert_equivalent(&r, "p0");
    }
}

// ── M4: compiled candidate table equivalence ─────────────────────────────────

mod compiled_m4 {
    use super::DevNullEgress;
    use crate::Capabilities;
    use crate::kernel::compiled::{CompiledCandidate, CompiledCandidates};
    use crate::transport::forwarding::data_handle::capability_matches_flow;
    use crate::transport::forwarding::types::FlowSemantics;
    use crate::{EgressPlugin, ExitId};

    fn egress(id: &str, stream: bool, datagram: bool, groups: &[&str]) -> Box<dyn EgressPlugin> {
        Box::new(DevNullEgress {
            id: ExitId(id.into()),
            caps: Capabilities {
                protocol: "test".into(),
                supports_stream: stream,
                supports_datagram: datagram,
                max_payload_bytes: None,
                groups: groups.iter().map(|g| (*g).to_string()).collect(),
            },
        })
    }

    /// Pre-M4 reference: a full `dyn EgressPlugin` scan in index order applying
    /// the canonical capability predicate plus the route-group/target-sink
    /// filter and the fail-closed rule. No health filter (empty unhealthy set),
    /// so the both-`None` fallback equals the first pass.
    fn reference_scan(
        egresses: &[Box<dyn EgressPlugin>],
        want: FlowSemantics,
        route_group: Option<&str>,
        target_sink: Option<&str>,
    ) -> (Vec<ExitId>, Vec<usize>) {
        let keep = |caps: &Capabilities, id: &ExitId| -> bool {
            if !capability_matches_flow(caps, want) {
                return false;
            }
            if let Some(sink) = target_sink {
                if id.0 != sink {
                    return false;
                }
            }
            match route_group {
                Some(g) => caps.groups.iter().any(|x| x == g),
                None => true,
            }
        };
        let mut cands = Vec::new();
        let mut map = Vec::new();
        for (idx, e) in egresses.iter().enumerate() {
            if keep(e.capabilities(), e.id()) {
                cands.push(e.id().clone());
                map.push(idx);
            }
        }
        if cands.is_empty() && (route_group.is_some() || target_sink.is_some()) {
            return (Vec::new(), Vec::new());
        }
        (cands, map)
    }

    /// Faithful copy of `dispatch::healthy_candidates` minus the health
    /// snapshot: bucket the compiled table, apply the same group/sink filter,
    /// and the same empty → fail-closed / both-`None` fallback branches.
    fn compiled_path(
        cc: &CompiledCandidates,
        want: FlowSemantics,
        route_group: Option<&str>,
        target_sink: Option<&str>,
    ) -> (Vec<ExitId>, Vec<usize>) {
        let bucket = cc.bucket(want);
        let keep = |c: &CompiledCandidate| -> bool {
            if let Some(sink) = target_sink {
                if c.exit_id.0 != sink {
                    return false;
                }
            }
            match route_group {
                Some(g) => c.groups.iter().any(|x| x == g),
                None => true,
            }
        };
        let mut cands = Vec::new();
        let mut map = Vec::new();
        for c in bucket.iter() {
            if keep(c) {
                cands.push(c.exit_id.clone());
                map.push(c.egress_idx);
            }
        }
        if cands.is_empty() {
            if route_group.is_some() || target_sink.is_some() {
                return (Vec::new(), Vec::new());
            }
            return bucket
                .iter()
                .filter(|c| keep(c))
                .map(|c| (c.exit_id.clone(), c.egress_idx))
                .collect::<Vec<_>>()
                .into_iter()
                .unzip();
        }
        (cands, map)
    }

    #[test]
    fn compiled_candidates_match_healthy_candidates_for_all_groups() {
        let egresses: Vec<Box<dyn EgressPlugin>> = vec![
            egress("e0", true, false, &["alpha"]),
            egress("e1", false, true, &["beta"]),
            egress("e2", true, true, &["gamma"]),
            egress("e3", true, false, &["alpha", "gamma"]),
            egress("e4", false, true, &[]),
            egress("e5", true, true, &["beta", "gamma"]),
        ];
        let cc = CompiledCandidates::from_egresses(&egresses);
        let semantics = [
            FlowSemantics::ByteStream,
            FlowSemantics::Datagram,
            FlowSemantics::Message,
        ];
        let groups = [
            None,
            Some("alpha"),
            Some("beta"),
            Some("gamma"),
            Some("delta"),
        ];
        for &want in &semantics {
            for &g in &groups {
                assert_eq!(
                    compiled_path(&cc, want, g, None),
                    reference_scan(&egresses, want, g, None),
                    "compiled candidate set diverged for semantics {want:?} group {g:?}"
                );
            }
        }
    }

    #[test]
    fn compiled_candidates_fail_closed_for_unknown_target_sink() {
        let egresses: Vec<Box<dyn EgressPlugin>> = vec![
            egress("e0", true, false, &["alpha"]),
            egress("e1", true, true, &["beta"]),
            egress("e2", false, true, &[]),
        ];
        let cc = CompiledCandidates::from_egresses(&egresses);
        for &want in &[
            FlowSemantics::ByteStream,
            FlowSemantics::Datagram,
            FlowSemantics::Message,
        ] {
            let (cands, map) = compiled_path(&cc, want, None, Some("ghost-exit"));
            assert!(
                cands.is_empty() && map.is_empty(),
                "unknown target sink must fail closed for {want:?}, got {cands:?}"
            );
            assert_eq!(
                compiled_path(&cc, want, None, Some("ghost-exit")),
                reference_scan(&egresses, want, None, Some("ghost-exit")),
                "fail-closed path diverged from reference scan for {want:?}"
            );
        }
        // A real sink still resolves — proves the empty sets above are the
        // unknown-sink fail-closed, not a blanket empty bucket.
        let (cands, _) = compiled_path(&cc, FlowSemantics::ByteStream, None, Some("e1"));
        assert_eq!(cands, vec![ExitId("e1".into())]);
    }
}

#[test]
fn bus_event_core_carries_typed_observation_envelope() {
    use crate::BusEvent;
    use crate::kernel::observation::{
        CoreEventId, EventEnvelope, EventPayload, EventPayloadInner, EventTypeId,
    };
    let ev = BusEvent::Core(EventEnvelope {
        type_id: EventTypeId::Core(CoreEventId::PathIoError),
        payload: EventPayload(Arc::new(EventPayloadInner {
            selected_exit: Some("e1".into()),
            close_reason: Some("upstream EOF".into()),
            payload_bytes: 1500,
            ..Default::default()
        })),
        at_ns: 1234,
    });
    match ev {
        BusEvent::Core(env) => {
            assert_eq!(env.type_id, EventTypeId::Core(CoreEventId::PathIoError));
            assert_eq!(env.payload.0.selected_exit.as_deref(), Some("e1"));
        }
        _ => panic!("variant mismatch"),
    }
}
