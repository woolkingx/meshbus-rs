//! M0 cost-model baseline for the schema-compiled event-core optimization plan.
//!
//! These tests are `#[ignore]` by default. Run with:
//!   cargo test -p mesh-bus-core event_core_cost --release -- \
//!       --ignored --nocapture --test-threads=1
//!
//! They only print ns/event labels; M0 sets no acceptance threshold. M2/M4/M3
//! re-run the same benches to compare the compiled path against this baseline.

use crate::kernel::compiled::CompiledCandidates;
use crate::kernel::observation::{
    CoreEventId, EventEnvelope, EventPayload, EventTypeId, ObservationBus,
};
use crate::kernel::{
    CompiledPipelineSet, Event, HookId, HookKind, HookSpec, KernelCtx, KernelRegistry, Pipeline,
    PipelineId, SinkId, SinkSpec, SourceId, SourceSpec, Verdict, Wiring,
    run_pipeline_with_registry,
};
use crate::transport::forwarding::data_handle::capability_matches_flow;
use crate::{
    Capabilities, EgressPlugin, ExitId, ExitResult, FlowSemantics, Frame, Measurement, ReturnEvent,
    SessionId,
};
use async_trait::async_trait;
use mb_endpoint::Endpoint;
use std::collections::HashSet;
use std::time::Instant;

// ── pipeline bench: registry lookup path ──────────────────────────────────────

fn continue_hook(_e: &mut Event, _c: &mut KernelCtx) -> Verdict {
    Verdict::Continue
}

fn accept_hook(_e: &mut Event, _c: &mut KernelCtx) -> Verdict {
    Verdict::Accept(SinkId::new("sink"))
}

fn hook_spec(id: &str, may_accept: &[&str]) -> HookSpec {
    HookSpec {
        id: HookId::new(id),
        kind: HookKind::Net,
        allowed_namespaces: vec![],
        reads: vec![],
        writes: vec![],
        may_terminate: !may_accept.is_empty(),
        may_jump: false,
        may_jump_to: vec![],
        may_accept_to: may_accept.iter().map(|s| SinkId::new(*s)).collect(),
        side_effect_only: false,
    }
}

/// Four-hook forward shape: three Continue hooks then a terminal Accept,
/// mirroring net.resolve → net.enrich → policy.rule → transport.pick.
fn forward_registry() -> (KernelRegistry, PipelineId) {
    let mut r = KernelRegistry::default();
    let names = ["net.resolve", "net.enrich", "policy.rule", "transport.pick"];
    for n in &names[..3] {
        r.hooks.insert(HookId::new(*n), hook_spec(n, &[]));
        r.fns.insert(HookId::new(*n), continue_hook);
    }
    let term = names[3];
    r.hooks
        .insert(HookId::new(term), hook_spec(term, &["sink"]));
    r.fns.insert(HookId::new(term), accept_hook);
    let pid = PipelineId::new("forward");
    r.pipelines.insert(
        pid.clone(),
        Pipeline {
            id: pid.clone(),
            hooks: names.iter().map(|n| HookId::new(*n)).collect(),
        },
    );
    r.sources.insert(
        SourceId::new("src"),
        SourceSpec {
            id: SourceId::new("src"),
            kind: "application/source".into(),
            initial_writes: vec![],
        },
    );
    r.sinks.insert(
        SinkId::new("sink"),
        SinkSpec {
            id: SinkId::new("sink"),
            kind: "stream_egress".into(),
        },
    );
    r.wirings.push(Wiring {
        source: SourceId::new("src"),
        pipeline: pid.clone(),
    });
    (r, pid)
}

#[test]
#[ignore]
fn cost_pipeline_compiled_vs_registry_lookup() {
    let (reg, pid) = forward_registry();
    let iters: u64 = 1_000_000;
    let mut accepts = 0u64;
    let start = Instant::now();
    for _ in 0..iters {
        let mut ev = Event::default();
        let mut ctx = KernelCtx::default();
        let v = run_pipeline_with_registry(&reg, &pid, &mut ev, &mut ctx).expect("pipeline runs");
        if matches!(v, Verdict::Accept(_)) {
            accepts += 1;
        }
    }
    let ns_reg = start.elapsed().as_nanos() as f64 / iters as f64;
    println!("[cost] pipeline_registry_lookup: {ns_reg:.1} ns/event over {iters} events");
    assert_eq!(accepts, iters);

    // Compiled path: verify + intern + graph-compile once, then run the
    // pre-resolved HookFn pointers per event.
    let compiled = CompiledPipelineSet::compile(&reg).expect("registry compiles");
    let mut accepts_c = 0u64;
    let start_c = Instant::now();
    for _ in 0..iters {
        let mut ev = Event::default();
        let mut ctx = KernelCtx::default();
        let v = compiled
            .run_pipeline(&pid, &mut ev, &mut ctx)
            .expect("compiled pipeline runs");
        if matches!(v, Verdict::Accept(_)) {
            accepts_c += 1;
        }
    }
    let ns_compiled = start_c.elapsed().as_nanos() as f64 / iters as f64;
    println!("[cost] pipeline_compiled_lookup: {ns_compiled:.1} ns/event over {iters} events");
    assert_eq!(accepts_c, iters);
}

// ── candidate bench: representative healthy_candidates scan ────────────────────

struct BenchEgress {
    id: ExitId,
    caps: Capabilities,
}

#[async_trait]
impl EgressPlugin for BenchEgress {
    fn id(&self) -> &ExitId {
        &self.id
    }
    fn capabilities(&self) -> &Capabilities {
        &self.caps
    }
    async fn send(&self, _f: Frame) -> ExitResult {
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

fn bench_egresses(n: usize) -> Vec<Box<dyn EgressPlugin>> {
    (0..n)
        .map(|i| {
            Box::new(BenchEgress {
                id: ExitId(format!("exit-{i}")),
                caps: Capabilities {
                    protocol: "tcp".into(),
                    supports_stream: true,
                    supports_datagram: false,
                    max_payload_bytes: None,
                    groups: vec![],
                },
            }) as Box<dyn EgressPlugin>
        })
        .collect()
}

/// Representative scan equivalent to `kernel::dispatch::healthy_candidates`'
/// inner loop: dyn `capabilities()` + `capability_matches_flow` + route-group
/// (None here) + unhealthy `HashSet::contains`, building the candidate/idx
/// pair vectors. M4 replaces this exact loop with the compiled table.
fn representative_scan(egresses: &[Box<dyn EgressPlugin>], unhealthy: &HashSet<String>) -> usize {
    let mut candidates: Vec<ExitId> = Vec::new();
    let mut map: Vec<usize> = Vec::new();
    for (idx, exit) in egresses.iter().enumerate() {
        let caps = exit.capabilities();
        if !capability_matches_flow(caps, FlowSemantics::ByteStream) {
            continue;
        }
        if !unhealthy.contains(&exit.id().0) {
            candidates.push(exit.id().clone());
            map.push(idx);
        }
    }
    candidates.len() + map.len()
}

/// Compiled-table equivalent of `representative_scan`. The bucket is already
/// capability-filtered at bus build, so candidate lookup is bucket iteration
/// plus the byte-identical `healthy_candidates` health filter (route_group and
/// target_sink are None here, matching the scan baseline). Returns the same
/// `len()+len()` so the two arms are assertion-comparable.
fn compiled_scan(cc: &CompiledCandidates, unhealthy: &HashSet<String>) -> usize {
    let mut candidates: Vec<ExitId> = Vec::new();
    let mut map: Vec<usize> = Vec::new();
    for c in cc.bucket(FlowSemantics::ByteStream) {
        if !unhealthy.contains(&c.exit_id.0) {
            candidates.push(c.exit_id.clone());
            map.push(c.egress_idx);
        }
    }
    candidates.len() + map.len()
}

fn time_loop(iters: u64, mut f: impl FnMut() -> usize) -> (f64, usize) {
    let mut acc = 0usize;
    let start = Instant::now();
    for _ in 0..iters {
        acc = acc.wrapping_add(f());
    }
    (start.elapsed().as_nanos() as f64 / iters as f64, acc)
}

#[test]
#[ignore]
fn cost_candidate_table_vs_egress_scan() {
    let unhealthy = HashSet::new();
    let iters: u64 = 200_000;
    let mut gate_n: Vec<usize> = Vec::new();
    for n in [8usize, 32, 128] {
        let egresses = bench_egresses(n);
        let cc = CompiledCandidates::from_egresses(&egresses);
        let (ns_scan, a1) = time_loop(iters, || representative_scan(&egresses, &unhealthy));
        let (ns_comp, a2) = time_loop(iters, || compiled_scan(&cc, &unhealthy));
        assert_eq!(
            a1, a2,
            "compiled candidate set must match the scan at n={n}"
        );
        let faster = ns_comp < ns_scan;
        if n >= 32 && !faster {
            gate_n.push(n);
        }
        println!(
            "[cost] candidate n={n}: scan {ns_scan:.1} ns, compiled {ns_comp:.1} ns \
             over {iters} scans -> compiled {} (acc={a1})",
            if faster { "faster" } else { "not faster" }
        );
    }
    if gate_n.is_empty() {
        println!("[cost] candidate verdict: compiled path faster at 32 and 128 egresses");
    } else {
        println!(
            "[cost] candidate verdict: compiled path NOT faster at {gate_n:?}; recommend \
             keeping the compiled path behind an egress-count gate (M0 sets no acceptance \
             threshold at the cost layer)"
        );
    }
}

// ── observer bench: routed slot delivery vs unconditional fan-out ──────────────

fn now_ns(start: Instant, iters: u64) -> f64 {
    start.elapsed().as_nanos() as f64 / iters as f64
}

#[tokio::test]
#[ignore]
async fn cost_observer_routed_vs_unconditional_fanout() {
    use tokio::sync::mpsc;
    let ty = EventTypeId::Core(CoreEventId::FlowOpened);
    let iters: u64 = 100_000;
    for n in [1usize, 8, 32] {
        let bus = ObservationBus::new();
        let mut drains = Vec::new();
        for _ in 0..n {
            let (tx, mut rx) = mpsc::channel::<EventEnvelope>(64);
            bus.wire_subscriber(ty, tx);
            drains.push(tokio::spawn(
                async move { while rx.recv().await.is_some() {} },
            ));
        }
        let start = Instant::now();
        for _ in 0..iters {
            bus.publish(ty, EventPayload::empty());
        }
        let routed = now_ns(start, iters);

        let mut senders = Vec::new();
        let mut drains2 = Vec::new();
        for _ in 0..n {
            let (tx, mut rx) = mpsc::channel::<EventEnvelope>(64);
            senders.push(tx);
            drains2.push(tokio::spawn(
                async move { while rx.recv().await.is_some() {} },
            ));
        }
        let start = Instant::now();
        for _ in 0..iters {
            for s in &senders {
                let _ = s.try_send(EventEnvelope {
                    type_id: ty,
                    payload: EventPayload::empty(),
                    at_ns: 0,
                });
            }
        }
        let unconditional = now_ns(start, iters);

        println!(
            "[cost] observer n={n}: routed {routed:.1} ns/event, \
             unconditional_fanout {unconditional:.1} ns/event over {iters} events"
        );
        for d in drains.into_iter().chain(drains2) {
            d.abort();
        }
    }
}
