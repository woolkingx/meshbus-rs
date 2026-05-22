// Irreducible-timing invariants for the kernel dispatch runtime.
// These tests prove pure temporal properties (wall-clock bounds, concurrency
// ordering, shutdown drain, poll task lifecycle) that cannot be expressed as
// frame.schema.json → return-event.schema.json data fixtures.
//
// Data-contract tests (dispatch transform owner-contract) have been moved to:
//   crates/mesh-bus-core/tests/dispatch_contract.rs  (9 cases)
//   crates/mesh-bus-core/tests/dispatch_datagram.rs  (6 cases)
//
// EgressPlugin is a published owner-test API (decision 0.4.39).
// The impls below are legitimate public-API usage for timing probes,
// not fake backdoor plugins.

use crate::{
    BusBuilder, Capabilities, EgressPlugin, ExitId, ExitResult, Frame, Measurement, RankContext,
    ReturnEvent, ReturnSemantics, ScheduleDecision, SchedulerPlugin, SessionId,
};
use async_trait::async_trait;
use bytes::Bytes;
use mb_endpoint::Endpoint;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use tokio::sync::{Mutex, mpsc};

struct FirstExitScheduler;
impl SchedulerPlugin for FirstExitScheduler {
    fn schedule(&self, candidates: &[ExitId], _ctx: &RankContext) -> ScheduleDecision {
        ScheduleDecision::ordered((0..candidates.len()).collect())
    }
    fn feedback(&self, _r: &ExitResult, _payload_bytes: u64, _at_ms: u64) {}
}

fn stream_caps() -> Capabilities {
    Capabilities {
        protocol: "test".into(),
        supports_stream: true,
        supports_datagram: false,
        max_payload_bytes: None,
        groups: Vec::new(),
    }
}

// ── Timing invariant 1: concurrent dispatch is non-blocking ──────────────────
/// Wall-clock: 3 concurrent sessions each wait 200ms egress → total < 500ms.
/// Proves: dispatch uses async concurrency (not sequential serialisation) across sessions.
#[tokio::test]
async fn concurrent_sessions_do_not_block() {
    use tokio::time::{Duration, Instant};

    struct SlowExit {
        id: ExitId,
        caps: Capabilities,
    }
    #[async_trait]
    impl EgressPlugin for SlowExit {
        fn id(&self) -> &ExitId {
            &self.id
        }
        fn capabilities(&self) -> &Capabilities {
            &self.caps
        }
        async fn send(&self, frame: Frame) -> ExitResult {
            tokio::time::sleep(Duration::from_millis(200)).await;
            ExitResult {
                exit_id: self.id.clone(),
                success: true,
                rtt_ms: 200,
                local_endpoint: None,
                return_event: ReturnEvent::Data {
                    seq: frame.seq,
                    payload: frame.payload,
                },
            }
        }
        async fn poll(&self, _: &SessionId) -> ReturnEvent {
            ReturnEvent::Idle
        }
        async fn probe(&self, _: &Endpoint) -> Measurement {
            Measurement {
                exit_id: self.id.clone(),
                at_ms: 0,
                rtt_ms: 200,
                payload_bytes: 0,
                jitter_ms: None,
                throughput_bps: None,
                success: true,
            }
        }
        async fn close(&self, _: &SessionId) {}
    }

    let bus = BusBuilder::new()
        .scheduler(Box::new(FirstExitScheduler))
        .add_egress(Box::new(SlowExit {
            id: ExitId("slow".into()),
            caps: stream_caps(),
        }))
        .build()
        .await;
    let port = bus.port();
    let _h = bus.spawn();

    let make_call = |port: crate::BusPort| async move {
        let mut s = port.open_session(Endpoint::new("x", 1).expect("ep")).await;
        s.submit
            .send(Frame::data(
                s.id.clone(),
                0,
                Endpoint::new("x", 1).expect("ep"),
                Bytes::from_static(b"x"),
            ))
            .await
            .expect("send");
        let _ = s.returns.recv().await.expect("return");
    };

    let start = Instant::now();
    let _ = tokio::join!(
        make_call(port.clone()),
        make_call(port.clone()),
        make_call(port)
    );
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_millis(500),
        "concurrent sessions blocked: {elapsed:?}"
    );
}

// ── Timing invariant 2: same-session frames dispatched in order, no overlap ──
/// Ordering + no-overlap: two sequential frames for same session are serialised.
/// AtomicBool in_flight: swap(true) detects concurrent send; 80ms sleep amplifies race window.
#[tokio::test]
async fn same_session_frames_are_dispatched_in_order_without_overlap() {
    use tokio::time::Duration;

    struct OrderedExit {
        id: ExitId,
        caps: Capabilities,
        in_flight: AtomicBool,
        overlap_count: Arc<AtomicU32>,
        seen: Arc<Mutex<Vec<u64>>>,
    }
    #[async_trait]
    impl EgressPlugin for OrderedExit {
        fn id(&self) -> &ExitId {
            &self.id
        }
        fn capabilities(&self) -> &Capabilities {
            &self.caps
        }
        async fn send(&self, frame: Frame) -> ExitResult {
            if self.in_flight.swap(true, Ordering::SeqCst) {
                self.overlap_count.fetch_add(1, Ordering::SeqCst);
            }
            tokio::time::sleep(Duration::from_millis(80)).await;
            self.seen.lock().await.push(frame.seq);
            self.in_flight.store(false, Ordering::SeqCst);
            ExitResult {
                exit_id: self.id.clone(),
                success: true,
                rtt_ms: 80,
                local_endpoint: None,
                return_event: ReturnEvent::Data {
                    seq: frame.seq,
                    payload: frame.payload,
                },
            }
        }
        async fn poll(&self, _: &SessionId) -> ReturnEvent {
            ReturnEvent::Idle
        }
        async fn probe(&self, _: &Endpoint) -> Measurement {
            Measurement {
                exit_id: self.id.clone(),
                at_ms: 0,
                rtt_ms: 80,
                payload_bytes: 0,
                jitter_ms: None,
                throughput_bps: None,
                success: true,
            }
        }
        async fn close(&self, _: &SessionId) {}
    }

    let overlap = Arc::new(AtomicU32::new(0));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let bus = BusBuilder::new()
        .scheduler(Box::new(FirstExitScheduler))
        .add_egress(Box::new(OrderedExit {
            id: ExitId("ordered".into()),
            caps: stream_caps(),
            in_flight: AtomicBool::new(false),
            overlap_count: overlap.clone(),
            seen: seen.clone(),
        }))
        .build()
        .await;
    let port = bus.port();
    let handle = bus.spawn();
    let mut session = port.open_session(Endpoint::new("x", 1).expect("ep")).await;
    for seq in [0, 1] {
        session
            .submit
            .send(Frame::data(
                session.id.clone(),
                seq,
                Endpoint::new("x", 1).expect("ep"),
                Bytes::from_static(b"x"),
            ))
            .await
            .expect("send");
    }
    let _ = session.returns.recv().await.expect("first");
    let _ = session.returns.recv().await.expect("second");
    handle.shutdown().await;
    assert_eq!(overlap.load(Ordering::SeqCst), 0);
    assert_eq!(*seen.lock().await, vec![0, 1]);
}

// ── Timing invariant 3: replicate fan-out returns exactly once ───────────────
/// Dedup + timing: replicate sends to both exits; only first (5ms) return arrives.
/// 80ms sleep + 20ms timeout proves the second return is deduped, not just late.
#[tokio::test]
async fn replicate_sends_to_multiple_egresses_and_returns_once() {
    use tokio::time::{Duration, timeout};

    struct ReplicaExit {
        id: ExitId,
        caps: Capabilities,
        send_count: Arc<AtomicU32>,
        delay: Duration,
        payload: Bytes,
    }
    #[async_trait]
    impl EgressPlugin for ReplicaExit {
        fn id(&self) -> &ExitId {
            &self.id
        }
        fn capabilities(&self) -> &Capabilities {
            &self.caps
        }
        async fn send(&self, frame: Frame) -> ExitResult {
            self.send_count.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
            ExitResult {
                exit_id: self.id.clone(),
                success: true,
                rtt_ms: self.delay.as_millis() as u64,
                local_endpoint: None,
                return_event: ReturnEvent::Data {
                    seq: frame.seq,
                    payload: self.payload.clone(),
                },
            }
        }
        async fn poll(&self, _: &SessionId) -> ReturnEvent {
            ReturnEvent::Idle
        }
        async fn probe(&self, _: &Endpoint) -> Measurement {
            Measurement {
                exit_id: self.id.clone(),
                at_ms: 0,
                rtt_ms: self.delay.as_millis() as u64,
                payload_bytes: 0,
                jitter_ms: None,
                throughput_bps: None,
                success: true,
            }
        }
        async fn close(&self, _: &SessionId) {}
    }

    struct ReplicateScheduler;
    impl SchedulerPlugin for ReplicateScheduler {
        fn schedule(&self, candidates: &[ExitId], _: &RankContext) -> ScheduleDecision {
            ScheduleDecision::replicate((0..candidates.len()).collect())
        }
        fn feedback(&self, _: &ExitResult, _: u64, _: u64) {}
    }

    let first_count = Arc::new(AtomicU32::new(0));
    let second_count = Arc::new(AtomicU32::new(0));
    let bus = BusBuilder::new()
        .scheduler(Box::new(ReplicateScheduler))
        .add_egress(Box::new(ReplicaExit {
            id: ExitId("fast".into()),
            caps: stream_caps(),
            send_count: first_count.clone(),
            delay: Duration::from_millis(5),
            payload: Bytes::from_static(b"fast"),
        }))
        .add_egress(Box::new(ReplicaExit {
            id: ExitId("slow".into()),
            caps: stream_caps(),
            send_count: second_count.clone(),
            delay: Duration::from_millis(50),
            payload: Bytes::from_static(b"slow"),
        }))
        .build()
        .await;
    let port = bus.port();
    let handle = bus.spawn();
    let mut session = port
        .open_session(Endpoint::new("example.com", 443).expect("ep"))
        .await;
    session
        .submit
        .send(Frame::data(
            session.id.clone(),
            7,
            Endpoint::new("example.com", 443).expect("ep"),
            Bytes::from_static(b"hello"),
        ))
        .await
        .expect("send");

    let evt = session.returns.recv().await.expect("first return");
    match evt {
        ReturnEvent::Data { payload, .. } => assert_eq!(&payload[..], b"fast"),
        _ => panic!("expected first Data"),
    }
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(first_count.load(Ordering::SeqCst), 1);
    assert_eq!(second_count.load(Ordering::SeqCst), 1);
    assert!(
        timeout(Duration::from_millis(20), session.returns.recv())
            .await
            .is_err(),
        "replicated packet produced more than one return event"
    );
    handle.shutdown().await;
}

// ── Timing invariant 4: replicate dedup with duplicate packet_id ─────────────
/// Replicate + PacketDedup: two frames same (flow_id, packet_id) → exactly one return.
/// 20ms timeout proves second is suppressed (not just late).
#[tokio::test]
async fn replicate_duplicate_packet_id_for_flow_returns_once() {
    use tokio::time::{Duration, timeout};

    struct CountingExit {
        id: ExitId,
        caps: Capabilities,
        send_count: Arc<AtomicU32>,
    }
    #[async_trait]
    impl EgressPlugin for CountingExit {
        fn id(&self) -> &ExitId {
            &self.id
        }
        fn capabilities(&self) -> &Capabilities {
            &self.caps
        }
        async fn send(&self, frame: Frame) -> ExitResult {
            self.send_count.fetch_add(1, Ordering::SeqCst);
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
        async fn poll(&self, _: &SessionId) -> ReturnEvent {
            ReturnEvent::Idle
        }
        async fn probe(&self, _: &Endpoint) -> Measurement {
            Measurement {
                exit_id: self.id.clone(),
                at_ms: 0,
                rtt_ms: 1,
                payload_bytes: 0,
                jitter_ms: None,
                throughput_bps: None,
                success: true,
            }
        }
        async fn close(&self, _: &SessionId) {}
    }

    struct ReplicateScheduler;
    impl SchedulerPlugin for ReplicateScheduler {
        fn schedule(&self, candidates: &[ExitId], _: &RankContext) -> ScheduleDecision {
            ScheduleDecision::replicate((0..candidates.len()).collect())
        }
        fn feedback(&self, _: &ExitResult, _: u64, _: u64) {}
    }

    let send_count = Arc::new(AtomicU32::new(0));
    let bus = BusBuilder::new()
        .scheduler(Box::new(ReplicateScheduler))
        .add_egress(Box::new(CountingExit {
            id: ExitId("dedup".into()),
            caps: stream_caps(),
            send_count: send_count.clone(),
        }))
        .build()
        .await;
    let port = bus.port();
    let handle = bus.spawn();
    let mut session = port
        .open_session(Endpoint::new("example.com", 443).expect("ep"))
        .await;
    let target = Endpoint::new("example.com", 443).expect("ep");
    let frame = Frame::data(
        session.id.clone(),
        11,
        target.clone(),
        Bytes::from_static(b"first"),
    );
    let mut duplicate = Frame::data(
        session.id.clone(),
        12,
        target,
        Bytes::from_static(b"second"),
    );
    duplicate.packet_id = frame.packet_id;
    duplicate.flow_id = frame.flow_id.clone();

    session.submit.send(frame).await.expect("send");
    session.submit.send(duplicate).await.expect("send dup");

    let _ = session.returns.recv().await.expect("first");
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(send_count.load(Ordering::SeqCst), 2);
    assert!(
        timeout(Duration::from_millis(20), session.returns.recv())
            .await
            .is_err(),
        "duplicate packet_id produced more than one return event"
    );
    handle.shutdown().await;
}

// ── Timing invariant 5: shutdown drains in-flight dispatch ───────────────────
/// Temporal: shutdown() must block until an in-flight egress::send finishes.
/// 120ms timeout proves shutdown does not return prematurely.
#[tokio::test]
async fn shutdown_waits_for_in_flight_dispatch_to_finish() {
    use tokio::sync::oneshot;
    use tokio::time::{Duration, timeout};

    struct BlockingExit {
        id: ExitId,
        caps: Capabilities,
        started: Arc<AtomicU32>,
        release_rx: tokio::sync::Mutex<Option<oneshot::Receiver<()>>>,
    }
    #[async_trait]
    impl EgressPlugin for BlockingExit {
        fn id(&self) -> &ExitId {
            &self.id
        }
        fn capabilities(&self) -> &Capabilities {
            &self.caps
        }
        async fn send(&self, frame: Frame) -> ExitResult {
            self.started.fetch_add(1, Ordering::SeqCst);
            let rx = self.release_rx.lock().await.take().expect("release rx");
            let _ = rx.await;
            ExitResult {
                exit_id: self.id.clone(),
                success: true,
                rtt_ms: 50,
                local_endpoint: None,
                return_event: ReturnEvent::Data {
                    seq: frame.seq,
                    payload: frame.payload,
                },
            }
        }
        async fn poll(&self, _: &SessionId) -> ReturnEvent {
            ReturnEvent::Idle
        }
        async fn probe(&self, _: &Endpoint) -> Measurement {
            Measurement {
                exit_id: self.id.clone(),
                at_ms: 0,
                rtt_ms: 1,
                payload_bytes: 0,
                jitter_ms: None,
                throughput_bps: None,
                success: true,
            }
        }
        async fn close(&self, _: &SessionId) {}
    }

    let (release_tx, release_rx) = oneshot::channel();
    let started = Arc::new(AtomicU32::new(0));
    let bus = BusBuilder::new()
        .scheduler(Box::new(FirstExitScheduler))
        .add_egress(Box::new(BlockingExit {
            id: ExitId("slow".into()),
            caps: stream_caps(),
            started: started.clone(),
            release_rx: tokio::sync::Mutex::new(Some(release_rx)),
        }))
        .build()
        .await;
    let port = bus.port();
    let handle = bus.spawn();
    let session = port.open_session(Endpoint::new("x", 1).expect("ep")).await;
    session
        .submit
        .send(Frame::data(
            session.id.clone(),
            0,
            Endpoint::new("x", 1).expect("ep"),
            Bytes::from_static(b"hello"),
        ))
        .await
        .expect("send");
    while started.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }

    let shutdown = tokio::spawn(async move {
        handle.shutdown().await;
    });
    assert!(
        timeout(Duration::from_millis(120), shutdown).await.is_err(),
        "shutdown returned before in-flight dispatch finished"
    );
    release_tx.send(()).expect("release");
}

// ── Timing invariant 6: snapshot responds under dispatch saturation ───────────
/// Command channel responsiveness: snapshot() must reply even while 512+ sends are blocked.
/// 120ms timeout on snapshot() proves it does not queue behind dispatch permits.
#[tokio::test]
async fn snapshot_responds_while_dispatch_concurrency_is_saturated() {
    use tokio::time::{Duration, timeout};

    struct BlockingExit {
        id: ExitId,
        caps: Capabilities,
        started: Arc<AtomicU32>,
        release: Arc<AtomicBool>,
    }
    #[async_trait]
    impl EgressPlugin for BlockingExit {
        fn id(&self) -> &ExitId {
            &self.id
        }
        fn capabilities(&self) -> &Capabilities {
            &self.caps
        }
        async fn send(&self, frame: Frame) -> ExitResult {
            self.started.fetch_add(1, Ordering::SeqCst);
            while !self.release.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
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
        async fn poll(&self, _: &SessionId) -> ReturnEvent {
            ReturnEvent::Idle
        }
        async fn probe(&self, _: &Endpoint) -> Measurement {
            Measurement {
                exit_id: self.id.clone(),
                at_ms: 0,
                rtt_ms: 1,
                payload_bytes: 0,
                jitter_ms: None,
                throughput_bps: None,
                success: true,
            }
        }
        async fn close(&self, _: &SessionId) {}
    }

    let started = Arc::new(AtomicU32::new(0));
    let release = Arc::new(AtomicBool::new(false));
    let bus = BusBuilder::new()
        .scheduler(Box::new(FirstExitScheduler))
        .add_egress(Box::new(BlockingExit {
            id: ExitId("blocked".into()),
            caps: stream_caps(),
            started: started.clone(),
            release: release.clone(),
        }))
        .build()
        .await;
    let port = bus.port();
    let handle = bus.spawn();
    for seq in 0..513 {
        let session = port.open_session(Endpoint::new("x", 1).expect("ep")).await;
        tokio::spawn(async move {
            session
                .submit
                .send(Frame::data(
                    session.id.clone(),
                    seq,
                    Endpoint::new("x", 1).expect("ep"),
                    Bytes::from_static(b"x"),
                ))
                .await
                .expect("send");
        });
    }
    while started.load(Ordering::SeqCst) < 512 {
        tokio::task::yield_now().await;
    }
    tokio::time::sleep(Duration::from_millis(20)).await;

    let snapshot = timeout(Duration::from_millis(120), handle.snapshot()).await;
    release.store(true, Ordering::SeqCst);
    handle.shutdown().await;
    assert!(
        snapshot.is_ok(),
        "snapshot must not wait behind dispatch permit saturation"
    );
}

// ── Timing invariant 7: replicate close aborts all poll tasks ────────────────
/// Poll task lifecycle: after Close frame, poll task count freezes.
/// 80ms sleep post-close + compare proves tasks stop incrementing.
#[tokio::test]
async fn replicate_close_aborts_all_session_polls() {
    use tokio::time::Duration;

    struct PollingReplica {
        id: ExitId,
        caps: Capabilities,
        poll_count: Arc<AtomicU32>,
    }
    #[async_trait]
    impl EgressPlugin for PollingReplica {
        fn id(&self) -> &ExitId {
            &self.id
        }
        fn capabilities(&self) -> &Capabilities {
            &self.caps
        }
        async fn send(&self, frame: Frame) -> ExitResult {
            ExitResult {
                exit_id: self.id.clone(),
                success: true,
                rtt_ms: 1,
                local_endpoint: None,
                return_event: ReturnEvent::Data {
                    seq: frame.seq,
                    payload: Bytes::from_static(b"ok"),
                },
            }
        }
        async fn poll(&self, _: &SessionId) -> ReturnEvent {
            self.poll_count.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(2)).await;
            ReturnEvent::Idle
        }
        async fn probe(&self, _: &Endpoint) -> Measurement {
            Measurement {
                exit_id: self.id.clone(),
                at_ms: 0,
                rtt_ms: 1,
                payload_bytes: 0,
                jitter_ms: None,
                throughput_bps: None,
                success: true,
            }
        }
        async fn close(&self, _: &SessionId) {}
    }

    struct ReplicateAll;
    impl SchedulerPlugin for ReplicateAll {
        fn schedule(&self, candidates: &[ExitId], _: &RankContext) -> ScheduleDecision {
            ScheduleDecision::replicate((0..candidates.len()).collect())
        }
        fn feedback(&self, _: &ExitResult, _: u64, _: u64) {}
    }

    let pa = Arc::new(AtomicU32::new(0));
    let pb = Arc::new(AtomicU32::new(0));
    let bus = BusBuilder::new()
        .scheduler(Box::new(ReplicateAll))
        .add_egress(Box::new(PollingReplica {
            id: ExitId("a".into()),
            caps: stream_caps(),
            poll_count: pa.clone(),
        }))
        .add_egress(Box::new(PollingReplica {
            id: ExitId("b".into()),
            caps: stream_caps(),
            poll_count: pb.clone(),
        }))
        .build()
        .await;
    let port = bus.port();
    let handle = bus.spawn();
    let target = Endpoint::new("example.com", 443).expect("ep");
    let mut session = port.open_session(target.clone()).await;
    session
        .submit
        .send(Frame::data(
            session.id.clone(),
            1,
            target.clone(),
            Bytes::from_static(b"hi"),
        ))
        .await
        .expect("send");
    let _ = session.returns.recv().await.expect("first");

    tokio::time::sleep(Duration::from_millis(40)).await;
    assert!(
        pa.load(Ordering::SeqCst) > 0 && pb.load(Ordering::SeqCst) > 0,
        "both exits must have running poll tasks before close"
    );

    session
        .submit
        .send(Frame::close(session.id.clone(), 2, target))
        .await
        .expect("close");
    tokio::time::sleep(Duration::from_millis(40)).await;
    let a1 = pa.load(Ordering::SeqCst);
    let b1 = pb.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(
        pa.load(Ordering::SeqCst),
        a1,
        "exit a poll task kept running after Close"
    );
    assert_eq!(
        pb.load(Ordering::SeqCst),
        b1,
        "exit b poll task kept running after Close"
    );
    handle.shutdown().await;
}
