//! Integration bench: two stub stream egresses with asymmetric RTT.
//!
//! fast: 5 ms delay,  slow: 50 ms delay
//!
//! Each test opens N independent sessions (one connect + one send per session)
//! so the scheduler is consulted fresh for every request — no flow-pin lock-in.
//! After a warm-up window, CakeScheduler must converge to fast ≥ 90 %.
//!
//! Run:
//!   cargo test -p mesh-bus-bin cake_adaptive -- --nocapture

use async_trait::async_trait;
use bytes::Bytes;
use mb_endpoint::Endpoint;
use mesh_bus_core::{
    BusBuilder, BusSessionInfo, BusSessionRequest, Capabilities, DisconnectReason, ExitId,
    StreamEgress, StreamRecvHalf, StreamSendHalf, StreamSession,
};
use mesh_bus_scheduler_cake::CakeScheduler;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;
use tokio::time::sleep;

static CAKE_ADAPTIVE_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

// ---------------------------------------------------------------------------
// DelayEgress — stub StreamEgress with configurable fixed delay
// ---------------------------------------------------------------------------

struct DelayEgress {
    id: ExitId,
    delay: Duration,
    send_count: Arc<AtomicU64>,
}

struct DelaySession {
    delay: Duration,
    send_count: Arc<AtomicU64>,
    info: BusSessionInfo,
    last: Option<DisconnectReason>,
}

struct DelaySendHalf {
    delay: Duration,
    send_count: Arc<AtomicU64>,
}

struct DelayRecvHalf;

#[async_trait]
impl StreamSendHalf for DelaySendHalf {
    async fn send(&mut self, _payload: Bytes) -> Result<(), DisconnectReason> {
        sleep(self.delay).await;
        self.send_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    async fn shutdown_write(&mut self) {}

    async fn abort(&mut self, _reason: DisconnectReason) {}
}

#[async_trait]
impl StreamRecvHalf for DelayRecvHalf {
    async fn recv(&mut self) -> Option<Bytes> {
        None
    }

    fn last_error(&self) -> Option<&DisconnectReason> {
        None
    }
}

#[async_trait]
impl StreamSession for DelaySession {
    async fn connect(&mut self) -> Result<&BusSessionInfo, DisconnectReason> {
        // Sleep here so the Open frame measures actual egress RTT.
        // Without this, egress_adapter records rtt≈0 for all opens,
        // making the scheduler unable to distinguish exits during warmup.
        sleep(self.delay).await;
        Ok(&self.info)
    }

    fn into_tcp_splice(
        self: Box<Self>,
    ) -> Result<mesh_bus_core::TcpSpliceSession, Box<dyn StreamSession>> {
        Err(self)
    }

    fn split(self: Box<Self>) -> (Box<dyn StreamSendHalf>, Box<dyn StreamRecvHalf>) {
        let send = DelaySendHalf {
            delay: self.delay,
            send_count: self.send_count,
        };
        (Box::new(send), Box::new(DelayRecvHalf))
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

#[async_trait]
impl StreamEgress for DelayEgress {
    fn id(&self) -> &ExitId {
        &self.id
    }

    fn capabilities(&self) -> &Capabilities {
        static CAPS: std::sync::OnceLock<Capabilities> = std::sync::OnceLock::new();
        CAPS.get_or_init(|| Capabilities {
            protocol: "delay-stub".into(),
            supports_stream: true,
            supports_datagram: false,
            max_payload_bytes: None,
            groups: Vec::new(),
        })
    }

    async fn open_stream(
        &self,
        _request: &BusSessionRequest,
        info: BusSessionInfo,
    ) -> Result<Box<dyn StreamSession>, DisconnectReason> {
        Ok(Box::new(DelaySession {
            delay: self.delay,
            send_count: self.send_count.clone(),
            info,
            last: None,
        }))
    }
}

// ---------------------------------------------------------------------------
// Build helpers
// ---------------------------------------------------------------------------

fn make_egress(id: &str, delay_ms: u64, counter: Arc<AtomicU64>) -> Box<dyn StreamEgress> {
    Box::new(DelayEgress {
        id: ExitId(id.into()),
        delay: Duration::from_millis(delay_ms),
        send_count: counter,
    })
}

fn target() -> Endpoint {
    Endpoint::new("stub.internal", 80).expect("target endpoint")
}

// Send one frame through a fresh session.
// The scheduler is consulted on the Open frame (connect); the Data send is
// flow-pinned to that exit. Counter increments happen in DelaySendHalf::send.
async fn send_one_frame(port: &mesh_bus_core::BusPort) {
    let mut session = port
        .open_stream(BusSessionRequest::stream(target()))
        .await
        .expect("open stream");
    session.connect().await.expect("connect");
    let (mut tx, _rx) = session.split();
    let _ = tx.send(Bytes::from_static(b"x")).await;
}

// ---------------------------------------------------------------------------
// Test 1: convergence — fast must win > 90 % of 200 sends
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cake_adaptive_converges_on_low_rtt_exit() {
    let _guard = CAKE_ADAPTIVE_TEST_LOCK.lock().await;
    let fast_count = Arc::new(AtomicU64::new(0));
    let slow_count = Arc::new(AtomicU64::new(0));

    let bus = BusBuilder::new()
        .scheduler(Box::new(CakeScheduler::new()))
        .add_stream_egress(make_egress("fast", 5, fast_count.clone()))
        .add_stream_egress(make_egress("slow", 50, slow_count.clone()))
        .build()
        .await;
    let port = bus.port();
    let handle = bus.spawn();

    let n = 200usize;
    for _ in 0..n {
        send_one_frame(&port).await;
    }

    handle.shutdown().await;

    let fast = fast_count.load(Ordering::Relaxed);
    let slow = slow_count.load(Ordering::Relaxed);
    let total = fast + slow;
    let ratio = if total == 0 {
        0.0
    } else {
        fast as f64 / total as f64
    };

    println!("CAKE_ADAPTIVE_CONVERGE fast={fast} slow={slow} total={total} ratio={ratio:.3}");

    assert!(
        total > 0,
        "no sends recorded; egress adapter may not be calling send on the StreamSendHalf"
    );
    assert!(
        ratio >= 0.90,
        "fast exit ratio {ratio:.3} < 0.90 (fast={fast}, slow={slow}); \
         CakeScheduler is not converging — check feedback wiring in Tasks 7/9/11"
    );
}

// ---------------------------------------------------------------------------
// Test 2: no oscillation — after 50-frame warmup, slow appears ≤ 5 times
// in the following 100-frame observation window.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cake_adaptive_no_oscillation_under_stable_asymmetry() {
    let _guard = CAKE_ADAPTIVE_TEST_LOCK.lock().await;
    let fast_count = Arc::new(AtomicU64::new(0));
    let slow_count = Arc::new(AtomicU64::new(0));

    let bus = BusBuilder::new()
        .scheduler(Box::new(CakeScheduler::new()))
        .add_stream_egress(make_egress("fast", 5, fast_count.clone()))
        .add_stream_egress(make_egress("slow", 50, slow_count.clone()))
        .build()
        .await;
    let port = bus.port();
    let handle = bus.spawn();

    // Warmup: let the scheduler accumulate RTT data across both exits
    for _ in 0..50 {
        send_one_frame(&port).await;
    }

    // Reset counters to observe only the post-warmup window
    fast_count.store(0, Ordering::Relaxed);
    slow_count.store(0, Ordering::Relaxed);

    for _ in 0..100 {
        send_one_frame(&port).await;
    }

    handle.shutdown().await;

    let fast = fast_count.load(Ordering::Relaxed);
    let slow = slow_count.load(Ordering::Relaxed);

    println!("CAKE_ADAPTIVE_NO_OSCILLATION post-warmup fast={fast} slow={slow}");

    assert!(
        slow <= 5,
        "slow exit appeared {slow} times in 100-frame post-warmup window (fast={fast}); \
         scheduler is oscillating — check hysteresis in Task 11"
    );
}
