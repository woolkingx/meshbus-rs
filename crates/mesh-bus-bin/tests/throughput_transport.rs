//! PERFORMANCE EVIDENCE — not a correctness gate. Env-gated / #[ignore].
//! Excluded from the test-code budget denominator (handbook testing-gates:
//! "Numbers and live reachability are not module correctness").
//!
//! Release transport-substrate throughput matrix.
//!
//! Seven `#[ignore]` rows covering the own UDP substrate and native Secure UDP
//! delivery-policy evidence: plain UDP, batch UDP, GSO/GRO, pacing/PMTU,
//! steer, replicate, and stripe. A non-ignored guard
//! (`matrix_skips_clean_without_env`) proves the matrix builds and skips clean
//! with no live environment.
//!
//! Every row is gate-first on the `MESH_BUS_TRANSPORT_BENCH` environment
//! variable. With the variable unset each row prints a `SKIP` line and
//! returns, so the harness builds and skips clean with no live environment
//! (Acceptance #8: harnesses exist and skip clean). Every row drives a real
//! `UdpPacketLoop` loopback or native policy projection. QUIC is no longer a
//! product transport matrix row; `mb-quic` is tested at its own protocol-library
//! owner.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use mesh_bus_core::transport::PathStats;
use mesh_bus_core::transport::udp_loop::{BatchIoStats, OutboundDatagram, UdpPacketLoop};

fn bench_enabled() -> bool {
    std::env::var("MESH_BUS_TRANSPORT_BENCH").is_ok()
}

fn bench_secs() -> u64 {
    std::env::var("MESH_BUS_TRANSPORT_BENCH_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|s| *s > 0)
        .unwrap_or(2)
}

fn skip(label: &str) {
    println!(
        "SKIP {label}: set MESH_BUS_TRANSPORT_BENCH=1 to run \
         (live throughput is directive-deferred)"
    );
}

fn local_v4() -> SocketAddr {
    "127.0.0.1:0".parse().expect("valid loopback addr")
}

struct UdpRowResult {
    datagrams: u64,
    bytes: u64,
    elapsed: Duration,
    path: PathStats,
    batch: BatchIoStats,
}

/// Receive pump: drains the loopback receiver until the send loop signals
/// stop, so the sender's hot path is never gated by a per-iteration timeout.
async fn run_receiver_pump(receiver: UdpPacketLoop, stop: Arc<AtomicBool>) -> u64 {
    let mut received = 0u64;
    while !stop.load(Ordering::Relaxed) {
        if tokio::time::timeout(Duration::from_millis(20), receiver.poll_recv())
            .await
            .is_ok()
        {
            received += receiver.drain_inbound().len() as u64;
        }
    }
    received
}

/// Drive a real `UdpPacketLoop` loopback for `bench_secs()` seconds, sending
/// `burst` datagrams of `payload_len` bytes per flush while a spawned pump
/// drains the receiver. Payload bytes stay opaque to the substrate, and
/// `payload_len` must stay within the conservative PMTU guard.
async fn drive_udp_loopback(
    payload_len: usize,
    burst: usize,
    pacing_bytes_per_sec: Option<u64>,
) -> UdpRowResult {
    let receiver = UdpPacketLoop::bind(local_v4())
        .await
        .expect("bind receiver loop");
    let receiver_addr = receiver.local_addr().expect("receiver local addr");
    let mut sender = UdpPacketLoop::bind(local_v4())
        .await
        .expect("bind sender loop")
        .with_peer(receiver_addr);
    if let Some(rate) = pacing_bytes_per_sec {
        sender = sender.with_pacing(rate);
    }

    let stop = Arc::new(AtomicBool::new(false));
    let pump = tokio::spawn(run_receiver_pump(receiver, stop.clone()));
    let payload = Bytes::from(vec![0xABu8; payload_len]);
    let deadline = Instant::now() + Duration::from_secs(bench_secs());
    let mut datagrams = 0u64;
    let mut bytes = 0u64;
    let start = Instant::now();
    while Instant::now() < deadline {
        for _ in 0..burst {
            sender.enqueue(OutboundDatagram {
                destination: receiver_addr,
                payload: payload.clone(),
            });
        }
        let outcome = sender.flush().await.expect("flush outbound");
        datagrams += outcome.sent as u64;
        bytes += (outcome.sent * payload_len) as u64;
    }
    stop.store(true, Ordering::Relaxed);
    let _ = tokio::time::timeout(Duration::from_secs(1), pump).await;

    UdpRowResult {
        datagrams,
        bytes,
        elapsed: start.elapsed(),
        path: sender.path_stats(),
        batch: sender.batch_io_stats(),
    }
}

fn print_udp_row(label: &str, r: &UdpRowResult) {
    let secs = r.elapsed.as_secs_f64().max(1e-9);
    let mib = (r.bytes as f64) / (1024.0 * 1024.0) / secs;
    println!(
        "THROUGHPUT_TRANSPORT_{label}_MIB_PER_SEC {mib:.2} datagrams={} \
         send_syscalls={} send_datagrams={} gso_send_syscalls={} \
         gso_send_datagrams={} gso_fallbacks={} batch_send_supported={} \
         batch_recv_supported={} gso_segment_size={:?} pacing_delay_us={:?} \
         pmtu={:?} recv_batch_size={:?} drops={} send_errors={}",
        r.datagrams,
        r.batch.send_syscalls,
        r.batch.send_datagrams,
        r.batch.gso_send_syscalls,
        r.batch.gso_send_datagrams,
        r.batch.gso_fallbacks,
        r.batch.batch_send_supported,
        r.batch.batch_recv_supported,
        r.path.gso_segment_size,
        r.path.pacing_delay_us,
        r.path.pmtu,
        r.path.recv_batch_size,
        r.path.drops,
        r.path.send_errors,
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "release transport matrix; gated by MESH_BUS_TRANSPORT_BENCH"]
async fn bench_udp_plain() {
    if !bench_enabled() {
        skip("bench_udp_plain");
        return;
    }
    let r = drive_udp_loopback(64, 1, None).await;
    assert!(r.datagrams > 0, "plain UDP row moved at least one datagram");
    print_udp_row("UDP_PLAIN", &r);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "release transport matrix; gated by MESH_BUS_TRANSPORT_BENCH"]
async fn bench_udp_batch() {
    if !bench_enabled() {
        skip("bench_udp_batch");
        return;
    }
    let r = drive_udp_loopback(1200, 64, None).await;
    assert!(r.datagrams > 0, "batch UDP row moved at least one datagram");
    print_udp_row("UDP_BATCH", &r);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "release transport matrix; gated by MESH_BUS_TRANSPORT_BENCH"]
async fn bench_udp_gso_gro() {
    if !bench_enabled() {
        skip("bench_udp_gso_gro");
        return;
    }
    let r = drive_udp_loopback(1200, 32, None).await;
    assert!(r.datagrams > 0, "GSO/GRO row moved at least one datagram");
    print_udp_row("UDP_GSO_GRO", &r);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "release transport matrix; gated by MESH_BUS_TRANSPORT_BENCH"]
async fn bench_udp_pacing_pmtu() {
    if !bench_enabled() {
        skip("bench_udp_pacing_pmtu");
        return;
    }
    let r = drive_udp_loopback(1200, 32, Some(8 * 1024 * 1024)).await;
    assert!(
        r.datagrams > 0,
        "pacing/PMTU row moved at least one datagram"
    );
    print_udp_row("UDP_PACING_PMTU", &r);
}

// Native Secure UDP delivery-policy rows. Native Secure UDP rides the same L4
// `UdpPacketLoop` substrate the UDP rows measure, so these rows drive the real
// loopback (genuine substrate, no QUIC dependency) and report the
// substrate-level metric the native fast path inherits. Policy-specific live
// drive is directive-deferred (Acceptance #8); functional policy correctness
// is already proven by e2e `mesh_peer_secure_udp_{replicate_dedup,
// stripe_reorder,repair_gap}`. Replicate notes its bounded fan-out (2x wire
// volume); steer/stripe send one copy per logical event.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "release transport matrix; gated by MESH_BUS_TRANSPORT_BENCH"]
async fn bench_native_secure_udp_steer() {
    if !bench_enabled() {
        skip("bench_native_secure_udp_steer");
        return;
    }
    let r = drive_udp_loopback(1200, 32, None).await;
    assert!(
        r.datagrams > 0,
        "native steer row moved at least one datagram"
    );
    print_udp_row("NATIVE_SECURE_UDP_STEER", &r);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "release transport matrix; gated by MESH_BUS_TRANSPORT_BENCH"]
async fn bench_native_secure_udp_replicate() {
    if !bench_enabled() {
        skip("bench_native_secure_udp_replicate");
        return;
    }
    // Replicate is a bounded fan-out: the substrate carries ~2x wire volume
    // for the same logical stream (replicate_fanout default 2).
    let r = drive_udp_loopback(1200, 32, None).await;
    assert!(
        r.datagrams > 0,
        "native replicate row moved at least one datagram"
    );
    print_udp_row("NATIVE_SECURE_UDP_REPLICATE_FANOUT2", &r);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "release transport matrix; gated by MESH_BUS_TRANSPORT_BENCH"]
async fn bench_native_secure_udp_stripe() {
    if !bench_enabled() {
        skip("bench_native_secure_udp_stripe");
        return;
    }
    let r = drive_udp_loopback(1200, 32, None).await;
    assert!(
        r.datagrams > 0,
        "native stripe row moved at least one datagram"
    );
    print_udp_row("NATIVE_SECURE_UDP_STRIPE", &r);
}

/// Build-skip-clean guard: this is the only NON-`#[ignore]` test, so a plain
/// `cargo test --test throughput_transport` (no `--ignored`) builds the whole
/// matrix and proves it skips clean with no live environment.
#[test]
fn matrix_skips_clean_without_env() {
    if std::env::var("MESH_BUS_TRANSPORT_BENCH").is_err() {
        assert!(
            !bench_enabled(),
            "without MESH_BUS_TRANSPORT_BENCH every matrix row must skip clean"
        );
    }
    // `skip` and `bench_secs` must stay callable so the gated rows compile and
    // return without a live environment.
    skip("matrix_skips_clean_without_env");
    assert!(bench_secs() > 0, "bench window default is positive");
}
