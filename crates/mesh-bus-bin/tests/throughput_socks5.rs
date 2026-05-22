//! PERFORMANCE EVIDENCE — not a correctness gate. Env-gated / #[ignore].
//! Excluded from the test-code budget denominator (handbook testing-gates:
//! "Numbers and live reachability are not module correctness").
//!
//! Mock-to-mock SOCKS5 throughput baseline benchmark.
//!
//! All topology is in-process: TCP echo server → mesh-bus SOCKS5 ingress + TCP egress →
//! SOCKS5 client sends/receives bytes through the relay, measures MiB/s end-to-end.
//!
//! Run:
//!   cargo test --release --package mesh-bus-bin --test throughput_socks5 -- --ignored --nocapture
//!
//! Tests are #[ignore] so normal `cargo test` skips them.

use bytes::BytesMut;
use mb_endpoint::Endpoint;
use mb_proto_socks5::{Reply, decode_reply_frame, encode_connect_request, encode_greeting};
use std::net::SocketAddr;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;

const CHUNK_BYTES: usize = 64 * 1024;
const FLOOR_MIB_PER_SEC: f64 = 50.0;
const REGRESSION_RATIO: f64 = 0.90;

fn bench_secs() -> u64 {
    std::env::var("MESH_BUS_BENCH_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3)
}

fn io_timing_enabled() -> bool {
    std::env::var("MESH_BUS_BENCH_IO_TIMING")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn socket_buffer_yaml() -> String {
    std::env::var("MESH_BUS_SOCKET_BUFFER_BYTES")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .map(|bytes| {
            format!(
                "    socket_recv_buffer_bytes: {bytes}\n    socket_send_buffer_bytes: {bytes}\n"
            )
        })
        .unwrap_or_default()
}

fn baseline_key() -> String {
    std::env::var("MESH_BUS_BENCH_HOST").unwrap_or_else(|_| "default".to_string())
}

fn baseline_path() -> std::path::PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    std::path::PathBuf::from(manifest_dir)
        .join("..")
        .join("..")
        .join("bench_baselines")
        .join(format!("{}.json", baseline_key()))
}

fn load_baseline(label: &str) -> Option<f64> {
    let raw = std::fs::read_to_string(baseline_path()).ok()?;
    let map: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&raw).ok()?;
    map.get(label).and_then(|v| v.as_f64())
}

#[derive(Clone, Copy, Debug, Default)]
struct ConnectTiming {
    total: Duration,
    tcp_connect: Duration,
    greeting: Duration,
    request_reply: Duration,
}

#[derive(Clone, Copy, Debug, Default)]
struct DriveTiming {
    bytes: u64,
    iterations: u64,
    connect: ConnectTiming,
    write_total: Duration,
    read_total: Duration,
    writer_task: Duration,
    reader_task: Duration,
}

#[derive(Clone, Copy, Debug, Default)]
struct BenchTiming {
    echo_setup: Duration,
    bus_setup: Duration,
    drive: Duration,
    shutdown: Duration,
    drive_detail: DriveTiming,
    echo: EchoSnapshot,
}

#[derive(Debug, Default)]
struct EchoStats {
    connections: AtomicU64,
    read_bytes: AtomicU64,
    write_bytes: AtomicU64,
    iterations: AtomicU64,
    read_us: AtomicU64,
    write_us: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default)]
struct EchoSnapshot {
    connections: u64,
    read_bytes: u64,
    write_bytes: u64,
    iterations: u64,
    read_total: Duration,
    write_total: Duration,
}

impl EchoStats {
    fn snapshot(&self) -> EchoSnapshot {
        EchoSnapshot {
            connections: self.connections.load(Ordering::Relaxed),
            read_bytes: self.read_bytes.load(Ordering::Relaxed),
            write_bytes: self.write_bytes.load(Ordering::Relaxed),
            iterations: self.iterations.load(Ordering::Relaxed),
            read_total: Duration::from_micros(self.read_us.load(Ordering::Relaxed)),
            write_total: Duration::from_micros(self.write_us.load(Ordering::Relaxed)),
        }
    }
}

fn duration_ms(duration: Duration) -> u128 {
    duration.as_millis()
}

fn print_timing(label: &str, timing: &BenchTiming) {
    let d = timing.drive_detail;
    println!(
        "TIMING_SOCKS5_{label} setup_echo_ms={} setup_bus_ms={} drive_ms={} shutdown_ms={}",
        duration_ms(timing.echo_setup),
        duration_ms(timing.bus_setup),
        duration_ms(timing.drive),
        duration_ms(timing.shutdown)
    );
    println!(
        "TIMING_SOCKS5_{label} connect_total_ms={} tcp_connect_ms={} greeting_ms={} request_reply_ms={}",
        duration_ms(d.connect.total),
        duration_ms(d.connect.tcp_connect),
        duration_ms(d.connect.greeting),
        duration_ms(d.connect.request_reply)
    );
    println!(
        "TIMING_SOCKS5_{label} io_write_ms={} io_read_ms={} writer_task_ms={} reader_task_ms={} iterations={}",
        duration_ms(d.write_total),
        duration_ms(d.read_total),
        duration_ms(d.writer_task),
        duration_ms(d.reader_task),
        d.iterations
    );
    println!(
        "TIMING_SOCKS5_{label} echo_connections={} echo_read_bytes={} echo_write_bytes={} echo_read_ms={} echo_write_ms={} echo_iterations={}",
        timing.echo.connections,
        timing.echo.read_bytes,
        timing.echo.write_bytes,
        duration_ms(timing.echo.read_total),
        duration_ms(timing.echo.write_total),
        timing.echo.iterations
    );
}

/// Spawn a TCP echo server, return its address.
async fn spawn_echo() -> (SocketAddr, Arc<EchoStats>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("echo bind");
    let addr = listener.local_addr().expect("echo addr");
    let stats = Arc::new(EchoStats::default());
    let server_stats = stats.clone();
    let time_io = io_timing_enabled();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                break;
            };
            let _ = s.set_nodelay(true);
            let stats = server_stats.clone();
            stats.connections.fetch_add(1, Ordering::Relaxed);
            tokio::spawn(async move {
                let mut buf = vec![0u8; CHUNK_BYTES];
                loop {
                    let read_start = time_io.then(Instant::now);
                    let n = match s.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => n,
                        Err(_) => break,
                    };
                    if let Some(started) = read_start {
                        stats
                            .read_us
                            .fetch_add(started.elapsed().as_micros() as u64, Ordering::Relaxed);
                    }
                    stats.read_bytes.fetch_add(n as u64, Ordering::Relaxed);

                    let write_start = time_io.then(Instant::now);
                    if s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    if let Some(started) = write_start {
                        stats
                            .write_us
                            .fetch_add(started.elapsed().as_micros() as u64, Ordering::Relaxed);
                    }
                    stats.write_bytes.fetch_add(n as u64, Ordering::Relaxed);
                    stats.iterations.fetch_add(1, Ordering::Relaxed);
                }
            });
        }
    });
    (addr, stats)
}

/// Spawn mesh-bus in-process with SOCKS5 ingress + TCP egress.
/// Returns the SOCKS5 listen address and a shutdown handle.
async fn spawn_bus_ingress() -> (SocketAddr, mesh_bus_core::BusHandle) {
    use mesh_bus_runtime::{Config, parse_config, run};

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("ingress bind");
    let listen_addr = listener.local_addr().expect("ingress addr");
    // Drop the listener so the runtime can rebind it by address.
    drop(listener);

    let yaml = format!(
        r#"
ingresses:
  - kind: Socks5
    listen: {listen}
{ingress_socket_buffers}egresses:
  - kind: Tcp
    id: direct
    timeout_ms: 10000
{egress_socket_buffers}"#,
        listen = listen_addr,
        ingress_socket_buffers = socket_buffer_yaml(),
        egress_socket_buffers = socket_buffer_yaml()
    );
    let cfg: Config = parse_config(&yaml).expect("bench config");
    let handle = run(cfg, std::path::Path::new("."))
        .await
        .expect("bus start");

    // Wait until the SOCKS5 port is accepting.
    for _ in 0..100 {
        if TcpStream::connect(listen_addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    (listen_addr, handle)
}

/// Open a SOCKS5 CONNECT to `target` through the relay at `proxy`.
async fn socks5_connect(proxy: SocketAddr, target: &Endpoint) -> (TcpStream, ConnectTiming) {
    let total_start = Instant::now();
    let tcp_start = Instant::now();
    let mut s = TcpStream::connect(proxy).await.expect("connect proxy");
    let tcp_connect = tcp_start.elapsed();
    let _ = s.set_nodelay(true);

    let greeting_start = Instant::now();
    s.write_all(&encode_greeting(&[mb_proto_socks5::Method::NoAuth]))
        .await
        .expect("write greeting");
    let mut auth = [0u8; 2];
    s.read_exact(&mut auth).await.expect("read auth");
    assert_eq!(auth, [0x05, 0x00]);
    let greeting = greeting_start.elapsed();

    let request_start = Instant::now();
    s.write_all(&encode_connect_request(target))
        .await
        .expect("write connect");
    let mut reply_buf = [0u8; 10];
    s.read_exact(&mut reply_buf).await.expect("read reply");
    let mut bm = BytesMut::from(&reply_buf[..]);
    let reply = decode_reply_frame(&mut bm).expect("decode reply");
    assert_eq!(reply.reply, Reply::Succeeded, "CONNECT must succeed");
    let request_reply = request_start.elapsed();

    (
        s,
        ConnectTiming {
            total: total_start.elapsed(),
            tcp_connect,
            greeting,
            request_reply,
        },
    )
}

/// Drive one SOCKS5 CONNECT for `duration`, return bytes relayed.
async fn drive_single(proxy: SocketAddr, target: &Endpoint, duration: Duration) -> DriveTiming {
    let (mut stream, connect) = socks5_connect(proxy, target).await;
    let chunk = Arc::new(vec![0xabu8; CHUNK_BYTES]);
    let deadline = Instant::now() + duration;
    let mut total_bytes = 0u64;
    let mut iterations = 0u64;
    let mut write_total = Duration::ZERO;
    let mut read_total = Duration::ZERO;
    let mut recv_buf = vec![0u8; CHUNK_BYTES];
    let time_io = io_timing_enabled();

    while Instant::now() < deadline {
        let write_start = time_io.then(Instant::now);
        stream.write_all(&chunk).await.expect("write chunk");
        if let Some(started) = write_start {
            write_total += started.elapsed();
        }
        let read_start = time_io.then(Instant::now);
        stream.read_exact(&mut recv_buf).await.expect("read echo");
        if let Some(started) = read_start {
            read_total += started.elapsed();
        }
        total_bytes += CHUNK_BYTES as u64;
        iterations += 1;
    }
    DriveTiming {
        bytes: total_bytes,
        iterations,
        connect,
        write_total,
        read_total,
        ..DriveTiming::default()
    }
}

/// Drive one SOCKS5 CONNECT for `duration` in full-duplex streaming mode:
/// independent writer/reader halves, no per-chunk handshake. Returns bytes echoed back.
async fn drive_single_stream(
    proxy: SocketAddr,
    target: &Endpoint,
    duration: Duration,
) -> DriveTiming {
    let (stream, connect) = socks5_connect(proxy, target).await;
    let (mut rd, mut wr) = stream.into_split();
    let deadline = Instant::now() + duration;

    let writer = tokio::spawn(async move {
        let started = Instant::now();
        let chunk = vec![0xabu8; CHUNK_BYTES];
        let mut iterations = 0u64;
        while Instant::now() < deadline {
            if wr.write_all(&chunk).await.is_err() {
                break;
            }
            iterations += 1;
        }
        let _ = wr.shutdown().await;
        (started.elapsed(), iterations)
    });

    let reader = tokio::spawn(async move {
        let started = Instant::now();
        let mut buf = vec![0u8; CHUNK_BYTES];
        let mut total = 0u64;
        loop {
            match rd.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    total += n as u64;
                    if Instant::now() >= deadline {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        (total, started.elapsed())
    });

    let (writer_task, iterations) = writer.await.unwrap_or_default();
    let (bytes, reader_task) = reader.await.unwrap_or_default();
    DriveTiming {
        bytes,
        iterations,
        connect,
        writer_task,
        reader_task,
        ..DriveTiming::default()
    }
}

/// Drive N concurrent SOCKS5 CONNECTs for `duration`, return aggregate bytes.
async fn drive_concurrent(
    proxy: SocketAddr,
    target: Endpoint,
    concurrency: usize,
    duration: Duration,
) -> DriveTiming {
    let mut set = JoinSet::new();
    for _ in 0..concurrency {
        let t = target.clone();
        set.spawn(async move { drive_single(proxy, &t, duration).await });
    }
    let mut total = DriveTiming::default();
    while let Some(res) = set.join_next().await {
        let item = res.expect("bench task");
        total.bytes += item.bytes;
        total.iterations += item.iterations;
        total.write_total += item.write_total;
        total.read_total += item.read_total;
        total.connect.total += item.connect.total;
        total.connect.tcp_connect += item.connect.tcp_connect;
        total.connect.greeting += item.connect.greeting;
        total.connect.request_reply += item.connect.request_reply;
    }
    total
}

fn print_result(label: &str, bytes: u64, elapsed: Duration, concurrency: usize) {
    let secs = elapsed.as_secs_f64();
    let mib_per_sec = bytes as f64 / secs / (1024.0 * 1024.0);
    let chunks = bytes / CHUNK_BYTES as u64;
    println!("THROUGHPUT_SOCKS5_{label}_MIB_PER_SEC={mib_per_sec:.2}");
    println!(
        "  elapsed_ms={} chunks={} chunk_bytes={} concurrency={} total_bytes={}",
        elapsed.as_millis(),
        chunks,
        CHUNK_BYTES,
        concurrency,
        bytes
    );
    assert!(
        mib_per_sec >= FLOOR_MIB_PER_SEC,
        "{label}: throughput {mib_per_sec:.2} MiB/s is below sanity floor {FLOOR_MIB_PER_SEC} MiB/s"
    );
    if let Some(baseline) = load_baseline(label) {
        let ratio = mib_per_sec / baseline;
        println!("  baseline_mib_per_sec={baseline:.2} ratio={ratio:.3}");
        assert!(
            ratio >= REGRESSION_RATIO,
            "{label}: measured {mib_per_sec:.2} MiB/s vs baseline {baseline:.2} MiB/s, ratio {ratio:.3} < {REGRESSION_RATIO}"
        );
    } else {
        println!(
            "  baseline=absent (run with MESH_BUS_BENCH_HOST=<host> and create bench_baselines/<host>.json to enable ratio gate)"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn bench_single_connection() {
    let setup_echo = Instant::now();
    let (echo_addr, echo_stats) = spawn_echo().await;
    let echo_setup = setup_echo.elapsed();
    let setup_bus = Instant::now();
    let (proxy, handle) = spawn_bus_ingress().await;
    let bus_setup = setup_bus.elapsed();
    let target = Endpoint::new(echo_addr.ip().to_string(), echo_addr.port()).expect("target");
    let duration = Duration::from_secs(bench_secs());

    let t0 = Instant::now();
    let drive = drive_single(proxy, &target, duration).await;
    let elapsed = t0.elapsed();

    let shutdown = Instant::now();
    handle.shutdown().await;
    let shutdown = shutdown.elapsed();
    print_result("LOOPBACK_1CONN", drive.bytes, elapsed, 1);
    print_timing(
        "LOOPBACK_1CONN",
        &BenchTiming {
            echo_setup,
            bus_setup,
            drive: elapsed,
            shutdown,
            drive_detail: drive,
            echo: echo_stats.snapshot(),
        },
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn bench_stream_1conn() {
    let setup_echo = Instant::now();
    let (echo_addr, echo_stats) = spawn_echo().await;
    let echo_setup = setup_echo.elapsed();
    let setup_bus = Instant::now();
    let (proxy, handle) = spawn_bus_ingress().await;
    let bus_setup = setup_bus.elapsed();
    let target = Endpoint::new(echo_addr.ip().to_string(), echo_addr.port()).expect("target");
    let duration = Duration::from_secs(bench_secs());

    let t0 = Instant::now();
    let drive = drive_single_stream(proxy, &target, duration).await;
    let elapsed = t0.elapsed();

    let shutdown = Instant::now();
    handle.shutdown().await;
    let shutdown = shutdown.elapsed();
    print_result("LOOPBACK_STREAM_1CONN", drive.bytes, elapsed, 1);
    print_timing(
        "LOOPBACK_STREAM_1CONN",
        &BenchTiming {
            echo_setup,
            bus_setup,
            drive: elapsed,
            shutdown,
            drive_detail: drive,
            echo: echo_stats.snapshot(),
        },
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn bench_concurrent_8() {
    let setup_echo = Instant::now();
    let (echo_addr, echo_stats) = spawn_echo().await;
    let echo_setup = setup_echo.elapsed();
    let setup_bus = Instant::now();
    let (proxy, handle) = spawn_bus_ingress().await;
    let bus_setup = setup_bus.elapsed();
    let target = Endpoint::new(echo_addr.ip().to_string(), echo_addr.port()).expect("target");
    let duration = Duration::from_secs(bench_secs());

    let t0 = Instant::now();
    let drive = drive_concurrent(proxy, target, 8, duration).await;
    let elapsed = t0.elapsed();

    let shutdown = Instant::now();
    handle.shutdown().await;
    let shutdown = shutdown.elapsed();
    print_result("LOOPBACK_8CONN", drive.bytes, elapsed, 8);
    print_timing(
        "LOOPBACK_8CONN",
        &BenchTiming {
            echo_setup,
            bus_setup,
            drive: elapsed,
            shutdown,
            drive_detail: drive,
            echo: echo_stats.snapshot(),
        },
    );
}
