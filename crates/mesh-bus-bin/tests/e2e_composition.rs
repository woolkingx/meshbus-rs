//! Product composition fixtures. Drives the REAL in-process bus via
//! mesh_bus_runtime::{parse_config, run}; readiness is a deterministic
//! TCP/UDP connect probe, never a fixed sleep. Composition only — it must
//! not retest codec/crypto/reorder/schema (owned elsewhere).
//!
//! Config YAML in fixtures may use these placeholders substituted at runtime:
//!   {{TCP_LISTEN}}     — free TCP addr for TCP/SOCKS5 ingress listen
//!   {{UDP_LISTEN}}     — free UDP addr for UDP ingress listen
//!   {{TCP_ECHO}}       — addr of the test TCP echo server
//!   {{UDP_ECHO}}       — addr of the test UDP echo server
//!   {{METRICS_LISTEN}} — free TCP addr for Prometheus HTTP metrics
//!   {{ALLOW_RULE_CHAIN}} — temp allow-all rule chain path
//!   {{RULE_CHAIN}}     — temp rule chain from input.rule_chain_yaml
mod e2e_client;

use bytes::BytesMut;
use e2e_client::{
    direct_tcp_roundtrip, direct_udp_roundtrip, dispatch_total_for, free_tcp_addr, free_udp_addr,
    http_get, socks5_tcp_roundtrip, socks5_udp_roundtrip, spawn_tcp_echo, spawn_udp_echo,
    wait_for_tcp_listener,
};
use mb_endpoint::Endpoint;
use mb_proto_socks5::{
    Reply, decode_reply_frame, decode_udp_datagram, decode_user_pass_reply, encode_connect_request,
    encode_greeting, encode_reply_with_endpoint, encode_udp_datagram, encode_user_pass_request,
};
use mesh_bus_runtime::{parse_config, run};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream as TokioTcpStream;
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinSet;

#[derive(Deserialize)]
struct Case {
    id: String,
    owner: String,
    kind: String,
    case: String,
    schema_ref: String,
    input: Input,
    expect: Expect,
    #[serde(default)]
    observations: Vec<serde_yaml::Value>,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Probe {
    /// Direct TCP roundtrip (raw TCP ingress → TCP egress).
    DirectTcp {
        #[serde(default)]
        payload: Option<String>,
        #[serde(default)]
        payload_hex: Option<String>,
    },
    /// Direct UDP roundtrip (raw UDP ingress → UDP egress).
    DirectUdp { payload: String },
    /// SOCKS5 CONNECT roundtrip (SOCKS5 ingress → TCP egress → TCP echo).
    Socks5Tcp { payload: String },
    /// SOCKS5 user/pass CONNECT roundtrip.
    Socks5AuthTcp {
        username: String,
        password: String,
        payload: String,
    },
    /// SOCKS5 user/pass rejection path.
    Socks5AuthReject { username: String, password: String },
    /// Denied SOCKS5 CONNECT followed by an allowed CONNECT roundtrip.
    Socks5DenyThenAllow {
        blocked_host: String,
        blocked_port: u16,
        allow_payload: String,
    },
    /// SOCKS5 BIND local peer relay in both directions.
    Socks5Bind {
        peer_payload: String,
        client_payload: String,
    },
    /// SOCKS5 UDP ASSOCIATE roundtrip (SOCKS5 ingress → UDP egress → UDP echo).
    Socks5Udp { payload: String },
    /// SOCKS5 UDP ASSOCIATE through an upstream SOCKS5 UDP egress.
    Socks5UdpViaUpstream { payload: String },
    /// SOCKS5 CONNECT with a large payload (integrity check).
    Socks5LargeTcp { size_bytes: usize },
    /// N concurrent SOCKS5 CONNECT roundtrips + optional dispatch metrics assert.
    Socks5ConcurrentTcp {
        count: u8,
        payload_len: usize,
        #[serde(default)]
        expect_dispatch_min: Option<u64>,
    },
    /// N concurrent SOCKS5 TCP + M concurrent SOCKS5 UDP roundtrips.
    Socks5ConcurrentTcpUdp { tcp_count: u8, udp_count: u8 },
    /// Single SOCKS5 TCP roundtrip then scrape metrics and assert substrings.
    Socks5TcpThenMetrics {
        payload: String,
        assert_metrics_contains: Vec<String>,
    },
}

#[derive(Deserialize)]
struct Input {
    yaml: String,
    #[serde(default)]
    probe: Option<Probe>,
    #[serde(default)]
    rule_chain_yaml: Option<String>,
}

#[derive(Deserialize)]
struct Expect {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    metrics: Option<MetricsExpect>,
}

#[derive(Deserialize)]
struct MetricsExpect {
    #[serde(default)]
    dispatch_total: BTreeMap<String, DispatchTotalExpect>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum DispatchTotalExpect {
    Exact(u64),
    Bounds {
        #[serde(default)]
        min: Option<u64>,
        #[serde(default)]
        exact: Option<u64>,
    },
}

fn substitute(
    tmpl: &str,
    tcp_listen: &str,
    udp_listen: &str,
    tcp_echo: &str,
    udp_echo: &str,
    metrics: &str,
    upstream_socks5_udp: Option<u16>,
    rule_chain: Option<&Path>,
) -> String {
    tmpl.replace("{{TCP_LISTEN}}", tcp_listen)
        .replace("{{UDP_LISTEN}}", udp_listen)
        .replace("{{TCP_ECHO}}", tcp_echo)
        .replace("{{UDP_ECHO}}", udp_echo)
        .replace("{{METRICS_LISTEN}}", metrics)
        .replace(
            "{{UPSTREAM_SOCKS5_UDP}}",
            &upstream_socks5_udp
                .map(|port| format!("127.0.0.1:{port}"))
                .unwrap_or_default(),
        )
        .replace(
            "{{ALLOW_RULE_CHAIN}}",
            &allow_rule_chain().display().to_string(),
        )
        .replace(
            "{{RULE_CHAIN}}",
            &rule_chain
                .map(|path| path.display().to_string())
                .unwrap_or_default(),
        )
}

fn allow_rule_chain() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("mesh-bus-e2e-allow-{}.yaml", std::process::id()));
    std::fs::write(&path, "default: allow\nrules: []\n").expect("write allow rule chain");
    path
}

fn probe_payload(name: &str, payload: Option<&str>, payload_hex: Option<&str>) -> Vec<u8> {
    match (payload, payload_hex) {
        (Some(text), None) => text.as_bytes().to_vec(),
        (None, Some(hex)) => decode_hex(name, hex),
        _ => panic!("[{name}] define exactly one of payload or payload_hex"),
    }
}

fn decode_hex(name: &str, hex: &str) -> Vec<u8> {
    assert!(
        hex.len() % 2 == 0,
        "[{name}] payload_hex must have even length"
    );
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .unwrap_or_else(|_| panic!("[{name}] invalid payload_hex"))
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn product_composition_fixtures() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/e2e");
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .expect("fixtures/e2e")
        .filter_map(|e| {
            let p = e.unwrap().path();
            if p.extension().and_then(|x| x.to_str()) == Some("yaml") {
                Some(p)
            } else {
                None
            }
        })
        .collect();
    entries.sort();

    for p in entries {
        let c: Case = serde_yaml::from_str(&std::fs::read_to_string(&p).unwrap())
            .unwrap_or_else(|e| panic!("fixture {p:?}: {e}"));
        assert_eq!(c.owner, "mesh-bus-bin.e2e", "[{}] owner", c.id);
        assert_eq!(c.kind, "service-composition", "[{}] kind", c.id);
        assert_eq!(
            c.schema_ref, "schemas/test-runtime.schema.json",
            "[{}] schema_ref",
            c.id
        );
        assert!(
            c.observations.is_empty(),
            "[{}] observations must be empty in this runner",
            c.id
        );
        assert!(
            c.tags.is_empty(),
            "[{}] tags must be empty in this runner",
            c.id
        );
        run_case(c).await;
    }
}

async fn run_case(c: Case) {
    let tcp_listen = free_tcp_addr();
    let udp_listen = free_udp_addr();
    let tcp_echo = spawn_tcp_echo().await;
    let udp_echo = spawn_udp_echo().await;
    let metrics = free_tcp_addr();
    let rule_chain = c
        .input
        .rule_chain_yaml
        .as_ref()
        .map(|yaml| write_temp_rule_chain(&c.id, yaml));
    let upstream_socks5_udp = if matches!(
        c.input.probe.as_ref(),
        Some(Probe::Socks5UdpViaUpstream { .. })
    ) {
        Some(spawn_fake_upstream_socks5_udp().await)
    } else {
        None
    };

    let yaml = substitute(
        &c.input.yaml,
        &tcp_listen.to_string(),
        &udp_listen.to_string(),
        &tcp_echo.to_string(),
        &udp_echo.to_string(),
        &metrics.to_string(),
        upstream_socks5_udp,
        rule_chain.as_deref(),
    );

    let cfg = parse_config(&yaml).unwrap_or_else(|e| panic!("[{}] parse: {e:#}", c.id));
    let handle = run(cfg, Path::new(".")).await;

    if !c.expect.ok {
        assert!(handle.is_err(), "[{}] expected boot failure", c.id);
        return;
    }
    let handle = handle.unwrap_or_else(|e| panic!("[{}] boot: {e:#}", c.id));

    match c.case.as_str() {
        "e2e.boot_shutdown" => assert!(c.input.probe.is_none(), "[{}] boot case has probe", c.id),
        "e2e.roundtrip" => assert!(
            c.input.probe.is_some(),
            "[{}] roundtrip case needs probe",
            c.id
        ),
        other => panic!("[{}] unsupported case {other}", c.id),
    }

    if let Some(probe) = c.input.probe {
        run_probe(
            &c.id, probe, tcp_listen, udp_listen, tcp_echo, udp_echo, metrics,
        )
        .await;
    }

    if let Some(metrics_expect) = &c.expect.metrics {
        assert_metrics(&c.id, metrics, metrics_expect).await;
    }
    handle.shutdown().await;
    if let Some(path) = rule_chain {
        let _ = std::fs::remove_file(path);
    }
}

async fn run_probe(
    name: &str,
    probe: Probe,
    tcp_listen: std::net::SocketAddr,
    udp_listen: std::net::SocketAddr,
    tcp_echo: std::net::SocketAddr,
    udp_echo: std::net::SocketAddr,
    metrics: std::net::SocketAddr,
) {
    match probe {
        Probe::DirectTcp {
            payload,
            payload_hex,
        } => {
            wait_for_tcp_listener(tcp_listen).await;
            let bytes = probe_payload(name, payload.as_deref(), payload_hex.as_deref());
            direct_tcp_roundtrip(tcp_listen, &bytes).await;
        }

        Probe::DirectUdp { payload } => {
            direct_udp_roundtrip(udp_listen, payload.as_bytes()).await;
        }

        Probe::Socks5Tcp { payload } => {
            wait_for_tcp_listener(tcp_listen).await;
            let target = Endpoint::new(tcp_echo.ip().to_string(), tcp_echo.port())
                .expect("tcp echo endpoint");
            socks5_tcp_roundtrip(tcp_listen, target, payload.as_bytes()).await;
        }

        Probe::Socks5AuthTcp {
            username,
            password,
            payload,
        } => {
            wait_for_tcp_listener(tcp_listen).await;
            let target = Endpoint::new(tcp_echo.ip().to_string(), tcp_echo.port())
                .expect("tcp echo endpoint");
            socks5_user_pass_connect_roundtrip(
                tcp_listen,
                target,
                payload.as_bytes(),
                username.as_bytes(),
                password.as_bytes(),
            )
            .await;
        }

        Probe::Socks5AuthReject { username, password } => {
            wait_for_tcp_listener(tcp_listen).await;
            socks5_user_pass_rejects(tcp_listen, username.as_bytes(), password.as_bytes()).await;
        }

        Probe::Socks5DenyThenAllow {
            blocked_host,
            blocked_port,
            allow_payload,
        } => {
            wait_for_tcp_listener(tcp_listen).await;
            let blocked = Endpoint::new(blocked_host, blocked_port).expect("blocked endpoint");
            socks5_connect_reply(tcp_listen, &blocked, Reply::ConnectionNotAllowed).await;
            let target = Endpoint::new(tcp_echo.ip().to_string(), tcp_echo.port())
                .expect("tcp echo endpoint");
            socks5_tcp_roundtrip(tcp_listen, target, allow_payload.as_bytes()).await;
        }

        Probe::Socks5Bind {
            peer_payload,
            client_payload,
        } => {
            wait_for_tcp_listener(tcp_listen).await;
            socks5_bind_roundtrip(
                tcp_listen,
                peer_payload.as_bytes(),
                client_payload.as_bytes(),
            )
            .await;
        }

        Probe::Socks5Udp { payload } => {
            wait_for_tcp_listener(tcp_listen).await;
            let target = Endpoint::new(udp_echo.ip().to_string(), udp_echo.port())
                .expect("udp echo endpoint");
            socks5_udp_roundtrip(tcp_listen, target, payload.as_bytes()).await;
        }

        Probe::Socks5UdpViaUpstream { payload } => {
            wait_for_tcp_listener(tcp_listen).await;
            let target = Endpoint::new(udp_echo.ip().to_string(), udp_echo.port())
                .expect("udp echo endpoint");
            socks5_udp_roundtrip(tcp_listen, target, payload.as_bytes()).await;
        }

        Probe::Socks5LargeTcp { size_bytes } => {
            wait_for_tcp_listener(tcp_listen).await;
            let target = Endpoint::new(tcp_echo.ip().to_string(), tcp_echo.port())
                .expect("tcp echo endpoint");
            let mut client = TokioTcpStream::connect(tcp_listen)
                .await
                .expect("connect socks");
            client
                .write_all(&encode_greeting(&[mb_proto_socks5::Method::NoAuth]))
                .await
                .expect("write greeting");
            let mut auth = [0u8; 2];
            client.read_exact(&mut auth).await.expect("read auth");
            assert_eq!(auth, [0x05, 0x00]);
            client
                .write_all(&encode_connect_request(&target))
                .await
                .expect("write connect");
            let mut rep = [0u8; 10];
            client.read_exact(&mut rep).await.expect("read reply");
            let mut rep_buf = BytesMut::from(&rep[..]);
            let reply = decode_reply_frame(&mut rep_buf).expect("decode reply");
            assert_eq!(reply.reply, Reply::Succeeded);
            let payload: Vec<u8> = (0..size_bytes).map(|i| (i & 0xff) as u8).collect();
            let payload_clone = payload.clone();
            let (mut rh, mut wh) = client.split();
            let writer = async move {
                wh.write_all(&payload_clone)
                    .await
                    .expect("write large payload");
                wh.shutdown().await.expect("shutdown write");
            };
            let mut out = vec![0u8; size_bytes];
            let reader = async {
                rh.read_exact(&mut out).await.expect("read large echo");
            };
            tokio::join!(writer, reader);
            assert_eq!(&out[..], &payload[..], "[{name}] large payload corrupted");
        }

        Probe::Socks5ConcurrentTcp {
            count,
            payload_len,
            expect_dispatch_min,
        } => {
            wait_for_tcp_listener(tcp_listen).await;
            let target = Endpoint::new(tcp_echo.ip().to_string(), tcp_echo.port())
                .expect("tcp echo endpoint");
            let mut tasks = JoinSet::new();
            for i in 0..count {
                let t = target.clone();
                tasks.spawn(async move {
                    let payload = vec![i; payload_len];
                    socks5_tcp_roundtrip(tcp_listen, t, &payload).await;
                });
            }
            while let Some(r) = tasks.join_next().await {
                r.expect("concurrent tcp task");
            }
            if let Some(min) = expect_dispatch_min {
                wait_for_tcp_listener(metrics).await;
                let response = http_get(metrics, "/metrics").await;
                let line = response
                    .lines()
                    .find(|l| l.starts_with("mesh_bus_dispatch_success_total{"))
                    .unwrap_or_else(|| {
                        panic!("[{name}] dispatch_success counter not found in metrics")
                    });
                let actual: u64 = line
                    .split_whitespace()
                    .last()
                    .expect("metric value")
                    .parse()
                    .expect("metric value u64");
                assert!(
                    actual >= min,
                    "[{name}] expected >={min} successful dispatches, got {actual}"
                );
            }
        }

        Probe::Socks5ConcurrentTcpUdp {
            tcp_count,
            udp_count,
        } => {
            wait_for_tcp_listener(tcp_listen).await;
            let tcp_target = Endpoint::new(tcp_echo.ip().to_string(), tcp_echo.port())
                .expect("tcp echo endpoint");
            let udp_target = Endpoint::new(udp_echo.ip().to_string(), udp_echo.port())
                .expect("udp echo endpoint");
            let mut tasks = JoinSet::new();
            for i in 0..tcp_count {
                let t = tcp_target.clone();
                tasks.spawn(async move {
                    let payload = vec![i; 1024];
                    socks5_tcp_roundtrip(tcp_listen, t, &payload).await;
                });
            }
            for i in 0..udp_count {
                let t = udp_target.clone();
                tasks.spawn(async move {
                    let payload = vec![b'a' + (i % 26); 256];
                    socks5_udp_roundtrip(tcp_listen, t, &payload).await;
                });
            }
            while let Some(r) = tasks.join_next().await {
                r.expect("concurrent tcp/udp task");
            }
        }

        Probe::Socks5TcpThenMetrics {
            payload,
            assert_metrics_contains,
        } => {
            wait_for_tcp_listener(tcp_listen).await;
            let target = Endpoint::new(tcp_echo.ip().to_string(), tcp_echo.port())
                .expect("tcp echo endpoint");
            socks5_tcp_roundtrip(tcp_listen, target, payload.as_bytes()).await;
            wait_for_tcp_listener(metrics).await;
            let response = http_get(metrics, "/metrics").await;
            assert!(
                response.starts_with("HTTP/1.1 200 OK"),
                "[{name}] metrics HTTP 200"
            );
            for s in &assert_metrics_contains {
                assert!(
                    response.contains(s.as_str()),
                    "[{name}] metrics missing: {s}\ngot:\n{response}"
                );
            }
        }
    }
}

async fn assert_metrics(name: &str, metrics: std::net::SocketAddr, expect: &MetricsExpect) {
    wait_for_tcp_listener(metrics).await;
    let response = http_get(metrics, "/metrics").await;
    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "[{name}] metrics HTTP 200"
    );
    for (exit_id, item) in &expect.dispatch_total {
        let actual = dispatch_total_for(&response, exit_id);
        match item {
            DispatchTotalExpect::Exact(exact) => assert_eq!(
                actual, *exact,
                "[{name}] expected dispatch_total for {exit_id} == {exact}\n{response}"
            ),
            DispatchTotalExpect::Bounds { min, exact } => {
                if let Some(min) = min {
                    assert!(
                        actual >= *min,
                        "[{name}] expected dispatch_total for {exit_id} >= {min}, got {actual}\n{response}"
                    );
                }
                if let Some(exact) = exact {
                    assert_eq!(
                        actual, *exact,
                        "[{name}] expected dispatch_total for {exit_id} == {exact}\n{response}"
                    );
                }
            }
        }
    }
}

async fn socks5_user_pass_connect_roundtrip(
    listen: std::net::SocketAddr,
    target: Endpoint,
    payload: &[u8],
    username: &[u8],
    password: &[u8],
) {
    let mut client = TokioTcpStream::connect(listen)
        .await
        .expect("connect socks");
    client
        .write_all(&encode_greeting(&[mb_proto_socks5::Method::UserPass]))
        .await
        .expect("write greeting");
    let mut method = [0u8; 2];
    client.read_exact(&mut method).await.expect("read method");
    assert_eq!(method, [0x05, 0x02], "server must select UserPass");

    let req = encode_user_pass_request(username, password).expect("encode user_pass");
    client.write_all(&req).await.expect("write user_pass");
    let mut auth_reply = [0u8; 2];
    client
        .read_exact(&mut auth_reply)
        .await
        .expect("read user_pass reply");
    let mut auth_buf = BytesMut::from(&auth_reply[..]);
    let status = decode_user_pass_reply(&mut auth_buf).expect("decode user_pass reply");
    assert_eq!(status, 0x00, "auth must succeed");

    client
        .write_all(&encode_connect_request(&target))
        .await
        .expect("write connect");
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.expect("read reply");
    let mut reply_buf = BytesMut::from(&reply[..]);
    let parsed = decode_reply_frame(&mut reply_buf).expect("decode reply");
    assert_eq!(parsed.reply, Reply::Succeeded);

    client.write_all(payload).await.expect("write payload");
    let mut out = vec![0u8; payload.len()];
    client.read_exact(&mut out).await.expect("read echo");
    assert_eq!(out, payload);
}

async fn socks5_user_pass_rejects(listen: std::net::SocketAddr, username: &[u8], password: &[u8]) {
    let mut client = TokioTcpStream::connect(listen)
        .await
        .expect("connect socks");
    client
        .write_all(&encode_greeting(&[mb_proto_socks5::Method::UserPass]))
        .await
        .expect("write greeting");
    let mut method = [0u8; 2];
    client.read_exact(&mut method).await.expect("read method");
    assert_eq!(method, [0x05, 0x02], "server must select UserPass");

    let req = encode_user_pass_request(username, password).expect("encode user_pass");
    client.write_all(&req).await.expect("write user_pass");
    let mut reply = [0u8; 2];
    client
        .read_exact(&mut reply)
        .await
        .expect("read user_pass reply");
    let mut reply_buf = BytesMut::from(&reply[..]);
    let status = decode_user_pass_reply(&mut reply_buf).expect("decode user_pass reply");
    assert_ne!(status, 0x00, "wrong password must produce non-zero status");

    let mut tail = [0u8; 1];
    let n = client.read(&mut tail).await.unwrap_or(0);
    assert_eq!(n, 0, "server must close connection after auth failure");
}

async fn socks5_connect_reply(listen: std::net::SocketAddr, target: &Endpoint, want: Reply) {
    let mut client = TokioTcpStream::connect(listen)
        .await
        .expect("connect socks");
    client
        .write_all(&encode_greeting(&[mb_proto_socks5::Method::NoAuth]))
        .await
        .expect("write greeting");
    let mut auth = [0u8; 2];
    client.read_exact(&mut auth).await.expect("read auth");
    assert_eq!(auth, [0x05, 0x00]);
    client
        .write_all(&encode_connect_request(target))
        .await
        .expect("write connect");
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.expect("read reply");
    let mut reply_buf = BytesMut::from(&reply[..]);
    let parsed = decode_reply_frame(&mut reply_buf).expect("decode reply");
    assert_eq!(parsed.reply, want);
}

async fn socks5_bind_roundtrip(
    listen: std::net::SocketAddr,
    peer_payload: &[u8],
    client_payload: &[u8],
) {
    let mut client = TokioTcpStream::connect(listen)
        .await
        .expect("connect socks");
    client
        .write_all(&encode_greeting(&[mb_proto_socks5::Method::NoAuth]))
        .await
        .expect("write greeting");
    let mut auth = [0u8; 2];
    client.read_exact(&mut auth).await.expect("read auth");
    assert_eq!(auth, [0x05, 0x00]);

    // VER=5 CMD=BIND RSV=0 ATYP=IPv4 127.0.0.1:80 (declared peer hint).
    client
        .write_all(&[0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50])
        .await
        .expect("write bind");

    let mut first = [0u8; 10];
    client
        .read_exact(&mut first)
        .await
        .expect("read first reply");
    let mut first_buf = BytesMut::from(&first[..]);
    let first = decode_reply_frame(&mut first_buf).expect("decode first reply");
    assert_eq!(first.reply, Reply::Succeeded);
    let listener_ep = first
        .endpoint
        .expect("first reply carries listener endpoint");

    let mut remote = TokioTcpStream::connect(format!("127.0.0.1:{}", listener_ep.port()))
        .await
        .expect("remote peer connect");

    let mut second = [0u8; 10];
    client
        .read_exact(&mut second)
        .await
        .expect("read second reply");
    let mut second_buf = BytesMut::from(&second[..]);
    let second = decode_reply_frame(&mut second_buf).expect("decode second reply");
    assert_eq!(second.reply, Reply::Succeeded);

    remote.write_all(peer_payload).await.expect("peer write");
    let mut got = vec![0u8; peer_payload.len()];
    client
        .read_exact(&mut got)
        .await
        .expect("client reads peer");
    assert_eq!(got, peer_payload);

    client
        .write_all(client_payload)
        .await
        .expect("client write");
    let mut got2 = vec![0u8; client_payload.len()];
    remote
        .read_exact(&mut got2)
        .await
        .expect("peer reads client");
    assert_eq!(got2, client_payload);
}

async fn upstream_udp_relay_loop(relay: UdpSocket) {
    let mut buf = [0u8; 2048];
    loop {
        let (n, peer) = match relay.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(_) => break,
        };
        let mut frame = BytesMut::from(&buf[..n]);
        let dg = match decode_udp_datagram(&mut frame) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let out = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind upstream egress");
        let target = format!("{}:{}", dg.target.host(), dg.target.port());
        out.send_to(&dg.payload, &target)
            .await
            .expect("forward to target");
        let mut rbuf = [0u8; 2048];
        let (rn, _) = out.recv_from(&mut rbuf).await.expect("recv target reply");
        let wrapped = encode_udp_datagram(&dg.target, &rbuf[..rn]);
        relay
            .send_to(&wrapped, peer)
            .await
            .expect("relay reply back");
    }
}

async fn spawn_fake_upstream_socks5_udp() -> u16 {
    let relay = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind upstream relay");
    let relay_addr = relay.local_addr().expect("relay addr");
    let relay_ep = Endpoint::new(relay_addr.ip().to_string(), relay_addr.port()).expect("relay ep");
    let l = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream control");
    let port = l.local_addr().expect("control addr").port();
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.expect("accept control");
        let mut hb = [0u8; 512];
        let _ = s.read(&mut hb).await.expect("read greeting");
        s.write_all(&[0x05, 0x00]).await.expect("write method");
        let _ = s.read(&mut hb).await.expect("read associate");
        s.write_all(&encode_reply_with_endpoint(Reply::Succeeded, &relay_ep))
            .await
            .expect("write associate reply");
        tokio::spawn(upstream_udp_relay_loop(relay));
        let mut tail = [0u8; 64];
        loop {
            match s.read(&mut tail).await {
                Ok(0) | Err(_) => break,
                Ok(_) => continue,
            }
        }
    });
    port
}

fn write_temp_rule_chain(id: &str, yaml: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "mesh-bus-e2e-rule-{}-{}.yaml",
        std::process::id(),
        id
    ));
    std::fs::write(&path, yaml).expect("write fixture rule chain");
    path
}
