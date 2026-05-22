//! Product topology fixtures.
//!
//! These are binary-backed because a product topology is data executed by the
//! real `mesh-bus run --config` product runner. This harness only binds
//! ephemeral resources, starts nodes from fixture-owned config YAML, sends a
//! probe, and checks declared observations.
#[allow(dead_code)]
mod e2e_client;
#[allow(dead_code)]
mod e2e_process;

use bytes::BytesMut;
use e2e_client::{
    free_tcp_addr, free_udp_addr, socks5_tcp_roundtrip, socks5_udp_roundtrip, spawn_tcp_echo,
    spawn_udp_echo,
};
use e2e_process::{spawn_mesh_bus, stop_child, write_temp_config, write_temp_rule_chain};
use mb_endpoint::Endpoint;
use mb_proto_socks5::{Reply, decode_connect_request, decode_greeting, encode_reply_with_endpoint};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

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
struct Input {
    resources: Vec<Resource>,
    nodes: Vec<Node>,
    #[serde(default)]
    probe: Option<Probe>,
    #[serde(default)]
    probes: Vec<Probe>,
}

#[derive(Deserialize)]
struct Expect {
    #[serde(default)]
    echo_payload: Option<String>,
    #[serde(default)]
    recorders: Vec<RecorderExpect>,
    #[serde(default)]
    wire: Option<WireExpect>,
}

#[derive(Deserialize)]
struct Resource {
    name: String,
    #[serde(flatten)]
    kind: ResourceKind,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ResourceKind {
    TcpAddr,
    UdpAddr,
    TcpEcho,
    UdpEcho,
    Socks5StreamProxy,
    UdpRecorder,
    RuleChain {
        yaml: String,
    },
    UdpRelay {
        forward_to: String,
        #[serde(default)]
        capture: bool,
        #[serde(default)]
        policy: RelayPolicy,
    },
}

#[derive(Clone, Default, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum RelayPolicy {
    #[default]
    PassThrough,
    Reorder {
        hold_index: usize,
        release_after: usize,
    },
    DropIndex {
        index: usize,
    },
}

#[derive(Deserialize)]
struct Node {
    name: String,
    config_yaml: String,
    #[serde(default)]
    start_after_ms: u64,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Probe {
    UdpRoundtrip {
        target: String,
        payload: String,
        #[serde(default)]
        expect_payload: Option<String>,
        #[serde(default = "default_timeout_ms")]
        timeout_ms: u64,
    },
    UdpSequence {
        target: String,
        payloads: Vec<String>,
        #[serde(default = "default_delay_ms")]
        delay_ms: u64,
    },
    TcpRoundtrip {
        target: String,
        payload: String,
    },
    Socks5Tcp {
        listen: String,
        target: String,
        payload: String,
    },
    HttpConnectTcp {
        listen: String,
        target: String,
        payload: String,
    },
    Socks5TcpSized {
        listen: String,
        target: String,
        size_bytes: usize,
    },
    Socks5Udp {
        listen: String,
        target: String,
        payload: String,
    },
}

#[derive(Deserialize)]
struct WireExpect {
    capture: String,
    #[serde(default)]
    fail_closed_target: Option<String>,
    #[serde(default)]
    no_magic: Option<String>,
    #[serde(default)]
    no_plaintext: Vec<String>,
    #[serde(default)]
    tamper_fail_closed: bool,
    #[serde(default)]
    replay_fail_closed: bool,
}

#[derive(Deserialize)]
struct RecorderExpect {
    name: String,
    payloads: Vec<String>,
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
}

#[tokio::test(flavor = "multi_thread")]
async fn product_topology_fixtures() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/topology");
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .expect("fixtures/topology")
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
    if let Ok(filter) = std::env::var("MESH_BUS_TOPOLOGY_FIXTURE") {
        entries.retain(|p| {
            p.file_stem()
                .and_then(|s| s.to_str())
                .is_some_and(|name| name.contains(&filter))
        });
        assert!(
            !entries.is_empty(),
            "no topology fixture matched {filter:?}"
        );
    }

    for p in entries {
        let c: Case = serde_yaml::from_str(&std::fs::read_to_string(&p).unwrap())
            .unwrap_or_else(|e| panic!("fixture {p:?}: {e}"));
        assert_eq!(c.owner, "mesh-bus-bin.product-topology", "[{}] owner", c.id);
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
        assert_eq!(c.case, "e2e.product_topology", "[{}] case", c.id);
        eprintln!("running topology fixture {}", c.id);
        run_topology(c).await;
    }
}

async fn run_topology(c: Case) {
    let env = FixtureEnv::new(&c).await;
    let mut children = spawn_nodes(&c, &env.bindings).await;
    for probe in c.input.probe.iter().chain(c.input.probes.iter()) {
        run_probe(&c, &env.bindings, probe).await;
    }

    if let Some(wire) = &c.expect.wire {
        assert_wire(&c, &env, wire).await;
    }
    for recorder in &c.expect.recorders {
        assert_recorder(&c, &env, recorder).await;
    }
    stop_nodes(&mut children);
    env.cleanup();
}

struct FixtureEnv {
    bindings: BTreeMap<String, String>,
    captures: BTreeMap<String, std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>>,
    recorders: BTreeMap<String, std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>>,
    temp_files: Vec<std::path::PathBuf>,
}

impl FixtureEnv {
    async fn new(c: &Case) -> Self {
        let mut bindings = BTreeMap::new();
        let mut captures = BTreeMap::new();
        let mut recorders = BTreeMap::new();
        let mut temp_files = Vec::new();

        for resource in &c.input.resources {
            match &resource.kind {
                ResourceKind::TcpAddr => bind_addr(&mut bindings, &resource.name, free_tcp_addr()),
                ResourceKind::UdpAddr => bind_addr(&mut bindings, &resource.name, free_udp_addr()),
                ResourceKind::TcpEcho => {
                    bind_addr(&mut bindings, &resource.name, spawn_tcp_echo().await)
                }
                ResourceKind::UdpEcho => {
                    bind_addr(&mut bindings, &resource.name, spawn_udp_echo().await)
                }
                ResourceKind::Socks5StreamProxy => bind_addr(
                    &mut bindings,
                    &resource.name,
                    spawn_socks5_stream_proxy().await,
                ),
                ResourceKind::UdpRecorder => {
                    let (addr, received) = spawn_udp_recorder().await;
                    bind_addr(&mut bindings, &resource.name, addr);
                    recorders.insert(resource.name.clone(), received);
                }
                ResourceKind::RuleChain { .. } | ResourceKind::UdpRelay { .. } => {}
            }
        }

        for resource in &c.input.resources {
            match &resource.kind {
                ResourceKind::RuleChain { yaml } => {
                    let yaml = expand(yaml, &bindings);
                    let path = write_temp_rule_chain(&format!("{}-{}", c.id, resource.name), &yaml);
                    bindings.insert(resource.name.clone(), path.display().to_string());
                    temp_files.push(path);
                }
                ResourceKind::UdpRelay {
                    forward_to,
                    capture,
                    policy,
                } => {
                    let relay = UdpSocket::bind("127.0.0.1:0")
                        .await
                        .expect("bind udp relay");
                    let relay_addr = relay.local_addr().expect("relay addr");
                    let captured: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>> =
                        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
                    let forward_to = expand(forward_to, &bindings)
                        .parse::<std::net::SocketAddr>()
                        .unwrap_or_else(|e| panic!("[{}] invalid relay forward_to: {e}", c.id));
                    bind_addr(&mut bindings, &resource.name, relay_addr);
                    if *capture {
                        captures.insert(resource.name.clone(), std::sync::Arc::clone(&captured));
                    }
                    tokio::spawn(udp_relay_loop(
                        relay,
                        forward_to,
                        *capture,
                        policy.clone(),
                        captured,
                    ));
                }
                _ => {}
            }
        }

        Self {
            bindings,
            captures,
            recorders,
            temp_files,
        }
    }

    fn cleanup(&self) {
        for path in &self.temp_files {
            let _ = std::fs::remove_file(path);
        }
    }
}

async fn udp_relay_loop(
    relay: UdpSocket,
    forward_to: std::net::SocketAddr,
    capture: bool,
    policy: RelayPolicy,
    captured: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
) {
    let mut buf = [0u8; 2048];
    let mut a_addr: Option<std::net::SocketAddr> = None;
    let mut ab_index = 0usize;
    let mut held: Option<Vec<u8>> = None;
    loop {
        let Ok((n, from)) = relay.recv_from(&mut buf).await else {
            break;
        };
        if from == forward_to {
            if let Some(a) = a_addr {
                let _ = relay.send_to(&buf[..n], a).await;
            }
        } else {
            a_addr = Some(from);
            let pkt = buf[..n].to_vec();
            if capture {
                captured.lock().expect("capture lock").push(pkt.clone());
            }
            match &policy {
                RelayPolicy::PassThrough => {
                    let _ = relay.send_to(&pkt, forward_to).await;
                }
                RelayPolicy::Reorder {
                    hold_index,
                    release_after,
                } => {
                    if ab_index == *hold_index {
                        held = Some(pkt);
                    } else if ab_index == *release_after {
                        let _ = relay.send_to(&pkt, forward_to).await;
                        if let Some(h) = held.take() {
                            let _ = relay.send_to(&h, forward_to).await;
                        }
                    } else {
                        let _ = relay.send_to(&pkt, forward_to).await;
                    }
                }
                RelayPolicy::DropIndex { index } => {
                    if ab_index != *index {
                        let _ = relay.send_to(&pkt, forward_to).await;
                    }
                }
            }
            ab_index += 1;
        }
    }
}

async fn spawn_nodes(c: &Case, bindings: &BTreeMap<String, String>) -> Vec<std::process::Child> {
    let mut children = Vec::new();
    for node in &c.input.nodes {
        let config_yaml = expand(&node.config_yaml, bindings);
        let cfg = write_temp_config(&format!("{}-{}", c.id, node.name), &config_yaml);
        let child = spawn_mesh_bus(&cfg);
        children.push(child);
        if node.start_after_ms > 0 {
            tokio::time::sleep(Duration::from_millis(node.start_after_ms)).await;
        }
    }
    children
}

async fn run_probe(c: &Case, bindings: &BTreeMap<String, String>, probe: &Probe) {
    match probe {
        Probe::UdpRoundtrip {
            target,
            payload,
            expect_payload,
            timeout_ms,
        } => {
            let target = expand(target, bindings)
                .parse::<std::net::SocketAddr>()
                .unwrap_or_else(|e| panic!("[{}] invalid probe target: {e}", c.id));
            let client = UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind udp client");
            client
                .send_to(payload.as_bytes(), target)
                .await
                .expect("send udp probe");
            let mut buf = [0u8; 2048];
            let (n, _) = tokio::time::timeout(
                Duration::from_millis(*timeout_ms),
                client.recv_from(&mut buf),
            )
            .await
            .expect("mesh udp timeout")
            .expect("recv mesh udp");
            let expect = expect_payload
                .as_ref()
                .or(c.expect.echo_payload.as_ref())
                .unwrap_or(payload);
            assert_eq!(&buf[..n], expect.as_bytes());
        }
        Probe::UdpSequence {
            target,
            payloads,
            delay_ms,
        } => {
            let target = expand(target, bindings)
                .parse::<std::net::SocketAddr>()
                .unwrap_or_else(|e| panic!("[{}] invalid probe target: {e}", c.id));
            let client = UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind udp sequence client");
            for payload in payloads {
                client
                    .send_to(payload.as_bytes(), target)
                    .await
                    .expect("send udp sequence packet");
                tokio::time::sleep(Duration::from_millis(*delay_ms)).await;
            }
        }
        Probe::TcpRoundtrip { target, payload } => {
            let target = expand(target, bindings)
                .parse::<std::net::SocketAddr>()
                .unwrap_or_else(|e| panic!("[{}] invalid tcp target: {e}", c.id));
            let mut client = TcpStream::connect(target)
                .await
                .expect("connect tcp topology target");
            client
                .write_all(payload.as_bytes())
                .await
                .expect("write tcp");
            let mut out = vec![0u8; payload.len()];
            client.read_exact(&mut out).await.expect("read tcp");
            assert_eq!(out, payload.as_bytes());
        }
        Probe::Socks5Tcp {
            listen,
            target,
            payload,
        } => {
            let listen = expand(listen, bindings)
                .parse::<std::net::SocketAddr>()
                .unwrap_or_else(|e| panic!("[{}] invalid socks listen: {e}", c.id));
            let target = endpoint_from_addr(c, bindings, target);
            socks5_tcp_roundtrip(listen, target, payload.as_bytes()).await;
        }
        Probe::HttpConnectTcp {
            listen,
            target,
            payload,
        } => {
            let listen = expand(listen, bindings)
                .parse::<std::net::SocketAddr>()
                .unwrap_or_else(|e| panic!("[{}] invalid http connect listen: {e}", c.id));
            let target = endpoint_from_addr(c, bindings, target);
            http_connect_tcp_roundtrip(listen, target, payload.as_bytes()).await;
        }
        Probe::Socks5TcpSized {
            listen,
            target,
            size_bytes,
        } => {
            let listen = expand(listen, bindings)
                .parse::<std::net::SocketAddr>()
                .unwrap_or_else(|e| panic!("[{}] invalid socks listen: {e}", c.id));
            let target = endpoint_from_addr(c, bindings, target);
            let payload = deterministic_payload(*size_bytes);
            socks5_tcp_roundtrip(listen, target, &payload).await;
        }
        Probe::Socks5Udp {
            listen,
            target,
            payload,
        } => {
            let listen = expand(listen, bindings)
                .parse::<std::net::SocketAddr>()
                .unwrap_or_else(|e| panic!("[{}] invalid socks listen: {e}", c.id));
            let target = endpoint_from_addr(c, bindings, target);
            socks5_udp_roundtrip(listen, target, payload.as_bytes()).await;
        }
    }
}

async fn http_connect_tcp_roundtrip(
    listen: std::net::SocketAddr,
    target: Endpoint,
    payload: &[u8],
) {
    let mut client = TcpStream::connect(listen)
        .await
        .expect("connect http proxy");
    client
        .write_all(
            format!(
                "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
                target.host(),
                target.port(),
                target.host(),
                target.port()
            )
            .as_bytes(),
        )
        .await
        .expect("write http connect");
    let response = read_http_response_head(&mut client).await;
    assert!(
        std::str::from_utf8(&response)
            .expect("utf8 response")
            .starts_with("HTTP/1.1 200"),
        "HTTP CONNECT response was {}",
        String::from_utf8_lossy(&response)
    );
    client
        .write_all(payload)
        .await
        .expect("write tunnel payload");
    let mut out = vec![0u8; payload.len()];
    client.read_exact(&mut out).await.expect("read tunnel echo");
    assert_eq!(out, payload);
}

async fn read_http_response_head(client: &mut TcpStream) -> Vec<u8> {
    let mut out = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        client.read_exact(&mut byte).await.expect("read http head");
        out.push(byte[0]);
        if out.ends_with(b"\r\n\r\n") {
            return out;
        }
    }
}

async fn assert_fail_closed(
    c: &Case,
    env: &FixtureEnv,
    wire: &WireExpect,
    sealed: &[u8],
    tamper: bool,
) {
    let target_template = wire.fail_closed_target.as_deref().unwrap_or(&wire.capture);
    let target = expand(target_template, &env.bindings)
        .parse::<std::net::SocketAddr>()
        .unwrap_or_else(|e| panic!("[{}] invalid fail-closed target: {e}", c.id));
    let probe = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind fail-closed probe");
    let mut packet = sealed.to_vec();
    if tamper {
        let last = packet.len() - 1;
        packet[last] ^= 0xff;
    }
    probe
        .send_to(&packet, target)
        .await
        .expect("send fail-closed packet");
    let mut probe_buf = [0u8; 2048];
    let reply =
        tokio::time::timeout(Duration::from_millis(500), probe.recv_from(&mut probe_buf)).await;
    assert!(reply.is_err(), "[{}] packet must fail closed", c.id);
}

async fn assert_wire(c: &Case, env: &FixtureEnv, wire: &WireExpect) {
    let capture = env
        .captures
        .get(&wire.capture)
        .unwrap_or_else(|| panic!("[{}] unknown capture {}", c.id, wire.capture));
    let frames = capture.lock().expect("capture lock").clone();
    assert!(!frames.is_empty(), "[{}] no captured envelopes", c.id);
    for pkt in &frames {
        assert!(pkt.len() >= 2, "[{}] envelope shorter than header", c.id);
        if let Some(hex) = &wire.no_magic {
            let magic = decode_hex(&c.id, hex);
            assert_ne!(
                &pkt[..magic.len()],
                magic.as_slice(),
                "[{}] forbidden magic present on wire",
                c.id
            );
        }
        for text in &wire.no_plaintext {
            let needle = expand(text, &env.bindings);
            assert!(
                !contains_subslice(pkt, needle.as_bytes()),
                "[{}] plaintext {needle:?} visible on wire",
                c.id
            );
        }
    }

    let sealed = frames
        .iter()
        .max_by_key(|p| p.len())
        .cloned()
        .expect("captured sealed envelope");
    if wire.tamper_fail_closed {
        assert_fail_closed(c, env, wire, &sealed, true).await;
    }
    if wire.replay_fail_closed {
        assert_fail_closed(c, env, wire, &sealed, false).await;
    }
}

fn stop_nodes(children: &mut [std::process::Child]) {
    for child in children.iter_mut().rev() {
        stop_child(child);
    }
}

async fn assert_recorder(c: &Case, env: &FixtureEnv, expect: &RecorderExpect) {
    let recorder = env
        .recorders
        .get(&expect.name)
        .unwrap_or_else(|| panic!("[{}] unknown recorder {}", c.id, expect.name));
    let want: Vec<Vec<u8>> = expect
        .payloads
        .iter()
        .map(|p| expand(p, &env.bindings).into_bytes())
        .collect();
    let deadline = std::time::Instant::now() + Duration::from_millis(expect.timeout_ms);
    loop {
        if recorder.lock().expect("recorder lock").len() >= want.len()
            || std::time::Instant::now() >= deadline
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let got = recorder.lock().expect("recorder lock").clone();
    assert_eq!(
        got, want,
        "[{}] recorder {} payload order",
        c.id, expect.name
    );
}

async fn spawn_udp_recorder() -> (
    std::net::SocketAddr,
    std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
) {
    let recorder = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind udp recorder");
    let addr = recorder.local_addr().expect("udp recorder addr");
    let received: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = std::sync::Arc::clone(&received);
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let Ok((n, _)) = recorder.recv_from(&mut buf).await else {
                break;
            };
            sink.lock().expect("recorder lock").push(buf[..n].to_vec());
        }
    });
    (addr, received)
}

async fn spawn_socks5_stream_proxy() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind socks5 stream proxy");
    let addr = listener.local_addr().expect("socks5 proxy addr");
    let bind_ep = Endpoint::new(addr.ip().to_string(), addr.port()).expect("socks5 bind ep");
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            tokio::spawn(handle_socks5_stream_proxy_client(client, bind_ep.clone()));
        }
    });
    addr
}

async fn handle_socks5_stream_proxy_client(mut client: TcpStream, bind_ep: Endpoint) {
    let Ok(target) = socks5_stream_handshake(&mut client, &bind_ep).await else {
        return;
    };
    let Ok(mut upstream) = TcpStream::connect(format!("{}:{}", target.host(), target.port())).await
    else {
        return;
    };
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
}

async fn socks5_stream_handshake(
    client: &mut TcpStream,
    bind_ep: &Endpoint,
) -> Result<Endpoint, ()> {
    let mut buf = BytesMut::with_capacity(512);
    read_socks5_frame(client, &mut buf).await?;
    decode_greeting(&mut buf).map_err(|_| ())?;
    client.write_all(&[0x05, 0x00]).await.map_err(|_| ())?;
    buf.clear();
    read_socks5_frame(client, &mut buf).await?;
    let target = decode_connect_request(&mut buf).map_err(|_| ())?;
    client
        .write_all(&encode_reply_with_endpoint(Reply::Succeeded, bind_ep))
        .await
        .map_err(|_| ())?;
    Ok(target)
}

async fn read_socks5_frame(client: &mut TcpStream, buf: &mut BytesMut) -> Result<(), ()> {
    let mut chunk = [0u8; 512];
    let n = client.read(&mut chunk).await.map_err(|_| ())?;
    if n == 0 {
        return Err(());
    }
    buf.extend_from_slice(&chunk[..n]);
    Ok(())
}

fn bind_addr(bindings: &mut BTreeMap<String, String>, name: &str, addr: std::net::SocketAddr) {
    bindings.insert(name.to_string(), addr.to_string());
    bindings.insert(format!("{name}_PORT"), addr.port().to_string());
}

fn deterministic_payload(size: usize) -> Vec<u8> {
    (0..size).map(|i| b'a' + (i % 26) as u8).collect()
}

fn endpoint_from_addr(c: &Case, bindings: &BTreeMap<String, String>, target: &str) -> Endpoint {
    let expanded = expand(target, bindings);
    if let Ok(addr) = expanded.parse::<std::net::SocketAddr>() {
        return Endpoint::new(addr.ip().to_string(), addr.port()).expect("endpoint");
    }
    let (host, port) = expanded
        .rsplit_once(':')
        .unwrap_or_else(|| panic!("[{}] endpoint target must be host:port", c.id));
    let port = port
        .parse::<u16>()
        .unwrap_or_else(|e| panic!("[{}] invalid endpoint port: {e}", c.id));
    Endpoint::new(host.to_string(), port).expect("endpoint")
}

fn expand(template: &str, bindings: &BTreeMap<String, String>) -> String {
    let mut out = template.to_string();
    for (key, value) in bindings {
        out = out.replace(&format!("{{{{{key}}}}}"), value);
    }
    out
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len() && haystack.windows(needle.len()).any(|w| w == needle)
}

fn decode_hex(name: &str, hex: &str) -> Vec<u8> {
    assert!(
        hex.len() % 2 == 0,
        "[{name}] hex string must have even length"
    );
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .unwrap_or_else(|_| panic!("[{name}] invalid hex"))
        })
        .collect()
}

fn default_timeout_ms() -> u64 {
    1000
}

fn default_delay_ms() -> u64 {
    150
}
