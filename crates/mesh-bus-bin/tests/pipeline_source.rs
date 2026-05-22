use bytes::BytesMut;
use mb_endpoint::Endpoint;
use mb_proto_socks5::{Reply, decode_reply_frame, encode_connect_request, encode_greeting};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::test(flavor = "multi_thread")]
async fn pipeline_source_ingress_index_attaches_only_selected_ingress() {
    let echo = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind tcp echo");
    let echo_addr = echo.local_addr().expect("tcp echo addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = echo.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });

    let rule_path = write_temp_file(
        "mesh-bus-pipeline-source-index-rules",
        "yaml",
        r#"
default: deny
rules: []
"#,
    );
    let listen_open = free_tcp_addr();
    let listen_piped = free_tcp_addr();
    let cfg = write_temp_file(
        "mesh-bus-pipeline-source-index",
        "yaml",
        &format!(
            r#"
ingresses:
  - kind: Socks5
    listen: {listen_open}
  - kind: Socks5
    listen: {listen_piped}
egresses:
  - kind: Tcp
    id: direct
    timeout_ms: 1000
pipeline:
  rule_chain_forward: {rule_path}
  source:
    ingress_index: 1
"#,
            rule_path = rule_path.display(),
        ),
    );
    let mut child = spawn_mesh_bus(&cfg);
    wait_for_tcp_listener(listen_open).await;
    wait_for_tcp_listener(listen_piped).await;

    let target = Endpoint::new(echo_addr.ip().to_string(), echo_addr.port()).expect("target");
    socks5_tcp_roundtrip(listen_open, target.clone(), b"source-index-open").await;

    let reply = socks5_connect_reply(listen_piped, target).await;
    assert_eq!(
        reply,
        Reply::ConnectionNotAllowed,
        "pipeline.source.ingress_index=1 must attach the deny pipeline only to the second ingress"
    );

    stop_child(&mut child);
    let _ = std::fs::remove_file(&rule_path);
    let _ = std::fs::remove_file(&cfg);
}

fn free_tcp_addr() -> std::net::SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind free tcp port");
    listener.local_addr().expect("free tcp addr")
}

fn write_temp_file(name: &str, ext: &str, body: &str) -> std::path::PathBuf {
    let millis = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system time")
        .as_millis();
    let path = std::env::temp_dir().join(format!("{name}-{}-{millis}.{ext}", std::process::id()));
    std::fs::write(&path, body).expect("write temp file");
    path
}

fn spawn_mesh_bus(config: &std::path::Path) -> std::process::Child {
    let bin = env!("CARGO_BIN_EXE_mesh-bus");
    let (stdout, stderr) = if std::env::var_os("MESH_BUS_TEST_LOG").is_some() {
        (Stdio::inherit(), Stdio::inherit())
    } else {
        (Stdio::null(), Stdio::null())
    };
    Command::new(bin)
        .arg("run")
        .arg("--config")
        .arg(config)
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .expect("spawn mesh-bus binary")
}

async fn socks5_tcp_roundtrip(listen: std::net::SocketAddr, target: Endpoint, payload: &[u8]) {
    let mut client = TcpStream::connect(listen).await.expect("connect socks");
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
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.expect("read reply");
    let mut reply_buf = BytesMut::from(&reply[..]);
    let reply = decode_reply_frame(&mut reply_buf).expect("decode reply");
    assert_eq!(reply.reply, Reply::Succeeded);
    client.write_all(payload).await.expect("write payload");
    let mut out = vec![0u8; payload.len()];
    client.read_exact(&mut out).await.expect("read echo");
    assert_eq!(out, payload);
}

async fn socks5_connect_reply(listen: std::net::SocketAddr, target: Endpoint) -> Reply {
    let mut client = TcpStream::connect(listen).await.expect("connect socks");
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
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.expect("read reply");
    let mut reply_buf = BytesMut::from(&reply[..]);
    decode_reply_frame(&mut reply_buf)
        .expect("decode reply")
        .reply
}

async fn wait_for_tcp_listener(addr: std::net::SocketAddr) {
    for _ in 0..50 {
        if let Ok(stream) = TcpStream::connect(addr).await {
            drop(stream);
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("listener {addr} did not open");
}

fn stop_child(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}
