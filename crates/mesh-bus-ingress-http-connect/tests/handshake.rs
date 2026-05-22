use mesh_bus_core::{
    BusBuilder, ExitId, ExitResult, IngressPlugin, RankContext, ScheduleDecision, SchedulerPlugin,
};
use mesh_bus_egress_tcp::TcpEgress;
use mesh_bus_ingress_http_connect::{BasicAuth, HttpConnectIngress};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct First;
impl SchedulerPlugin for First {
    fn schedule(&self, c: &[ExitId], _ctx: &RankContext) -> ScheduleDecision {
        ScheduleDecision::ordered((0..c.len()).collect())
    }
    fn feedback(&self, _r: &ExitResult, _payload_bytes: u64, _at_ms: u64) {}
}

async fn spawn_echo_server() -> u16 {
    let echo = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let port = echo.local_addr().expect("echo addr").port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = echo.accept().await.expect("accept echo");
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    let n = s.read(&mut buf).await.expect("read echo");
                    if n == 0 {
                        break;
                    }
                    s.write_all(&buf[..n]).await.expect("write echo");
                }
            });
        }
    });
    port
}

async fn spawn_http_ingress(auth: Option<BasicAuth>) -> u16 {
    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_stream_egress(Box::new(TcpEgress::new(
            ExitId("tcp".into()),
            Duration::from_millis(500),
        )))
        .build()
        .await;
    let port = bus.port();
    let _bh = bus.spawn();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ingress");
    let bind_port = listener.local_addr().expect("ingress addr").port();
    let mut ingress = HttpConnectIngress::new(listener);
    if let Some(auth) = auth {
        ingress = ingress.with_auth_basic(auth);
    }
    tokio::spawn(async move { Box::new(ingress).run(port).await.expect("ingress run") });
    bind_port
}

async fn read_head(stream: &mut TcpStream) -> Vec<u8> {
    let mut out = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).await.expect("read response");
        out.push(byte[0]);
        if out.ends_with(b"\r\n\r\n") {
            return out;
        }
    }
}

#[tokio::test]
async fn connect_success_tunnels_opaque_bytes() {
    let echo_port = spawn_echo_server().await;
    let proxy_port = spawn_http_ingress(None).await;
    let mut client = TcpStream::connect(format!("127.0.0.1:{proxy_port}"))
        .await
        .expect("connect proxy");
    client
        .write_all(
            format!(
                "CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\nHost: 127.0.0.1:{echo_port}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .expect("write connect");
    let response = read_head(&mut client).await;
    assert!(
        std::str::from_utf8(&response)
            .unwrap()
            .starts_with("HTTP/1.1 200")
    );
    client
        .write_all(&[0x16, 0x03, 0x01, 0x00, 0x01])
        .await
        .expect("opaque write");
    let mut echoed = [0u8; 5];
    client.read_exact(&mut echoed).await.expect("opaque echo");
    assert_eq!(echoed, [0x16, 0x03, 0x01, 0x00, 0x01]);
}

#[tokio::test]
async fn malformed_connect_target_returns_400() {
    let proxy_port = spawn_http_ingress(None).await;
    let mut client = TcpStream::connect(format!("127.0.0.1:{proxy_port}"))
        .await
        .expect("connect proxy");
    client
        .write_all(b"CONNECT / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .expect("write malformed");
    let response = read_head(&mut client).await;
    assert!(
        std::str::from_utf8(&response)
            .unwrap()
            .starts_with("HTTP/1.1 400")
    );
}

#[tokio::test]
async fn absolute_form_get_rewrites_for_upstream() {
    let echo_port = spawn_echo_server().await;
    let proxy_port = spawn_http_ingress(None).await;
    let mut client = TcpStream::connect(format!("127.0.0.1:{proxy_port}"))
        .await
        .expect("connect proxy");
    client
        .write_all(format!("GET http://127.0.0.1:{echo_port}/a?q=1 HTTP/1.1\r\nHost: ignored\r\nUser-Agent: test\r\n\r\n").as_bytes())
        .await
        .expect("write request");
    let mut buf = vec![0u8; 96];
    let n = client.read(&mut buf).await.expect("read echo");
    let echoed = std::str::from_utf8(&buf[..n]).expect("utf8 echo");
    assert!(echoed.starts_with(&format!(
        "GET /a?q=1 HTTP/1.1\r\nHost: 127.0.0.1:{echo_port}\r\n"
    )));
    assert!(echoed.contains("User-Agent: test\r\n"));
    assert!(!echoed.contains("Host: ignored"));
}

#[tokio::test]
async fn basic_auth_returns_407_then_allows_valid_header() {
    let echo_port = spawn_echo_server().await;
    let auth = BasicAuth::new().with_user("alice", "secret");
    let proxy_port = spawn_http_ingress(Some(auth)).await;

    let mut denied = TcpStream::connect(format!("127.0.0.1:{proxy_port}"))
        .await
        .expect("connect proxy denied");
    denied
        .write_all(
            format!(
                "CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\nHost: 127.0.0.1:{echo_port}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .expect("write denied");
    let response = read_head(&mut denied).await;
    assert!(
        std::str::from_utf8(&response)
            .unwrap()
            .starts_with("HTTP/1.1 407")
    );

    let mut allowed = TcpStream::connect(format!("127.0.0.1:{proxy_port}"))
        .await
        .expect("connect proxy allowed");
    allowed
        .write_all(format!("CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\nHost: 127.0.0.1:{echo_port}\r\nProxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\n\r\n").as_bytes())
        .await
        .expect("write allowed");
    let response = read_head(&mut allowed).await;
    assert!(
        std::str::from_utf8(&response)
            .unwrap()
            .starts_with("HTTP/1.1 200")
    );
}
