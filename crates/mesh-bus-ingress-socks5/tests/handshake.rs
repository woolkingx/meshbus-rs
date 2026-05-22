use mb_rule::{Action, MatchExpr, Predicate, Rule, RuleChain, RuleSetRegistry, RuleSocks5Command};
use mesh_bus_core::{
    BusBuilder, BusPathInfo, BusSessionInfo, BusSessionRequest, Capabilities, DisconnectReason,
    ExitId, ExitResult, IngressPlugin, Measurement, PathState, RankContext, ScheduleDecision,
    SchedulerPlugin, StreamEgress, StreamRecvHalf, StreamSendHalf, StreamSession,
};
use mesh_bus_egress_tcp::TcpEgress;
use mesh_bus_ingress_socks5::{RulePolicy, Socks5Ingress};
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

struct BySessionParity;

impl SchedulerPlugin for BySessionParity {
    fn schedule(&self, c: &[ExitId], _ctx: &RankContext) -> ScheduleDecision {
        if c.len() < 2 {
            return ScheduleDecision::ordered((0..c.len()).collect());
        }
        let n = _ctx
            .session_id
            .0
            .strip_prefix("s-")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(1);
        if n % 2 == 1 {
            ScheduleDecision::ordered(vec![0, 1])
        } else {
            ScheduleDecision::ordered(vec![1, 0])
        }
    }

    fn feedback(&self, _r: &ExitResult, _payload_bytes: u64, _at_ms: u64) {}
}

struct CloseOnOpen {
    id: ExitId,
    reason: DisconnectReason,
}

struct BndOnOpen {
    id: ExitId,
    local_port: u16,
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

#[async_trait::async_trait]
impl StreamEgress for CloseOnOpen {
    fn id(&self) -> &ExitId {
        &self.id
    }

    fn capabilities(&self) -> &Capabilities {
        static CAPS: std::sync::OnceLock<Capabilities> = std::sync::OnceLock::new();
        CAPS.get_or_init(stream_caps)
    }

    async fn open_stream(
        &self,
        _request: &BusSessionRequest,
        info: BusSessionInfo,
    ) -> Result<Box<dyn StreamSession>, DisconnectReason> {
        Ok(Box::new(CloseSession {
            info,
            reason: self.reason.clone(),
        }))
    }
}

#[async_trait::async_trait]
impl StreamEgress for BndOnOpen {
    fn id(&self) -> &ExitId {
        &self.id
    }

    fn capabilities(&self) -> &Capabilities {
        static CAPS: std::sync::OnceLock<Capabilities> = std::sync::OnceLock::new();
        CAPS.get_or_init(stream_caps)
    }

    async fn open_stream(
        &self,
        request: &BusSessionRequest,
        mut info: BusSessionInfo,
    ) -> Result<Box<dyn StreamSession>, DisconnectReason> {
        info.paths = vec![BusPathInfo {
            exit_id: self.id.clone(),
            local: mb_endpoint::Endpoint::new("127.0.0.1", self.local_port)
                .expect("local endpoint"),
            remote: request.target.clone(),
            measurement: Measurement {
                exit_id: self.id.clone(),
                at_ms: 0,
                rtt_ms: 1,
                payload_bytes: 0,
                jitter_ms: None,
                throughput_bps: None,
                success: true,
            },
            state: PathState::Active,
        }];
        info.primary = 0;
        Ok(Box::new(EchoSession { info }))
    }
}

struct CloseSession {
    info: BusSessionInfo,
    reason: DisconnectReason,
}

#[async_trait::async_trait]
impl StreamSession for CloseSession {
    async fn connect(&mut self) -> Result<&BusSessionInfo, DisconnectReason> {
        Err(self.reason.clone())
    }

    fn into_tcp_splice(
        self: Box<Self>,
    ) -> Result<mesh_bus_core::TcpSpliceSession, Box<dyn StreamSession>> {
        Err(self)
    }

    fn split(self: Box<Self>) -> (Box<dyn StreamSendHalf>, Box<dyn StreamRecvHalf>) {
        (Box::new(NoopSend), Box::new(NoopRecv))
    }

    async fn abort(&mut self, _reason: DisconnectReason) {}

    fn info(&self) -> &BusSessionInfo {
        &self.info
    }

    fn last_error(&self) -> Option<&DisconnectReason> {
        Some(&self.reason)
    }
}

struct EchoSession {
    info: BusSessionInfo,
}

#[async_trait::async_trait]
impl StreamSession for EchoSession {
    async fn connect(&mut self) -> Result<&BusSessionInfo, DisconnectReason> {
        Ok(&self.info)
    }

    fn into_tcp_splice(
        self: Box<Self>,
    ) -> Result<mesh_bus_core::TcpSpliceSession, Box<dyn StreamSession>> {
        Err(self)
    }

    fn split(self: Box<Self>) -> (Box<dyn StreamSendHalf>, Box<dyn StreamRecvHalf>) {
        (Box::new(NoopSend), Box::new(NoopRecv))
    }

    async fn abort(&mut self, _reason: DisconnectReason) {}

    fn info(&self) -> &BusSessionInfo {
        &self.info
    }

    fn last_error(&self) -> Option<&DisconnectReason> {
        None
    }
}

struct NoopSend;

#[async_trait::async_trait]
impl StreamSendHalf for NoopSend {
    async fn send(&mut self, _payload: bytes::Bytes) -> Result<(), DisconnectReason> {
        Ok(())
    }

    async fn shutdown_write(&mut self) {}

    async fn abort(&mut self, _reason: DisconnectReason) {}
}

struct NoopRecv;

#[async_trait::async_trait]
impl StreamRecvHalf for NoopRecv {
    async fn recv(&mut self) -> Option<bytes::Bytes> {
        None
    }

    fn last_error(&self) -> Option<&DisconnectReason> {
        None
    }
}

async fn connect_reply(bind_port: u16, target_port: u16) -> [u8; 10] {
    let mut client = TcpStream::connect(format!("127.0.0.1:{bind_port}"))
        .await
        .expect("client connect");
    client
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("write greeting");
    let mut auth = [0u8; 2];
    client.read_exact(&mut auth).await.expect("read auth");
    assert_eq!(auth, [0x05, 0x00]);
    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&target_port.to_be_bytes());
    client.write_all(&req).await.expect("write connect");
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.expect("read reply");
    reply
}

async fn spawn_socks_ingress_with_bus(bus: mesh_bus_core::Bus) -> u16 {
    let port = bus.port();
    let _bh = bus.spawn();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ingress");
    let bind_port = listener.local_addr().expect("ingress addr").port();
    let ingress = Socks5Ingress::new(listener);
    tokio::spawn(async move { Box::new(ingress).run(port).await.expect("ingress run") });
    bind_port
}

#[tokio::test]
async fn end_to_end_socks5_to_tcp_echo() {
    let echo = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let echo_port = echo.local_addr().expect("echo addr").port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = echo.accept().await.expect("accept echo");
            tokio::spawn(async move {
                let mut buf = vec![0u8; 1024];
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
    let ingress = Socks5Ingress::new(listener);
    tokio::spawn(async move { Box::new(ingress).run(port).await.expect("ingress run") });

    let mut client = TcpStream::connect(format!("127.0.0.1:{bind_port}"))
        .await
        .expect("client connect");

    // SOCKS5 greeting: VER=5, NMETHODS=1, METHOD=0 (NoAuth)
    client
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("write greeting");
    let mut auth = [0u8; 2];
    client.read_exact(&mut auth).await.expect("read auth");
    assert_eq!(auth, [0x05, 0x00]);

    // CONNECT 127.0.0.1:echo_port (IPv4)
    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&echo_port.to_be_bytes());
    client.write_all(&req).await.expect("write connect");
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.expect("read reply");
    assert_eq!(reply[1], 0x00, "SOCKS5 reply must be Succeeded");
    let bind_port = u16::from_be_bytes([reply[8], reply[9]]);
    assert_ne!(
        bind_port, 0,
        "SOCKS5 BND.PORT should come from BusSessionInfo path"
    );

    // payload roundtrip
    client.write_all(b"hi").await.expect("write payload");
    let mut buf = [0u8; 2];
    client.read_exact(&mut buf).await.expect("read echo");
    assert_eq!(&buf, b"hi");
}

#[tokio::test]
async fn connect_refused_reply_is_sent_before_success() {
    let unused = TcpListener::bind("127.0.0.1:0").await.expect("bind unused");
    let refused_port = unused.local_addr().expect("unused addr").port();
    drop(unused);

    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_stream_egress(Box::new(TcpEgress::new(
            ExitId("tcp".into()),
            Duration::from_millis(200),
        )))
        .build()
        .await;
    let port = bus.port();
    let _bh = bus.spawn();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ingress");
    let bind_port = listener.local_addr().expect("ingress addr").port();
    let ingress = Socks5Ingress::new(listener);
    tokio::spawn(async move { Box::new(ingress).run(port).await.expect("ingress run") });

    let mut client = TcpStream::connect(format!("127.0.0.1:{bind_port}"))
        .await
        .expect("client connect");
    client
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("write greeting");
    let mut auth = [0u8; 2];
    client.read_exact(&mut auth).await.expect("read auth");
    assert_eq!(auth, [0x05, 0x00]);

    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&refused_port.to_be_bytes());
    client.write_all(&req).await.expect("write connect");
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.expect("read reply");
    assert_eq!(reply[1], 0x05, "refused target must not get Succeeded");
}

#[tokio::test]
async fn connect_disconnect_reasons_map_to_rfc1928_reply_codes() {
    for (reason, code) in [
        (DisconnectReason::NetworkUnreachable, 0x03),
        (DisconnectReason::HostUnreachable, 0x04),
        (DisconnectReason::TtlExpired, 0x06),
        (DisconnectReason::Other("boom".into()), 0x01),
    ] {
        let bus = BusBuilder::new()
            .scheduler(Box::new(First))
            .add_stream_egress(Box::new(CloseOnOpen {
                id: ExitId(format!("close-{code}")),
                reason,
            }))
            .build()
            .await;
        let bind_port = spawn_socks_ingress_with_bus(bus).await;
        let reply = connect_reply(bind_port, 80).await;
        assert_eq!(reply[1], code, "wrong SOCKS5 reply for REP 0x{code:02x}");
    }
}

#[tokio::test]
async fn multi_egress_bnd_addr_reflects_selected_exit_path() {
    let bus = BusBuilder::new()
        .scheduler(Box::new(BySessionParity))
        .add_stream_egress(Box::new(BndOnOpen {
            id: ExitId("wan-a".into()),
            local_port: 40101,
        }))
        .add_stream_egress(Box::new(BndOnOpen {
            id: ExitId("wan-b".into()),
            local_port: 40102,
        }))
        .build()
        .await;
    let bind_port = spawn_socks_ingress_with_bus(bus).await;

    let first = connect_reply(bind_port, 80).await;
    let second = connect_reply(bind_port, 80).await;

    assert_eq!(first[1], 0x00);
    assert_eq!(second[1], 0x00);
    assert_eq!(u16::from_be_bytes([first[8], first[9]]), 40101);
    assert_eq!(u16::from_be_bytes([second[8], second[9]]), 40102);
}

#[tokio::test]
async fn end_to_end_socks5_domainname_target() {
    let echo = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let echo_port = echo.local_addr().expect("echo addr").port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = echo.accept().await.expect("accept echo");
            tokio::spawn(async move {
                let mut buf = vec![0u8; 1024];
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
    let ingress = Socks5Ingress::new(listener);
    tokio::spawn(async move { Box::new(ingress).run(port).await.expect("ingress run") });

    let mut client = TcpStream::connect(format!("127.0.0.1:{bind_port}"))
        .await
        .expect("client connect");

    client
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("write greeting");
    let mut auth = [0u8; 2];
    client.read_exact(&mut auth).await.expect("read auth");
    assert_eq!(auth, [0x05, 0x00]);

    let domain = b"localhost";
    let mut req = vec![0x05, 0x01, 0x00, 0x03, domain.len() as u8];
    req.extend_from_slice(domain);
    req.extend_from_slice(&echo_port.to_be_bytes());
    client.write_all(&req).await.expect("write connect");
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.expect("read reply");
    assert_eq!(reply[1], 0x00, "DOMAINNAME CONNECT must succeed");
    assert_eq!(reply[3], 0x01, "BND.ADDR may be returned as IPv4");
    assert_ne!(
        u16::from_be_bytes([reply[8], reply[9]]),
        0,
        "DOMAINNAME CONNECT should still expose a nonzero BND.PORT"
    );

    client.write_all(b"yo").await.expect("write payload");
    let mut buf = [0u8; 2];
    client.read_exact(&mut buf).await.expect("read echo");
    assert_eq!(&buf, b"yo");
}

#[tokio::test]
async fn end_to_end_socks5_streams_large_response_after_single_request() {
    let server = TcpListener::bind("127.0.0.1:0").await.expect("bind server");
    let server_port = server.local_addr().expect("server addr").port();
    tokio::spawn(async move {
        let (mut s, _) = server.accept().await.expect("accept server");
        let mut request = [0u8; 4];
        s.read_exact(&mut request).await.expect("read request");
        s.write_all(&vec![b'a'; 16 * 1024])
            .await
            .expect("write first chunk");
        s.write_all(&vec![b'b'; 16 * 1024])
            .await
            .expect("write second chunk");
    });

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
    let ingress = Socks5Ingress::new(listener);
    tokio::spawn(async move { Box::new(ingress).run(port).await.expect("ingress run") });

    let mut client = TcpStream::connect(format!("127.0.0.1:{bind_port}"))
        .await
        .expect("client connect");
    client
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("write greeting");
    let mut auth = [0u8; 2];
    client.read_exact(&mut auth).await.expect("read auth");
    assert_eq!(auth, [0x05, 0x00]);

    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&server_port.to_be_bytes());
    client.write_all(&req).await.expect("write connect");
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.expect("read reply");
    assert_eq!(reply[1], 0x00, "SOCKS5 reply must be Succeeded");

    client.write_all(b"GET ").await.expect("write request");
    let mut payload = vec![0u8; 32 * 1024];
    client
        .read_exact(&mut payload)
        .await
        .expect("read large response");
    assert!(payload[..16 * 1024].iter().all(|b| *b == b'a'));
    assert!(payload[16 * 1024..].iter().all(|b| *b == b'b'));
}

#[tokio::test]
async fn client_write_eof_keeps_read_side_open_until_upstream_fin() {
    let server = TcpListener::bind("127.0.0.1:0").await.expect("bind server");
    let server_port = server.local_addr().expect("server addr").port();
    tokio::spawn(async move {
        let (mut s, _) = server.accept().await.expect("accept server");
        let mut received = Vec::new();
        s.read_to_end(&mut received)
            .await
            .expect("read request eof");
        assert_eq!(&received[..], b"head");
        s.write_all(b"tail").await.expect("write tail");
        s.shutdown().await.expect("server shutdown");
    });

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
    let ingress = Socks5Ingress::new(listener);
    tokio::spawn(async move { Box::new(ingress).run(port).await.expect("ingress run") });

    let mut client = TcpStream::connect(format!("127.0.0.1:{bind_port}"))
        .await
        .expect("client connect");
    client
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("write greeting");
    let mut auth = [0u8; 2];
    client.read_exact(&mut auth).await.expect("read auth");
    assert_eq!(auth, [0x05, 0x00]);

    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&server_port.to_be_bytes());
    client.write_all(&req).await.expect("write connect");
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.expect("read reply");
    assert_eq!(reply[1], 0x00, "SOCKS5 reply must be Succeeded");

    client.write_all(b"head").await.expect("write head");
    client.shutdown().await.expect("client write shutdown");

    let mut tail = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(1), client.read_exact(&mut tail))
        .await
        .expect("tail timeout")
        .expect("read tail");
    assert_eq!(&tail, b"tail");
}

#[tokio::test]
async fn handshake_timeout_drops_idle_client() {
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
    let ingress = Socks5Ingress::new(listener);
    tokio::spawn(async move { Box::new(ingress).run(port).await.expect("ingress run") });

    let mut client = TcpStream::connect(format!("127.0.0.1:{bind_port}"))
        .await
        .expect("client connect");

    // Never send greeting. Server must close us within HANDSHAKE_TIMEOUT (5s).
    let mut buf = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(7), client.read(&mut buf)).await;
    let n = read
        .expect("server must close before our 7s deadline")
        .expect("read");
    assert_eq!(n, 0, "server-side EOF expected after handshake timeout");
}

#[tokio::test]
async fn malformed_greeting_fails_fast_without_waiting_for_handshake_timeout() {
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
    let ingress = Socks5Ingress::new(listener).with_handshake_timeout(Duration::from_secs(5));
    tokio::spawn(async move { Box::new(ingress).run(port).await.expect("ingress run") });

    let mut client = TcpStream::connect(format!("127.0.0.1:{bind_port}"))
        .await
        .expect("client connect");
    client
        .write_all(&[0x04, 0x01, 0x00])
        .await
        .expect("write malformed greeting");

    let mut buf = [0u8; 1];
    let n = tokio::time::timeout(Duration::from_millis(250), client.read(&mut buf))
        .await
        .expect("malformed greeting must close before handshake timeout")
        .expect("read");
    assert_eq!(n, 0, "server-side EOF expected for malformed greeting");
}

#[tokio::test]
async fn greeting_without_noauth_is_rejected() {
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
    let ingress = Socks5Ingress::new(listener);
    tokio::spawn(async move { Box::new(ingress).run(port).await.expect("ingress run") });

    let mut client = TcpStream::connect(format!("127.0.0.1:{bind_port}"))
        .await
        .expect("client connect");

    client
        .write_all(&[0x05, 0x01, 0x01])
        .await
        .expect("write greeting");
    let mut auth = [0u8; 2];
    client.read_exact(&mut auth).await.expect("read auth");
    assert_eq!(auth, [0x05, 0xff]);
}

#[tokio::test]
async fn greeting_with_zero_methods_is_rejected() {
    // RFC 1928 NMETHODS = 1..255; some hostile/buggy clients send 0.
    // The ingress must reply METHOD=0xff and close, not panic on the empty list.
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
    let ingress = Socks5Ingress::new(listener);
    tokio::spawn(async move { Box::new(ingress).run(port).await.expect("ingress run") });

    let mut client = TcpStream::connect(format!("127.0.0.1:{bind_port}"))
        .await
        .expect("client connect");

    client
        .write_all(&[0x05, 0x00])
        .await
        .expect("write empty greeting");
    let mut auth = [0u8; 2];
    client.read_exact(&mut auth).await.expect("read auth");
    assert_eq!(auth, [0x05, 0xff]);
}

/// RstOnWrite: a mock egress whose recv_half returns None as soon as send() is called once.
/// This simulates upstream close mid-transfer without going through the TCP splice path.
struct RstOnWrite {
    id: ExitId,
}

impl RstOnWrite {
    fn new(id: ExitId) -> Self {
        Self { id }
    }
}

#[async_trait::async_trait]
impl StreamEgress for RstOnWrite {
    fn id(&self) -> &ExitId {
        &self.id
    }
    fn capabilities(&self) -> &Capabilities {
        static CAPS: std::sync::OnceLock<Capabilities> = std::sync::OnceLock::new();
        CAPS.get_or_init(stream_caps)
    }
    async fn open_stream(
        &self,
        _request: &BusSessionRequest,
        info: BusSessionInfo,
    ) -> Result<Box<dyn StreamSession>, DisconnectReason> {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        Ok(Box::new(RstOnWriteSession { info, tx, rx }))
    }
}

struct RstOnWriteSession {
    info: BusSessionInfo,
    tx: tokio::sync::mpsc::Sender<()>,
    rx: tokio::sync::mpsc::Receiver<()>,
}

#[async_trait::async_trait]
impl StreamSession for RstOnWriteSession {
    async fn connect(&mut self) -> Result<&BusSessionInfo, DisconnectReason> {
        Ok(&self.info)
    }
    fn into_tcp_splice(
        self: Box<Self>,
    ) -> Result<mesh_bus_core::TcpSpliceSession, Box<dyn StreamSession>> {
        Err(self)
    }
    fn split(self: Box<Self>) -> (Box<dyn StreamSendHalf>, Box<dyn StreamRecvHalf>) {
        (
            Box::new(RstSendHalf { tx: self.tx }),
            Box::new(RstRecvHalf { rx: self.rx }),
        )
    }
    async fn abort(&mut self, _reason: DisconnectReason) {}
    fn info(&self) -> &BusSessionInfo {
        &self.info
    }
    fn last_error(&self) -> Option<&DisconnectReason> {
        None
    }
}

struct RstSendHalf {
    tx: tokio::sync::mpsc::Sender<()>,
}

#[async_trait::async_trait]
impl StreamSendHalf for RstSendHalf {
    async fn send(&mut self, _payload: bytes::Bytes) -> Result<(), DisconnectReason> {
        // Signal recv-half to terminate (simulate upstream RST on first write).
        let _ = self.tx.try_send(());
        Ok(())
    }
    async fn shutdown_write(&mut self) {}
    async fn abort(&mut self, _reason: DisconnectReason) {}
}

struct RstRecvHalf {
    rx: tokio::sync::mpsc::Receiver<()>,
}

#[async_trait::async_trait]
impl StreamRecvHalf for RstRecvHalf {
    async fn recv(&mut self) -> Option<bytes::Bytes> {
        // Block until send-half signals, then return None (upstream closed).
        self.rx.recv().await;
        None
    }
    fn last_error(&self) -> Option<&DisconnectReason> {
        None
    }
}

#[tokio::test]
async fn upstream_rst_during_data_transfer_sends_fin_to_client() {
    // Mock egress: accept the stream, on first send signal recv to return None (upstream RST).
    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_stream_egress(Box::new(RstOnWrite::new(ExitId("rst".into()))))
        .build()
        .await;
    let port = bus.port();
    let _bh = bus.spawn();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ingress");
    let bind_port = listener.local_addr().expect("ingress addr").port();
    let ingress = Socks5Ingress::new(listener);
    tokio::spawn(async move { Box::new(ingress).run(port).await.expect("ingress run") });

    let mut client = TcpStream::connect(format!("127.0.0.1:{bind_port}"))
        .await
        .expect("client connect");
    client
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("write greeting");
    let mut auth = [0u8; 2];
    client.read_exact(&mut auth).await.expect("read auth");
    assert_eq!(auth, [0x05, 0x00]);
    // Target port 80 — RstOnWrite accepts any target.
    let req = [0x05u8, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50];
    client.write_all(&req).await.expect("write connect");
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.expect("read reply");
    assert_eq!(reply[1], 0x00, "CONNECT must succeed");

    // Send data to trigger recv-half None (simulated upstream RST).
    let _ = client.write_all(b"trigger").await;

    // Ingress must forward FIN to client (read returns 0) within 5s.
    let mut buf = [0u8; 1];
    let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut buf))
        .await
        .expect("must not hang after upstream RST")
        .unwrap_or(0);
    assert_eq!(n, 0, "client must receive FIN when upstream closes");
}

#[tokio::test]
async fn concurrent_connections_all_complete_cleanly() {
    let echo = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let echo_port = echo.local_addr().expect("echo addr").port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = echo.accept().await.expect("accept echo");
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64];
                loop {
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    if s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

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
    let ingress = Socks5Ingress::new(listener);
    tokio::spawn(async move { Box::new(ingress).run(port).await.expect("ingress run") });

    const N: usize = 10;
    let handles: Vec<_> = (0..N)
        .map(|_| {
            tokio::spawn(async move {
                let mut client = TcpStream::connect(format!("127.0.0.1:{bind_port}"))
                    .await
                    .expect("client connect");
                client
                    .write_all(&[0x05, 0x01, 0x00])
                    .await
                    .expect("write greeting");
                let mut auth = [0u8; 2];
                client.read_exact(&mut auth).await.expect("read auth");
                assert_eq!(auth, [0x05, 0x00]);
                let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
                req.extend_from_slice(&echo_port.to_be_bytes());
                client.write_all(&req).await.expect("write connect");
                let mut reply = [0u8; 10];
                client.read_exact(&mut reply).await.expect("read reply");
                assert_eq!(reply[1], 0x00, "CONNECT must succeed");
                client.write_all(b"ping").await.expect("write payload");
                let mut buf = [0u8; 4];
                client.read_exact(&mut buf).await.expect("read echo");
                assert_eq!(&buf, b"ping");
                client.shutdown().await.expect("client shutdown");
            })
        })
        .collect();

    for handle in handles {
        tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .expect("connection must complete within 10s")
            .expect("connection task must not panic");
    }
}

// ── SOCKS5 BIND local-relay coverage ─────────────────────────────────────────

async fn spawn_bind_ingress(policy: Option<RulePolicy>, timeout: Option<Duration>) -> u16 {
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
    let mut ingress = Socks5Ingress::new(listener);
    if let Some(policy) = policy {
        ingress = ingress.with_rule_policy(policy);
    }
    if let Some(timeout) = timeout {
        ingress = ingress.with_handshake_timeout(timeout);
    }
    tokio::spawn(async move { Box::new(ingress).run(port).await.expect("ingress run") });
    bind_port
}

async fn greet(client: &mut TcpStream) {
    client
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("write greeting");
    let mut auth = [0u8; 2];
    client.read_exact(&mut auth).await.expect("read auth");
    assert_eq!(auth, [0x05, 0x00]);
}

fn bind_request(ip: [u8; 4], port: u16) -> [u8; 10] {
    let [ph, pl] = port.to_be_bytes();
    [0x05, 0x02, 0x00, 0x01, ip[0], ip[1], ip[2], ip[3], ph, pl]
}

fn bnd_port(reply: &[u8; 10]) -> u16 {
    u16::from_be_bytes([reply[8], reply[9]])
}

#[tokio::test]
async fn bind_two_replies_then_relays_bidirectionally() {
    let bind_port = spawn_bind_ingress(None, None).await;
    let mut client = TcpStream::connect(format!("127.0.0.1:{bind_port}"))
        .await
        .expect("client connect");
    greet(&mut client).await;
    client
        .write_all(&bind_request([127, 0, 0, 1], 80))
        .await
        .expect("write bind");

    let mut first = [0u8; 10];
    client
        .read_exact(&mut first)
        .await
        .expect("read first reply");
    assert_eq!(first[0], 0x05);
    assert_eq!(first[1], 0x00, "first BIND reply must be Succeeded");
    assert_eq!(first[3], 0x01, "listener BND must be IPv4 on loopback");
    let listener_port = bnd_port(&first);
    assert_ne!(listener_port, 0, "first reply must carry the listener port");

    let mut remote = TcpStream::connect(format!("127.0.0.1:{listener_port}"))
        .await
        .expect("remote peer connect");

    let mut second = [0u8; 10];
    client
        .read_exact(&mut second)
        .await
        .expect("read second reply");
    assert_eq!(second[1], 0x00, "second BIND reply must be Succeeded");

    remote.write_all(b"from-peer").await.expect("peer write");
    let mut got = [0u8; 9];
    client
        .read_exact(&mut got)
        .await
        .expect("client reads peer");
    assert_eq!(&got, b"from-peer");

    client
        .write_all(b"from-client")
        .await
        .expect("client write");
    let mut got2 = [0u8; 11];
    remote
        .read_exact(&mut got2)
        .await
        .expect("peer reads client");
    assert_eq!(&got2, b"from-client");
}

#[tokio::test]
async fn bind_rejects_wrong_peer_ip() {
    let bind_port = spawn_bind_ingress(None, None).await;
    let mut client = TcpStream::connect(format!("127.0.0.1:{bind_port}"))
        .await
        .expect("client connect");
    greet(&mut client).await;
    // Declared peer IP 10.0.0.1 never matches a loopback connector.
    client
        .write_all(&bind_request([10, 0, 0, 1], 80))
        .await
        .expect("write bind");

    let mut first = [0u8; 10];
    client
        .read_exact(&mut first)
        .await
        .expect("read first reply");
    assert_eq!(first[1], 0x00, "first reply still succeeds");
    let listener_port = bnd_port(&first);

    let _remote = TcpStream::connect(format!("127.0.0.1:{listener_port}"))
        .await
        .expect("remote peer connect");

    let mut head = [0u8; 2];
    client
        .read_exact(&mut head)
        .await
        .expect("read second head");
    assert_eq!(
        head,
        [0x05, 0x02],
        "wrong peer IP must reply REP 0x02 ConnectionNotAllowed"
    );
}

#[tokio::test]
async fn bind_accept_timeout_replies_ttl_expired() {
    let bind_port = spawn_bind_ingress(None, Some(Duration::from_millis(300))).await;
    let mut client = TcpStream::connect(format!("127.0.0.1:{bind_port}"))
        .await
        .expect("client connect");
    greet(&mut client).await;
    client
        .write_all(&bind_request([127, 0, 0, 1], 80))
        .await
        .expect("write bind");

    let mut first = [0u8; 10];
    client
        .read_exact(&mut first)
        .await
        .expect("read first reply");
    assert_eq!(first[1], 0x00);

    // No remote peer connects; the accept times out (reuses handshake_timeout).
    let mut head = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut head))
        .await
        .expect("timeout reply must arrive")
        .expect("read second head");
    assert_eq!(
        head,
        [0x05, 0x06],
        "accept timeout must reply REP 0x06 TtlExpired"
    );
}

#[tokio::test]
async fn bind_denied_by_rule_replies_connection_not_allowed() {
    let chain = RuleChain {
        rules: vec![Rule {
            id: None,
            r#match: MatchExpr::Term(Predicate::Socks5CommandEq(RuleSocks5Command::Bind)),
            action: Action::Deny,
        }],
        default: Action::Allow,
    };
    let policy = RulePolicy::new(chain, RuleSetRegistry::default());
    let bind_port = spawn_bind_ingress(Some(policy), None).await;

    let mut client = TcpStream::connect(format!("127.0.0.1:{bind_port}"))
        .await
        .expect("client connect");
    greet(&mut client).await;
    client
        .write_all(&bind_request([127, 0, 0, 1], 80))
        .await
        .expect("write bind");

    let mut head = [0u8; 2];
    client.read_exact(&mut head).await.expect("read reply head");
    assert_eq!(
        head,
        [0x05, 0x02],
        "rule-denied BIND must reply REP 0x02 before opening a listener"
    );
}

// Stream egress whose upstream is permanently silent: it never sends and
// never closes. The recv half blocks forever; dropping it (which only
// happens if the relay tears the returns direction down) signals teardown.
struct SilentUpstreamEgress {
    id: ExitId,
    torn_down: tokio::sync::mpsc::UnboundedSender<()>,
}

#[async_trait::async_trait]
impl StreamEgress for SilentUpstreamEgress {
    fn id(&self) -> &ExitId {
        &self.id
    }

    fn capabilities(&self) -> &Capabilities {
        static CAPS: std::sync::OnceLock<Capabilities> = std::sync::OnceLock::new();
        CAPS.get_or_init(stream_caps)
    }

    async fn open_stream(
        &self,
        _request: &BusSessionRequest,
        info: BusSessionInfo,
    ) -> Result<Box<dyn StreamSession>, DisconnectReason> {
        Ok(Box::new(SilentSession {
            info,
            torn_down: self.torn_down.clone(),
        }))
    }
}

struct SilentSession {
    info: BusSessionInfo,
    torn_down: tokio::sync::mpsc::UnboundedSender<()>,
}

#[async_trait::async_trait]
impl StreamSession for SilentSession {
    async fn connect(&mut self) -> Result<&BusSessionInfo, DisconnectReason> {
        Ok(&self.info)
    }

    fn into_tcp_splice(
        self: Box<Self>,
    ) -> Result<mesh_bus_core::TcpSpliceSession, Box<dyn StreamSession>> {
        Err(self)
    }

    fn split(self: Box<Self>) -> (Box<dyn StreamSendHalf>, Box<dyn StreamRecvHalf>) {
        (
            Box::new(NoopSend),
            Box::new(SilentRecv {
                torn_down: self.torn_down,
            }),
        )
    }

    async fn abort(&mut self, _reason: DisconnectReason) {}

    fn info(&self) -> &BusSessionInfo {
        &self.info
    }

    fn last_error(&self) -> Option<&DisconnectReason> {
        None
    }
}

struct SilentRecv {
    torn_down: tokio::sync::mpsc::UnboundedSender<()>,
}

#[async_trait::async_trait]
impl StreamRecvHalf for SilentRecv {
    async fn recv(&mut self) -> Option<bytes::Bytes> {
        std::future::pending::<Option<bytes::Bytes>>().await
    }

    fn last_error(&self) -> Option<&DisconnectReason> {
        None
    }
}

impl Drop for SilentRecv {
    fn drop(&mut self) {
        let _ = self.torn_down.send(());
    }
}

#[tokio::test]
async fn connect_relay_teardown_is_symmetric() {
    // Upstream is permanently silent (never sends, never closes). When the
    // client fully closes, the send direction ends; symmetric teardown must
    // abort the forever-blocked returns direction and drop the session
    // promptly. Without it the relay joins both halves and hangs forever.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_stream_egress(Box::new(SilentUpstreamEgress {
            id: ExitId("silent".into()),
            torn_down: tx,
        }))
        .build()
        .await;
    let bind_port = spawn_socks_ingress_with_bus(bus).await;

    let mut client = TcpStream::connect(format!("127.0.0.1:{bind_port}"))
        .await
        .expect("client connect");
    client
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("write greeting");
    let mut auth = [0u8; 2];
    client.read_exact(&mut auth).await.expect("read auth");
    assert_eq!(auth, [0x05, 0x00]);
    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&53u16.to_be_bytes());
    client.write_all(&req).await.expect("write connect");
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.expect("read reply");
    assert_eq!(reply[1], 0x00, "SOCKS5 reply must be Succeeded");

    drop(client);

    tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("relay must tear down promptly after client close, not hang on the silent upstream")
        .expect("teardown signal");
}
