use super::*;

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
