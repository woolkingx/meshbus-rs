use super::*;

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
