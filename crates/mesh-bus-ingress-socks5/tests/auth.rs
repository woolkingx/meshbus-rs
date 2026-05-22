//! RFC 1929 user/password subnegotiation integration tests.

use mesh_bus_core::{
    BusBuilder, BusPathInfo, BusSessionInfo, BusSessionRequest, Capabilities, DisconnectReason,
    ExitId, ExitResult, IngressPlugin, Measurement, PathState, RankContext, ScheduleDecision,
    SchedulerPlugin, StreamEgress, StreamRecvHalf, StreamSendHalf, StreamSession,
};
use mesh_bus_ingress_socks5::{AuthConfig, Socks5Ingress};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct First;
impl SchedulerPlugin for First {
    fn schedule(&self, c: &[ExitId], _ctx: &RankContext) -> ScheduleDecision {
        ScheduleDecision::ordered((0..c.len()).collect())
    }
    fn feedback(&self, _r: &ExitResult, _payload_bytes: u64, _at_ms: u64) {}
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
        Ok(Box::new(IdleSession { info }))
    }
}

struct IdleSession {
    info: BusSessionInfo,
}

#[async_trait::async_trait]
impl StreamSession for IdleSession {
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

async fn spawn_auth_ingress(auth: AuthConfig) -> u16 {
    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_stream_egress(Box::new(BndOnOpen {
            id: ExitId("bnd".into()),
            local_port: 49_152,
        }))
        .build()
        .await;
    let port = bus.port();
    let _bh = bus.spawn();
    std::mem::forget(_bh);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ingress");
    let bind_port = listener.local_addr().expect("ingress addr").port();
    let ingress = Socks5Ingress::new(listener).with_auth(auth);
    tokio::spawn(async move { Box::new(ingress).run(port).await.expect("ingress run") });
    bind_port
}

#[tokio::test]
async fn rejects_client_without_user_pass_method() {
    let bind_port = spawn_auth_ingress(AuthConfig::new().with_user("alice", "s3cret")).await;
    let mut client = TcpStream::connect(format!("127.0.0.1:{bind_port}"))
        .await
        .expect("client connect");
    // Offer only NoAuth.
    client
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("write greeting");
    let mut resp = [0u8; 2];
    client
        .read_exact(&mut resp)
        .await
        .expect("read method reply");
    assert_eq!(resp, [0x05, 0xff]);
}

#[tokio::test]
async fn user_pass_success_then_connect_succeeds() {
    let bind_port = spawn_auth_ingress(AuthConfig::new().with_user("alice", "s3cret")).await;
    let mut client = TcpStream::connect(format!("127.0.0.1:{bind_port}"))
        .await
        .expect("client connect");
    // Offer UserPass.
    client
        .write_all(&[0x05, 0x01, 0x02])
        .await
        .expect("write greeting");
    let mut method = [0u8; 2];
    client
        .read_exact(&mut method)
        .await
        .expect("read method reply");
    assert_eq!(method, [0x05, 0x02]);
    // RFC 1929 subnegotiation.
    let subneg: Vec<u8> = [&[0x01u8, 5][..], b"alice", &[6][..], b"s3cret"].concat();
    client.write_all(&subneg).await.expect("write subneg");
    let mut sub_reply = [0u8; 2];
    client
        .read_exact(&mut sub_reply)
        .await
        .expect("read subneg reply");
    assert_eq!(sub_reply, [0x01, 0x00]);
    // CONNECT 127.0.0.1:9 — BndOnOpen accepts any target.
    let req = [0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 9];
    client.write_all(&req).await.expect("write connect");
    let mut reply = [0u8; 10];
    client
        .read_exact(&mut reply)
        .await
        .expect("read connect reply");
    assert_eq!(reply[0], 0x05);
    assert_eq!(reply[1], 0x00, "REP=Succeeded");
}

#[tokio::test]
async fn user_pass_wrong_password_closes_connection() {
    let bind_port = spawn_auth_ingress(AuthConfig::new().with_user("alice", "s3cret")).await;
    let mut client = TcpStream::connect(format!("127.0.0.1:{bind_port}"))
        .await
        .expect("client connect");
    client
        .write_all(&[0x05, 0x01, 0x02])
        .await
        .expect("write greeting");
    let mut method = [0u8; 2];
    client
        .read_exact(&mut method)
        .await
        .expect("read method reply");
    assert_eq!(method, [0x05, 0x02]);
    let subneg: Vec<u8> = [&[0x01u8, 5][..], b"alice", &[5][..], b"wrong"].concat();
    client.write_all(&subneg).await.expect("write subneg");
    let mut sub_reply = [0u8; 2];
    client
        .read_exact(&mut sub_reply)
        .await
        .expect("read subneg reply");
    assert_eq!(sub_reply, [0x01, 0xff]);
    // After failure, server closes — further read returns 0.
    let mut tail = [0u8; 1];
    let n = client.read(&mut tail).await.unwrap_or(0);
    assert_eq!(n, 0, "server must close after auth failure");
}

#[tokio::test]
async fn user_pass_unknown_user_closes_connection() {
    let bind_port = spawn_auth_ingress(AuthConfig::new().with_user("alice", "s3cret")).await;
    let mut client = TcpStream::connect(format!("127.0.0.1:{bind_port}"))
        .await
        .expect("client connect");
    client
        .write_all(&[0x05, 0x01, 0x02])
        .await
        .expect("write greeting");
    let mut method = [0u8; 2];
    client
        .read_exact(&mut method)
        .await
        .expect("read method reply");
    let subneg: Vec<u8> = [&[0x01u8, 3][..], b"bob", &[3][..], b"any"].concat();
    client.write_all(&subneg).await.expect("write subneg");
    let mut sub_reply = [0u8; 2];
    client
        .read_exact(&mut sub_reply)
        .await
        .expect("read subneg reply");
    assert_eq!(sub_reply[0], 0x01);
    assert_ne!(sub_reply[1], 0x00, "unknown user must not succeed");
}

#[tokio::test]
async fn user_pass_subneg_wrong_version_closes_connection() {
    // RFC 1929 subneg VER must be 0x01. If client sends VER=0x05 (SOCKS version),
    // ingress must reject and close.
    let bind_port = spawn_auth_ingress(AuthConfig::new().with_user("alice", "s3cret")).await;
    let mut client = TcpStream::connect(format!("127.0.0.1:{bind_port}"))
        .await
        .expect("client connect");
    // Offer UserPass method.
    client
        .write_all(&[0x05, 0x01, 0x02])
        .await
        .expect("write greeting");
    let mut method = [0u8; 2];
    client
        .read_exact(&mut method)
        .await
        .expect("read method reply");
    assert_eq!(method, [0x05, 0x02]);
    // Send subneg with VER=0x05 instead of 0x01 (wrong version).
    let subneg: Vec<u8> = [&[0x05u8, 5][..], b"alice", &[6][..], b"s3cret"].concat();
    client.write_all(&subneg).await.expect("write bad subneg");
    // Ingress should reject: either send failure reply then close, or just close.
    // Either way, a subsequent read must return 0 (connection closed).
    let mut buf = [0u8; 8];
    let n = tokio::time::timeout(std::time::Duration::from_secs(3), client.read(&mut buf))
        .await
        .expect("must close within timeout")
        .unwrap_or(0);
    // Server may send [0x01, 0xff] failure reply before closing.
    // In any case the connection must be closed (no further data possible).
    let closed = n == 0 || (n >= 2 && buf[0] == 0x01 && buf[1] != 0x00);
    assert!(
        closed,
        "bad subneg VER must result in auth failure or connection close; got {n} bytes: {buf:?}"
    );
    // After the server's response (if any), the connection must be closed.
    if n > 0 {
        let mut tail = [0u8; 1];
        let tail_n =
            tokio::time::timeout(std::time::Duration::from_secs(2), client.read(&mut tail))
                .await
                .expect("must close after auth failure reply")
                .unwrap_or(0);
        assert_eq!(tail_n, 0, "server must close after auth failure");
    }
}

#[test]
fn gssapi_gate_is_off_in_default_build() {
    // Documents the shipped full-RFC posture: GSSAPI is reserved and gated off
    // behind the default-off `gssapi` cargo feature with no authenticator
    // backend. The gate suite builds with default features.
    assert!(
        !mesh_bus_ingress_socks5::GSSAPI_SUPPORTED,
        "default build must not claim GSSAPI support"
    );
}

#[tokio::test]
async fn gssapi_only_client_rejected_no_acceptable_methods() {
    // No AuthConfig => NoAuth is the only negotiable method. A client offering
    // ONLY GSSAPI (0x01) must get the RFC1928 0x05 0xff no-acceptable-methods
    // reply and the connection must close. This is the documented non-full
    // build mode behavior.
    let bind_port = spawn_auth_ingress(AuthConfig::new()).await;
    let mut client = TcpStream::connect(format!("127.0.0.1:{bind_port}"))
        .await
        .expect("client connect");
    client
        .write_all(&[0x05, 0x01, 0x01])
        .await
        .expect("write greeting");
    let mut resp = [0u8; 2];
    client
        .read_exact(&mut resp)
        .await
        .expect("read method reply");
    assert_eq!(resp, [0x05, 0xff], "GSSAPI-only must be rejected");
    let mut tail = [0u8; 1];
    let n = client.read(&mut tail).await.unwrap_or(0);
    assert_eq!(n, 0, "server must close after no-acceptable-methods");
}

#[tokio::test]
async fn gssapi_offered_with_noauth_negotiates_noauth() {
    // A greeting that offers GSSAPI AND NoAuth must still negotiate NoAuth;
    // GSSAPI presence does not break negotiation of a supported method.
    let bind_port = spawn_auth_ingress(AuthConfig::new()).await;
    let mut client = TcpStream::connect(format!("127.0.0.1:{bind_port}"))
        .await
        .expect("client connect");
    client
        .write_all(&[0x05, 0x02, 0x01, 0x00])
        .await
        .expect("write greeting");
    let mut method = [0u8; 2];
    client
        .read_exact(&mut method)
        .await
        .expect("read method reply");
    assert_eq!(
        method,
        [0x05, 0x00],
        "must select NoAuth despite GSSAPI offer"
    );
}

#[tokio::test]
async fn no_auth_config_keeps_no_auth_path() {
    // Empty AuthConfig disables auth entirely.
    let bind_port = spawn_auth_ingress(AuthConfig::new()).await;
    let mut client = TcpStream::connect(format!("127.0.0.1:{bind_port}"))
        .await
        .expect("client connect");
    client
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("write greeting");
    let mut method = [0u8; 2];
    client
        .read_exact(&mut method)
        .await
        .expect("read method reply");
    assert_eq!(method, [0x05, 0x00]);
}
