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

#[path = "handshake/bind_cases.rs"]
mod bind_cases;
#[path = "handshake/connect_cases.rs"]
mod connect_cases;

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
