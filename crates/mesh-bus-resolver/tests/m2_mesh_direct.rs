//! M2 MeshDirect integration tests.
//!
//! Uses an in-memory MockOpener / MockSession that runs the real RFC 1035
//! encode/decode (via `mb-proto-dns`) but skips the UDP wire so tests stay
//! deterministic. The mock honours the `BusDatagramSession` contract.

use async_trait::async_trait;
use bytes::Bytes;
use mb_endpoint::Endpoint;
use mb_proto_dns::{
    Message, Name, QType as DnsQType, Question, RClass, RData, ResourceRecord, decode, encode,
};
use mesh_bus_core::{
    BusDatagramRecvHalf, BusDatagramSendHalf, BusDatagramSession, BusSessionInfo,
    BusSessionRequest, DisconnectReason, ScheduleMode, SendError,
};
use mesh_bus_resolver::{
    AnswerRecord, ConsumerId, DatagramOpener, Pool, PoolMode, QType, ResolveError, ResolveRequest,
    ResolverBuilder, ResolverHandle, ResolverSource, ServerPolicy, UpstreamScheme, UpstreamServer,
    WinnerExit,
};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

// ── Mock ─────────────────────────────────────────────────────────────────────

#[derive(Clone)]
enum MockBehavior {
    ReplyA(Vec<Ipv4Addr>),
    ReplyBadTxid,
    ReplyBadQname,
    Silent,
}

struct MockOpener {
    behaviors: HashMap<SocketAddr, MockBehavior>,
}

#[async_trait]
impl DatagramOpener for MockOpener {
    async fn open_datagram(
        &self,
        req: BusSessionRequest,
    ) -> Result<Box<dyn BusDatagramSession>, DisconnectReason> {
        let addr: SocketAddr = req
            .target_key
            .as_deref()
            .and_then(|s| s.parse().ok())
            .ok_or(DisconnectReason::AddressNotSupported)?;
        let behavior = self
            .behaviors
            .get(&addr)
            .cloned()
            .ok_or(DisconnectReason::NoUsableExit)?;
        Ok(Box::new(MockSession::new(behavior)))
    }
}

struct MockSession {
    behavior: MockBehavior,
    pending_reply: Option<Bytes>,
    info: BusSessionInfo,
}

impl MockSession {
    fn new(behavior: MockBehavior) -> Self {
        Self {
            behavior,
            pending_reply: None,
            info: BusSessionInfo::empty_for_test(ScheduleMode::Ordered),
        }
    }
}

#[async_trait]
impl BusDatagramSession for MockSession {
    async fn send_to(&mut self, _target: Endpoint, payload: Bytes) -> Result<(), SendError> {
        let query = decode::decode_message(&payload).map_err(|_| SendError::Closed)?;
        let q = query
            .questions
            .first()
            .expect("test sends one question")
            .clone();
        let bytes = match &self.behavior {
            MockBehavior::ReplyA(ips) => {
                let mut m = Message::default();
                m.header.id = query.header.id;
                m.header.flags = 0x8180; // QR=1, RD=1, RA=1, RCODE=0
                m.questions.push(q.clone());
                for ip in ips {
                    m.answers.push(ResourceRecord {
                        name: q.name.clone(),
                        qtype: DnsQType::A,
                        qclass: RClass::In,
                        ttl: 60,
                        data: RData::A(*ip),
                    });
                }
                encode::encode_message(&m).expect("encode reply")
            }
            MockBehavior::ReplyBadTxid => {
                let mut m = Message::default();
                m.header.id = query.header.id.wrapping_add(1);
                m.header.flags = 0x8180;
                m.questions.push(q);
                encode::encode_message(&m).expect("encode reply")
            }
            MockBehavior::ReplyBadQname => {
                let mut m = Message::default();
                m.header.id = query.header.id;
                m.header.flags = 0x8180;
                m.questions.push(Question {
                    name: Name::from_ascii("other.example.com.").expect("valid name"),
                    qtype: q.qtype,
                    qclass: q.qclass,
                });
                encode::encode_message(&m).expect("encode reply")
            }
            MockBehavior::Silent => return Ok(()),
        };
        self.pending_reply = Some(Bytes::from(bytes));
        Ok(())
    }

    async fn recv_from(&mut self) -> Option<(Endpoint, Bytes)> {
        if let Some(reply) = self.pending_reply.take() {
            return Some((
                Endpoint::new("127.0.0.1", 53).expect("valid endpoint"),
                reply,
            ));
        }
        // Block forever; the resolver's per-query timeout fires.
        std::future::pending::<()>().await;
        None
    }

    fn info(&self) -> &BusSessionInfo {
        &self.info
    }

    fn max_payload_bytes(&self) -> usize {
        4096
    }

    async fn close(&mut self) {}

    fn split(self: Box<Self>) -> (Box<dyn BusDatagramSendHalf>, Box<dyn BusDatagramRecvHalf>) {
        let shared = Arc::new(tokio::sync::Mutex::new(*self));
        (
            Box::new(MockSendHalf {
                shared: shared.clone(),
            }),
            Box::new(MockRecvHalf { shared }),
        )
    }
}

struct MockSendHalf {
    shared: Arc<tokio::sync::Mutex<MockSession>>,
}

#[async_trait]
impl BusDatagramSendHalf for MockSendHalf {
    async fn send_to(&mut self, target: Endpoint, payload: Bytes) -> Result<(), SendError> {
        self.shared.lock().await.send_to(target, payload).await
    }

    async fn close(&mut self) {
        self.shared.lock().await.close().await;
    }
}

struct MockRecvHalf {
    shared: Arc<tokio::sync::Mutex<MockSession>>,
}

#[async_trait]
impl BusDatagramRecvHalf for MockRecvHalf {
    async fn recv_from(&mut self) -> Option<(Endpoint, Bytes)> {
        self.shared.lock().await.recv_from().await
    }

    fn last_error(&self) -> Option<&DisconnectReason> {
        None
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn addr(s: &str) -> SocketAddr {
    s.parse().expect("valid socket addr")
}

fn make_request(qname: &str) -> ResolveRequest {
    ResolveRequest {
        qname: qname.into(),
        qtype: QType::A,
        consumer: ConsumerId("test".into()),
    }
}

fn make_pool(id: &str, server_policy: ServerPolicy, addrs: &[SocketAddr]) -> Pool {
    Pool {
        id: id.into(),
        mode: PoolMode::MeshDirect { server_policy },
        servers: addrs
            .iter()
            .map(|a| UpstreamServer {
                scheme: UpstreamScheme::Udp,
                addr: *a,
            })
            .collect(),
        route_group: None,
    }
}

fn build_resolver(
    pool: Pool,
    behaviors: HashMap<SocketAddr, MockBehavior>,
    timeout: Duration,
) -> impl ResolverHandle {
    ResolverBuilder::new()
        .with_pool(pool)
        .with_default_pool("p")
        .with_datagram_opener(Arc::new(MockOpener { behaviors }))
        .with_query_timeout(timeout)
        .build()
        .expect("resolver builds")
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn round_robin_single_shot_succeeds() {
    let s1 = addr("127.0.0.1:5301");
    let behaviors = HashMap::from([(s1, MockBehavior::ReplyA(vec![Ipv4Addr::new(1, 2, 3, 4)]))]);
    let pool = make_pool("p", ServerPolicy::RoundRobin, &[s1]);
    let resolver = build_resolver(pool, behaviors, Duration::from_secs(1));

    let (ans, sig) = resolver
        .resolve(make_request("example.com"))
        .await
        .expect("resolve ok");
    assert_eq!(
        ans.records,
        vec![AnswerRecord::A(Ipv4Addr::new(1, 2, 3, 4))]
    );
    assert_eq!(ans.source, ResolverSource::MeshDirect { server: s1 });
    assert!(!ans.truncated);

    assert!(matches!(sig.winner_exit, WinnerExit::SinglePath { server } if server == s1));
    assert_eq!(sig.attempted, 1);
    assert_eq!(sig.answer_count, 1);
    assert!(!sig.truncated);
}

#[tokio::test]
async fn round_robin_cycles_across_servers() {
    let s1 = addr("127.0.0.1:5311");
    let s2 = addr("127.0.0.1:5312");
    let s3 = addr("127.0.0.1:5313");
    let behaviors = HashMap::from([
        (s1, MockBehavior::ReplyA(vec![Ipv4Addr::new(1, 1, 1, 1)])),
        (s2, MockBehavior::ReplyA(vec![Ipv4Addr::new(2, 2, 2, 2)])),
        (s3, MockBehavior::ReplyA(vec![Ipv4Addr::new(3, 3, 3, 3)])),
    ]);
    let pool = make_pool("p", ServerPolicy::RoundRobin, &[s1, s2, s3]);
    let resolver = build_resolver(pool, behaviors, Duration::from_secs(1));

    let mut winners = Vec::new();
    for _ in 0..4 {
        let (_, sig) = resolver
            .resolve(make_request("example.com"))
            .await
            .expect("resolve ok");
        match sig.winner_exit {
            WinnerExit::SinglePath { server } => winners.push(server),
            other => panic!("expected SinglePath, got {other:?}"),
        }
    }
    assert_eq!(winners, vec![s1, s2, s3, s1]);
}

#[tokio::test]
async fn txid_mismatch_is_rejected_per_rfc_5452() {
    let s1 = addr("127.0.0.1:5321");
    let behaviors = HashMap::from([(s1, MockBehavior::ReplyBadTxid)]);
    let pool = make_pool("p", ServerPolicy::RoundRobin, &[s1]);
    let resolver = build_resolver(pool, behaviors, Duration::from_millis(200));

    let (err, _sig) = resolver
        .resolve(make_request("example.com"))
        .await
        .expect_err("must reject bad txid");
    match err {
        ResolveError::Io(msg) => assert!(msg.contains("TXID"), "got {msg}"),
        other => panic!("expected Io(TXID mismatch), got {other:?}"),
    }
}

#[tokio::test]
async fn qname_mismatch_is_rejected_per_rfc_5452() {
    let s1 = addr("127.0.0.1:5322");
    let behaviors = HashMap::from([(s1, MockBehavior::ReplyBadQname)]);
    let pool = make_pool("p", ServerPolicy::RoundRobin, &[s1]);
    let resolver = build_resolver(pool, behaviors, Duration::from_millis(200));

    let (err, _sig) = resolver
        .resolve(make_request("example.com"))
        .await
        .expect_err("must reject bad qname");
    match err {
        ResolveError::Io(msg) => {
            assert!(msg.contains("QNAME") || msg.contains("TXID"), "got {msg}")
        }
        other => panic!("expected Io mismatch, got {other:?}"),
    }
}

#[tokio::test]
async fn silent_server_triggers_timeout_error() {
    let s1 = addr("127.0.0.1:5331");
    let behaviors = HashMap::from([(s1, MockBehavior::Silent)]);
    let pool = make_pool("p", ServerPolicy::RoundRobin, &[s1]);
    let budget = Duration::from_millis(100);
    let resolver = build_resolver(pool, behaviors, budget);

    let (err, _sig) = resolver
        .resolve(make_request("example.com"))
        .await
        .expect_err("must timeout");
    match err {
        ResolveError::Timeout(d) => assert_eq!(d, budget),
        other => panic!("expected Timeout({budget:?}), got {other:?}"),
    }
}

#[tokio::test]
async fn empty_server_list_is_rejected() {
    let pool = make_pool("p", ServerPolicy::RoundRobin, &[]);
    let resolver = build_resolver(pool, HashMap::new(), Duration::from_millis(100));

    let (err, _sig) = resolver
        .resolve(make_request("example.com"))
        .await
        .expect_err("empty pool must error");
    match err {
        ResolveError::Io(msg) => assert!(msg.contains("no servers"), "got {msg}"),
        other => panic!("expected Io(no servers), got {other:?}"),
    }
}

#[tokio::test]
async fn fanout_first_wins_others_become_losers() {
    let s1 = addr("127.0.0.1:5341");
    let s2 = addr("127.0.0.1:5342");
    let s3 = addr("127.0.0.1:5343");
    let behaviors = HashMap::from([
        (s1, MockBehavior::ReplyA(vec![Ipv4Addr::new(9, 9, 9, 1)])),
        (s2, MockBehavior::ReplyA(vec![Ipv4Addr::new(9, 9, 9, 2)])),
        (s3, MockBehavior::ReplyA(vec![Ipv4Addr::new(9, 9, 9, 3)])),
    ]);
    let pool = make_pool("p", ServerPolicy::FanOut { k: 2 }, &[s1, s2, s3]);
    let resolver = build_resolver(pool, behaviors, Duration::from_secs(1));

    let (ans, sig) = resolver
        .resolve(make_request("example.com"))
        .await
        .expect("fanout ok");
    assert_eq!(sig.attempted, 2);
    match sig.winner_exit {
        WinnerExit::FanOut { winner, losers } => {
            assert_eq!(
                winner, s1,
                "select_fanout picks the first k servers in order"
            );
            assert_eq!(losers, vec![s2]);
            assert_eq!(ans.source, ResolverSource::MeshDirect { server: s1 });
        }
        other => panic!("expected FanOut winner_exit, got {other:?}"),
    }
}

#[tokio::test]
async fn fanout_winner_when_first_silent_second_replies() {
    let s1 = addr("127.0.0.1:5351");
    let s2 = addr("127.0.0.1:5352");
    let behaviors = HashMap::from([
        (s1, MockBehavior::Silent),
        (s2, MockBehavior::ReplyA(vec![Ipv4Addr::new(8, 8, 8, 8)])),
    ]);
    let pool = make_pool("p", ServerPolicy::FanOut { k: 2 }, &[s1, s2]);
    // Short budget per-shot — silent s1 times out, s2 still answers.
    let resolver = build_resolver(pool, behaviors, Duration::from_millis(100));

    let (ans, sig) = resolver
        .resolve(make_request("example.com"))
        .await
        .expect("fanout ok when one server answers");
    assert_eq!(sig.attempted, 2);
    match sig.winner_exit {
        WinnerExit::FanOut { winner, losers } => {
            assert_eq!(winner, s2);
            assert_eq!(losers, vec![s1]);
        }
        other => panic!("expected FanOut winner_exit, got {other:?}"),
    }
    assert_eq!(
        ans.records,
        vec![AnswerRecord::A(Ipv4Addr::new(8, 8, 8, 8))]
    );
}

#[tokio::test]
async fn fanout_all_silent_returns_error() {
    let s1 = addr("127.0.0.1:5361");
    let s2 = addr("127.0.0.1:5362");
    let behaviors = HashMap::from([(s1, MockBehavior::Silent), (s2, MockBehavior::Silent)]);
    let pool = make_pool("p", ServerPolicy::FanOut { k: 2 }, &[s1, s2]);
    let resolver = build_resolver(pool, behaviors, Duration::from_millis(50));

    let (err, _sig) = resolver
        .resolve(make_request("example.com"))
        .await
        .expect_err("all-silent fanout must error");
    match err {
        ResolveError::Io(msg) => assert!(msg.contains("fanout attempts failed"), "got {msg}"),
        other => panic!("expected Io(all fanout failed), got {other:?}"),
    }
}

#[tokio::test]
async fn meshdirect_without_opener_returns_explicit_error() {
    let s1 = addr("127.0.0.1:5371");
    let pool = make_pool("p", ServerPolicy::RoundRobin, &[s1]);
    let resolver = ResolverBuilder::new()
        .with_pool(pool)
        .with_default_pool("p")
        // Intentionally no with_datagram_opener
        .build()
        .expect("builds without opener (validate doesn't require it)");

    let (err, _sig) = resolver
        .resolve(make_request("example.com"))
        .await
        .expect_err("must require opener");
    match err {
        ResolveError::Io(msg) => assert!(msg.contains("DatagramOpener"), "got {msg}"),
        other => panic!("expected Io(opener required), got {other:?}"),
    }
}
