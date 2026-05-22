//! M1 Tunneled (RFC 7766 TCP) integration tests.
//!
//! Uses an in-memory MockStreamOpener + MockStream{Send,Recv} pair backed by an
//! `mpsc` channel pair. The send half parses each framed query through the real
//! mb-proto-dns codec, builds a reply per behavior, and writes it back as a
//! length-prefix-framed payload on the recv half.

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use mb_proto_dns::framing::{try_read_tcp_frame, write_tcp_frame};
use mb_proto_dns::{
    Message, Name, QType as DnsQType, Question, RClass, RData, ResourceRecord, decode, encode,
};
use mesh_bus_core::{
    BusSessionInfo, BusSessionRequest, BusStreamRecvHalf, BusStreamSendHalf, BusStreamSession,
    DisconnectReason, ScheduleMode,
};
use mesh_bus_resolver::{
    AnswerRecord, ConsumerId, Pool, PoolMode, QType, ResolveError, ResolveRequest, ResolverBuilder,
    ResolverHandle, ResolverSource, ServerPolicy, StreamOpener, UpstreamScheme, UpstreamServer,
    WinnerExit,
};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::mpsc;

// ── Mock behavior ────────────────────────────────────────────────────────────

#[derive(Clone)]
enum MockBehavior {
    ReplyA(Vec<Ipv4Addr>),
    ReplyBadTxid,
    ReplyBadQname,
    Silent,
    /// Replies for the first query then closes the stream so subsequent reads
    /// observe EOF (used to assert cache eviction recovery).
    ReplyThenClose(Vec<Ipv4Addr>),
}

struct MockStreamOpener {
    behaviors: HashMap<SocketAddr, MockBehavior>,
}

#[async_trait]
impl StreamOpener for MockStreamOpener {
    async fn open_stream(
        &self,
        req: BusSessionRequest,
    ) -> Result<Box<dyn BusStreamSession>, DisconnectReason> {
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

// ── Mock session, send half, recv half ───────────────────────────────────────

struct MockSession {
    info: BusSessionInfo,
    // Take()n when split() is called.
    send_half: Option<MockSend>,
    recv_half: Option<MockRecv>,
}

impl MockSession {
    fn new(behavior: MockBehavior) -> Self {
        // recv side delivers framed bytes from the server back to the client.
        let (reply_tx, reply_rx) = mpsc::channel::<Bytes>(8);
        let state = Arc::new(AsyncMutex::new(SendState {
            behavior,
            rx_buf: BytesMut::with_capacity(4096),
            reply_tx,
            closed: false,
        }));
        Self {
            info: BusSessionInfo::empty_for_test(ScheduleMode::Ordered),
            send_half: Some(MockSend { state }),
            recv_half: Some(MockRecv { reply_rx }),
        }
    }
}

#[async_trait]
impl BusStreamSession for MockSession {
    async fn connect(&mut self) -> Result<&BusSessionInfo, DisconnectReason> {
        Ok(&self.info)
    }
    fn into_tcp_splice(
        self: Box<Self>,
    ) -> Result<mesh_bus_core::TcpSpliceSession, Box<dyn BusStreamSession>> {
        Err(self)
    }
    fn split(mut self: Box<Self>) -> (Box<dyn BusStreamSendHalf>, Box<dyn BusStreamRecvHalf>) {
        let s = self.send_half.take().expect("split once");
        let r = self.recv_half.take().expect("split once");
        (Box::new(s), Box::new(r))
    }
    async fn abort(&mut self, _reason: DisconnectReason) {}
    fn info(&self) -> &BusSessionInfo {
        &self.info
    }
    fn last_error(&self) -> Option<&DisconnectReason> {
        None
    }
}

struct SendState {
    behavior: MockBehavior,
    rx_buf: BytesMut,
    reply_tx: mpsc::Sender<Bytes>,
    closed: bool,
}

struct MockSend {
    state: Arc<AsyncMutex<SendState>>,
}

#[async_trait]
impl BusStreamSendHalf for MockSend {
    async fn send(&mut self, payload: Bytes) -> Result<(), DisconnectReason> {
        let mut st = self.state.lock().await;
        if st.closed {
            return Err(DisconnectReason::SessionClosed);
        }
        st.rx_buf.extend_from_slice(&payload);
        // Drain any complete frames the client has sent us.
        while let Some(frame) = try_read_tcp_frame(&mut st.rx_buf) {
            let query = decode::decode_message(&frame).expect("client sent a valid query");
            let q = query
                .questions
                .first()
                .expect("test sends one question")
                .clone();
            let (reply_bytes, then_close) = match &st.behavior {
                MockBehavior::ReplyA(ips) => (build_reply_a(&query, &q, ips), false),
                MockBehavior::ReplyBadTxid => (build_reply_bad_txid(&query, &q), false),
                MockBehavior::ReplyBadQname => (build_reply_bad_qname(&query, &q), false),
                MockBehavior::Silent => continue,
                MockBehavior::ReplyThenClose(ips) => (build_reply_a(&query, &q, ips), true),
            };
            let mut framed = BytesMut::with_capacity(reply_bytes.len() + 2);
            write_tcp_frame(&mut framed, &reply_bytes);
            let _ = st.reply_tx.send(framed.freeze()).await;
            if then_close {
                st.closed = true;
                drop(std::mem::replace(
                    &mut st.reply_tx,
                    mpsc::channel::<Bytes>(1).0,
                ));
            }
        }
        Ok(())
    }
    async fn shutdown_write(&mut self) {}
    async fn abort(&mut self, _reason: DisconnectReason) {}
}

struct MockRecv {
    reply_rx: mpsc::Receiver<Bytes>,
}

#[async_trait]
impl BusStreamRecvHalf for MockRecv {
    async fn recv(&mut self) -> Option<Bytes> {
        self.reply_rx.recv().await
    }
    fn last_error(&self) -> Option<&DisconnectReason> {
        None
    }
}

// ── Reply builders ───────────────────────────────────────────────────────────

fn build_reply_a(query: &Message, q: &Question, ips: &[Ipv4Addr]) -> Vec<u8> {
    let mut m = Message::default();
    m.header.id = query.header.id;
    m.header.flags = 0x8180;
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

fn build_reply_bad_txid(query: &Message, q: &Question) -> Vec<u8> {
    let mut m = Message::default();
    m.header.id = query.header.id.wrapping_add(1);
    m.header.flags = 0x8180;
    m.questions.push(q.clone());
    encode::encode_message(&m).expect("encode reply")
}

fn build_reply_bad_qname(query: &Message, q: &Question) -> Vec<u8> {
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
        mode: PoolMode::Tunneled { server_policy },
        servers: addrs
            .iter()
            .map(|a| UpstreamServer {
                scheme: UpstreamScheme::Tcp,
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
        .with_stream_opener(Arc::new(MockStreamOpener { behaviors }))
        .with_query_timeout(timeout)
        .build()
        .expect("resolver builds")
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn round_robin_single_shot_succeeds() {
    let s1 = addr("127.0.0.1:5401");
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
    assert_eq!(ans.source, ResolverSource::Tunneled { server: s1 });
    assert!(!ans.truncated);
    assert!(matches!(sig.winner_exit, WinnerExit::SinglePath { server } if server == s1));
    assert_eq!(sig.attempted, 1);
    assert_eq!(sig.answer_count, 1);
}

#[tokio::test]
async fn cached_connection_serves_two_queries() {
    let s1 = addr("127.0.0.1:5402");
    let behaviors = HashMap::from([(s1, MockBehavior::ReplyA(vec![Ipv4Addr::new(5, 5, 5, 5)]))]);
    let pool = make_pool("p", ServerPolicy::RoundRobin, &[s1]);
    let resolver = build_resolver(pool, behaviors, Duration::from_secs(1));

    for _ in 0..2 {
        let (ans, sig) = resolver
            .resolve(make_request("example.com"))
            .await
            .expect("resolve ok");
        assert_eq!(
            ans.records,
            vec![AnswerRecord::A(Ipv4Addr::new(5, 5, 5, 5))]
        );
        assert!(matches!(sig.winner_exit, WinnerExit::SinglePath { server } if server == s1));
    }
}

#[tokio::test]
async fn round_robin_cycles_across_servers() {
    let s1 = addr("127.0.0.1:5411");
    let s2 = addr("127.0.0.1:5412");
    let s3 = addr("127.0.0.1:5413");
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
    let s1 = addr("127.0.0.1:5421");
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
    let s1 = addr("127.0.0.1:5422");
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
    let s1 = addr("127.0.0.1:5431");
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
    let s1 = addr("127.0.0.1:5441");
    let s2 = addr("127.0.0.1:5442");
    let s3 = addr("127.0.0.1:5443");
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
            assert_eq!(winner, s1);
            assert_eq!(losers, vec![s2]);
            assert_eq!(ans.source, ResolverSource::Tunneled { server: s1 });
        }
        other => panic!("expected FanOut winner_exit, got {other:?}"),
    }
}

#[tokio::test]
async fn fanout_winner_when_first_silent_second_replies() {
    let s1 = addr("127.0.0.1:5451");
    let s2 = addr("127.0.0.1:5452");
    let behaviors = HashMap::from([
        (s1, MockBehavior::Silent),
        (s2, MockBehavior::ReplyA(vec![Ipv4Addr::new(8, 8, 8, 8)])),
    ]);
    let pool = make_pool("p", ServerPolicy::FanOut { k: 2 }, &[s1, s2]);
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
    let s1 = addr("127.0.0.1:5461");
    let s2 = addr("127.0.0.1:5462");
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
async fn tunneled_without_opener_returns_explicit_error() {
    let s1 = addr("127.0.0.1:5471");
    let pool = make_pool("p", ServerPolicy::RoundRobin, &[s1]);
    let resolver = ResolverBuilder::new()
        .with_pool(pool)
        .with_default_pool("p")
        .build()
        .expect("builds without opener");

    let (err, _sig) = resolver
        .resolve(make_request("example.com"))
        .await
        .expect_err("must require opener");
    match err {
        ResolveError::Io(msg) => assert!(msg.contains("StreamOpener"), "got {msg}"),
        other => panic!("expected Io(StreamOpener required), got {other:?}"),
    }
}

#[tokio::test]
async fn stream_close_after_first_reply_evicts_cache_and_second_query_reopens() {
    let s1 = addr("127.0.0.1:5481");
    let behaviors = HashMap::from([(
        s1,
        MockBehavior::ReplyThenClose(vec![Ipv4Addr::new(7, 7, 7, 7)]),
    )]);
    let pool = make_pool("p", ServerPolicy::RoundRobin, &[s1]);
    // Each open is a fresh MockSession (with fresh behavior copy); after the
    // first answer the server-side closes; the resolver must evict and reopen.
    let resolver = build_resolver(pool, behaviors, Duration::from_millis(500));

    let (ans1, _) = resolver
        .resolve(make_request("example.com"))
        .await
        .expect("first resolve ok");
    assert_eq!(
        ans1.records,
        vec![AnswerRecord::A(Ipv4Addr::new(7, 7, 7, 7))]
    );

    // Second resolve: cached conn is now closed, so first attempt will fail with
    // EOF on the still-cached recv channel. ResolveError::Io evicts; but since
    // we only have one shot per call (RoundRobin), the call itself errors. That
    // is the documented behavior — surface the upstream close as Io.
    let (err, _) = resolver
        .resolve(make_request("example.com"))
        .await
        .expect_err("cached-then-closed conn surfaces Io");
    match err {
        ResolveError::Io(_) => {}
        other => panic!("expected Io(closed), got {other:?}"),
    }

    // Third resolve: cache has been evicted, so we reopen — succeeds again.
    let (ans3, _) = resolver
        .resolve(make_request("example.com"))
        .await
        .expect("post-eviction reopen ok");
    assert_eq!(
        ans3.records,
        vec![AnswerRecord::A(Ipv4Addr::new(7, 7, 7, 7))]
    );
}
