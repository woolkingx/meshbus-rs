use async_trait::async_trait;
use bytes::Bytes;
use mb_endpoint::Endpoint;
use mb_proto_dns::{Message, QType as DnsQType, RClass, RData, ResourceRecord, decode, encode};
use mesh_bus_core::{
    BusDatagramRecvHalf, BusDatagramSendHalf, BusDatagramSession, BusSessionInfo,
    BusSessionRequest, DisconnectReason, ScheduleMode, SendError,
};
use mesh_bus_resolver::cache::{CacheKey, DnsCache};
use mesh_bus_resolver::data_handle::{ResolverBuilder, ResolverHandle};
use mesh_bus_resolver::types::*;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

// ── Test 1: pre-warmed cache short-circuits resolve() ──────────────────────

#[tokio::test]
async fn resolve_returns_from_positive_cache_when_warm() {
    let cache = Arc::new(DnsCache::new());
    cache.put_positive(
        CacheKey {
            qname: "cached.test.".into(),
            qtype: QType::A,
        },
        vec![AnswerRecord::A(Ipv4Addr::new(10, 0, 0, 1))],
        Duration::from_secs(60),
    );

    let pool = Pool {
        id: "stub".into(),
        mode: PoolMode::SystemMode,
        servers: vec![],
        route_group: None,
    };

    let resolver = ResolverBuilder::new()
        .with_pool(pool)
        .with_default_pool("stub")
        .with_cache(cache.clone())
        .build()
        .expect("build");

    let req = ResolveRequest {
        qname: "cached.test.".into(),
        qtype: QType::A,
        consumer: ConsumerId("test".into()),
    };
    let (ans, sig) = resolver.resolve(req).await.expect("hit cache");
    assert_eq!(
        ans.records,
        vec![AnswerRecord::A(Ipv4Addr::new(10, 0, 0, 1))]
    );
    assert_eq!(sig.qname_key, "cached.test.");
    assert_eq!(sig.pool, "cache");
    assert_eq!(sig.answer_count, 1);
}

// ── Test 2: post-resolve cache write uses wire-derived RFC 2181 min TTL ────

struct TtlMockOpener {
    ttl_secs: u32,
}

#[async_trait]
impl mesh_bus_resolver::DatagramOpener for TtlMockOpener {
    async fn open_datagram(
        &self,
        _req: BusSessionRequest,
    ) -> Result<Box<dyn BusDatagramSession>, DisconnectReason> {
        Ok(Box::new(TtlMockSession {
            ttl_secs: self.ttl_secs,
            pending_reply: None,
            info: BusSessionInfo::empty_for_test(ScheduleMode::Ordered),
        }))
    }
}

struct TtlMockSession {
    ttl_secs: u32,
    pending_reply: Option<Bytes>,
    info: BusSessionInfo,
}

#[async_trait]
impl BusDatagramSession for TtlMockSession {
    async fn send_to(&mut self, _target: Endpoint, payload: Bytes) -> Result<(), SendError> {
        let query = decode::decode_message(&payload).map_err(|_| SendError::Closed)?;
        let q = query
            .questions
            .first()
            .expect("test sends one question")
            .clone();
        let mut m = Message::default();
        m.header.id = query.header.id;
        m.header.flags = 0x8180; // QR=1, RD=1, RA=1, RCODE=0
        m.questions.push(q.clone());
        m.answers.push(ResourceRecord {
            name: q.name.clone(),
            qtype: DnsQType::A,
            qclass: RClass::In,
            ttl: self.ttl_secs,
            data: RData::A(Ipv4Addr::new(192, 0, 2, 7)),
        });
        let bytes = encode::encode_message(&m).expect("encode reply");
        self.pending_reply = Some(Bytes::from(bytes));
        Ok(())
    }

    async fn recv_from(&mut self) -> Option<(Endpoint, Bytes)> {
        if let Some(reply) = self.pending_reply.take() {
            return Some((Endpoint::new("127.0.0.1", 53).expect("endpoint"), reply));
        }
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
            Box::new(TtlMockSendHalf {
                shared: shared.clone(),
            }),
            Box::new(TtlMockRecvHalf { shared }),
        )
    }
}

struct TtlMockSendHalf {
    shared: Arc<tokio::sync::Mutex<TtlMockSession>>,
}

#[async_trait]
impl BusDatagramSendHalf for TtlMockSendHalf {
    async fn send_to(&mut self, target: Endpoint, payload: Bytes) -> Result<(), SendError> {
        self.shared.lock().await.send_to(target, payload).await
    }

    async fn close(&mut self) {
        self.shared.lock().await.close().await;
    }
}

struct TtlMockRecvHalf {
    shared: Arc<tokio::sync::Mutex<TtlMockSession>>,
}

#[async_trait]
impl BusDatagramRecvHalf for TtlMockRecvHalf {
    async fn recv_from(&mut self) -> Option<(Endpoint, Bytes)> {
        self.shared.lock().await.recv_from().await
    }

    fn last_error(&self) -> Option<&DisconnectReason> {
        None
    }
}

#[tokio::test]
async fn cache_ttl_matches_min_rr_ttl_from_wire() {
    let cache = Arc::new(DnsCache::new());
    let server: SocketAddr = "127.0.0.1:5399".parse().expect("addr");
    let pool = Pool {
        id: "p".into(),
        mode: PoolMode::MeshDirect {
            server_policy: ServerPolicy::RoundRobin,
        },
        servers: vec![UpstreamServer {
            scheme: UpstreamScheme::Udp,
            addr: server,
        }],
        route_group: None,
    };

    let resolver = ResolverBuilder::new()
        .with_pool(pool)
        .with_default_pool("p")
        .with_cache(cache.clone())
        .with_datagram_opener(Arc::new(TtlMockOpener { ttl_secs: 120 }))
        .with_query_timeout(Duration::from_secs(1))
        .build()
        .expect("build");

    let req = ResolveRequest {
        qname: "ttl120.example.org.".into(),
        qtype: QType::A,
        consumer: ConsumerId("test".into()),
    };
    let (ans, _sig) = resolver.resolve(req).await.expect("resolve ok");
    assert_eq!(
        ans.records,
        vec![AnswerRecord::A(Ipv4Addr::new(192, 0, 2, 7))]
    );
    assert_eq!(ans.min_rr_ttl, 120);

    let key = CacheKey {
        qname: "ttl120.example.org.".into(),
        qtype: QType::A,
    };
    let hit = cache.lookup(&key).expect("populated by resolve()");
    let remaining = hit.remaining();
    assert!(remaining >= Duration::from_secs(110), "got {remaining:?}");
    assert!(remaining <= Duration::from_secs(121), "got {remaining:?}");
}
