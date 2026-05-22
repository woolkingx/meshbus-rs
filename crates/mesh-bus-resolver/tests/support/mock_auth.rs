#![allow(dead_code)]

use bytes::BytesMut;
use mb_proto_dns::{Message, Name, QType, RData, ResourceRecord, decode, encode, framing};
use mesh_bus_resolver::AnswerRecord;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Mutex;

pub struct MockAuth {
    pub udp_addr: SocketAddr,
    pub tcp_addr: SocketAddr,
    pub hits: Arc<Mutex<Vec<HitTap>>>,
}

#[derive(Debug, Clone)]
pub struct HitTap {
    pub via: &'static str, // "udp" or "tcp"
    pub txid: u16,
    pub qname: String,
    pub qtype: u16,
    pub source_port: u16,
}

// Zone key uses u16 for qtype because QType does not derive Hash.
pub async fn spawn_mock_auth(zone: HashMap<(String, u16), Vec<AnswerRecord>>) -> MockAuth {
    let udp = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind udp socket");
    let udp_addr = udp.local_addr().expect("udp local_addr");
    let tcp = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind tcp listener");
    let tcp_addr = tcp.local_addr().expect("tcp local_addr");
    let hits: Arc<Mutex<Vec<HitTap>>> = Arc::new(Mutex::new(Vec::new()));
    let zone = Arc::new(zone);

    {
        let hits = hits.clone();
        let zone = zone.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let (n, peer) = match udp.recv_from(&mut buf).await {
                    Ok(x) => x,
                    Err(_) => continue,
                };
                let msg = match decode::decode_message(&buf[..n]) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                let reply = build_reply(&msg, &zone);
                if let Ok(bytes) = encode::encode_message(&reply) {
                    let _ = udp.send_to(&bytes, peer).await;
                    let mut h = hits.lock().await;
                    h.push(HitTap {
                        via: "udp",
                        txid: msg.header.id,
                        qname: msg
                            .questions
                            .first()
                            .map(|q| q.name.as_ascii_lower().to_string())
                            .unwrap_or_default(),
                        qtype: msg.questions.first().map(|q| q.qtype as u16).unwrap_or(0),
                        source_port: peer.port(),
                    });
                }
            }
        });
    }

    {
        let hits = hits.clone();
        let zone = zone.clone();
        tokio::spawn(async move {
            loop {
                let (mut sock, peer) = match tcp.accept().await {
                    Ok(x) => x,
                    Err(_) => continue,
                };
                let hits = hits.clone();
                let zone = zone.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = BytesMut::with_capacity(4096);
                    loop {
                        let mut chunk = [0u8; 4096];
                        let n = match sock.read(&mut chunk).await {
                            Ok(0) => return,
                            Ok(n) => n,
                            Err(_) => return,
                        };
                        buf.extend_from_slice(&chunk[..n]);
                        while let Some(frame) = framing::try_read_tcp_frame(&mut buf) {
                            if let Ok(msg) = decode::decode_message(&frame) {
                                let reply = build_reply(&msg, &zone);
                                if let Ok(bytes) = encode::encode_message(&reply) {
                                    let mut out = BytesMut::new();
                                    framing::write_tcp_frame(&mut out, &bytes);
                                    let _ = sock.write_all(&out).await;
                                    let mut h = hits.lock().await;
                                    h.push(HitTap {
                                        via: "tcp",
                                        txid: msg.header.id,
                                        qname: msg
                                            .questions
                                            .first()
                                            .map(|q| q.name.as_ascii_lower().to_string())
                                            .unwrap_or_default(),
                                        qtype: msg
                                            .questions
                                            .first()
                                            .map(|q| q.qtype as u16)
                                            .unwrap_or(0),
                                        source_port: peer.port(),
                                    });
                                }
                            }
                        }
                    }
                });
            }
        });
    }

    MockAuth {
        udp_addr,
        tcp_addr,
        hits,
    }
}

fn build_reply(req: &Message, zone: &HashMap<(String, u16), Vec<AnswerRecord>>) -> Message {
    let mut reply = Message::default();
    reply.header.id = req.header.id;
    reply.header.flags = 0x8180; // QR=1, RD=1, RA=1, NOERROR

    let mut answers = Vec::new();
    for q in &req.questions {
        reply.questions.push(q.clone());
        // Zone key uses u16 because QType does not derive Hash.
        let key = (q.name.as_ascii_lower().to_string(), q.qtype as u16);
        if let Some(records) = zone.get(&key) {
            for rec in records {
                answers.push(ResourceRecord {
                    name: q.name.clone(),
                    qtype: q.qtype,
                    qclass: q.qclass,
                    ttl: 60,
                    data: match rec {
                        AnswerRecord::A(v) => RData::A(*v),
                        AnswerRecord::Aaaa(v) => RData::Aaaa(*v),
                        AnswerRecord::Ptr(s) => {
                            RData::Ptr(Name::from_ascii(s).expect("valid PTR name"))
                        }
                        AnswerRecord::Cname(s) => {
                            RData::Cname(Name::from_ascii(s).expect("valid CNAME"))
                        }
                        AnswerRecord::Txt(parts) => RData::Txt(parts.clone()),
                    },
                });
            }
        }
    }

    if answers.is_empty() {
        reply.header.flags |= 0x0003; // RCODE NXDOMAIN
    }
    reply.answers = answers;
    // set_counts must be called before encode_message reads qd/an/ns/ar via getters.
    reply.header.set_counts(
        reply.questions.len() as u16,
        reply.answers.len() as u16,
        0,
        0,
    );
    reply
}

/// Returns a minimal zone with one A record for functional acceptance tests.
pub fn zone_acceptance() -> HashMap<(String, u16), Vec<AnswerRecord>> {
    let mut z = HashMap::new();
    z.insert(
        ("host.acceptance.".into(), QType::A as u16),
        vec![AnswerRecord::A(Ipv4Addr::new(192, 0, 2, 99))],
    );
    z
}
