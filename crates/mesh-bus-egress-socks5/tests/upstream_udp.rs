use bytes::{Bytes, BytesMut};
use mb_endpoint::Endpoint;
use mb_proto_socks5::{
    Command, Reply, decode_greeting, decode_request, decode_udp_datagram,
    encode_reply_with_endpoint, encode_udp_datagram,
};
use mesh_bus_core::{BusSessionInfo, BusSessionRequest, DatagramEgress, ExitId, ScheduleMode};
use mesh_bus_egress_socks5::Socks5UdpEgress;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::timeout;

async fn fake_udp_relay_loop(relay: UdpSocket, reply_source: Option<Endpoint>) {
    let mut dbuf = vec![0u8; 65_535];
    loop {
        let (n, peer) = match relay.recv_from(&mut dbuf).await {
            Ok(v) => v,
            Err(_) => break,
        };
        let mut frame = BytesMut::from(&dbuf[..n]);
        let dg = decode_udp_datagram(&mut frame).expect("decode udp datagram");
        if let Some(src) = &reply_source {
            let wrapped = encode_udp_datagram(src, &dg.payload);
            let _ = relay.send_to(&wrapped, peer).await;
        }
    }
}

/// Fake upstream SOCKS5 UDP ASSOCIATE server. Returns the control TCP port and
/// a receiver that fires once the control connection observes EOF (association
/// terminated). `reply_source` Some echoes the payload back wrapped with that
/// source endpoint; None drains datagrams without replying.
async fn spawn_fake_socks5_udp(
    reply_source: Option<Endpoint>,
) -> (u16, tokio::sync::oneshot::Receiver<()>) {
    let relay = UdpSocket::bind("127.0.0.1:0").await.expect("bind relay");
    let relay_addr = relay.local_addr().expect("relay addr");
    let relay_ep = Endpoint::new(relay_addr.ip().to_string(), relay_addr.port()).expect("relay ep");
    let l = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind control");
    let port = l.local_addr().expect("local addr").port();
    let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.expect("accept control");
        let mut buf = BytesMut::with_capacity(512);
        let mut chunk = [0u8; 512];
        let n = s.read(&mut chunk).await.expect("read greeting");
        buf.extend_from_slice(&chunk[..n]);
        let _ = decode_greeting(&mut buf).expect("decode greeting");
        s.write_all(&[0x05, 0x00]).await.expect("write auth");
        buf.clear();
        let n = s.read(&mut chunk).await.expect("read associate");
        buf.extend_from_slice(&chunk[..n]);
        let req = decode_request(&mut buf).expect("decode request");
        assert_eq!(req.command, Command::UdpAssociate);
        s.write_all(&encode_reply_with_endpoint(Reply::Succeeded, &relay_ep))
            .await
            .expect("write reply");
        tokio::spawn(fake_udp_relay_loop(relay, reply_source));
        let mut tail = [0u8; 64];
        loop {
            match s.read(&mut tail).await {
                Ok(0) | Err(_) => break,
                Ok(_) => continue,
            }
        }
        let _ = closed_tx.send(());
    });
    (port, closed_rx)
}

async fn open_udp_session(
    exit: &Socks5UdpEgress,
    target: &Endpoint,
) -> Box<dyn mesh_bus_core::DatagramSession> {
    let request = BusSessionRequest::datagram(target.clone());
    exit.open_datagram(
        &request,
        BusSessionInfo::empty_for_test(ScheduleMode::Ordered),
    )
    .await
    .expect("open datagram")
}

fn make_udp_egress(port: u16) -> Socks5UdpEgress {
    Socks5UdpEgress::new(
        ExitId("up".into()),
        format!("127.0.0.1:{port}"),
        Duration::from_millis(500),
    )
}

#[tokio::test]
async fn socks5_udp_egress_associate_sends_and_receives_datagram() {
    let reply_source = Endpoint::new("203.0.113.7", 9999).expect("reply source");
    let (port, _closed) = spawn_fake_socks5_udp(Some(reply_source.clone())).await;
    let exit = make_udp_egress(port);
    let target = Endpoint::new("example.com", 53).expect("target");
    let mut session = open_udp_session(&exit, &target).await;
    session
        .send_to(target.clone(), Bytes::from_static(b"ping"))
        .await
        .expect("send_to");
    let (src, payload) = timeout(Duration::from_millis(500), session.recv_from())
        .await
        .expect("recv timeout")
        .expect("datagram");
    assert_eq!(src, reply_source);
    assert_eq!(&payload[..], b"ping");
}

#[tokio::test]
async fn socks5_udp_egress_send_to_does_not_wait_for_response() {
    let (port, _closed) = spawn_fake_socks5_udp(None).await;
    let exit = make_udp_egress(port);
    let target = Endpoint::new("example.com", 53).expect("target");
    let mut session = open_udp_session(&exit, &target).await;
    timeout(
        Duration::from_millis(100),
        session.send_to(target.clone(), Bytes::from_static(b"ping")),
    )
    .await
    .expect("send_to must return without waiting for a response")
    .expect("send_to ok");
}

#[tokio::test]
async fn socks5_udp_egress_recv_returns_udp_reply_source() {
    let reply_source = Endpoint::new("198.51.100.42", 4000).expect("reply source");
    let (port, _closed) = spawn_fake_socks5_udp(Some(reply_source.clone())).await;
    let exit = make_udp_egress(port);
    let target = Endpoint::new("example.com", 53).expect("target");
    let mut session = open_udp_session(&exit, &target).await;
    session
        .send_to(target.clone(), Bytes::from_static(b"q"))
        .await
        .expect("send");
    let (src, _payload) = timeout(Duration::from_millis(500), session.recv_from())
        .await
        .expect("recv timeout")
        .expect("datagram");
    assert_eq!(src, reply_source);
    assert_ne!(src, target);
}

#[tokio::test]
async fn socks5_udp_egress_close_drops_control_association() {
    let reply_source = Endpoint::new("203.0.113.7", 9999).expect("reply source");
    let (port, closed) = spawn_fake_socks5_udp(Some(reply_source)).await;
    let exit = make_udp_egress(port);
    let target = Endpoint::new("example.com", 53).expect("target");
    let mut session = open_udp_session(&exit, &target).await;
    session.close().await;
    timeout(Duration::from_millis(500), closed)
        .await
        .expect("control association must terminate after close()")
        .expect("closed signal");
}
