//! Shared product-facing client helpers for e2e tests.
//!
//! Used by both `e2e.rs` (imperative residue) and `e2e_composition.rs`
//! (in-process composition fixtures). One copy — no reimplementation.

use bytes::BytesMut;
use mb_endpoint::Endpoint;
use mb_proto_socks5::{
    Reply, decode_reply_frame, decode_udp_datagram, encode_connect_request, encode_greeting,
    encode_udp_associate_request, encode_udp_datagram,
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

/// Bind a loopback TCP echo server and return its address.
pub async fn spawn_tcp_echo() -> std::net::SocketAddr {
    let echo = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind tcp echo");
    let addr = echo.local_addr().expect("tcp echo addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = echo.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

/// Bind a loopback UDP echo socket and return its address.
pub async fn spawn_udp_echo() -> std::net::SocketAddr {
    let echo = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp echo");
    let addr = echo.local_addr().expect("udp echo addr");
    tokio::spawn(async move {
        let mut buf = [0u8; 65535];
        loop {
            let Ok((n, peer)) = echo.recv_from(&mut buf).await else {
                break;
            };
            let _ = echo.send_to(&buf[..n], peer).await;
        }
    });
    addr
}

/// Allocate a free TCP address by briefly binding port 0.
pub fn free_tcp_addr() -> std::net::SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind free tcp");
    l.local_addr().expect("free tcp addr")
}

/// Allocate a free UDP address by briefly binding port 0.
pub fn free_udp_addr() -> std::net::SocketAddr {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind free udp");
    s.local_addr().expect("free udp addr")
}

/// Poll until the TCP listener at `addr` accepts a connection, up to 5 s.
pub async fn wait_for_tcp_listener(addr: std::net::SocketAddr) {
    for _ in 0..250 {
        if let Ok(s) = TcpStream::connect(addr).await {
            drop(s);
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("listener did not open at {addr}");
}

/// SOCKS5 CONNECT roundtrip: sends `payload` through the SOCKS5 ingress at
/// `listen` targeting `target`, asserts the echo comes back intact.
/// Also asserts BND.ADDR/BND.PORT are present in the CONNECT reply.
pub async fn socks5_tcp_roundtrip(listen: std::net::SocketAddr, target: Endpoint, payload: &[u8]) {
    let mut client = TcpStream::connect(listen).await.expect("connect socks");
    client
        .write_all(&encode_greeting(&[mb_proto_socks5::Method::NoAuth]))
        .await
        .expect("write greeting");
    let mut auth = [0u8; 2];
    client.read_exact(&mut auth).await.expect("read auth");
    assert_eq!(auth, [0x05, 0x00]);
    client
        .write_all(&encode_connect_request(&target))
        .await
        .expect("write connect");
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.expect("read reply");
    let mut reply_buf = BytesMut::from(&reply[..]);
    let reply = decode_reply_frame(&mut reply_buf).expect("decode reply");
    assert_eq!(reply.reply, Reply::Succeeded);
    assert!(
        reply.endpoint.is_some(),
        "CONNECT success should expose BND.ADDR/BND.PORT"
    );
    client.write_all(payload).await.expect("write payload");
    let mut out = vec![0u8; payload.len()];
    client.read_exact(&mut out).await.expect("read echo");
    assert_eq!(out, payload);
}

/// SOCKS5 UDP ASSOCIATE roundtrip: associates, sends one datagram via `encode_udp_datagram`,
/// asserts the echo comes back intact.
pub async fn socks5_udp_roundtrip(listen: std::net::SocketAddr, target: Endpoint, payload: &[u8]) {
    let udp = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind udp client");
    let udp_addr = udp.local_addr().expect("udp client addr");
    let declared = Endpoint::new(udp_addr.ip().to_string(), udp_addr.port()).expect("declared");
    let mut control = TcpStream::connect(listen).await.expect("connect socks");
    control
        .write_all(&encode_greeting(&[mb_proto_socks5::Method::NoAuth]))
        .await
        .expect("write greeting");
    let mut auth = [0u8; 2];
    control.read_exact(&mut auth).await.expect("read auth");
    assert_eq!(auth, [0x05, 0x00]);
    control
        .write_all(&encode_udp_associate_request(&declared))
        .await
        .expect("write udp associate");
    let mut reply = [0u8; 10];
    control.read_exact(&mut reply).await.expect("read reply");
    let mut reply_buf = BytesMut::from(&reply[..]);
    let reply = decode_reply_frame(&mut reply_buf).expect("decode reply");
    assert_eq!(reply.reply, Reply::Succeeded);
    let relay = reply.endpoint.expect("udp relay endpoint");
    let relay_addr = format!("{}:{}", relay.host(), relay.port());
    udp.send_to(&encode_udp_datagram(&target, payload), &relay_addr)
        .await
        .expect("send relay packet");
    let mut buf = [0u8; 2048];
    let (n, _) = tokio::time::timeout(Duration::from_secs(1), udp.recv_from(&mut buf))
        .await
        .expect("udp timeout")
        .expect("recv relay response");
    let mut response = BytesMut::from(&buf[..n]);
    let datagram = decode_udp_datagram(&mut response).expect("decode udp relay response");
    assert_eq!(datagram.target, target);
    assert_eq!(&datagram.payload[..], payload);
}

/// Raw TCP roundtrip (direct TCP ingress, not SOCKS5).
pub async fn direct_tcp_roundtrip(listen: std::net::SocketAddr, payload: &[u8]) {
    let mut client = TcpStream::connect(listen)
        .await
        .expect("connect direct tcp ingress");
    client.write_all(payload).await.expect("write payload");
    let mut out = vec![0u8; payload.len()];
    client.read_exact(&mut out).await.expect("read echo");
    assert_eq!(out, payload);
}

/// Raw UDP roundtrip (direct UDP ingress, not SOCKS5).
pub async fn direct_udp_roundtrip(listen: std::net::SocketAddr, payload: &[u8]) {
    let client = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind udp client");
    client.send_to(payload, listen).await.expect("send udp");
    let mut out = vec![0u8; payload.len().max(1)];
    let (n, _) = tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut out))
        .await
        .expect("direct udp timeout")
        .expect("recv udp");
    assert_eq!(&out[..n], payload);
}

/// HTTP GET helper: sends a minimal GET request, reads until EOF, returns raw response.
pub async fn http_get(addr: std::net::SocketAddr, path: &str) -> String {
    let mut client = TcpStream::connect(addr).await.expect("connect http");
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n");
    client
        .write_all(request.as_bytes())
        .await
        .expect("write http request");
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .await
        .expect("read http response");
    String::from_utf8(response).expect("utf8 http response")
}

/// Sum `mesh_bus_dispatch_total` for a given `exit_id` label from a Prometheus
/// text format metrics response body.
pub fn dispatch_total_for(response: &str, exit_id: &str) -> u64 {
    let needle = format!("exit_id=\"{exit_id}\"");
    response
        .lines()
        .filter(|l| l.starts_with("mesh_bus_dispatch_total{") && l.contains(&needle))
        .filter_map(|l| l.rsplit(' ').next())
        .filter_map(|v| v.trim().parse::<u64>().ok())
        .sum()
}
