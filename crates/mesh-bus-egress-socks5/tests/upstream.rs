use bytes::{Bytes, BytesMut};
use mb_endpoint::Endpoint;
use mb_proto_socks5::{
    Method, Reply, decode_connect_request, decode_greeting, decode_user_pass_request, encode_reply,
    encode_reply_with_endpoint, encode_user_pass_reply,
};
use mesh_bus_core::{
    BusSessionInfo, BusSessionRequest, DisconnectReason, ExitId, ScheduleMode, StreamEgress,
};
use mesh_bus_egress_socks5::{Socks5Egress, Socks5UpstreamAuth};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;

fn make_egress(port: u16) -> (Socks5Egress, BusSessionRequest) {
    let exit = Socks5Egress::new(
        ExitId("up".into()),
        format!("127.0.0.1:{port}"),
        Duration::from_millis(500),
    );
    let request = BusSessionRequest::stream(Endpoint::new("example.com", 443).expect("target"));
    (exit, request)
}

#[test]
fn upstream_auth_debug_redacts_password() {
    let auth = Socks5UpstreamAuth {
        username: b"alice".to_vec(),
        password: b"s3cret".to_vec(),
    };
    let debug = format!("{auth:?}");
    assert!(
        debug.contains("username"),
        "missing username field: {debug}"
    );
    assert!(
        debug.contains("redacted"),
        "missing redaction marker: {debug}"
    );
    assert!(
        !debug.contains("s3cret"),
        "password leaked through Debug: {debug}"
    );
}

async fn open_session(
    exit: &Socks5Egress,
    request: &BusSessionRequest,
) -> Result<(), DisconnectReason> {
    let mut session = exit
        .open_stream(
            request,
            BusSessionInfo::empty_for_test(ScheduleMode::Ordered),
        )
        .await
        .expect("open stream");
    session.connect().await.map(|_| ())
}

async fn spawn_fake_socks5() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake socks5");
    let port = l.local_addr().expect("local addr").port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.expect("accept");
            tokio::spawn(async move {
                let mut buf = BytesMut::with_capacity(512);
                let mut chunk = [0u8; 512];
                let n = s.read(&mut chunk).await.expect("read greeting");
                buf.extend_from_slice(&chunk[..n]);
                let _ = decode_greeting(&mut buf).expect("decode greeting");
                s.write_all(&[0x05, 0x00]).await.expect("write auth");
                buf.clear();
                let n = s.read(&mut chunk).await.expect("read connect");
                buf.extend_from_slice(&chunk[..n]);
                let _ = decode_connect_request(&mut buf).expect("decode connect");
                s.write_all(&encode_reply(Reply::Succeeded))
                    .await
                    .expect("write reply");
                let mut data = vec![0u8; 1024];
                loop {
                    let n = s.read(&mut data).await.expect("read data");
                    if n == 0 {
                        break;
                    }
                    s.write_all(&data[..n]).await.expect("write echo");
                }
            });
        }
    });
    port
}

async fn connected_session(
    exit: &Socks5Egress,
    target: Endpoint,
) -> (
    Box<dyn mesh_bus_core::StreamSendHalf>,
    Box<dyn mesh_bus_core::StreamRecvHalf>,
) {
    let request = BusSessionRequest::stream(target);
    let mut session = exit
        .open_stream(
            &request,
            BusSessionInfo::empty_for_test(ScheduleMode::Ordered),
        )
        .await
        .expect("open stream");
    let info = session.connect().await.expect("connect");
    assert_eq!(info.paths[info.primary].exit_id, ExitId("up".into()));
    session.split()
}

#[tokio::test]
async fn upstream_handshake_read_is_bounded_by_timeout() {
    let l = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stalling upstream");
    let upstream_port = l.local_addr().expect("local addr").port();
    tokio::spawn(async move {
        let (_s, _) = l.accept().await.expect("accept stalling upstream");
        tokio::time::sleep(Duration::from_secs(1)).await;
    });

    let exit = Socks5Egress::new(
        ExitId("up".into()),
        format!("127.0.0.1:{upstream_port}"),
        Duration::from_millis(25),
    );
    let request = BusSessionRequest::stream(Endpoint::new("example.com", 443).expect("target"));
    let mut session = exit
        .open_stream(
            &request,
            BusSessionInfo::empty_for_test(ScheduleMode::Ordered),
        )
        .await
        .expect("open stream");

    let result = timeout(Duration::from_millis(250), session.connect())
        .await
        .expect("session.connect must return on the configured timeout");
    assert_eq!(result.unwrap_err(), DisconnectReason::TimedOut);
}

#[tokio::test]
async fn dispatches_through_upstream() {
    let upstream_port = spawn_fake_socks5().await;
    let exit = Socks5Egress::new(
        ExitId("up".into()),
        format!("127.0.0.1:{upstream_port}"),
        Duration::from_millis(500),
    );
    let target = Endpoint::new("example.com", 443).expect("endpoint");
    let (mut send, mut recv) = connected_session(&exit, target).await;
    send.send(Bytes::from_static(b"hello")).await.expect("send");
    let payload = timeout(Duration::from_millis(500), recv.recv())
        .await
        .expect("poll timeout")
        .expect("payload");
    assert_eq!(&payload[..], b"hello");
}

#[tokio::test]
async fn socks5_egress_stream_conformance_open_path_echo_and_close() {
    let upstream_port = spawn_fake_socks5().await;
    let exit = Socks5Egress::new(
        ExitId("up".into()),
        format!("127.0.0.1:{upstream_port}"),
        Duration::from_millis(500),
    );
    let caps = exit.capabilities();
    assert!(caps.supports_stream);
    assert!(!caps.supports_datagram);

    let target = Endpoint::new("example.com", 443).expect("endpoint");
    let (mut send, mut recv) = connected_session(&exit, target).await;
    send.send(Bytes::from_static(b"hello")).await.expect("send");
    let payload = timeout(Duration::from_millis(500), recv.recv())
        .await
        .expect("poll timeout")
        .expect("payload");
    assert_eq!(&payload[..], b"hello");
    send.abort(mesh_bus_core::DisconnectReason::SessionClosed)
        .await;
}

#[tokio::test]
async fn poll_streams_large_response_after_single_send() {
    let l = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake socks5");
    let upstream_port = l.local_addr().expect("local addr").port();
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.expect("accept");
        let mut buf = BytesMut::with_capacity(512);
        let mut chunk = [0u8; 512];
        let n = s.read(&mut chunk).await.expect("read greeting");
        buf.extend_from_slice(&chunk[..n]);
        let _ = decode_greeting(&mut buf).expect("decode greeting");
        s.write_all(&[0x05, 0x00]).await.expect("write auth");
        buf.clear();
        let n = s.read(&mut chunk).await.expect("read connect");
        buf.extend_from_slice(&chunk[..n]);
        let _ = decode_connect_request(&mut buf).expect("decode connect");
        s.write_all(&encode_reply(Reply::Succeeded))
            .await
            .expect("write reply");
        let mut request = [0u8; 4];
        s.read_exact(&mut request).await.expect("read request");
        s.write_all(&vec![b'a'; 16 * 1024])
            .await
            .expect("write first chunk");
        s.write_all(&vec![b'b'; 16 * 1024])
            .await
            .expect("write second chunk");
    });

    let exit = Socks5Egress::new(
        ExitId("up".into()),
        format!("127.0.0.1:{upstream_port}"),
        Duration::from_millis(500),
    );
    let target = Endpoint::new("example.com", 443).expect("endpoint");
    let (mut send, mut recv) = connected_session(&exit, target).await;
    send.send(Bytes::from_static(b"GET ")).await.expect("send");

    let mut payload = Vec::new();
    while payload.len() < 32 * 1024 {
        let chunk = timeout(Duration::from_millis(500), recv.recv())
            .await
            .expect("poll timeout")
            .expect("payload");
        payload.extend_from_slice(&chunk);
    }
    assert_eq!(payload.len(), 32 * 1024);
    assert!(payload[..16 * 1024].iter().all(|b| *b == b'a'));
    assert!(payload[16 * 1024..].iter().all(|b| *b == b'b'));
}

// C5: upstream replies with non-Succeeded reply code
async fn spawn_fake_socks5_with_reply(reply_code: u8) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake socks5");
    let port = l.local_addr().expect("local addr").port();
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.expect("accept");
        let mut buf = BytesMut::with_capacity(512);
        let mut chunk = [0u8; 512];
        let n = s.read(&mut chunk).await.expect("read greeting");
        buf.extend_from_slice(&chunk[..n]);
        let _ = decode_greeting(&mut buf).expect("decode greeting");
        s.write_all(&[0x05, 0x00]).await.expect("write auth");
        buf.clear();
        let n = s.read(&mut chunk).await.expect("read connect");
        buf.extend_from_slice(&chunk[..n]);
        let _ = decode_connect_request(&mut buf).expect("decode connect");
        // Reply with the specified failure code: [VER REP RSV ATYP addr(4) port(2)]
        let reply_frame = [0x05, reply_code, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        s.write_all(&reply_frame).await.expect("write reply");
    });
    port
}

#[tokio::test]
async fn upstream_connection_refused_reply_returns_disconnect_reason() {
    let port = spawn_fake_socks5_with_reply(0x05).await;
    let (exit, request) = make_egress(port);
    let result = timeout(Duration::from_millis(500), open_session(&exit, &request))
        .await
        .expect("must not hang");
    assert_eq!(result.unwrap_err(), DisconnectReason::ConnectionRefused);
}

#[tokio::test]
async fn upstream_host_unreachable_reply_returns_disconnect_reason() {
    let port = spawn_fake_socks5_with_reply(0x04).await;
    let (exit, request) = make_egress(port);
    let result = timeout(Duration::from_millis(500), open_session(&exit, &request))
        .await
        .expect("must not hang");
    assert_eq!(result.unwrap_err(), DisconnectReason::HostUnreachable);
}

// C6: upstream drops connection after greeting response
#[tokio::test]
async fn upstream_drops_connection_after_greeting_returns_error() {
    let l = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake socks5");
    let port = l.local_addr().expect("local addr").port();
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.expect("accept");
        let mut buf = BytesMut::with_capacity(512);
        let mut chunk = [0u8; 512];
        let n = s.read(&mut chunk).await.expect("read greeting");
        buf.extend_from_slice(&chunk[..n]);
        let _ = decode_greeting(&mut buf).expect("decode greeting");
        s.write_all(&[0x05, 0x00]).await.expect("write auth");
        drop(s); // EOF after greeting
    });
    let (exit, request) = make_egress(port);
    let result = timeout(Duration::from_millis(500), open_session(&exit, &request))
        .await
        .expect("must not hang");
    assert!(result.is_err(), "expected error after upstream EOF, got Ok");
}

// Extra: upstream accept then immediate drop (no bytes sent)
#[tokio::test]
async fn upstream_drops_immediately_after_accept_returns_error() {
    let l = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake socks5");
    let port = l.local_addr().expect("local addr").port();
    tokio::spawn(async move {
        let (_s, _) = l.accept().await.expect("accept");
        // drop immediately — sends TCP FIN with no bytes
    });
    let (exit, request) = make_egress(port);
    let result = timeout(Duration::from_millis(500), open_session(&exit, &request))
        .await
        .expect("must not hang");
    assert!(
        result.is_err(),
        "expected error after upstream silent drop, got Ok"
    );
}

// C7: upstream demands RFC1929 user/pass subnegotiation
async fn spawn_fake_socks5_userpass(status: u8) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake socks5");
    let port = l.local_addr().expect("local addr").port();
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.expect("accept");
        let mut buf = BytesMut::with_capacity(512);
        let mut chunk = [0u8; 512];
        let n = s.read(&mut chunk).await.expect("read greeting");
        buf.extend_from_slice(&chunk[..n]);
        let greeting = decode_greeting(&mut buf).expect("decode greeting");
        assert!(
            greeting.methods.contains(&Method::UserPass),
            "client must offer UserPass when auth is configured"
        );
        s.write_all(&[0x05, 0x02]).await.expect("select user/pass");
        buf.clear();
        let n = s.read(&mut chunk).await.expect("read user/pass");
        buf.extend_from_slice(&chunk[..n]);
        let creds = decode_user_pass_request(&mut buf).expect("decode user/pass");
        assert_eq!(creds.username, b"alice");
        assert_eq!(creds.password, b"s3cret");
        s.write_all(&encode_user_pass_reply(status))
            .await
            .expect("write user/pass reply");
        if status != 0x00 {
            return;
        }
        buf.clear();
        let n = s.read(&mut chunk).await.expect("read connect");
        buf.extend_from_slice(&chunk[..n]);
        let _ = decode_connect_request(&mut buf).expect("decode connect");
        s.write_all(&encode_reply(Reply::Succeeded))
            .await
            .expect("write reply");
        let mut data = vec![0u8; 1024];
        loop {
            let n = s.read(&mut data).await.expect("read data");
            if n == 0 {
                break;
            }
            s.write_all(&data[..n]).await.expect("write echo");
        }
    });
    port
}

#[tokio::test]
async fn upstream_user_pass_auth_success() {
    let port = spawn_fake_socks5_userpass(0x00).await;
    let exit = Socks5Egress::new(
        ExitId("up".into()),
        format!("127.0.0.1:{port}"),
        Duration::from_millis(500),
    )
    .with_auth(Socks5UpstreamAuth {
        username: b"alice".to_vec(),
        password: b"s3cret".to_vec(),
    });
    let target = Endpoint::new("example.com", 443).expect("endpoint");
    let (mut send, mut recv) = connected_session(&exit, target).await;
    send.send(Bytes::from_static(b"hello")).await.expect("send");
    let payload = timeout(Duration::from_millis(500), recv.recv())
        .await
        .expect("poll timeout")
        .expect("payload");
    assert_eq!(&payload[..], b"hello");
}

#[tokio::test]
async fn upstream_user_pass_auth_rejects_bad_credentials() {
    let port = spawn_fake_socks5_userpass(0xff).await;
    let exit = Socks5Egress::new(
        ExitId("up".into()),
        format!("127.0.0.1:{port}"),
        Duration::from_millis(500),
    )
    .with_auth(Socks5UpstreamAuth {
        username: b"alice".to_vec(),
        password: b"s3cret".to_vec(),
    });
    let request = BusSessionRequest::stream(Endpoint::new("example.com", 443).expect("target"));
    let result = timeout(Duration::from_millis(500), open_session(&exit, &request))
        .await
        .expect("must not hang");
    assert!(result.is_err(), "expected auth rejection error, got Ok");
}

// C8: upstream BND reply carries a DOMAIN / IPv6 endpoint, not the IPv4 minimum
async fn spawn_fake_socks5_bnd(bnd: Endpoint) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake socks5");
    let port = l.local_addr().expect("local addr").port();
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.expect("accept");
        let mut buf = BytesMut::with_capacity(512);
        let mut chunk = [0u8; 512];
        let n = s.read(&mut chunk).await.expect("read greeting");
        buf.extend_from_slice(&chunk[..n]);
        let _ = decode_greeting(&mut buf).expect("decode greeting");
        s.write_all(&[0x05, 0x00]).await.expect("write auth");
        buf.clear();
        let n = s.read(&mut chunk).await.expect("read connect");
        buf.extend_from_slice(&chunk[..n]);
        let _ = decode_connect_request(&mut buf).expect("decode connect");
        s.write_all(&encode_reply_with_endpoint(Reply::Succeeded, &bnd))
            .await
            .expect("write reply");
        let mut data = vec![0u8; 1024];
        loop {
            let n = s.read(&mut data).await.expect("read data");
            if n == 0 {
                break;
            }
            s.write_all(&data[..n]).await.expect("write echo");
        }
    });
    port
}

#[tokio::test]
async fn upstream_connect_reads_domain_bnd_reply() {
    let bnd = Endpoint::new("relay.example.net", 1080).expect("bnd");
    let port = spawn_fake_socks5_bnd(bnd.clone()).await;
    let exit = Socks5Egress::new(
        ExitId("up".into()),
        format!("127.0.0.1:{port}"),
        Duration::from_millis(500),
    );
    let request = BusSessionRequest::stream(Endpoint::new("example.com", 443).expect("target"));
    let mut session = exit
        .open_stream(
            &request,
            BusSessionInfo::empty_for_test(ScheduleMode::Ordered),
        )
        .await
        .expect("open stream");
    let info = session.connect().await.expect("connect");
    assert_eq!(info.paths[info.primary].local, bnd);
}

#[tokio::test]
async fn upstream_connect_reads_ipv6_bnd_reply() {
    let bnd = Endpoint::new("2001:db8::1", 1080).expect("bnd");
    let port = spawn_fake_socks5_bnd(bnd.clone()).await;
    let exit = Socks5Egress::new(
        ExitId("up".into()),
        format!("127.0.0.1:{port}"),
        Duration::from_millis(500),
    );
    let request = BusSessionRequest::stream(Endpoint::new("example.com", 443).expect("target"));
    let mut session = exit
        .open_stream(
            &request,
            BusSessionInfo::empty_for_test(ScheduleMode::Ordered),
        )
        .await
        .expect("open stream");
    let info = session.connect().await.expect("connect");
    assert_eq!(info.paths[info.primary].local, bnd);
}
