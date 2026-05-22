//! Shared upstream SOCKS5 handshake helpers: auth negotiation and ATYP-aware
//! reply reading. Generic over the control stream so the stream egress and the
//! datagram (UDP ASSOCIATE) egress reuse the exact same handshake.

use bytes::BytesMut;
use mb_endpoint::Endpoint;
use mb_proto_socks5::{
    CodecError, Method, Reply, ReplyFrame, USER_PASS_STATUS_SUCCESS, decode_reply_frame,
    decode_user_pass_reply, encode_greeting, encode_user_pass_request, reply_frame_total_len,
};
use mesh_bus_core::DisconnectReason;
use std::future::Future;
use std::io;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Upstream SOCKS5 credentials for RFC1929 user/pass subnegotiation.
#[derive(Clone)]
pub struct Socks5UpstreamAuth {
    pub username: Vec<u8>,
    pub password: Vec<u8>,
}

impl std::fmt::Debug for Socks5UpstreamAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Socks5UpstreamAuth")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

pub(crate) async fn timed_io<T>(
    timeout: Duration,
    op: impl Future<Output = io::Result<T>>,
) -> Result<T, DisconnectReason> {
    tokio::time::timeout(timeout, op)
        .await
        .map_err(|_| DisconnectReason::TimedOut)?
        .map_err(disconnect_reason)
}

/// Negotiate the SOCKS5 auth method on an already-connected upstream control
/// stream. Offers UserPass+NoAuth when credentials are present and NoAuth only
/// otherwise, then runs RFC1929 user/pass subnegotiation if the upstream
/// selects method 0x02.
pub(crate) async fn negotiate_auth<S>(
    stream: &mut S,
    timeout: Duration,
    auth: Option<&Socks5UpstreamAuth>,
) -> Result<(), DisconnectReason>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let methods: &[Method] = match auth {
        Some(_) => &[Method::UserPass, Method::NoAuth],
        None => &[Method::NoAuth],
    };
    timed_io(timeout, stream.write_all(&encode_greeting(methods))).await?;
    let mut sel = [0u8; 2];
    timed_io(timeout, stream.read_exact(&mut sel)).await?;
    if sel[0] != 0x05 {
        return Err(DisconnectReason::Other(format!(
            "upstream socks5 version: {:#x}",
            sel[0]
        )));
    }
    match sel[1] {
        0x00 => Ok(()),
        0x02 => user_pass_subnegotiate(stream, timeout, auth).await,
        0xff => Err(DisconnectReason::Other(
            "upstream rejected all offered auth methods".into(),
        )),
        other => Err(DisconnectReason::Other(format!(
            "upstream selected unsupported auth method: {other:#x}"
        ))),
    }
}

async fn user_pass_subnegotiate<S>(
    stream: &mut S,
    timeout: Duration,
    auth: Option<&Socks5UpstreamAuth>,
) -> Result<(), DisconnectReason>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let creds = auth.ok_or_else(|| {
        DisconnectReason::Other("upstream demanded user/pass but none configured".into())
    })?;
    let req = encode_user_pass_request(&creds.username, &creds.password)
        .map_err(|e| DisconnectReason::Other(e.to_string()))?;
    timed_io(timeout, stream.write_all(&req)).await?;
    let mut reply = [0u8; 2];
    timed_io(timeout, stream.read_exact(&mut reply)).await?;
    let mut rbuf = BytesMut::from(&reply[..]);
    let status =
        decode_user_pass_reply(&mut rbuf).map_err(|e| DisconnectReason::Other(e.to_string()))?;
    if status == USER_PASS_STATUS_SUCCESS {
        Ok(())
    } else {
        Err(DisconnectReason::Other(format!(
            "upstream rejected credentials: {status:#x}"
        )))
    }
}

/// Read and decode one upstream SOCKS5 reply frame. The wire length is
/// ATYP-driven and a DOMAIN BND needs its length octet before the full size is
/// known, so the read is staged (fixed header, then length-resolved tail). The
/// L6 codec owns the length math via `reply_frame_total_len`; no inline ATYP
/// byte arithmetic lives here.
pub(crate) async fn read_reply_frame_atyp<S>(
    stream: &mut S,
    timeout: Duration,
) -> Result<ReplyFrame, DisconnectReason>
where
    S: AsyncRead + Unpin,
{
    let mut frame = vec![0u8; 4];
    timed_io(timeout, stream.read_exact(&mut frame)).await?;
    let total = match reply_frame_total_len(&frame) {
        Ok(total) => total,
        Err(CodecError::Incomplete) => {
            let mut len = [0u8; 1];
            timed_io(timeout, stream.read_exact(&mut len)).await?;
            frame.push(len[0]);
            reply_frame_total_len(&frame).map_err(|e| DisconnectReason::Other(e.to_string()))?
        }
        Err(e) => return Err(DisconnectReason::Other(e.to_string())),
    };
    let have = frame.len();
    frame.resize(total, 0);
    timed_io(timeout, stream.read_exact(&mut frame[have..])).await?;
    let mut buf = BytesMut::from(&frame[..]);
    decode_reply_frame(&mut buf).map_err(|e| DisconnectReason::Other(e.to_string()))
}

pub(crate) fn endpoint_from_socket_addr(addr: std::net::SocketAddr) -> Endpoint {
    Endpoint::new(addr.ip().to_string(), addr.port()).expect("socket address is a valid endpoint")
}

pub(crate) fn disconnect_from_reply(reply: Reply) -> DisconnectReason {
    match reply {
        Reply::NetworkUnreachable => DisconnectReason::NetworkUnreachable,
        Reply::HostUnreachable => DisconnectReason::HostUnreachable,
        Reply::ConnectionRefused => DisconnectReason::ConnectionRefused,
        Reply::TtlExpired => DisconnectReason::TtlExpired,
        _ => DisconnectReason::Other(format!("socks5 reply: {reply:?}")),
    }
}

pub(crate) fn disconnect_reason(err: std::io::Error) -> DisconnectReason {
    match err.kind() {
        std::io::ErrorKind::ConnectionRefused => DisconnectReason::ConnectionRefused,
        std::io::ErrorKind::TimedOut => DisconnectReason::TimedOut,
        std::io::ErrorKind::NotConnected => DisconnectReason::NotConnected,
        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe => {
            DisconnectReason::ConnectionReset
        }
        std::io::ErrorKind::UnexpectedEof => DisconnectReason::UpstreamEof,
        _ => DisconnectReason::Other(err.to_string()),
    }
}
