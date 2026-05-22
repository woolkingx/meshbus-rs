//! Pure SOCKS5 wire codec. No I/O.

use bytes::{Buf, Bytes, BytesMut};
use mb_endpoint::Endpoint;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    NoAuth,
    GssApi,
    UserPass,
    Unknown(u8),
}

impl Method {
    fn wire_code(self) -> u8 {
        match self {
            Method::NoAuth => 0x00,
            Method::GssApi => 0x01,
            Method::UserPass => 0x02,
            Method::Unknown(code) => code,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    Succeeded = 0x00,
    GeneralFailure = 0x01,
    ConnectionNotAllowed = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    TtlExpired = 0x06,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}

fn reply_from_wire(code: u8) -> Reply {
    match code {
        0x00 => Reply::Succeeded,
        0x02 => Reply::ConnectionNotAllowed,
        0x03 => Reply::NetworkUnreachable,
        0x04 => Reply::HostUnreachable,
        0x05 => Reply::ConnectionRefused,
        0x06 => Reply::TtlExpired,
        0x07 => Reply::CommandNotSupported,
        0x08 => Reply::AddressTypeNotSupported,
        _ => Reply::GeneralFailure,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociate = 0x03,
}

#[derive(Debug)]
pub struct Greeting {
    pub methods: Vec<Method>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub command: Command,
    pub endpoint: Endpoint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyFrame {
    pub reply: Reply,
    pub endpoint: Option<Endpoint>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpDatagram {
    pub target: Endpoint,
    pub payload: Bytes,
}

pub const USER_PASS_VERSION: u8 = 0x01;
pub const USER_PASS_STATUS_SUCCESS: u8 = 0x00;
pub const USER_PASS_STATUS_FAILURE: u8 = 0xff;

#[derive(Clone, PartialEq, Eq)]
pub struct UserPassRequest {
    pub username: Vec<u8>,
    pub password: Vec<u8>,
}

impl std::fmt::Debug for UserPassRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserPassRequest")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, PartialEq, Eq, Error)]
pub enum CodecError {
    #[error("incomplete frame")]
    Incomplete,
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u8),
    #[error("invalid address type: {0}")]
    InvalidAtyp(u8),
    #[error("unsupported command: {0}")]
    UnsupportedCommand(u8),
    #[error("unsupported udp fragment: {0}")]
    UnsupportedFragment(u8),
    #[error("reserved byte must be zero: {0}")]
    ReservedNotZero(u8),
    #[error("invalid host bytes")]
    InvalidHost,
    #[error("endpoint rejected: {0}")]
    Endpoint(String),
    #[error("unsupported user/pass subnegotiation version: {0}")]
    UnsupportedAuthVersion(u8),
    #[error("invalid user/pass length (ulen and plen must be 1..=255)")]
    InvalidAuthLen,
}

pub fn encode_greeting(methods: &[Method]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + methods.len());
    out.push(0x05);
    out.push(methods.len() as u8);
    for m in methods {
        out.push(m.wire_code());
    }
    out
}

pub fn decode_greeting(buf: &mut BytesMut) -> Result<Greeting, CodecError> {
    if buf.len() < 2 {
        return Err(CodecError::Incomplete);
    }
    if buf[0] != 0x05 {
        return Err(CodecError::UnsupportedVersion(buf[0]));
    }
    let n = buf[1] as usize;
    if buf.len() < 2 + n {
        return Err(CodecError::Incomplete);
    }
    let methods: Vec<Method> = buf[2..2 + n]
        .iter()
        .map(|b| match b {
            0 => Method::NoAuth,
            1 => Method::GssApi,
            2 => Method::UserPass,
            other => Method::Unknown(*other),
        })
        .collect();
    buf.advance(2 + n);
    Ok(Greeting { methods })
}

pub fn encode_connect_request(target: &Endpoint) -> Vec<u8> {
    encode_request(Command::Connect, target)
}

pub fn encode_udp_associate_request(bind: &Endpoint) -> Vec<u8> {
    encode_request(Command::UdpAssociate, bind)
}

pub fn encode_request(command: Command, target: &Endpoint) -> Vec<u8> {
    let mut out = vec![0x05, command as u8, 0x00];
    encode_endpoint(target, &mut out);
    out
}

fn encode_endpoint(target: &Endpoint, out: &mut Vec<u8>) {
    if let Ok(ip4) = target.host().parse::<std::net::Ipv4Addr>() {
        out.push(0x01);
        out.extend_from_slice(&ip4.octets());
    } else if let Ok(ip6) = target.host().parse::<std::net::Ipv6Addr>() {
        out.push(0x04);
        out.extend_from_slice(&ip6.octets());
    } else {
        out.push(0x03);
        out.push(target.host().len() as u8);
        out.extend_from_slice(target.host().as_bytes());
    }
    out.extend_from_slice(&target.port().to_be_bytes());
}

pub fn decode_connect_request(buf: &mut BytesMut) -> Result<Endpoint, CodecError> {
    let request = decode_request(buf)?;
    if request.command != Command::Connect {
        return Err(CodecError::UnsupportedCommand(request.command as u8));
    }
    Ok(request.endpoint)
}

pub fn decode_request(buf: &mut BytesMut) -> Result<Request, CodecError> {
    if buf.len() < 7 {
        return Err(CodecError::Incomplete);
    }
    if buf[0] != 0x05 {
        return Err(CodecError::UnsupportedVersion(buf[0]));
    }
    let command = match buf[1] {
        0x01 => Command::Connect,
        0x02 => Command::Bind,
        0x03 => Command::UdpAssociate,
        other => return Err(CodecError::UnsupportedCommand(other)),
    };
    if buf[2] != 0 {
        return Err(CodecError::ReservedNotZero(buf[2]));
    }
    let (ep, total) = decode_endpoint_at(buf, 3)?;
    buf.advance(total);
    Ok(Request {
        command,
        endpoint: ep,
    })
}

fn decode_endpoint_at(buf: &BytesMut, offset: usize) -> Result<(Endpoint, usize), CodecError> {
    if buf.len() <= offset {
        return Err(CodecError::Incomplete);
    }
    let atyp = buf[offset];
    let (host, host_end) = match atyp {
        0x01 => {
            if buf.len() < offset + 1 + 4 + 2 {
                return Err(CodecError::Incomplete);
            }
            let start = offset + 1;
            let ip =
                std::net::Ipv4Addr::new(buf[start], buf[start + 1], buf[start + 2], buf[start + 3]);
            (ip.to_string(), start + 4)
        }
        0x03 => {
            if buf.len() < offset + 2 {
                return Err(CodecError::Incomplete);
            }
            let len = buf[offset + 1] as usize;
            if buf.len() < offset + 2 + len + 2 {
                return Err(CodecError::Incomplete);
            }
            let start = offset + 2;
            let host = std::str::from_utf8(&buf[start..start + len])
                .map_err(|_| CodecError::InvalidHost)?
                .to_string();
            (host, start + len)
        }
        0x04 => {
            if buf.len() < offset + 1 + 16 + 2 {
                return Err(CodecError::Incomplete);
            }
            let mut octets = [0u8; 16];
            let start = offset + 1;
            octets.copy_from_slice(&buf[start..start + 16]);
            (std::net::Ipv6Addr::from(octets).to_string(), start + 16)
        }
        _ => return Err(CodecError::InvalidAtyp(atyp)),
    };
    let port = u16::from_be_bytes([buf[host_end], buf[host_end + 1]]);
    let total = host_end + 2;
    let ep = Endpoint::new(host, port).map_err(|e| CodecError::Endpoint(e.to_string()))?;
    Ok((ep, total))
}

pub fn encode_reply(reply: Reply) -> Vec<u8> {
    vec![0x05, reply as u8, 0x00, 0x01, 127, 0, 0, 1, 0, 0]
}

pub fn encode_reply_with_endpoint(reply: Reply, bind: &Endpoint) -> Vec<u8> {
    let mut out = vec![0x05, reply as u8, 0x00];
    encode_endpoint(bind, &mut out);
    out
}

pub fn decode_reply(buf: &mut BytesMut) -> Result<Reply, CodecError> {
    if buf.len() < 10 {
        return Err(CodecError::Incomplete);
    }
    if buf[0] != 0x05 {
        return Err(CodecError::UnsupportedVersion(buf[0]));
    }
    if buf[2] != 0 {
        return Err(CodecError::ReservedNotZero(buf[2]));
    }
    let reply = reply_from_wire(buf[1]);
    let total = endpoint_total_at(buf, 3)?;
    buf.advance(total);
    Ok(reply)
}

pub fn decode_reply_frame(buf: &mut BytesMut) -> Result<ReplyFrame, CodecError> {
    if buf.len() < 10 {
        return Err(CodecError::Incomplete);
    }
    if buf[0] != 0x05 {
        return Err(CodecError::UnsupportedVersion(buf[0]));
    }
    if buf[2] != 0 {
        return Err(CodecError::ReservedNotZero(buf[2]));
    }
    let reply = reply_from_wire(buf[1]);
    let total = endpoint_total_at(buf, 3)?;
    let endpoint = decode_endpoint_at(buf, 3)
        .ok()
        .map(|(endpoint, _)| endpoint);
    buf.advance(total);
    Ok(ReplyFrame { reply, endpoint })
}

fn endpoint_total_at(buf: &BytesMut, offset: usize) -> Result<usize, CodecError> {
    if buf.len() <= offset {
        return Err(CodecError::Incomplete);
    }
    let total = match buf[offset] {
        0x01 => offset + 1 + 4 + 2,
        0x03 => {
            if buf.len() < offset + 2 {
                return Err(CodecError::Incomplete);
            }
            offset + 2 + buf[offset + 1] as usize + 2
        }
        0x04 => offset + 1 + 16 + 2,
        other => return Err(CodecError::InvalidAtyp(other)),
    };
    if buf.len() < total {
        return Err(CodecError::Incomplete);
    }
    Ok(total)
}

/// Total wire length of a reply frame (VER REP RSV ATYP BND.ADDR BND.PORT)
/// from a prefix of its bytes. `CodecError::Incomplete` means more bytes are
/// needed to decide the length: at least 4 for the fixed header, and one more
/// for the DOMAIN length octet. Single source of reply-frame length so L7
/// streaming reads never re-derive ATYP sizes inline.
pub fn reply_frame_total_len(buf: &[u8]) -> Result<usize, CodecError> {
    if buf.len() < 4 {
        return Err(CodecError::Incomplete);
    }
    match buf[3] {
        0x01 => Ok(4 + 4 + 2),
        0x04 => Ok(4 + 16 + 2),
        0x03 => {
            if buf.len() < 5 {
                return Err(CodecError::Incomplete);
            }
            Ok(4 + 1 + buf[4] as usize + 2)
        }
        other => Err(CodecError::InvalidAtyp(other)),
    }
}

pub fn encode_udp_datagram(target: &Endpoint, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x00, 0x00, 0x00];
    encode_endpoint(target, &mut out);
    out.extend_from_slice(payload);
    out
}

pub fn encode_user_pass_request(username: &[u8], password: &[u8]) -> Result<Vec<u8>, CodecError> {
    if username.is_empty() || username.len() > 255 {
        return Err(CodecError::InvalidAuthLen);
    }
    if password.is_empty() || password.len() > 255 {
        return Err(CodecError::InvalidAuthLen);
    }
    let mut out = Vec::with_capacity(3 + username.len() + password.len());
    out.push(USER_PASS_VERSION);
    out.push(username.len() as u8);
    out.extend_from_slice(username);
    out.push(password.len() as u8);
    out.extend_from_slice(password);
    Ok(out)
}

pub fn decode_user_pass_request(buf: &mut BytesMut) -> Result<UserPassRequest, CodecError> {
    if buf.len() < 2 {
        return Err(CodecError::Incomplete);
    }
    if buf[0] != USER_PASS_VERSION {
        return Err(CodecError::UnsupportedAuthVersion(buf[0]));
    }
    let ulen = buf[1] as usize;
    if ulen == 0 {
        return Err(CodecError::InvalidAuthLen);
    }
    if buf.len() < 2 + ulen + 1 {
        return Err(CodecError::Incomplete);
    }
    let plen = buf[2 + ulen] as usize;
    if plen == 0 {
        return Err(CodecError::InvalidAuthLen);
    }
    let total = 2 + ulen + 1 + plen;
    if buf.len() < total {
        return Err(CodecError::Incomplete);
    }
    let username = buf[2..2 + ulen].to_vec();
    let password = buf[2 + ulen + 1..total].to_vec();
    buf.advance(total);
    Ok(UserPassRequest { username, password })
}

pub fn encode_user_pass_reply(status: u8) -> Vec<u8> {
    vec![USER_PASS_VERSION, status]
}

pub fn decode_user_pass_reply(buf: &mut BytesMut) -> Result<u8, CodecError> {
    if buf.len() < 2 {
        return Err(CodecError::Incomplete);
    }
    if buf[0] != USER_PASS_VERSION {
        return Err(CodecError::UnsupportedAuthVersion(buf[0]));
    }
    let status = buf[1];
    buf.advance(2);
    Ok(status)
}

pub fn decode_udp_datagram(buf: &mut BytesMut) -> Result<UdpDatagram, CodecError> {
    if buf.len() < 7 {
        return Err(CodecError::Incomplete);
    }
    if buf[0] != 0 || buf[1] != 0 {
        return Err(CodecError::UnsupportedVersion(buf[0]));
    }
    if buf[2] != 0 {
        return Err(CodecError::UnsupportedFragment(buf[2]));
    }
    let (target, payload_start) = decode_endpoint_at(buf, 3)?;
    let payload = Bytes::copy_from_slice(&buf[payload_start..]);
    // SOCKS5 UDP relay is datagram-framed by the socket; consume exactly this datagram.
    buf.advance(buf.len());
    Ok(UdpDatagram { target, payload })
}
