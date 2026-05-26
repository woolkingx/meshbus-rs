//! SOCKS5 greeting and RFC1929 authentication.

use bytes::BytesMut;
use mb_proto_socks5::{
    CodecError, Method, USER_PASS_STATUS_FAILURE, USER_PASS_STATUS_SUCCESS, decode_greeting,
    decode_request, decode_user_pass_request, encode_user_pass_reply,
};
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::GSSAPI_SUPPORTED;

#[derive(Clone, Default)]
pub struct AuthConfig {
    users: HashMap<String, String>,
}

impl AuthConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_user(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.users.insert(username.into(), password.into());
        self
    }

    pub fn insert(&mut self, username: impl Into<String>, password: impl Into<String>) {
        self.users.insert(username.into(), password.into());
    }

    pub fn verify(&self, username: &str, password: &str) -> bool {
        self.users
            .get(username)
            .is_some_and(|stored| stored.as_str() == password)
    }

    pub fn is_empty(&self) -> bool {
        self.users.is_empty()
    }
}

pub(crate) struct Handshake {
    pub(crate) request: mb_proto_socks5::Request,
    pub(crate) authenticated_user: Option<String>,
}

pub(crate) async fn read_handshake(
    sock: &mut TcpStream,
    auth: Option<&AuthConfig>,
) -> Option<Handshake> {
    let mut buf = BytesMut::with_capacity(512);
    let mut chunk = [0u8; 512];

    loop {
        let n = match sock.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => n,
        };
        buf.extend_from_slice(&chunk[..n]);
        match decode_greeting(&mut buf) {
            Ok(greeting) => {
                let required_method = if auth.is_some() {
                    Method::UserPass
                } else {
                    Method::NoAuth
                };
                if !greeting.methods.contains(&required_method) {
                    if !GSSAPI_SUPPORTED && greeting.methods.contains(&Method::GssApi) {
                        tracing::debug!(
                            target: "mesh_bus.ingress.socks5",
                            "socks5_gssapi_unsupported"
                        );
                    }
                    let _ = sock.write_all(&[0x05, 0xff]).await;
                    return None;
                }
                let selected = match required_method {
                    Method::NoAuth => 0x00u8,
                    Method::UserPass => 0x02u8,
                    _ => unreachable!("required_method is constrained above"),
                };
                if sock.write_all(&[0x05, selected]).await.is_err() {
                    return None;
                }
                break;
            }
            Err(CodecError::Incomplete) => {}
            Err(_) => return None,
        }
    }

    let authenticated_user = match auth {
        Some(auth) => Some(run_user_pass_subnegotiation(sock, &mut buf, auth).await?),
        None => None,
    };

    loop {
        match decode_request(&mut buf) {
            Ok(request) => {
                return Some(Handshake {
                    request,
                    authenticated_user,
                });
            }
            Err(CodecError::Incomplete) => {}
            Err(_) => return None,
        }
        let n = match sock.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => n,
        };
        buf.extend_from_slice(&chunk[..n]);
    }
}

async fn run_user_pass_subnegotiation(
    sock: &mut TcpStream,
    buf: &mut BytesMut,
    auth: &AuthConfig,
) -> Option<String> {
    let mut chunk = [0u8; 512];
    loop {
        match decode_user_pass_request(buf) {
            Ok(req) => {
                let username = match std::str::from_utf8(&req.username) {
                    Ok(s) => s.to_string(),
                    Err(_) => {
                        let _ = sock
                            .write_all(&encode_user_pass_reply(USER_PASS_STATUS_FAILURE))
                            .await;
                        return None;
                    }
                };
                let password = match std::str::from_utf8(&req.password) {
                    Ok(s) => s,
                    Err(_) => {
                        let _ = sock
                            .write_all(&encode_user_pass_reply(USER_PASS_STATUS_FAILURE))
                            .await;
                        return None;
                    }
                };
                if !auth.verify(&username, password) {
                    let _ = sock
                        .write_all(&encode_user_pass_reply(USER_PASS_STATUS_FAILURE))
                        .await;
                    return None;
                }
                if sock
                    .write_all(&encode_user_pass_reply(USER_PASS_STATUS_SUCCESS))
                    .await
                    .is_err()
                {
                    return None;
                }
                return Some(username);
            }
            Err(mb_proto_socks5::CodecError::Incomplete) => {
                let n = match sock.read(&mut chunk).await {
                    Ok(0) | Err(_) => return None,
                    Ok(n) => n,
                };
                buf.extend_from_slice(&chunk[..n]);
            }
            Err(_) => {
                let _ = sock
                    .write_all(&encode_user_pass_reply(USER_PASS_STATUS_FAILURE))
                    .await;
                return None;
            }
        }
    }
}
