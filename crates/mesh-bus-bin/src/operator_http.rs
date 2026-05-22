use mesh_bus_core::BusSnapshotClient;
use mesh_bus_runtime::{Config, IngressCfg, OperatorAuthCfg, OperatorCfg};
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const MAX_REQUEST_BYTES: usize = 8192;

pub(crate) async fn serve_local_http(
    listener: TcpListener,
    cfg: Config,
    config_path: PathBuf,
    yaml: String,
    snapshot: BusSnapshotClient,
    version: &'static str,
    auth_token: Option<String>,
) {
    let state = Arc::new(OperatorHttpState {
        cfg,
        config_path,
        yaml,
        snapshot,
        version,
        auth_token,
    });
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            break;
        };
        let state = state.clone();
        tokio::spawn(async move {
            let _ = handle_connection(stream, state).await;
        });
    }
}

struct OperatorHttpState {
    cfg: Config,
    config_path: PathBuf,
    yaml: String,
    snapshot: BusSnapshotClient,
    version: &'static str,
    auth_token: Option<String>,
}

async fn handle_connection(
    mut stream: TcpStream,
    state: Arc<OperatorHttpState>,
) -> anyhow::Result<()> {
    let mut buf = vec![0u8; MAX_REQUEST_BYTES];
    let n = stream.read(&mut buf).await?;
    let request = String::from_utf8_lossy(&buf[..n]);
    let Some(parts) = request_parts(&request) else {
        return write_response(&mut stream, 400, "text/plain", "bad request\n").await;
    };
    if !authorized(&request, state.auth_token.as_deref()) {
        let status = if authorization_header(&request).is_some() {
            403
        } else {
            401
        };
        return write_response(&mut stream, status, "text/plain", "unauthorized\n").await;
    }
    match (parts.method, parts.path) {
        ("GET", "/status") => {
            let snapshot = state.snapshot.snapshot().await;
            let body = serde_json::to_string_pretty(&mesh_bus_operator_api::live_status_response(
                &state.cfg,
                &state.config_path,
                &state.yaml,
                state.version,
                &snapshot,
            ))?;
            write_response(&mut stream, 200, "application/json", &body).await
        }
        ("GET", "/metrics/snapshot") => {
            let snapshot = state.snapshot.snapshot().await;
            let body =
                serde_json::to_string_pretty(&mesh_bus_operator_api::metrics_snapshot_response(
                    &state.config_path,
                    &state.yaml,
                    &snapshot,
                ))?;
            write_response(&mut stream, 200, "application/json", &body).await
        }
        ("GET", "/config/effective") => {
            let body = serde_json::to_string_pretty(
                &mesh_bus_operator_api::effective_config_response(&state.config_path, &state.yaml)?,
            )?;
            write_response(&mut stream, 200, "application/json", &body).await
        }
        ("POST", "/probe/socks5") => {
            let body = handle_probe("socks5-connect", &state, parts.body).await?;
            write_response(&mut stream, 200, "application/json", &body).await
        }
        ("POST", "/probe/http-connect") => {
            let body = handle_probe("http-connect", &state, parts.body).await?;
            write_response(&mut stream, 200, "application/json", &body).await
        }
        ("POST", "/probe/mesh-peer") => {
            let body = handle_probe("mesh-peer", &state, parts.body).await?;
            write_response(&mut stream, 200, "application/json", &body).await
        }
        ("POST", "/diagnose/bundle") => {
            let snapshot = state.snapshot.snapshot().await;
            let body =
                serde_json::to_string_pretty(&mesh_bus_operator_api::diagnose_bundle_response(
                    &state.cfg,
                    &state.config_path,
                    &state.yaml,
                    state.version,
                    &snapshot,
                )?)?;
            write_response(&mut stream, 200, "application/json", &body).await
        }
        _ => write_response(&mut stream, 404, "text/plain", "not found\n").await,
    }
}

struct RequestParts<'a> {
    method: &'a str,
    path: &'a str,
    body: &'a str,
}

fn request_parts(request: &str) -> Option<RequestParts<'_>> {
    let line = request.lines().next()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?;
    let path = parts.next()?;
    let body = request
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or("");
    Some(RequestParts { method, path, body })
}

#[derive(Debug, Deserialize)]
struct ProbeRequest {
    target: Option<String>,
    route_group: Option<String>,
    timeout_ms: Option<u64>,
}

struct ProbeTarget {
    host: String,
    port: u16,
    authority: String,
}

async fn handle_probe(
    probe: &'static str,
    state: &OperatorHttpState,
    body: &str,
) -> anyhow::Result<String> {
    let request: ProbeRequest = if body.trim().is_empty() {
        ProbeRequest {
            target: None,
            route_group: None,
            timeout_ms: None,
        }
    } else {
        serde_json::from_str(body).map_err(|e| anyhow::anyhow!("bad probe json: {e}"))?
    };
    let target = request
        .target
        .clone()
        .unwrap_or_else(|| "https://example.com".to_string());
    let timeout = Duration::from_millis(request.timeout_ms.unwrap_or(5000));
    let before = state.snapshot.snapshot().await;
    let started = Instant::now();
    let result = match probe {
        "socks5-connect" => run_socks5_probe(&state.cfg, &target, timeout).await,
        "http-connect" => run_http_connect_probe(&state.cfg, &target, timeout).await,
        "mesh-peer" => run_mesh_peer_probe(&state.cfg, &target, timeout).await,
        _ => Err(anyhow::anyhow!("unknown probe {probe}")),
    };
    let after = state.snapshot.snapshot().await;
    let response = mesh_bus_operator_api::probe_response(
        probe,
        result.is_ok(),
        target,
        request.route_group,
        result
            .map(|_| "completed".to_string())
            .unwrap_or_else(|e| e.to_string()),
        &before,
        &after,
        started.elapsed().as_millis() as u64,
    );
    serde_json::to_string_pretty(&response).map_err(Into::into)
}

async fn run_socks5_probe(cfg: &Config, target: &str, timeout: Duration) -> anyhow::Result<()> {
    let listen = cfg
        .ingresses
        .iter()
        .find_map(|ingress| match ingress {
            IngressCfg::Socks5 { listen, .. } => Some(listen.as_str()),
            _ => None,
        })
        .ok_or_else(|| anyhow::anyhow!("no configured SOCKS5 ingress"))?;
    let target = parse_probe_target(target)?;
    let addr = loopback_addr(listen)?;
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| anyhow::anyhow!("socks5 probe connect timeout"))?
        .map_err(|e| anyhow::anyhow!("connect SOCKS5 ingress {addr}: {e}"))?;
    tokio::time::timeout(timeout, async {
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut method = [0u8; 2];
        stream.read_exact(&mut method).await?;
        if method != [0x05, 0x00] {
            return Err(anyhow::anyhow!("SOCKS5 NoAuth rejected: {:02x?}", method));
        }
        let request = socks5_connect_request(&target)?;
        stream.write_all(&request).await?;
        read_socks5_reply(&mut stream).await
    })
    .await
    .map_err(|_| anyhow::anyhow!("socks5 probe handshake timeout"))?
}

async fn run_http_connect_probe(
    cfg: &Config,
    target: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    let listen = cfg
        .ingresses
        .iter()
        .find_map(|ingress| match ingress {
            IngressCfg::HttpConnect { listen, .. } => Some(listen.as_str()),
            _ => None,
        })
        .ok_or_else(|| anyhow::anyhow!("no configured HTTP CONNECT ingress"))?;
    let target = parse_probe_target(target)?;
    let addr = loopback_addr(listen)?;
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| anyhow::anyhow!("http-connect probe connect timeout"))?
        .map_err(|e| anyhow::anyhow!("connect HTTP CONNECT ingress {addr}: {e}"))?;
    tokio::time::timeout(timeout, async {
        let request = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
            target.authority, target.authority
        );
        stream.write_all(request.as_bytes()).await?;
        let mut buf = [0u8; 128];
        let n = stream.read(&mut buf).await?;
        let head = String::from_utf8_lossy(&buf[..n]);
        if !head.starts_with("HTTP/1.1 200 ") {
            return Err(anyhow::anyhow!(
                "HTTP CONNECT failed: {}",
                head.lines().next().unwrap_or("")
            ));
        }
        Ok(())
    })
    .await
    .map_err(|_| anyhow::anyhow!("http-connect probe timeout"))?
}

async fn run_mesh_peer_probe(cfg: &Config, target: &str, timeout: Duration) -> anyhow::Result<()> {
    let has_peer = cfg
        .egresses
        .iter()
        .any(|egress| matches!(egress, mesh_bus_runtime::EgressCfg::MeshPeerUdp { .. }));
    if !has_peer {
        return Err(anyhow::anyhow!("no configured MeshPeerUdp egress"));
    }
    if cfg
        .ingresses
        .iter()
        .any(|ingress| matches!(ingress, IngressCfg::Socks5 { .. }))
    {
        return run_socks5_probe(cfg, target, timeout).await;
    }
    if cfg
        .ingresses
        .iter()
        .any(|ingress| matches!(ingress, IngressCfg::HttpConnect { .. }))
    {
        return run_http_connect_probe(cfg, target, timeout).await;
    }
    Err(anyhow::anyhow!(
        "mesh-peer probe requires a configured SOCKS5 or HTTP CONNECT ingress"
    ))
}

fn loopback_addr(listen: &str) -> anyhow::Result<SocketAddr> {
    let mut addr: SocketAddr = listen
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid listen address {listen}: {e}"))?;
    if addr.ip().is_unspecified() {
        addr.set_ip(if addr.is_ipv6() {
            IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
        } else {
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        });
    }
    Ok(addr)
}

fn parse_probe_target(input: &str) -> anyhow::Result<ProbeTarget> {
    let (raw, default_port) = if let Some(rest) = input.strip_prefix("https://") {
        (rest.split('/').next().unwrap_or(rest), Some(443))
    } else if let Some(rest) = input.strip_prefix("http://") {
        (rest.split('/').next().unwrap_or(rest), Some(80))
    } else {
        (input, None)
    };
    let (host, port) = if let Some(stripped) = raw.strip_prefix('[') {
        let (host, rest) = stripped
            .split_once(']')
            .ok_or_else(|| anyhow::anyhow!("invalid bracketed target {input}"))?;
        let port = rest
            .strip_prefix(':')
            .and_then(|p| p.parse().ok())
            .or(default_port)
            .ok_or_else(|| anyhow::anyhow!("target port required for {input}"))?;
        (host.to_string(), port)
    } else if let Some((host, port)) = raw.rsplit_once(':') {
        let port = port
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid target port in {input}: {e}"))?;
        (host.to_string(), port)
    } else {
        let port =
            default_port.ok_or_else(|| anyhow::anyhow!("target port required for {input}"))?;
        (raw.to_string(), port)
    };
    if host.is_empty() {
        return Err(anyhow::anyhow!("target host required"));
    }
    Ok(ProbeTarget {
        authority: format!("{host}:{port}"),
        host,
        port,
    })
}

fn socks5_connect_request(target: &ProbeTarget) -> anyhow::Result<Vec<u8>> {
    let mut out = vec![0x05, 0x01, 0x00];
    if let Ok(ip) = target.host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => {
                out.push(0x01);
                out.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                out.push(0x04);
                out.extend_from_slice(&v6.octets());
            }
        }
    } else {
        let host = target.host.as_bytes();
        if host.len() > u8::MAX as usize {
            return Err(anyhow::anyhow!("SOCKS5 domain too long"));
        }
        out.push(0x03);
        out.push(host.len() as u8);
        out.extend_from_slice(host);
    }
    out.extend_from_slice(&target.port.to_be_bytes());
    Ok(out)
}

async fn read_socks5_reply(stream: &mut TcpStream) -> anyhow::Result<()> {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 || head[1] != 0x00 {
        return Err(anyhow::anyhow!("SOCKS5 connect failed: {:02x?}", head));
    }
    match head[3] {
        0x01 => read_exact_discard(stream, 6).await,
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            read_exact_discard(stream, len[0] as usize + 2).await
        }
        0x04 => read_exact_discard(stream, 18).await,
        other => Err(anyhow::anyhow!("unknown SOCKS5 reply atyp {other}")),
    }
}

async fn read_exact_discard(stream: &mut TcpStream, len: usize) -> anyhow::Result<()> {
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(())
}

fn authorization_header(request: &str) -> Option<&str> {
    request.lines().skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("authorization") {
            Some(value.trim())
        } else {
            None
        }
    })
}

fn authorized(request: &str, token: Option<&str>) -> bool {
    let Some(expected) = token else {
        return true;
    };
    let Some(value) = authorization_header(request) else {
        return false;
    };
    let Some(actual) = value.strip_prefix("Bearer ") else {
        return false;
    };
    constant_time_eq(actual.as_bytes(), expected.as_bytes())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = a.len() ^ b.len();
    for i in 0..a.len().max(b.len()) {
        let av = a.get(i).copied().unwrap_or(0);
        let bv = b.get(i).copied().unwrap_or(0);
        diff |= (av ^ bv) as usize;
    }
    diff == 0
}

pub(crate) fn load_auth_token(cfg: &Config) -> anyhow::Result<Option<String>> {
    let Some(OperatorCfg::LocalHttp { auth, .. }) = cfg.operator.as_ref() else {
        return Ok(None);
    };
    let Some(OperatorAuthCfg::BearerTokenFile { path }) = auth else {
        return Ok(None);
    };
    let token = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("read operator token file {}: {e}", path.display()))?;
    let token = token.trim().to_string();
    if token.is_empty() {
        return Err(anyhow::anyhow!("operator token file is empty"));
    }
    Ok(Some(token))
}

async fn write_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &str,
) -> anyhow::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Internal Server Error",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await?;
    Ok(())
}
