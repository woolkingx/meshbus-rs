//! Pure HTTP/1.1 proxy request-head codec. No I/O.

use bytes::Bytes;
use mb_endpoint::{Endpoint, ParseError};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestKind {
    Connect,
    ForwardHttp { method: String, origin_form: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHead {
    pub kind: RequestKind,
    pub target: Endpoint,
    pub consumed: usize,
    pub forwarded_head: Bytes,
    pub proxy_authorization: Option<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HttpProxyError {
    #[error("request head incomplete")]
    Incomplete,
    #[error("request head exceeds max header bytes")]
    HeaderTooLarge,
    #[error("request head is not valid utf-8")]
    InvalidUtf8,
    #[error("malformed request line")]
    MalformedRequestLine,
    #[error("unsupported http version: {0}")]
    UnsupportedVersion(String),
    #[error("invalid connect target: {0}")]
    InvalidConnectTarget(String),
    #[error("unsupported method: {0}")]
    UnsupportedMethod(String),
    #[error("unsupported scheme: {0}")]
    UnsupportedScheme(String),
    #[error("malformed absolute-form request target")]
    MalformedAbsoluteForm,
    #[error("malformed header field")]
    MalformedHeader,
    #[error("endpoint rejected: {0}")]
    Endpoint(String),
}

pub fn parse_request_head(
    input: &[u8],
    max_header_bytes: usize,
) -> Result<Option<RequestHead>, HttpProxyError> {
    let Some(end) = find_header_end(input) else {
        if input.len() > max_header_bytes {
            return Err(HttpProxyError::HeaderTooLarge);
        }
        return Ok(None);
    };
    if end > max_header_bytes {
        return Err(HttpProxyError::HeaderTooLarge);
    }
    let head = std::str::from_utf8(&input[..end]).map_err(|_| HttpProxyError::InvalidUtf8)?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or(HttpProxyError::MalformedRequestLine)?;
    let (method, target, version) = parse_request_line(request_line)?;
    if version != "HTTP/1.1" {
        return Err(HttpProxyError::UnsupportedVersion(version.to_string()));
    }
    let headers = parse_headers(lines)?;
    let proxy_authorization = header_value(&headers, "proxy-authorization").map(str::to_string);

    if method == "CONNECT" {
        if target.starts_with('/') || target.contains("://") {
            return Err(HttpProxyError::InvalidConnectTarget(target.to_string()));
        }
        let endpoint = parse_endpoint(target)?;
        return Ok(Some(RequestHead {
            kind: RequestKind::Connect,
            target: endpoint,
            consumed: end,
            forwarded_head: Bytes::new(),
            proxy_authorization,
        }));
    }

    if method != "GET" && method != "HEAD" && method != "POST" && method != "PUT" {
        return Err(HttpProxyError::UnsupportedMethod(method.to_string()));
    }
    let absolute = parse_http_absolute_form(target)?;
    let endpoint = Endpoint::new(absolute.host.clone(), absolute.port).map_err(endpoint_error)?;
    let forwarded_head = rewrite_forward_head(method, version, &absolute, &headers);
    Ok(Some(RequestHead {
        kind: RequestKind::ForwardHttp {
            method: method.to_string(),
            origin_form: absolute.origin_form,
        },
        target: endpoint,
        consumed: end,
        forwarded_head: Bytes::from(forwarded_head),
        proxy_authorization,
    }))
}

fn find_header_end(input: &[u8]) -> Option<usize> {
    input
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|idx| idx + 4)
}

fn parse_request_line(line: &str) -> Result<(&str, &str, &str), HttpProxyError> {
    let mut parts = line.split(' ');
    let method = parts.next().ok_or(HttpProxyError::MalformedRequestLine)?;
    let target = parts.next().ok_or(HttpProxyError::MalformedRequestLine)?;
    let version = parts.next().ok_or(HttpProxyError::MalformedRequestLine)?;
    if parts.next().is_some() || method.is_empty() || target.is_empty() || version.is_empty() {
        return Err(HttpProxyError::MalformedRequestLine);
    }
    Ok((method, target, version))
}

fn parse_headers<'a>(
    lines: impl Iterator<Item = &'a str>,
) -> Result<Vec<(&'a str, &'a str)>, HttpProxyError> {
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(HttpProxyError::MalformedHeader);
        };
        if name.is_empty() || name.bytes().any(|b| b <= 0x20 || b == b':') {
            return Err(HttpProxyError::MalformedHeader);
        }
        headers.push((name, value.trim()));
    }
    Ok(headers)
}

fn header_value<'a>(headers: &'a [(&'a str, &'a str)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(header, _)| header.eq_ignore_ascii_case(name))
        .map(|(_, value)| *value)
}

fn parse_endpoint(input: &str) -> Result<Endpoint, HttpProxyError> {
    Endpoint::parse(input).map_err(endpoint_error)
}

fn endpoint_error(err: ParseError) -> HttpProxyError {
    HttpProxyError::Endpoint(err.to_string())
}

struct AbsoluteTarget {
    host: String,
    port: u16,
    authority: String,
    origin_form: String,
}

fn parse_http_absolute_form(input: &str) -> Result<AbsoluteTarget, HttpProxyError> {
    let Some(rest) = input.strip_prefix("http://") else {
        let scheme = input
            .split_once(':')
            .map(|(scheme, _)| scheme)
            .unwrap_or("");
        return Err(HttpProxyError::UnsupportedScheme(scheme.to_string()));
    };
    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    if authority_end == 0 {
        return Err(HttpProxyError::MalformedAbsoluteForm);
    }
    let authority = &rest[..authority_end];
    let suffix = &rest[authority_end..];
    let (endpoint, authority) = authority_to_endpoint(authority, 80)?;
    let origin_form = if suffix.is_empty() {
        "/".to_string()
    } else if suffix.starts_with('?') {
        format!("/{suffix}")
    } else {
        suffix.to_string()
    };
    Ok(AbsoluteTarget {
        host: endpoint.host().to_string(),
        port: endpoint.port(),
        authority,
        origin_form,
    })
}

fn authority_to_endpoint(
    authority: &str,
    default_port: u16,
) -> Result<(Endpoint, String), HttpProxyError> {
    if let Some(rest) = authority.strip_prefix('[') {
        let close = rest
            .find(']')
            .ok_or(HttpProxyError::MalformedAbsoluteForm)?;
        let host = &rest[..close];
        let after = &rest[close + 1..];
        if after.is_empty() {
            let endpoint = Endpoint::new(host, default_port).map_err(endpoint_error)?;
            return Ok((endpoint, format!("[{host}]")));
        }
        if after.starts_with(':') {
            let endpoint = Endpoint::parse(authority).map_err(endpoint_error)?;
            return Ok((endpoint, authority.to_string()));
        }
        return Err(HttpProxyError::MalformedAbsoluteForm);
    }
    if let Some((host, port)) = authority.rsplit_once(':') {
        if host.is_empty() || port.is_empty() {
            return Err(HttpProxyError::MalformedAbsoluteForm);
        }
        let endpoint = Endpoint::parse(authority).map_err(endpoint_error)?;
        return Ok((endpoint, authority.to_string()));
    }
    let endpoint = Endpoint::new(authority, default_port).map_err(endpoint_error)?;
    Ok((endpoint, authority.to_string()))
}

fn rewrite_forward_head(
    method: &str,
    version: &str,
    target: &AbsoluteTarget,
    headers: &[(&str, &str)],
) -> String {
    let mut out = String::new();
    out.push_str(method);
    out.push(' ');
    out.push_str(&target.origin_form);
    out.push(' ');
    out.push_str(version);
    out.push_str("\r\nHost: ");
    out.push_str(&target.authority);
    out.push_str("\r\n");
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("proxy-authorization")
            || name.eq_ignore_ascii_case("proxy-connection")
        {
            continue;
        }
        out.push_str(name);
        out.push_str(": ");
        out.push_str(value);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    out
}
