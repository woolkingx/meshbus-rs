use mb_proto_http_proxy::{HttpProxyError, RequestKind, parse_request_head};

#[test]
fn parse_connect_authority_form() {
    let input = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
    let parsed = parse_request_head(input, 4096)
        .expect("parse")
        .expect("complete");
    assert_eq!(parsed.kind, RequestKind::Connect);
    assert_eq!(parsed.target.host(), "example.com");
    assert_eq!(parsed.target.port(), 443);
    assert_eq!(parsed.consumed, input.len());
    assert!(parsed.forwarded_head.is_empty());
}

#[test]
fn reject_connect_origin_form() {
    let input = b"CONNECT / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let err = parse_request_head(input, 4096).expect_err("origin-form CONNECT rejects");
    assert_eq!(err, HttpProxyError::InvalidConnectTarget("/".to_string()));
}

#[test]
fn parse_absolute_form_get() {
    let input = b"GET http://example.com/a?q=1 HTTP/1.1\r\nHost: ignored\r\nUser-Agent: test\r\nProxy-Authorization: Basic abc\r\n\r\n";
    let parsed = parse_request_head(input, 4096)
        .expect("parse")
        .expect("complete");
    assert_eq!(
        parsed.kind,
        RequestKind::ForwardHttp {
            method: "GET".to_string(),
            origin_form: "/a?q=1".to_string(),
        }
    );
    assert_eq!(parsed.target.host(), "example.com");
    assert_eq!(parsed.target.port(), 80);
    assert_eq!(parsed.proxy_authorization.as_deref(), Some("Basic abc"));
    let head = std::str::from_utf8(&parsed.forwarded_head).expect("utf8 head");
    assert!(head.starts_with("GET /a?q=1 HTTP/1.1\r\nHost: example.com\r\n"));
    assert!(head.contains("User-Agent: test\r\n"));
    assert!(!head.contains("Proxy-Authorization"));
    assert!(!head.contains("Host: ignored"));
}

#[test]
fn reject_oversize_header() {
    let input = b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let err = parse_request_head(input, input.len() - 1).expect_err("oversize rejects");
    assert_eq!(err, HttpProxyError::HeaderTooLarge);
}

#[test]
fn incomplete_request_head_returns_none() {
    let input = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n";
    let parsed = parse_request_head(input, 4096).expect("incomplete not malformed");
    assert!(parsed.is_none());
}

#[test]
fn parse_ipv6_connect_authority_form() {
    let input = b"CONNECT [::1]:8443 HTTP/1.1\r\nHost: [::1]:8443\r\n\r\n";
    let parsed = parse_request_head(input, 4096)
        .expect("parse")
        .expect("complete");
    assert_eq!(parsed.target.host(), "::1");
    assert_eq!(parsed.target.port(), 8443);
}
