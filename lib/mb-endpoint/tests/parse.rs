use mb_endpoint::{Endpoint, ParseError};

#[test]
fn parses_host_port() {
    let ep = Endpoint::parse("example.com:443").expect("valid endpoint");
    assert_eq!(ep.host(), "example.com");
    assert_eq!(ep.port(), 443);
}

#[test]
fn parses_ipv4() {
    let ep = Endpoint::parse("127.0.0.1:8080").expect("valid endpoint");
    assert_eq!(ep.host(), "127.0.0.1");
    assert_eq!(ep.port(), 8080);
}

#[test]
fn parses_ipv6_bracketed() {
    let ep = Endpoint::parse("[::1]:443").expect("valid endpoint");
    assert_eq!(ep.host(), "::1");
    assert_eq!(ep.port(), 443);
}

#[test]
fn rejects_empty_host() {
    assert!(matches!(
        Endpoint::parse(":443"),
        Err(ParseError::EmptyHost)
    ));
}

#[test]
fn rejects_zero_port() {
    assert!(matches!(
        Endpoint::parse("example.com:0"),
        Err(ParseError::InvalidPort(_))
    ));
}

#[test]
fn rejects_oversize_host() {
    let long = "a".repeat(256);
    let s = format!("{long}:80");
    assert!(matches!(
        Endpoint::parse(&s),
        Err(ParseError::HostTooLong(_))
    ));
}
