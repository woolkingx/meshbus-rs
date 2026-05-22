use bytes::BytesMut;
use mb_endpoint::Endpoint;
use mb_proto_socks5::{
    CodecError, Command, Method, Reply, USER_PASS_STATUS_FAILURE, USER_PASS_STATUS_SUCCESS,
    USER_PASS_VERSION, UserPassRequest, decode_connect_request, decode_greeting, decode_reply,
    decode_reply_frame, decode_request, decode_udp_datagram, decode_user_pass_reply,
    decode_user_pass_request, encode_connect_request, encode_greeting, encode_reply,
    encode_udp_associate_request, encode_udp_datagram, encode_user_pass_reply,
    encode_user_pass_request, reply_frame_total_len,
};

#[test]
fn greeting_roundtrip() {
    let bytes = encode_greeting(&[Method::NoAuth]);
    let mut buf = BytesMut::from(&bytes[..]);
    let g = decode_greeting(&mut buf).expect("valid greeting");
    assert!(g.methods.contains(&Method::NoAuth));
}

#[test]
fn greeting_with_zero_methods_decodes_to_empty_list() {
    // NMETHODS=0 is technically out of RFC 1928 spec (METHODS = 1..255 octets)
    // but the codec must not panic. It decodes to an empty list so the L7
    // adapter can treat the client as "offers no acceptable methods" and reply
    // with METHOD=0xff.
    let mut buf = BytesMut::from(&[0x05, 0x00][..]);
    let g = decode_greeting(&mut buf).expect("valid greeting");
    assert!(g.methods.is_empty());
    assert_eq!(buf.len(), 0, "decoder must consume the full 2-byte header");
}

#[test]
fn greeting_preserves_unknown_methods() {
    let mut buf = BytesMut::from(&[0x05, 0x01, 0x80][..]);
    let g = decode_greeting(&mut buf).expect("valid greeting");
    assert_eq!(g.methods, vec![Method::Unknown(0x80)]);
    assert!(!g.methods.contains(&Method::NoAuth));
}

#[test]
fn connect_request_domain_roundtrip() {
    let target = Endpoint::new("example.com", 443).expect("valid endpoint");
    let bytes = encode_connect_request(&target);
    let mut buf = BytesMut::from(&bytes[..]);
    let parsed = decode_connect_request(&mut buf).expect("valid connect request");
    assert_eq!(parsed.host(), "example.com");
    assert_eq!(parsed.port(), 443);
}

#[test]
fn connect_request_ipv4_roundtrip() {
    let target = Endpoint::new("127.0.0.1", 8080).expect("valid endpoint");
    let bytes = encode_connect_request(&target);
    let mut buf = BytesMut::from(&bytes[..]);
    let parsed = decode_connect_request(&mut buf).expect("valid connect request");
    assert_eq!(parsed.host(), "127.0.0.1");
    assert_eq!(parsed.port(), 8080);
}

#[test]
fn udp_associate_request_roundtrip() {
    let bind = Endpoint::new("127.0.0.1", 9).expect("valid endpoint");
    let bytes = encode_udp_associate_request(&bind);
    let mut buf = BytesMut::from(&bytes[..]);
    let parsed = decode_request(&mut buf).expect("valid udp associate request");
    assert_eq!(parsed.command, Command::UdpAssociate);
    assert_eq!(parsed.endpoint.host(), "127.0.0.1");
    assert_eq!(parsed.endpoint.port(), 9);
}

#[test]
fn udp_datagram_domain_roundtrip() {
    let target = Endpoint::new("example.com", 5353).expect("valid endpoint");
    let bytes = encode_udp_datagram(&target, b"dns-payload");
    let mut buf = BytesMut::from(&bytes[..]);
    let parsed = decode_udp_datagram(&mut buf).expect("valid udp datagram");
    assert_eq!(parsed.target.host(), "example.com");
    assert_eq!(parsed.target.port(), 5353);
    assert_eq!(&parsed.payload[..], b"dns-payload");
}

#[test]
fn udp_datagram_rejects_fragmentation() {
    let target = Endpoint::new("127.0.0.1", 53).expect("valid endpoint");
    let mut bytes = encode_udp_datagram(&target, b"payload");
    bytes[2] = 1;
    let mut buf = BytesMut::from(&bytes[..]);
    assert!(decode_udp_datagram(&mut buf).is_err());
}

#[test]
fn rejects_oversize_domain() {
    // Manual oversize CONNECT (255-byte domain — valid per RFC, max domain label is 255)
    let mut req = vec![0x05, 0x01, 0x00, 0x03, 0xff];
    req.extend(std::iter::repeat(b'a').take(255));
    req.extend_from_slice(&80u16.to_be_bytes());
    let mut buf = BytesMut::from(&req[..]);
    // 0xff length byte means 255-byte domain — valid.
    let parsed = decode_connect_request(&mut buf).expect("255-byte domain is valid");
    assert_eq!(parsed.host().len(), 255);
}

#[test]
fn reply_roundtrip() {
    let bytes = encode_reply(Reply::Succeeded);
    let mut buf = BytesMut::from(&bytes[..]);
    let r = decode_reply(&mut buf).expect("valid reply");
    assert_eq!(r, Reply::Succeeded);
}

#[test]
fn reply_frame_decodes_nonzero_bind_endpoint() {
    let bind = Endpoint::new("127.0.0.1", 49152).expect("bind endpoint");
    let bytes = mb_proto_socks5::encode_reply_with_endpoint(Reply::Succeeded, &bind);
    let mut buf = BytesMut::from(&bytes[..]);
    let frame = decode_reply_frame(&mut buf).expect("valid reply frame");
    assert_eq!(frame.reply, Reply::Succeeded);
    assert_eq!(frame.endpoint, Some(bind));
}

#[test]
fn reply_frame_allows_zero_bind_endpoint() {
    let bytes = encode_reply(Reply::ConnectionRefused);
    let mut buf = BytesMut::from(&bytes[..]);
    let frame = decode_reply_frame(&mut buf).expect("valid reply frame");
    assert_eq!(frame.reply, Reply::ConnectionRefused);
    assert_eq!(frame.endpoint, None);
}

#[test]
fn command_not_supported_reply_wire_code() {
    let bytes = encode_reply(Reply::CommandNotSupported);
    assert_eq!(bytes[1], 0x07);
}

#[test]
fn user_pass_request_roundtrip() {
    let bytes = encode_user_pass_request(b"alice", b"s3cret").expect("encode user/pass request");
    assert_eq!(bytes[0], USER_PASS_VERSION);
    let mut buf = BytesMut::from(&bytes[..]);
    let parsed = decode_user_pass_request(&mut buf).expect("decode user/pass request");
    assert_eq!(
        parsed,
        UserPassRequest {
            username: b"alice".to_vec(),
            password: b"s3cret".to_vec(),
        }
    );
    assert!(buf.is_empty());
}

#[test]
fn user_pass_request_debug_redacts_password() {
    let request = UserPassRequest {
        username: b"alice".to_vec(),
        password: b"s3cret".to_vec(),
    };
    let debug = format!("{request:?}");
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

#[test]
fn user_pass_request_max_length_roundtrip() {
    let username = vec![b'u'; 255];
    let password = vec![b'p'; 255];
    let bytes = encode_user_pass_request(&username, &password).expect("encode max-length");
    let mut buf = BytesMut::from(&bytes[..]);
    let parsed = decode_user_pass_request(&mut buf).expect("decode max-length");
    assert_eq!(parsed.username.len(), 255);
    assert_eq!(parsed.password.len(), 255);
}

#[test]
fn user_pass_request_rejects_empty_username() {
    assert!(encode_user_pass_request(b"", b"p").is_err());
}

#[test]
fn user_pass_request_rejects_empty_password() {
    assert!(encode_user_pass_request(b"u", b"").is_err());
}

#[test]
fn user_pass_request_rejects_oversize() {
    let too_long = vec![b'x'; 256];
    assert!(encode_user_pass_request(&too_long, b"p").is_err());
    assert!(encode_user_pass_request(b"u", &too_long).is_err());
}

#[test]
fn user_pass_request_rejects_wrong_version() {
    // VER=0x05 (SOCKS version, not the subnegotiation version)
    let mut buf = BytesMut::from(&[0x05, 0x01, b'u', 0x01, b'p'][..]);
    assert!(decode_user_pass_request(&mut buf).is_err());
}

#[test]
fn user_pass_request_rejects_zero_ulen() {
    let mut buf = BytesMut::from(&[USER_PASS_VERSION, 0x00, 0x01, b'p'][..]);
    assert!(decode_user_pass_request(&mut buf).is_err());
}

#[test]
fn user_pass_request_rejects_zero_plen() {
    let mut buf = BytesMut::from(&[USER_PASS_VERSION, 0x01, b'u', 0x00][..]);
    assert!(decode_user_pass_request(&mut buf).is_err());
}

#[test]
fn user_pass_request_incomplete_buffer() {
    // Truncated mid-username
    let mut buf = BytesMut::from(&[USER_PASS_VERSION, 0x05, b'a', b'l'][..]);
    assert!(matches!(
        decode_user_pass_request(&mut buf),
        Err(mb_proto_socks5::CodecError::Incomplete)
    ));
}

#[test]
fn user_pass_reply_success_roundtrip() {
    let bytes = encode_user_pass_reply(USER_PASS_STATUS_SUCCESS);
    assert_eq!(bytes, vec![USER_PASS_VERSION, 0x00]);
    let mut buf = BytesMut::from(&bytes[..]);
    let status = decode_user_pass_reply(&mut buf).expect("decode reply");
    assert_eq!(status, USER_PASS_STATUS_SUCCESS);
}

#[test]
fn user_pass_reply_failure_roundtrip() {
    let bytes = encode_user_pass_reply(USER_PASS_STATUS_FAILURE);
    let mut buf = BytesMut::from(&bytes[..]);
    let status = decode_user_pass_reply(&mut buf).expect("decode reply");
    assert_eq!(status, USER_PASS_STATUS_FAILURE);
}

#[test]
fn user_pass_reply_rejects_wrong_version() {
    let mut buf = BytesMut::from(&[0x05, 0x00][..]);
    assert!(decode_user_pass_reply(&mut buf).is_err());
}

#[test]
fn rfc_failure_reply_codes_roundtrip() {
    for (reply, code) in [
        (Reply::NetworkUnreachable, 0x03),
        (Reply::HostUnreachable, 0x04),
        (Reply::ConnectionRefused, 0x05),
        (Reply::TtlExpired, 0x06),
    ] {
        let bytes = encode_reply(reply);
        assert_eq!(bytes[1], code);
        let mut buf = BytesMut::from(&bytes[..]);
        let parsed = decode_reply(&mut buf).expect("decode reply");
        assert_eq!(parsed, reply);
    }
}

// I7: Incomplete boundary tests — N-1 bytes returns Incomplete, never panics

#[test]
fn decode_greeting_with_one_byte_short_returns_incomplete() {
    // Full greeting: VER NMETHODS METHOD... — for 2 methods: [05 02 00 02] = 4 bytes
    // Send 3 bytes (2 methods declared but only 1 method byte provided)
    let mut buf = BytesMut::from(&[0x05, 0x02, 0x00][..]);
    let result = decode_greeting(&mut buf);
    assert_eq!(result.unwrap_err(), CodecError::Incomplete);
}

#[test]
fn decode_greeting_with_zero_bytes_returns_incomplete() {
    let mut buf = BytesMut::from(&[][..]);
    let result = decode_greeting(&mut buf);
    assert_eq!(result.unwrap_err(), CodecError::Incomplete);
}

#[test]
fn decode_request_with_header_only_returns_incomplete() {
    // VER CMD RSV ATYP (4 bytes) — missing IPv4 addr+port
    let mut buf = BytesMut::from(&[0x05, 0x01, 0x00, 0x01][..]);
    let result = decode_request(&mut buf);
    assert_eq!(result.unwrap_err(), CodecError::Incomplete);
}

#[test]
fn decode_request_with_three_bytes_returns_incomplete() {
    // Minimum check is 7 bytes; 3 bytes is clearly short
    let mut buf = BytesMut::from(&[0x05, 0x01, 0x00][..]);
    let result = decode_request(&mut buf);
    assert_eq!(result.unwrap_err(), CodecError::Incomplete);
}

#[test]
fn decode_reply_with_nine_bytes_returns_incomplete() {
    // decode_reply needs >= 10 bytes; 9 is N-1
    let full = encode_reply(Reply::Succeeded);
    assert_eq!(full.len(), 10);
    let mut buf = BytesMut::from(&full[..9]);
    let result = decode_reply(&mut buf);
    assert_eq!(result.unwrap_err(), CodecError::Incomplete);
}

#[test]
fn decode_reply_frame_with_nine_bytes_returns_incomplete() {
    let full = encode_reply(Reply::Succeeded);
    let mut buf = BytesMut::from(&full[..9]);
    let result = decode_reply_frame(&mut buf);
    assert_eq!(result.unwrap_err(), CodecError::Incomplete);
}

#[test]
fn decode_udp_datagram_with_six_bytes_returns_incomplete() {
    // Minimum is 7 bytes (RSV RSV FRAG ATYP + IPv4 4 bytes + port 2 bytes = 10, but check is >= 7)
    // For IPv4 target: [00 00 00 01 ip(4) port(2)] = 10 bytes minimum; send 6
    let target = Endpoint::new("1.2.3.4", 53).expect("valid endpoint");
    let full = encode_udp_datagram(&target, b"");
    assert!(
        full.len() >= 10,
        "IPv4 UDP datagram must be at least 10 bytes"
    );
    let mut buf = BytesMut::from(&full[..6]);
    let result = decode_udp_datagram(&mut buf);
    assert_eq!(result.unwrap_err(), CodecError::Incomplete);
}

#[test]
fn reply_code_address_type_not_supported_roundtrip() {
    let bytes = encode_reply(Reply::AddressTypeNotSupported);
    assert_eq!(bytes[1], 0x08);
    let mut buf = BytesMut::from(&bytes[..]);
    let parsed = decode_reply(&mut buf).expect("decode reply");
    assert_eq!(parsed, Reply::AddressTypeNotSupported);
}

#[test]
fn decode_request_rejects_nonzero_rsv() {
    let target = Endpoint::new("127.0.0.1", 8080).expect("valid endpoint");
    let mut bytes = encode_connect_request(&target);
    bytes[2] = 0x01;
    let mut buf = BytesMut::from(&bytes[..]);
    assert_eq!(
        decode_request(&mut buf).unwrap_err(),
        CodecError::ReservedNotZero(0x01)
    );
}

#[test]
fn decode_reply_rejects_nonzero_rsv() {
    let mut bytes = encode_reply(Reply::Succeeded);
    bytes[2] = 0x07;
    let mut buf = BytesMut::from(&bytes[..]);
    assert_eq!(
        decode_reply(&mut buf).unwrap_err(),
        CodecError::ReservedNotZero(0x07)
    );
}

#[test]
fn decode_reply_frame_rejects_nonzero_rsv() {
    let mut bytes = encode_reply(Reply::Succeeded);
    bytes[2] = 0xff;
    let mut buf = BytesMut::from(&bytes[..]);
    assert_eq!(
        decode_reply_frame(&mut buf).unwrap_err(),
        CodecError::ReservedNotZero(0xff)
    );
}

#[test]
fn bind_request_roundtrip() {
    let target = Endpoint::new("203.0.113.7", 1080).expect("valid endpoint");
    let bytes = mb_proto_socks5::encode_request(Command::Bind, &target);
    let mut buf = BytesMut::from(&bytes[..]);
    let parsed = decode_request(&mut buf).expect("valid bind request");
    assert_eq!(parsed.command, Command::Bind);
    assert_eq!(parsed.endpoint.host(), "203.0.113.7");
    assert_eq!(parsed.endpoint.port(), 1080);
}

#[test]
fn reply_frame_ipv6_endpoint_roundtrip() {
    let bind = Endpoint::new("2001:db8::1", 51820).expect("ipv6 endpoint");
    let bytes = mb_proto_socks5::encode_reply_with_endpoint(Reply::Succeeded, &bind);
    let mut buf = BytesMut::from(&bytes[..]);
    let frame = decode_reply_frame(&mut buf).expect("valid ipv6 reply frame");
    assert_eq!(frame.reply, Reply::Succeeded);
    assert_eq!(frame.endpoint, Some(bind));
}

#[test]
fn reply_frame_domain_endpoint_roundtrip() {
    let bind = Endpoint::new("relay.example.net", 7000).expect("domain endpoint");
    let bytes = mb_proto_socks5::encode_reply_with_endpoint(Reply::Succeeded, &bind);
    let mut buf = BytesMut::from(&bytes[..]);
    let frame = decode_reply_frame(&mut buf).expect("valid domain reply frame");
    assert_eq!(frame.reply, Reply::Succeeded);
    assert_eq!(frame.endpoint, Some(bind));
}

#[test]
fn reply_frame_total_len_ipv4() {
    assert_eq!(reply_frame_total_len(&[0x05, 0x00, 0x00, 0x01]), Ok(10));
}

#[test]
fn reply_frame_total_len_ipv6() {
    assert_eq!(reply_frame_total_len(&[0x05, 0x00, 0x00, 0x04]), Ok(22));
}

#[test]
fn reply_frame_total_len_domain_uses_length_octet() {
    // ATYP=DOMAIN, length octet 0x07 -> 4 + 1 + 7 + 2
    assert_eq!(
        reply_frame_total_len(&[0x05, 0x00, 0x00, 0x03, 0x07]),
        Ok(14)
    );
}

#[test]
fn reply_frame_total_len_domain_without_length_octet_incomplete() {
    assert_eq!(
        reply_frame_total_len(&[0x05, 0x00, 0x00, 0x03]),
        Err(CodecError::Incomplete)
    );
}

#[test]
fn reply_frame_total_len_short_header_incomplete() {
    assert_eq!(
        reply_frame_total_len(&[0x05, 0x00, 0x00]),
        Err(CodecError::Incomplete)
    );
}

#[test]
fn reply_frame_total_len_invalid_atyp() {
    assert_eq!(
        reply_frame_total_len(&[0x05, 0x00, 0x00, 0x09]),
        Err(CodecError::InvalidAtyp(0x09))
    );
}

// 3b: UDP datagram IPv4 roundtrip
#[test]
fn udp_datagram_ipv4_roundtrip() {
    let target = Endpoint::new("1.2.3.4", 5678).expect("valid endpoint");
    let payload = b"hello";
    let encoded = encode_udp_datagram(&target, payload);
    let mut buf = BytesMut::from(&encoded[..]);
    let decoded = decode_udp_datagram(&mut buf).expect("valid udp datagram");
    assert_eq!(decoded.target.host(), "1.2.3.4");
    assert_eq!(decoded.target.port(), 5678);
    assert_eq!(&decoded.payload[..], payload);
}
