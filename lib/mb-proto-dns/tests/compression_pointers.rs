use mb_proto_dns::*;

#[test]
fn decode_rejects_pointer_cycle() {
    // QNAME at offset 12 is a self-pointer 0xC00C → offset 12
    let mut bytes = vec![
        0x00, 0x01, // id
        0x00, 0x00, // flags
        0x00, 0x01, // qdcount=1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    bytes.extend_from_slice(&[0xC0, 0x0C]);
    bytes.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE A, QCLASS IN
    let err = decode::decode_message(&bytes).expect_err("must reject");
    assert!(matches!(err, DecodeError::CompressionLoop));
}

#[test]
fn decode_follows_backward_pointer() {
    // Build a real message that uses compression: question "a.test." and answer name as a pointer to it.
    // Header(12) + Q: 1 'a' 4 'test' 0 + QTYPE(2) + QCLASS(2) = 12 + 8 + 4 = 24
    // Then answer name = pointer 0xC00C (back to offset 12) + TYPE A + CLASS IN + TTL + RDLEN=4 + IP
    let mut bytes = vec![
        0x00, 0x42, // id
        0x81, 0x80, // QR=1 RD=1 RA=1
        0x00, 0x01, // qd
        0x00, 0x01, // an
        0x00, 0x00, 0x00, 0x00,
    ];
    // question name a.test.
    bytes.extend_from_slice(&[1, b'a', 4, b't', b'e', b's', b't', 0]);
    bytes.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE A, QCLASS IN
    // answer name = pointer back to offset 12
    bytes.extend_from_slice(&[0xC0, 0x0C]);
    bytes.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // TYPE A, CLASS IN
    bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL 60
    bytes.extend_from_slice(&[0x00, 0x04]); // RDLEN 4
    bytes.extend_from_slice(&[192, 0, 2, 7]); // IP
    let msg = decode::decode_message(&bytes).expect("decode");
    assert_eq!(msg.answers.len(), 1);
    assert_eq!(msg.answers[0].name.as_ascii_lower(), "a.test.");
}
