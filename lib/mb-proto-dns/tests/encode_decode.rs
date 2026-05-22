use mb_proto_dns::*;

#[test]
fn round_trips_a_query() {
    let mut msg = Message::default();
    msg.header.id = 0xABCD;
    msg.header.flags = 0x0100;
    msg.questions.push(Question {
        name: Name::from_ascii("WWW.Example.COM.").expect("name"),
        qtype: QType::A,
        qclass: RClass::In,
    });
    let bytes = encode::encode_message(&msg).expect("encode");
    let back = decode::decode_message(&bytes).expect("decode");
    assert_eq!(back.header.id, 0xABCD);
    assert_eq!(back.questions[0].name.as_ascii_lower(), "www.example.com.");
    assert_eq!(back.questions[0].qtype, QType::A);
}

#[test]
fn round_trips_a_answer() {
    use std::net::Ipv4Addr;
    let mut msg = Message::default();
    msg.header.id = 1;
    msg.header.flags = 0x8180; // QR=1, RD=1, RA=1
    msg.questions.push(Question {
        name: Name::from_ascii("a.test.").expect("name"),
        qtype: QType::A,
        qclass: RClass::In,
    });
    msg.answers.push(ResourceRecord {
        name: Name::from_ascii("a.test.").expect("name"),
        qtype: QType::A,
        qclass: RClass::In,
        ttl: 60,
        data: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    });
    let bytes = encode::encode_message(&msg).expect("encode");
    let back = decode::decode_message(&bytes).expect("decode");
    assert_eq!(back.answers.len(), 1);
    assert!(matches!(back.answers[0].data, RData::A(ip) if ip == Ipv4Addr::new(192,0,2,1)));
}

#[test]
fn encodes_minimal_a_query() {
    let mut msg = Message::default();
    msg.header.id = 0x1234;
    msg.header.flags = 0x0100; // RD=1
    msg.header.set_counts(1, 0, 0, 0);
    msg.questions.push(Question {
        name: Name::from_ascii("example.com.").expect("valid name"),
        qtype: QType::A,
        qclass: RClass::In,
    });
    let bytes = encode::encode_message(&msg).expect("encode");
    // Header (12 bytes) + QNAME(13) + QTYPE(2) + QCLASS(2) = 29
    assert_eq!(bytes.len(), 29);
    assert_eq!(&bytes[0..2], &[0x12, 0x34]);
    assert_eq!(&bytes[2..4], &[0x01, 0x00]);
    assert_eq!(&bytes[4..6], &[0x00, 0x01]); // qdcount=1
    assert_eq!(bytes[12], 7);
    assert_eq!(&bytes[13..20], b"example");
    assert_eq!(bytes[20], 3);
    assert_eq!(&bytes[21..24], b"com");
    assert_eq!(bytes[24], 0);
    assert_eq!(&bytes[25..27], &[0x00, 0x01]); // QTYPE A
    assert_eq!(&bytes[27..29], &[0x00, 0x01]); // QCLASS IN
}
