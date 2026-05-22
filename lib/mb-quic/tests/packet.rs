//! RFC 9000 packet-framing vectors: varints, packet numbers, headers.

use mb_quic::Version;
use mb_quic::packet::{
    ConnectionId, LongHeader, LongType, decode_packet_number, decode_varint, encode_packet_number,
    encode_varint, packet_number_len, parse_long_header, parse_short_header_dcid, varint_len,
    write_long_header,
};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn varint_rfc9000_appendix_a1_vectors() {
    // (wire bytes, decoded value) from RFC 9000 Appendix A.1.
    let cases: &[(&str, u64)] = &[
        ("c2197c5eff14e88c", 151_288_809_941_952_652),
        ("9d7f3e7d", 494_878_333),
        ("7bbd", 15_293),
        ("25", 37),
    ];
    for (wire, value) in cases {
        let bytes = hex(wire);
        let (got, n) = decode_varint(&bytes).unwrap();
        assert_eq!(got, *value, "decode {wire}");
        assert_eq!(n, bytes.len(), "consumed {wire}");
        let mut out = Vec::new();
        encode_varint(&mut out, *value);
        assert_eq!(out, bytes, "re-encode {wire}");
        assert_eq!(varint_len(*value), bytes.len(), "varint_len {wire}");
    }
}

#[test]
fn varint_short_buffer_is_rejected() {
    // 4-byte prefix but only 2 bytes present.
    assert!(decode_varint(&[0x9d, 0x7f]).is_err());
    assert!(decode_varint(&[]).is_err());
}

#[test]
fn packet_number_encode_rfc9000_appendix_a2() {
    // full pn 0xac5c02, largest acked 0xabe8b3 -> 2 bytes 0x5c02.
    let full = 0x00ac_5c02u64;
    let acked = 0x00ab_e8b3u64;
    let n = packet_number_len(full, Some(acked));
    assert_eq!(n, 2);
    let mut out = Vec::new();
    encode_packet_number(&mut out, full, n);
    assert_eq!(out, vec![0x5c, 0x02]);
}

#[test]
fn packet_number_decode_rfc9000_appendix_a3() {
    // largest 0xa82f30ea, truncated 0x9b32, 16 bits -> 0xa82f9b32.
    let got = decode_packet_number(0xa82f_30ea, 0x9b32, 16);
    assert_eq!(got, 0xa82f_9b32);
}

#[test]
fn long_header_round_trips() {
    let hdr = LongHeader {
        ty: LongType::Initial,
        version: Version::V1.to_u32(),
        dcid: ConnectionId::new(&hex("8394c8f03e515708")).unwrap(),
        scid: ConnectionId::new(&[0xaa, 0xbb, 0xcc, 0xdd]).unwrap(),
        token: vec![0x01, 0x02, 0x03],
    };
    let mut out = Vec::new();
    write_long_header(&mut out, &hdr, 0x03);
    let (parsed, lo, _off) = parse_long_header(&out).unwrap();
    assert_eq!(parsed.ty, LongType::Initial);
    assert_eq!(parsed.version, Version::V1.to_u32());
    assert_eq!(parsed.dcid, hdr.dcid);
    assert_eq!(parsed.scid, hdr.scid);
    assert_eq!(parsed.token, hdr.token);
    assert_eq!(lo, 0x03);
}

#[test]
fn handshake_long_header_has_no_token() {
    let hdr = LongHeader {
        ty: LongType::Handshake,
        version: Version::V1.to_u32(),
        dcid: ConnectionId::new(&[0x11, 0x22]).unwrap(),
        scid: ConnectionId::new(&[0x33]).unwrap(),
        token: Vec::new(),
    };
    let mut out = Vec::new();
    write_long_header(&mut out, &hdr, 0x00);
    let (parsed, _lo, _off) = parse_long_header(&out).unwrap();
    assert_eq!(parsed.ty, LongType::Handshake);
    assert!(parsed.token.is_empty());
}

#[test]
fn short_header_dcid_is_parsed() {
    let dcid = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33];
    let mut buf = vec![0x40];
    buf.extend_from_slice(&dcid);
    buf.extend_from_slice(&[0x99, 0x98]); // protected pn + payload
    let (cid, off) = parse_short_header_dcid(&buf, dcid.len()).unwrap();
    assert_eq!(cid.as_slice(), &dcid);
    assert_eq!(off, 1 + dcid.len());
}

#[test]
fn version_wire_mapping_is_exact() {
    assert_eq!(Version::V1.to_u32(), 0x0000_0001);
    assert_eq!(Version::from_u32(0x0000_0001), Some(Version::V1));
    assert_eq!(Version::from_u32(0x0000_0002), None);
    assert_eq!(Version::from_u32(0xff00_0020), None);
}
