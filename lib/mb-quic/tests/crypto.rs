//! RFC 9001 Appendix A.1 Initial-secret / key / IV / header-protection vectors,
//! plus a native AES-128-GCM seal/open round trip.

use mb_quic::Version;
use mb_quic::crypto::{PacketKeys, initial_secret};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// RFC 9001 Appendix A.1: client DCID 0x8394c8f03e515708.
const DCID: &str = "8394c8f03e515708";

#[test]
fn client_initial_secret_matches_rfc9001() {
    let dcid = hex(DCID);
    let got = initial_secret(&dcid, true, Version::V1);
    assert_eq!(
        got,
        hex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
    );
}

#[test]
fn server_initial_secret_matches_rfc9001() {
    let dcid = hex(DCID);
    let got = initial_secret(&dcid, false, Version::V1);
    assert_eq!(
        got,
        hex("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b")
    );
}

#[test]
fn client_initial_key_iv_hp_match_rfc9001() {
    let secret = hex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea");
    let (key, iv, hp) = PacketKeys::initial_material(&secret);
    assert_eq!(key, hex("1f369613dd76d5467730efcbe3b1a22d"), "client key");
    assert_eq!(iv, hex("fa044b2f42a3fd3b46fb255c"), "client iv");
    assert_eq!(hp, hex("9f50449e04a0e810283a1e9933adedd2"), "client hp");
}

#[test]
fn server_initial_key_iv_hp_match_rfc9001() {
    let secret = hex("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b");
    let (key, iv, hp) = PacketKeys::initial_material(&secret);
    assert_eq!(key, hex("cf3a5331653c364c88f0f379b6067e37"), "server key");
    assert_eq!(iv, hex("0ac1493ca1905853b0bba03e"), "server iv");
    assert_eq!(hp, hex("c206b8d9b9f0f37644430b490eeaa314"), "server hp");
}

#[test]
fn native_aead_seal_open_round_trips() {
    let dcid = hex(DCID);
    let secret = initial_secret(&dcid, true, Version::V1);
    let keys = PacketKeys::from_initial_secret(&secret);
    let header = vec![0xc3, 0x00, 0x00, 0x00, 0x01, 0x08];
    let plaintext = b"the quick brown fox jumps over the lazy dog".to_vec();
    let mut buf = plaintext.clone();
    keys.seal(42, &header, &mut buf).unwrap();
    assert!(buf.len() > plaintext.len(), "tag appended");
    let opened = keys.open(42, &header, &mut buf).unwrap().to_vec();
    assert_eq!(opened, plaintext);
}

#[test]
fn native_aead_open_rejects_wrong_packet_number() {
    let dcid = hex(DCID);
    let secret = initial_secret(&dcid, false, Version::V1);
    let keys = PacketKeys::from_initial_secret(&secret);
    let header = vec![0x40, 0x01, 0x02];
    let mut buf = b"payload".to_vec();
    keys.seal(7, &header, &mut buf).unwrap();
    assert!(keys.open(8, &header, &mut buf).is_err());
}

#[test]
fn header_mask_is_deterministic_and_five_bytes() {
    let secret = initial_secret(&hex(DCID), true, Version::V1);
    let keys = PacketKeys::from_initial_secret(&secret);
    let sample = hex("d1b1c98dd7689fb8ec11d242b123dc9b");
    let m1 = keys.header_mask(&sample).unwrap();
    let m2 = keys.header_mask(&sample).unwrap();
    assert_eq!(m1, m2);
    assert_eq!(m1.len(), 5);
}
