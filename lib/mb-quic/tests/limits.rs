//! Peer-driven allocation caps: a hostile peer must not be able to make frame
//! decode materialize an arbitrarily large `Vec` from one frame.

use mb_quic::Error;
use mb_quic::frame::Frame;
use mb_quic::packet::encode_varint;

const MAX: usize = 1 << 20; // mirrors frame::MAX_FRAME_PAYLOAD

#[test]
fn crypto_frame_rejects_oversize_len() {
    // The buffer actually contains `MAX + 1` payload bytes, so the existing
    // `off + len > buf.len()` short-buffer guard does NOT fire. Only an
    // explicit payload cap can reject this — that is what we assert.
    let over = MAX + 1;
    let mut b = vec![0x06u8];
    encode_varint(&mut b, 0); // offset = 0
    encode_varint(&mut b, over as u64); // len
    b.resize(b.len() + over, 0);
    let r = Frame::decode(&b);
    assert!(
        matches!(r, Err(Error::Malformed(_))),
        "oversize crypto len must be rejected before to_vec, got {r:?}"
    );
}

#[test]
fn datagram_frame_rejects_oversize_len() {
    let over = MAX + 1;
    let mut b = vec![0x31u8];
    encode_varint(&mut b, over as u64);
    b.resize(b.len() + over, 0);
    let r = Frame::decode(&b);
    assert!(
        matches!(r, Err(Error::Malformed(_))),
        "oversize datagram len must be rejected before to_vec, got {r:?}"
    );
}

#[test]
fn crypto_frame_within_cap_still_decodes() {
    let mut b = vec![0x06u8];
    encode_varint(&mut b, 0);
    encode_varint(&mut b, 4);
    b.extend_from_slice(&[1, 2, 3, 4]);
    let (f, _n) = Frame::decode(&b).expect("in-cap crypto frame must decode");
    assert_eq!(
        f,
        Frame::Crypto {
            offset: 0,
            data: vec![1, 2, 3, 4]
        }
    );
}
