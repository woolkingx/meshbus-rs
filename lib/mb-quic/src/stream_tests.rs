use super::*;

#[test]
fn stream_id_algebra_matches_rfc9000() {
    let c0 = StreamId::nth(Side::Client, true, 0);
    assert_eq!(c0.0, 0);
    assert_eq!(c0.initiator(), Side::Client);
    assert!(c0.is_bidi());
    let s_uni = StreamId::nth(Side::Server, false, 0);
    assert_eq!(s_uni.0, 0x3);
    assert_eq!(s_uni.initiator(), Side::Server);
    assert!(!s_uni.is_bidi());
}

#[test]
fn recv_stream_reassembles_after_out_of_order_delivery() {
    let mut r = RecvStream::default();
    r.ingest(5, b"world", false);
    assert!(r.read().is_empty(), "gap at 0..5 blocks delivery");
    r.ingest(0, b"hello", false);
    assert_eq!(r.read(), b"helloworld");
}

#[test]
fn recv_stream_ignores_duplicate_and_old_bytes() {
    let mut r = RecvStream::default();
    r.ingest(0, b"abcdef", false);
    assert_eq!(r.read(), b"abcdef");
    r.ingest(0, b"abc", false);
    assert!(r.read().is_empty());
}

#[test]
fn recv_stream_tracks_fin() {
    let mut r = RecvStream::default();
    r.ingest(0, b"done", true);
    assert_eq!(r.read(), b"done");
    assert!(r.is_finished());
}

#[test]
fn send_stream_chunks_and_marks_fin_on_last() {
    let mut s = SendStream::default();
    s.write(b"abcdef", true);
    assert_eq!(s.take(4), Some((0, b"abcd".to_vec(), false)));
    assert_eq!(s.take(4), Some((4, b"ef".to_vec(), true)));
    assert_eq!(s.take(4), None);
}

#[test]
fn stream_map_respects_peer_limit_then_grows() {
    let mut m = StreamMap::new(Side::Client, 1, 0);
    assert!(m.open(true).is_some());
    assert!(m.open(true).is_none());
    m.set_peer_max(true, 3);
    assert!(m.open(true).is_some());
    assert_eq!(m.len(), 2);
}

#[test]
fn stream_map_lists_sendable_in_id_order() {
    let mut m = StreamMap::new(Side::Client, 8, 0);
    let a = m.open(true).unwrap();
    let b = m.open(true).unwrap();
    m.entry(b.0).send.write(b"x", false);
    m.entry(a.0).send.write(b"y", false);
    assert_eq!(m.sendable(), vec![a.0, b.0]);
}
