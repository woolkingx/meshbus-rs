use bytes::Bytes;
use mb_chunker::Chunker;

#[test]
fn assigns_increasing_seq() {
    let mut c = Chunker::new(0);
    let f1 = c.next_frame(Bytes::from("a"));
    let f2 = c.next_frame(Bytes::from("b"));
    assert_eq!(f1.seq, 0);
    assert_eq!(f2.seq, 1);
}

#[test]
fn preserves_payload() {
    let mut c = Chunker::new(0);
    let f = c.next_frame(Bytes::from_static(b"hello"));
    assert_eq!(&f.payload[..], b"hello");
}
