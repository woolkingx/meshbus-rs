use bytes::Bytes;
use mb_reorder::ReorderBuffer;

#[test]
fn delivers_in_order_when_input_in_order() {
    let mut buf = ReorderBuffer::new(0);
    let out: Vec<_> = buf.insert(0, Bytes::from("a")).collect();
    assert_eq!(out.len(), 1);
    let out: Vec<_> = buf.insert(1, Bytes::from("b")).collect();
    assert_eq!(out.len(), 1);
}

#[test]
fn reorders_out_of_order_input() {
    let mut buf = ReorderBuffer::new(0);
    let out: Vec<_> = buf.insert(2, Bytes::from("c")).collect();
    assert!(out.is_empty(), "frame 2 cannot be delivered before 0,1");
    let out: Vec<_> = buf.insert(0, Bytes::from("a")).collect();
    assert_eq!(out, vec![Bytes::from("a")]);
    let out: Vec<_> = buf.insert(1, Bytes::from("b")).collect();
    assert_eq!(out, vec![Bytes::from("b"), Bytes::from("c")]);
}

#[test]
fn discards_duplicate_seq() {
    let mut buf = ReorderBuffer::new(0);
    let _ = buf.insert(0, Bytes::from("a")).count();
    let out: Vec<_> = buf.insert(0, Bytes::from("a-dup")).collect();
    assert!(out.is_empty());
}
