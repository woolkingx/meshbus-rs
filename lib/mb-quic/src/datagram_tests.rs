use super::*;

#[test]
fn outgoing_is_fifo_and_bounded() {
    let mut q = DatagramQueue::new(2);
    assert!(q.queue_outgoing(b"a".to_vec()));
    assert!(q.queue_outgoing(b"b".to_vec()));
    assert!(
        !q.queue_outgoing(b"c".to_vec()),
        "queue full drops datagram"
    );
    assert_eq!(q.take_outgoing(16), Some(b"a".to_vec()));
    assert_eq!(q.take_outgoing(16), Some(b"b".to_vec()));
    assert_eq!(q.take_outgoing(16), None);
}

#[test]
fn oversized_datagram_is_dropped_not_fragmented() {
    let mut q = DatagramQueue::new(4);
    q.queue_outgoing(vec![0u8; 100]);
    q.queue_outgoing(b"fits".to_vec());
    assert_eq!(q.take_outgoing(8), Some(b"fits".to_vec()));
}

#[test]
fn incoming_evicts_oldest_when_full() {
    let mut q = DatagramQueue::new(2);
    q.ingest(b"1".to_vec());
    q.ingest(b"2".to_vec());
    q.ingest(b"3".to_vec());
    assert_eq!(q.recv(), Some(b"2".to_vec()));
    assert_eq!(q.recv(), Some(b"3".to_vec()));
    assert_eq!(q.recv(), None);
}
