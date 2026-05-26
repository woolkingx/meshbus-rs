use super::*;

#[test]
fn recv_batch_scratch_reuses_packet_buffers() {
    let mut scratch = RecvBatchScratch::new();
    let before = scratch.buffer_ptrs_for_test();
    scratch.prepare_for_recv();
    scratch.prepare_for_recv();
    assert_eq!(scratch.buffer_ptrs_for_test(), before);
}
