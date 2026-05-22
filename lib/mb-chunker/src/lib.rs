//! Stream → Frame chunking with monotonic sequence.

use bytes::Bytes;

#[derive(Debug, Clone)]
pub struct Chunk {
    pub seq: u64,
    pub payload: Bytes,
}

pub struct Chunker {
    next_seq: u64,
}

impl Chunker {
    pub fn new(start_seq: u64) -> Self {
        Self {
            next_seq: start_seq,
        }
    }
    pub fn next_frame(&mut self, payload: Bytes) -> Chunk {
        let seq = self.next_seq;
        self.next_seq += 1;
        Chunk { seq, payload }
    }
}
