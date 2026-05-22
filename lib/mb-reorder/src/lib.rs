//! Reorder buffer for sequenced byte-stream reconstruction, plus the L5
//! `FamilyReorderState` that owns mesh-event family ordering, dedup, and
//! AckNack feedback without any transport-channel state.

use bytes::Bytes;
use mb_proto_mesh::{AckNack, CloseReasonWire, DataPackage, FamilyId, SeqRange};
use std::collections::BTreeMap;

pub struct ReorderBuffer {
    next: u64,
    pending: BTreeMap<u64, Bytes>,
}

impl ReorderBuffer {
    pub fn new(start_seq: u64) -> Self {
        Self {
            next: start_seq,
            pending: BTreeMap::new(),
        }
    }
    pub fn insert(&mut self, seq: u64, payload: Bytes) -> impl Iterator<Item = Bytes> + '_ {
        if seq >= self.next && !self.pending.contains_key(&seq) {
            self.pending.insert(seq, payload);
        }
        std::iter::from_fn(move || {
            if self.pending.contains_key(&self.next) {
                let v = self
                    .pending
                    .remove(&self.next)
                    .expect("key confirmed present");
                self.next += 1;
                Some(v)
            } else {
                None
            }
        })
    }
    pub fn next_expected(&self) -> u64 {
        self.next
    }
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

/// Max distance above the frontier the u128 bitmap can represent.
const FAMILY_BITMAP_BITS: u64 = 128;

/// Outcome of feeding one `DataPackage` into `FamilyReorderState`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FamilyPushOutcome {
    /// In-order frontier advanced; these packages are ready, lowest seq first.
    Deliver(Vec<DataPackage>),
    /// Stored out-of-order inside an already-known gap region.
    Buffered,
    /// Below the frontier or already buffered; dropped.
    Duplicate,
    /// Stored out-of-order and it extended the gap frontier; feedback follows.
    Gap(AckNack),
    /// Distance beyond the bounded reorder window; family is now terminal.
    WindowOverflow(AckNack),
}

/// L5 endpoint reconstruction and legality state for one event family.
/// No transport-channel state: it owns ordering and repair feedback only.
#[derive(Debug, Clone)]
pub struct FamilyReorderState {
    pub family_id: FamilyId,
    pub next_expected_seq: u64,
    pub received_bitmap: u128,
    pub reorder_window: u16,
    pub repair_deadline_ms: u64,
    buffer: BTreeMap<u64, DataPackage>,
    highest_seen: Option<u64>,
    closed: Option<CloseReasonWire>,
}

impl FamilyReorderState {
    pub fn new(
        family_id: FamilyId,
        start_seq: u64,
        reorder_window: u16,
        repair_deadline_ms: u64,
    ) -> Self {
        Self {
            family_id,
            next_expected_seq: start_seq,
            received_bitmap: 0,
            reorder_window,
            repair_deadline_ms,
            buffer: BTreeMap::new(),
            highest_seen: None,
            closed: None,
        }
    }

    fn window(&self) -> u64 {
        (self.reorder_window as u64).min(FAMILY_BITMAP_BITS)
    }

    fn rebuild_bitmap(&mut self) {
        let mut bits: u128 = 0;
        for &k in self.buffer.keys() {
            let d = k - self.next_expected_seq;
            if d < FAMILY_BITMAP_BITS {
                bits |= 1u128 << d;
            }
        }
        self.received_bitmap = bits;
    }

    pub fn push_package(&mut self, package: DataPackage) -> FamilyPushOutcome {
        if self.closed.is_some() {
            return FamilyPushOutcome::WindowOverflow(self.ack_snapshot());
        }
        let seq = package.seq;
        if seq < self.next_expected_seq || self.buffer.contains_key(&seq) {
            return FamilyPushOutcome::Duplicate;
        }
        if seq == self.next_expected_seq {
            let mut delivered = vec![package];
            self.next_expected_seq += 1;
            while let Some(next) = self.buffer.remove(&self.next_expected_seq) {
                delivered.push(next);
                self.next_expected_seq += 1;
            }
            self.rebuild_bitmap();
            return FamilyPushOutcome::Deliver(delivered);
        }
        if seq - self.next_expected_seq >= self.window() {
            self.closed = Some(CloseReasonWire::ProtocolError);
            return FamilyPushOutcome::WindowOverflow(self.ack_snapshot());
        }
        let extended_frontier = self.highest_seen.is_none_or(|h| seq > h);
        self.buffer.insert(seq, package);
        self.highest_seen = Some(self.highest_seen.map_or(seq, |h| h.max(seq)));
        self.rebuild_bitmap();
        if extended_frontier {
            FamilyPushOutcome::Gap(self.ack_snapshot())
        } else {
            FamilyPushOutcome::Buffered
        }
    }

    pub fn ack_snapshot(&self) -> AckNack {
        let mut missing_ranges = Vec::new();
        if let Some(highest) = self.highest_seen {
            let mut run_start: Option<u64> = None;
            for seq in self.next_expected_seq..=highest {
                if self.buffer.contains_key(&seq) {
                    if let Some(start) = run_start.take() {
                        missing_ranges.push(SeqRange {
                            start,
                            end: seq - 1,
                        });
                    }
                } else if run_start.is_none() {
                    run_start = Some(seq);
                }
            }
            if let Some(start) = run_start {
                missing_ranges.push(SeqRange {
                    start,
                    end: highest,
                });
            }
        }
        AckNack {
            family_id: self.family_id.clone(),
            cumulative_seq: self.next_expected_seq,
            received_bitmap: format!("{:032x}", self.received_bitmap),
            missing_ranges,
        }
    }

    pub fn close_reason(&self) -> Option<CloseReasonWire> {
        self.closed
    }
}
