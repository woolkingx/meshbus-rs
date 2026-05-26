//! Delivery coordinate and per-egress delivery policy.

use mb_proto_mesh::{AckNack, DeliveryMode, ReceiverMouth};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Shared, interior-mutable outbound delivery coordinate for one datagram
/// session. A peer PortOpen rotates the udp destination here and nowhere else:
/// session id, `next_seq`, route group, and family identity live in separate
/// session fields and are provably untouched by a coordinate rotation.
pub(crate) struct DeliveryCoord {
    addr: std::sync::Mutex<SocketAddr>,
    pub(crate) epoch: AtomicU64,
}

impl DeliveryCoord {
    pub(crate) fn new(addr: SocketAddr) -> Arc<Self> {
        Arc::new(Self {
            addr: std::sync::Mutex::new(addr),
            epoch: AtomicU64::new(0),
        })
    }

    pub(crate) fn addr(&self) -> SocketAddr {
        *self.addr.lock().unwrap()
    }

    /// Apply a peer PortOpen. Updates only the udp coordinate and its epoch.
    /// A strictly-older epoch is rejected (stale rotation). Make-before-break:
    /// the new coordinate is live the instant this returns true.
    pub(crate) fn apply_port_open(&self, mouth: &ReceiverMouth) -> bool {
        let Ok(new_addr) = mouth.udp_addr.parse::<SocketAddr>() else {
            return false;
        };
        if mouth.epoch < self.epoch.load(Ordering::Relaxed) {
            return false;
        }
        *self.addr.lock().unwrap() = new_addr;
        self.epoch.store(mouth.epoch, Ordering::Relaxed);
        true
    }
}

/// Bounded retransmit ring depth for `DeliveryMode::Repair`. One generation of
/// in-flight data packages; older entries fall off the front.
const REPAIR_RING_DEPTH: usize = 64;

/// Clamp config-supplied replicate fanout into a bounded duplicate-send count.
/// 0 is meaningless (no send), > 4 is unbounded amplification; both are
/// rejected to the nearest legal value.
pub(crate) fn replicate_count(fanout: u8) -> usize {
    (fanout as usize).clamp(1, 4)
}

/// Which configured mouth a striped DataPackage rides, by seq. Round-robin so
/// consecutive packages spread across mouths; with one mouth it is always 0
/// (Stripe degrades to Steer). Family identity/order is unaffected — the
/// receiver `FamilyReorderState` restores order regardless of arrival mouth.
/// Contract surface proven by `policy_tests`; multi-mouth wiring is the
/// documented D-M7.5 follow-up (egress holds one rotating coord today).
#[allow(dead_code)]
pub(crate) fn stripe_index(seq: u64, mouth_count: usize) -> usize {
    if mouth_count <= 1 {
        0
    } else {
        (seq as usize) % mouth_count
    }
}

/// Per-egress delivery policy. It changes only delivery coordinates (how the
/// one logical event stream maps onto sends); it never alters session id,
/// family id, seq, route_group, or target endpoint.
pub(crate) struct EgressPolicy {
    mode: DeliveryMode,
    replicate_fanout: u8,
    // Probe budget mechanism is test-proven (`policy_tests`); the periodic
    // probe sender loop is the documented D-M7.5 follow-up.
    #[allow(dead_code)]
    probe_budget: u8,
    #[allow(dead_code)]
    probe_used: AtomicU64,
    retransmit: std::sync::Mutex<std::collections::VecDeque<(u64, Vec<u8>)>>,
}

impl EgressPolicy {
    pub(crate) fn new(mode: DeliveryMode, replicate_fanout: u8, probe_budget: u8) -> Arc<Self> {
        Arc::new(Self {
            mode,
            replicate_fanout,
            probe_budget,
            probe_used: AtomicU64::new(0),
            retransmit: std::sync::Mutex::new(std::collections::VecDeque::new()),
        })
    }

    /// Stable wire policy id stamped on every event this egress wraps.
    pub(crate) fn policy_id(&self) -> &'static str {
        self.mode.policy_id()
    }

    /// How many copies of one logical event to send. Replicate fans out a
    /// bounded duplicate send; every other mode sends exactly once.
    pub(crate) fn send_copies(&self) -> usize {
        match self.mode {
            DeliveryMode::Replicate => replicate_count(self.replicate_fanout),
            _ => 1,
        }
    }

    /// Remember a data send so an inbound AckNack can retransmit it. Only used
    /// by Repair; the ring is bounded so it never grows without limit.
    pub(crate) fn remember(&self, seq: u64, bytes: &[u8]) {
        if self.mode != DeliveryMode::Repair || seq == 0 {
            return;
        }
        let mut ring = self.retransmit.lock().unwrap();
        ring.push_back((seq, bytes.to_vec()));
        while ring.len() > REPAIR_RING_DEPTH {
            ring.pop_front();
        }
    }

    /// Buffered (seq, bytes) the peer's AckNack says it is still missing.
    pub(crate) fn to_retransmit(&self, ack: &AckNack) -> Vec<Vec<u8>> {
        let ring = self.retransmit.lock().unwrap();
        ring.iter()
            .filter(|(seq, _)| {
                ack.missing_ranges
                    .iter()
                    .any(|r| *seq >= r.start && *seq <= r.end)
            })
            .map(|(_, bytes)| bytes.clone())
            .collect()
    }

    /// Budget gate for probe sends. Returns true at most `probe_budget` times;
    /// a probe never creates route truth, so an exhausted budget simply skips.
    #[allow(dead_code)]
    pub(crate) fn take_probe_token(&self) -> bool {
        let used = self.probe_used.fetch_add(1, Ordering::Relaxed);
        used < self.probe_budget as u64
    }
}
