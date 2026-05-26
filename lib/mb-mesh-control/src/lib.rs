//! Pure Mesh Protocol send-budget, RTT, loss, and repair control.
//!
//! This borrows QUIC's proven control primitives without importing QUIC
//! connection or stream ownership into Mesh Protocol.

use std::collections::BTreeMap;

use mb_proto_mesh::AckNack;

const GRANULARITY_US: u64 = 1_000;
const INITIAL_RTT_US: u64 = 333_000;
const MAX_ACK_DELAY_US: u64 = 25_000;
const MAX_DATAGRAM_BYTES: u64 = 1_200;
const INITIAL_WINDOW_BYTES: u64 = 10 * MAX_DATAGRAM_BYTES;
const MIN_WINDOW_BYTES: u64 = 2 * MAX_DATAGRAM_BYTES;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InflightPackage {
    pub seq: u64,
    pub sent_at_us: u64,
    pub size: u64,
    pub ack_eliciting: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AckUpdate {
    pub acked_seqs: Vec<u64>,
    pub lost_seqs: Vec<u64>,
}

#[derive(Clone, Debug)]
pub struct MeshRttEstimator {
    latest: u64,
    min: u64,
    smoothed: u64,
    rttvar: u64,
    sampled: bool,
}

impl Default for MeshRttEstimator {
    fn default() -> Self {
        Self {
            latest: INITIAL_RTT_US,
            min: INITIAL_RTT_US,
            smoothed: INITIAL_RTT_US,
            rttvar: INITIAL_RTT_US / 2,
            sampled: false,
        }
    }
}

impl MeshRttEstimator {
    pub fn smoothed(&self) -> u64 {
        self.smoothed
    }

    pub fn rttvar(&self) -> u64 {
        self.rttvar
    }

    fn on_sample(&mut self, rtt: u64, ack_delay: u64) {
        self.latest = rtt;
        if !self.sampled {
            self.min = rtt;
            self.smoothed = rtt;
            self.rttvar = rtt / 2;
            self.sampled = true;
            return;
        }
        self.min = self.min.min(rtt);
        let delay = ack_delay.min(MAX_ACK_DELAY_US);
        let adjusted = if rtt >= self.min + delay {
            rtt - delay
        } else {
            rtt
        };
        let var_sample = self.smoothed.abs_diff(adjusted);
        self.rttvar = (self.rttvar * 3 + var_sample) / 4;
        self.smoothed = (self.smoothed * 7 + adjusted) / 8;
    }

    fn pto_base(&self) -> u64 {
        self.smoothed + (4 * self.rttvar).max(GRANULARITY_US) + MAX_ACK_DELAY_US
    }
}

#[derive(Clone, Debug)]
pub struct MeshPathController {
    rtt: MeshRttEstimator,
    cwnd: u64,
    bytes_in_flight: u64,
    pto_count: u32,
    inflight: BTreeMap<u64, InflightPackage>,
    last_ack_eliciting_sent_at: Option<u64>,
}

impl Default for MeshPathController {
    fn default() -> Self {
        Self {
            rtt: MeshRttEstimator::default(),
            cwnd: INITIAL_WINDOW_BYTES,
            bytes_in_flight: 0,
            pto_count: 0,
            inflight: BTreeMap::new(),
            last_ack_eliciting_sent_at: None,
        }
    }
}

impl MeshPathController {
    pub fn rtt(&self) -> &MeshRttEstimator {
        &self.rtt
    }

    pub fn congestion_window(&self) -> u64 {
        self.cwnd
    }

    pub fn bytes_in_flight(&self) -> u64 {
        self.bytes_in_flight
    }

    pub fn pto_count(&self) -> u32 {
        self.pto_count
    }

    pub fn send_budget(&self) -> u64 {
        self.cwnd.saturating_sub(self.bytes_in_flight)
    }

    pub fn on_sent(&mut self, package: InflightPackage) {
        if package.ack_eliciting {
            self.last_ack_eliciting_sent_at = Some(package.sent_at_us);
            self.bytes_in_flight = self.bytes_in_flight.saturating_add(package.size);
        }
        self.inflight.insert(package.seq, package);
    }

    pub fn on_ack(&mut self, ack: &AckNack, ack_delay_us: u64, now_us: u64) -> AckUpdate {
        let mut update = AckUpdate::default();
        let missing = |seq: u64| {
            ack.missing_ranges
                .iter()
                .any(|range| seq >= range.start && seq <= range.end)
        };

        let seqs: Vec<u64> = self.inflight.keys().copied().collect();
        for seq in seqs {
            if missing(seq) {
                if let Some(package) = self.inflight.remove(&seq) {
                    self.bytes_in_flight = self.bytes_in_flight.saturating_sub(package.size);
                    update.lost_seqs.push(seq);
                }
            } else if let Some(package) = self.inflight.remove(&seq) {
                if package.ack_eliciting {
                    self.bytes_in_flight = self.bytes_in_flight.saturating_sub(package.size);
                    self.cwnd = self.cwnd.saturating_add(package.size);
                    let rtt = now_us.saturating_sub(package.sent_at_us);
                    self.rtt.on_sample(rtt, ack_delay_us);
                }
                update.acked_seqs.push(seq);
            }
        }

        if !update.acked_seqs.is_empty() {
            self.pto_count = 0;
        }
        update
    }

    pub fn loss_timer(&self) -> Option<u64> {
        let last = self.last_ack_eliciting_sent_at?;
        Some(last + (self.rtt.pto_base() << self.pto_count))
    }

    pub fn on_pto_expired(&mut self) {
        self.pto_count = self.pto_count.saturating_add(1);
        self.cwnd = self.cwnd.max(MIN_WINDOW_BYTES);
    }
}
