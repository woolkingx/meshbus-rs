//! RFC 9002 loss detection and congestion control.
//!
//! Time is injected as a monotonic microsecond counter so the engine stays
//! sans-I/O and deterministically testable. Three packet-number spaces share
//! one RTT estimator and one NewReno congestion controller (RFC 9002 §B).

use std::collections::BTreeMap;

use crate::frame::AckRange;

const GRANULARITY_US: u64 = 1_000;
const PACKET_THRESHOLD: u64 = 3;
const TIME_THRESHOLD_NUM: u64 = 9;
const TIME_THRESHOLD_DEN: u64 = 8;
const INITIAL_RTT_US: u64 = 333_000;
const MAX_DATAGRAM: u64 = 1_200;
const INITIAL_WINDOW: u64 = 10 * MAX_DATAGRAM;
const MIN_WINDOW: u64 = 2 * MAX_DATAGRAM;

/// Encryption-level index for the three packet-number spaces.
pub const SPACES: usize = 3;

/// RFC 9002 §5 RTT estimator.
#[derive(Clone, Debug)]
pub struct RttEstimator {
    latest: u64,
    min: u64,
    smoothed: u64,
    rttvar: u64,
    sampled: bool,
}

impl Default for RttEstimator {
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

impl RttEstimator {
    /// Smoothed RTT estimate (microseconds).
    pub fn smoothed(&self) -> u64 {
        self.smoothed
    }

    /// RFC 9002 §5.2/§5.3: fold one RTT sample, adjusting for ACK delay.
    pub fn on_sample(&mut self, rtt: u64, ack_delay: u64, max_ack_delay: u64) {
        self.latest = rtt;
        if !self.sampled {
            self.min = rtt;
            self.smoothed = rtt;
            self.rttvar = rtt / 2;
            self.sampled = true;
            return;
        }
        self.min = self.min.min(rtt);
        let mut adjusted = rtt;
        let delay = ack_delay.min(max_ack_delay);
        if rtt >= self.min + delay {
            adjusted = rtt - delay;
        }
        let var_sample = self.smoothed.abs_diff(adjusted);
        self.rttvar = (self.rttvar * 3 + var_sample) / 4;
        self.smoothed = (self.smoothed * 7 + adjusted) / 8;
    }

    /// RFC 9002 §6.2.1 PTO duration before exponential backoff.
    pub fn pto_base(&self, max_ack_delay: u64) -> u64 {
        self.smoothed + (4 * self.rttvar).max(GRANULARITY_US) + max_ack_delay
    }
}

/// One in-flight or pending-acknowledgement packet.
#[derive(Clone, Debug)]
pub struct SentPacket {
    /// Packet number within its space.
    pub pn: u64,
    /// Send timestamp (microseconds).
    pub time_sent: u64,
    /// Wire size (bytes) for congestion accounting.
    pub size: u64,
    /// Whether the packet elicits an ACK (RFC 9002 §2).
    pub ack_eliciting: bool,
}

/// RFC 9002 §7 NewReno congestion controller.
#[derive(Clone, Debug)]
pub struct Congestion {
    cwnd: u64,
    bytes_in_flight: u64,
    ssthresh: u64,
    recovery_start: u64,
}

impl Default for Congestion {
    fn default() -> Self {
        Self {
            cwnd: INITIAL_WINDOW,
            bytes_in_flight: 0,
            ssthresh: u64::MAX,
            recovery_start: 0,
        }
    }
}

impl Congestion {
    /// Current congestion window (bytes).
    pub fn window(&self) -> u64 {
        self.cwnd
    }

    /// Bytes currently considered in flight.
    pub fn in_flight(&self) -> u64 {
        self.bytes_in_flight
    }

    /// Spare congestion budget available to send now.
    pub fn available(&self) -> u64 {
        self.cwnd.saturating_sub(self.bytes_in_flight)
    }

    fn on_sent(&mut self, size: u64) {
        self.bytes_in_flight += size;
    }

    fn on_acked(&mut self, size: u64) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(size);
        if self.cwnd < self.ssthresh {
            self.cwnd += size; // slow start
        } else {
            self.cwnd += MAX_DATAGRAM * size / self.cwnd.max(1); // congestion avoidance
        }
    }

    /// RFC 9002 §7.3.2: enter recovery once per loss epoch (half cwnd).
    fn on_loss(&mut self, lost_bytes: u64, largest_lost_sent: u64) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(lost_bytes);
        if largest_lost_sent <= self.recovery_start {
            return;
        }
        self.recovery_start = largest_lost_sent;
        self.ssthresh = (self.cwnd / 2).max(MIN_WINDOW);
        self.cwnd = self.ssthresh;
    }
}

#[derive(Default)]
struct SpaceRecovery {
    sent: BTreeMap<u64, SentPacket>,
    largest_acked: Option<u64>,
    loss_time: Option<u64>,
    last_ack_eliciting: Option<u64>,
}

/// RFC 9002 loss-recovery state across all three packet-number spaces.
pub struct LossRecovery {
    spaces: [SpaceRecovery; SPACES],
    rtt: RttEstimator,
    cc: Congestion,
    pto_count: u32,
    max_ack_delay: u64,
}

impl Default for LossRecovery {
    fn default() -> Self {
        Self {
            spaces: Default::default(),
            rtt: RttEstimator::default(),
            cc: Congestion::default(),
            pto_count: 0,
            max_ack_delay: 25_000,
        }
    }
}

impl LossRecovery {
    /// RTT estimator (read-only).
    pub fn rtt(&self) -> &RttEstimator {
        &self.rtt
    }

    /// Congestion controller (read-only).
    pub fn congestion(&self) -> &Congestion {
        &self.cc
    }

    /// Consecutive PTO count (RFC 9002 §6.2 backoff exponent).
    pub fn pto_count(&self) -> u32 {
        self.pto_count
    }

    /// Record a transmitted packet (RFC 9002 §A.5).
    pub fn on_packet_sent(&mut self, space: usize, pkt: SentPacket) {
        self.cc.on_sent(pkt.size);
        let s = &mut self.spaces[space];
        if pkt.ack_eliciting {
            s.last_ack_eliciting = Some(pkt.time_sent);
        }
        s.sent.insert(pkt.pn, pkt);
    }

    fn acked_numbers(largest: u64, first_range: u64, ranges: &[AckRange]) -> Vec<(u64, u64)> {
        let mut blocks = Vec::new();
        let mut hi = largest;
        let mut lo = largest - first_range;
        blocks.push((lo, hi));
        for r in ranges {
            if lo < r.gap + 2 {
                break;
            }
            hi = lo - r.gap - 2;
            lo = hi - r.range;
            blocks.push((lo, hi));
        }
        blocks
    }

    /// Process an ACK frame (RFC 9002 §A.6/§5). Returns the newly acknowledged
    /// packets and updates RTT plus congestion state.
    pub fn on_ack(
        &mut self,
        space: usize,
        largest: u64,
        first_range: u64,
        ranges: &[AckRange],
        ack_delay: u64,
        now: u64,
    ) -> Vec<SentPacket> {
        let blocks = Self::acked_numbers(largest, first_range, ranges);
        let mut newly = Vec::new();
        {
            let s = &mut self.spaces[space];
            s.largest_acked = Some(s.largest_acked.map_or(largest, |v| v.max(largest)));
            for (lo, hi) in blocks {
                for pn in lo..=hi {
                    if let Some(p) = s.sent.remove(&pn) {
                        newly.push(p);
                    }
                }
            }
        }
        if let Some(newest) = newly
            .iter()
            .filter(|p| p.ack_eliciting)
            .max_by_key(|p| p.pn)
        {
            if newest.pn == largest {
                let rtt = now.saturating_sub(newest.time_sent);
                self.rtt.on_sample(rtt, ack_delay, self.max_ack_delay);
            }
        }
        for p in &newly {
            self.cc.on_acked(p.size);
        }
        if !newly.is_empty() {
            self.pto_count = 0;
        }
        newly
    }

    /// RFC 9002 §6.1 packet-threshold + time-threshold loss detection.
    pub fn detect_lost(&mut self, space: usize, now: u64) -> Vec<SentPacket> {
        let largest = match self.spaces[space].largest_acked {
            Some(v) => v,
            None => return Vec::new(),
        };
        let threshold = (self.rtt.latest.max(self.rtt.smoothed) * TIME_THRESHOLD_NUM
            / TIME_THRESHOLD_DEN)
            .max(GRANULARITY_US);
        let mut lost = Vec::new();
        let mut next_loss_time: Option<u64> = None;
        let s = &mut self.spaces[space];
        let pns: Vec<u64> = s.sent.keys().copied().collect();
        for pn in pns {
            if pn >= largest {
                continue;
            }
            let sent_time = s.sent[&pn].time_sent;
            let time_lost = sent_time + threshold;
            if largest - pn >= PACKET_THRESHOLD || now >= time_lost {
                lost.push(s.sent.remove(&pn).unwrap());
            } else {
                next_loss_time = Some(next_loss_time.map_or(time_lost, |t: u64| t.min(time_lost)));
            }
        }
        s.loss_time = next_loss_time;
        if !lost.is_empty() {
            let bytes = lost.iter().map(|p| p.size).sum();
            let largest_lost = lost.iter().map(|p| p.time_sent).max().unwrap();
            self.cc.on_loss(bytes, largest_lost);
        }
        lost
    }

    /// RFC 9002 §6.2 PTO/loss timer deadline (earliest across spaces).
    pub fn loss_timer(&self) -> Option<u64> {
        let loss = self.spaces.iter().filter_map(|s| s.loss_time).min();
        if loss.is_some() {
            return loss;
        }
        let last = self
            .spaces
            .iter()
            .filter_map(|s| s.last_ack_eliciting)
            .max()?;
        let pto = self.rtt.pto_base(self.max_ack_delay) << self.pto_count;
        Some(last + pto)
    }

    /// Arm the next PTO (RFC 9002 §6.2 exponential backoff).
    pub fn on_pto_expired(&mut self) {
        self.pto_count += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkt(pn: u64, t: u64) -> SentPacket {
        SentPacket {
            pn,
            time_sent: t,
            size: 1200,
            ack_eliciting: true,
        }
    }

    #[test]
    fn first_rtt_sample_seeds_estimator() {
        let mut lr = LossRecovery::default();
        lr.on_packet_sent(2, pkt(0, 0));
        let acked = lr.on_ack(2, 0, 0, &[], 0, 100_000);
        assert_eq!(acked.len(), 1);
        assert_eq!(lr.rtt().smoothed(), 100_000);
    }

    #[test]
    fn packet_threshold_declares_loss() {
        let mut lr = LossRecovery::default();
        for pn in 0..=3 {
            lr.on_packet_sent(2, pkt(pn, pn * 1_000));
        }
        lr.on_ack(2, 3, 0, &[], 0, 50_000);
        let lost = lr.detect_lost(2, 50_000);
        assert_eq!(lost.iter().map(|p| p.pn).collect::<Vec<_>>(), vec![0]);
    }

    #[test]
    fn time_threshold_declares_loss() {
        let mut lr = LossRecovery::default();
        lr.on_packet_sent(2, pkt(0, 0));
        lr.on_packet_sent(2, pkt(1, 1_000));
        lr.on_ack(2, 1, 0, &[], 0, 1_000);
        let lost = lr.detect_lost(2, 10_000_000);
        assert_eq!(lost.len(), 1);
        assert_eq!(lost[0].pn, 0);
    }

    #[test]
    fn ack_clears_in_flight_and_grows_window_in_slow_start() {
        let mut lr = LossRecovery::default();
        let base = lr.congestion().window();
        lr.on_packet_sent(2, pkt(0, 0));
        assert_eq!(lr.congestion().in_flight(), 1200);
        lr.on_ack(2, 0, 0, &[], 0, 30_000);
        assert_eq!(lr.congestion().in_flight(), 0);
        assert_eq!(lr.congestion().window(), base + 1200);
    }

    #[test]
    fn loss_halves_congestion_window() {
        let mut lr = LossRecovery::default();
        for pn in 0..=4 {
            lr.on_packet_sent(2, pkt(pn, pn * 1_000));
        }
        let before = lr.congestion().window();
        lr.on_ack(2, 4, 0, &[], 0, 30_000);
        lr.detect_lost(2, 30_000);
        assert!(lr.congestion().window() < before);
        assert!(lr.congestion().window() >= MIN_WINDOW);
    }

    #[test]
    fn pto_backoff_increments_and_resets_on_ack() {
        let mut lr = LossRecovery::default();
        lr.on_packet_sent(2, pkt(0, 0));
        lr.on_pto_expired();
        assert_eq!(lr.pto_count(), 1);
        lr.on_ack(2, 0, 0, &[], 0, 50_000);
        assert_eq!(lr.pto_count(), 0);
    }

    #[test]
    fn multi_range_ack_acknowledges_disjoint_blocks() {
        let mut lr = LossRecovery::default();
        for pn in 0..=4 {
            lr.on_packet_sent(2, pkt(pn, 0));
        }
        // ack 4, gap skips 2..=3, then range covers 0..=1.
        let acked = lr.on_ack(2, 4, 0, &[AckRange { gap: 1, range: 1 }], 0, 1_000);
        let mut pns: Vec<u64> = acked.iter().map(|p| p.pn).collect();
        pns.sort_unstable();
        assert_eq!(pns, vec![0, 1, 4]);
    }
}
