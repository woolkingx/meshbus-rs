//! RFC 9002 loss-recovery and congestion-control behaviour, exercised through
//! the public `mb_quic::recovery` surface (the boundary M6 builds on).

use mb_quic::frame::AckRange;
use mb_quic::recovery::{LossRecovery, SentPacket};

fn pkt(pn: u64, t: u64) -> SentPacket {
    SentPacket {
        pn,
        time_sent: t,
        size: 1200,
        ack_eliciting: true,
    }
}

#[test]
fn ack_processing_clears_in_flight_and_seeds_rtt() {
    let mut lr = LossRecovery::default();
    let base = lr.congestion().window();
    lr.on_packet_sent(2, pkt(0, 0));
    assert_eq!(lr.congestion().in_flight(), 1200);
    let acked = lr.on_ack(2, 0, 0, &[], 0, 80_000);
    assert_eq!(acked.iter().map(|p| p.pn).collect::<Vec<_>>(), vec![0]);
    assert_eq!(lr.congestion().in_flight(), 0);
    assert_eq!(lr.congestion().window(), base + 1200);
    assert_eq!(lr.rtt().smoothed(), 80_000);
}

#[test]
fn disjoint_ack_ranges_are_reconstructed_per_rfc9000() {
    let mut lr = LossRecovery::default();
    for pn in 0..=4 {
        lr.on_packet_sent(2, pkt(pn, 0));
    }
    // largest=4, first_range=0 -> {4}; gap=1,range=1 -> {0,1}; 2,3 stay unacked.
    let acked = lr.on_ack(2, 4, 0, &[AckRange { gap: 1, range: 1 }], 0, 1_000);
    let mut pns: Vec<u64> = acked.iter().map(|p| p.pn).collect();
    pns.sort_unstable();
    assert_eq!(pns, vec![0, 1, 4]);
}

#[test]
fn packet_threshold_then_time_threshold_declare_loss() {
    let mut lr = LossRecovery::default();
    for pn in 0..=3 {
        lr.on_packet_sent(2, pkt(pn, pn * 1_000));
    }
    lr.on_ack(2, 3, 0, &[], 0, 50_000);
    let lost = lr.detect_lost(2, 50_000);
    assert_eq!(lost.iter().map(|p| p.pn).collect::<Vec<_>>(), vec![0]);
}

#[test]
fn loss_halves_window_and_pto_backoff_resets_on_ack() {
    let mut lr = LossRecovery::default();
    for pn in 0..=4 {
        lr.on_packet_sent(2, pkt(pn, pn * 1_000));
    }
    let before = lr.congestion().window();
    lr.on_ack(2, 4, 0, &[], 0, 30_000);
    lr.detect_lost(2, 30_000);
    assert!(lr.congestion().window() < before);

    lr.on_packet_sent(2, pkt(5, 40_000));
    lr.on_pto_expired();
    assert_eq!(lr.pto_count(), 1);
    lr.on_ack(2, 5, 0, &[], 0, 70_000);
    assert_eq!(lr.pto_count(), 0);
    assert!(
        lr.loss_timer().is_some(),
        "PTO timer is armed while in flight"
    );
}
