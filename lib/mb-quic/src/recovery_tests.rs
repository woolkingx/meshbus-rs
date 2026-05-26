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
