use super::*;

#[test]
fn empty_goodput_is_zero() {
    assert_eq!(HealthWindow::new(64).goodput_bps(), 0);
}

#[test]
fn single_sample_goodput_is_zero() {
    let mut w = HealthWindow::new(64);
    w.record_payload(1_000_000, 1000);
    assert_eq!(w.goodput_bps(), 0);
}

#[test]
fn two_samples_compute_byte_rate() {
    // 1 MB at t=1000ms, 1 MB at t=2000ms -> 2 MB over 1s -> 2_000_000 B/s
    let mut w = HealthWindow::new(64);
    w.record_payload(1_000_000, 1000);
    w.record_payload(1_000_000, 2000);
    assert_eq!(w.goodput_bps(), 2_000_000);
}

#[test]
fn ringbuffer_evicts_oldest() {
    let mut w = HealthWindow::new(4);
    for i in 0..10u64 {
        w.record_payload(100, 1000 + i * 100);
    }
    // Last 4 samples at t=(1700,1800,1900,2000), span 300ms, 400 bytes -> 1333 B/s
    assert_eq!(w.goodput_bps(), 1333);
}
