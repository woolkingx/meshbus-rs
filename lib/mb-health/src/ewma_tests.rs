use super::*;

#[test]
fn empty_window_returns_zero() {
    let w = HealthWindow::new(64);
    assert_eq!(w.mean_rtt_ms(), 0);
}

#[test]
fn single_sample_is_returned_as_is() {
    let mut w = HealthWindow::new(64);
    w.record_rtt(100);
    assert_eq!(w.mean_rtt_ms(), 100);
}

#[test]
fn ewma_converges_with_alpha_one_eighth() {
    // 100, 200 -> 100 + (200-100)/8 = 112
    let mut w = HealthWindow::new(64);
    w.record_rtt(100);
    w.record_rtt(200);
    assert_eq!(w.mean_rtt_ms(), 112);
}

#[test]
fn ewma_resists_single_spike() {
    let mut w = HealthWindow::new(64);
    for _ in 0..5 {
        w.record_rtt(100);
    }
    w.record_rtt(1000);
    let m = w.mean_rtt_ms();
    assert!(m < 250, "EWMA should resist single spike, got {}", m);
    assert!(m > 100, "EWMA should still move toward spike, got {}", m);
}
