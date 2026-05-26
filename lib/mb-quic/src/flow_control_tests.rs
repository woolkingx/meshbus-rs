use super::*;

#[test]
fn consume_within_window_succeeds_and_tracks() {
    let mut fc = FlowController::new(100);
    assert!(fc.consume(40));
    assert_eq!(fc.used(), 40);
    assert_eq!(fc.available(), 60);
}

#[test]
fn consume_over_window_is_rejected_atomically() {
    let mut fc = FlowController::new(100);
    assert!(fc.consume(100));
    assert!(!fc.consume(1));
    assert_eq!(fc.used(), 100);
}

#[test]
fn limit_never_decreases() {
    let mut fc = FlowController::new(100);
    fc.set_limit(50);
    assert_eq!(fc.limit(), 100);
    fc.set_limit(200);
    assert_eq!(fc.limit(), 200);
}

#[test]
fn maybe_extend_advertises_when_half_consumed() {
    let mut fc = FlowController::new(100);
    assert_eq!(fc.maybe_extend(100), None);
    fc.consume(60);
    assert_eq!(fc.maybe_extend(100), Some(160));
    assert_eq!(fc.available(), 100);
}
