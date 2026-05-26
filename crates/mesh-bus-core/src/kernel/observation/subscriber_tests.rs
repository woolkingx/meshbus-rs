use super::*;
use crate::kernel::observation::{CoreEventId, EventTypeId};

#[test]
fn threshold_breach_transitions_to_unwired() {
    let mut tbl = SubscriberStatusTable::new();
    let key = (EventTypeId::Core(CoreEventId::FlowOpened), 0usize);
    for _ in 0..(MAX_LIFECYCLE_TIMEOUTS_BEFORE_UNWIRE - 1) {
        assert!(!tbl.record_timeout(key, 1_000));
    }
    assert!(tbl.record_timeout(key, 9_999));
    match tbl.snapshot().get(&key).unwrap() {
        SubscriberStatus::Unwired {
            reason,
            total_timeouts,
            ..
        } => {
            assert!(matches!(
                reason,
                UnwireReason::LifecycleTimeoutThresholdExceeded
            ));
            assert_eq!(*total_timeouts, MAX_LIFECYCLE_TIMEOUTS_BEFORE_UNWIRE);
        }
        other => panic!("expected Unwired, got {:?}", other),
    }
}
