use std::collections::BTreeMap;

use super::EventTypeId;

pub const MAX_LIFECYCLE_TIMEOUTS_BEFORE_UNWIRE: u32 = 8;

#[derive(Debug, Clone)]
pub enum SubscriberStatus {
    Healthy,
    Degraded {
        consecutive_timeouts: u32,
    },
    Unwired {
        reason: UnwireReason,
        at_ns: u64,
        total_timeouts: u32,
        last_timeout_at_ns: u64,
    },
}

#[derive(Debug, Clone, Copy)]
pub enum UnwireReason {
    LifecycleTimeoutThresholdExceeded,
    ChannelClosed,
    ScopeRevoked,
}

pub type SubKey = (EventTypeId, usize);

#[derive(Default)]
pub struct SubscriberStatusTable {
    map: BTreeMap<SubKey, SubscriberStatus>,
    cumulative: BTreeMap<SubKey, u32>,
}

impl SubscriberStatusTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns true iff this timeout transitioned the subscriber to Unwired.
    pub fn record_timeout(&mut self, key: SubKey, at_ns: u64) -> bool {
        let total = self
            .cumulative
            .entry(key)
            .and_modify(|v| *v += 1)
            .or_insert(1);
        let total = *total;
        let prev = self
            .map
            .get(&key)
            .cloned()
            .unwrap_or(SubscriberStatus::Healthy);
        let next = match prev {
            SubscriberStatus::Unwired { .. } => return false,
            SubscriberStatus::Healthy => SubscriberStatus::Degraded {
                consecutive_timeouts: 1,
            },
            SubscriberStatus::Degraded {
                consecutive_timeouts,
            } => {
                let c = consecutive_timeouts + 1;
                if c >= MAX_LIFECYCLE_TIMEOUTS_BEFORE_UNWIRE {
                    SubscriberStatus::Unwired {
                        reason: UnwireReason::LifecycleTimeoutThresholdExceeded,
                        at_ns,
                        total_timeouts: total,
                        last_timeout_at_ns: at_ns,
                    }
                } else {
                    SubscriberStatus::Degraded {
                        consecutive_timeouts: c,
                    }
                }
            }
        };
        let unwired_now = matches!(next, SubscriberStatus::Unwired { .. });
        self.map.insert(key, next);
        unwired_now
    }

    pub fn record_success(&mut self, key: SubKey) {
        if matches!(self.map.get(&key), Some(SubscriberStatus::Unwired { .. })) {
            return;
        }
        self.map.insert(key, SubscriberStatus::Healthy);
    }

    pub fn record_closed(&mut self, key: SubKey, at_ns: u64) {
        let total = self.cumulative.get(&key).copied().unwrap_or(0);
        self.map.insert(
            key,
            SubscriberStatus::Unwired {
                reason: UnwireReason::ChannelClosed,
                at_ns,
                total_timeouts: total,
                last_timeout_at_ns: at_ns,
            },
        );
    }

    pub fn record_scope_revoked(&mut self, key: SubKey, at_ns: u64) {
        let total = self.cumulative.get(&key).copied().unwrap_or(0);
        self.map.insert(
            key,
            SubscriberStatus::Unwired {
                reason: UnwireReason::ScopeRevoked,
                at_ns,
                total_timeouts: total,
                last_timeout_at_ns: at_ns,
            },
        );
    }

    pub fn snapshot(&self) -> BTreeMap<SubKey, SubscriberStatus> {
        self.map.clone()
    }
}

#[cfg(test)]
#[path = "subscriber_tests.rs"]
mod subscriber_tests;
