//! RFC 9000 §4 flow control.
//!
//! A [`FlowController`] tracks a single directional credit window: bytes that
//! may still be sent (peer-advertised `MAX_DATA` / `MAX_STREAM_DATA`) or, when
//! used for the receive side, bytes the peer may still send us before we must
//! extend its window.

/// One directional flow-control window.
#[derive(Clone, Debug)]
pub struct FlowController {
    limit: u64,
    used: u64,
}

impl FlowController {
    /// Create a controller with an initial absolute byte limit.
    pub fn new(initial_limit: u64) -> Self {
        Self {
            limit: initial_limit,
            used: 0,
        }
    }

    /// Bytes that may still be sent/received without exceeding the window.
    pub fn available(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }

    /// Total bytes consumed against the window.
    pub fn used(&self) -> u64 {
        self.used
    }

    /// Current absolute limit.
    pub fn limit(&self) -> u64 {
        self.limit
    }

    /// Consume `n` bytes. Returns `false` (and consumes nothing) if `n` would
    /// exceed the window — the caller must surface FLOW_CONTROL_ERROR.
    pub fn consume(&mut self, n: u64) -> bool {
        if n > self.available() {
            return false;
        }
        self.used += n;
        true
    }

    /// Raise the absolute limit (peer sent MAX_DATA / we extend the receive
    /// window). A smaller value than the current limit is ignored (RFC 9000
    /// §4.1: limits never decrease).
    pub fn set_limit(&mut self, new_limit: u64) {
        if new_limit > self.limit {
            self.limit = new_limit;
        }
    }

    /// Receive-side window maintenance: once consumed bytes pass half the
    /// window, return the new absolute limit to advertise, else `None`.
    pub fn maybe_extend(&mut self, window: u64) -> Option<u64> {
        if self.limit.saturating_sub(self.used) * 2 <= window {
            self.limit = self.used + window;
            Some(self.limit)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
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
}
