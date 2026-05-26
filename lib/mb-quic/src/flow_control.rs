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
#[path = "flow_control_tests.rs"]
mod flow_control_tests;
