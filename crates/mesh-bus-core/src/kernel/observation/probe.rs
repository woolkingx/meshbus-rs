use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct ForwarderProbe {
    pub publish_calls: AtomicU64,
    pub lock_hits: AtomicU64,
    pub atomic_hits: AtomicU64,
    pub broadcast_sends: AtomicU64,
    pub channel_sends: AtomicU64,
}

#[derive(Default, Clone, Debug)]
pub struct ProbeSnapshot {
    pub publish_calls: u64,
    pub lock_hits: u64,
    pub atomic_hits: u64,
    pub broadcast_sends: u64,
    pub channel_sends: u64,
}

impl ForwarderProbe {
    pub fn snapshot(&self) -> ProbeSnapshot {
        ProbeSnapshot {
            publish_calls: self.publish_calls.load(Ordering::Relaxed),
            lock_hits: self.lock_hits.load(Ordering::Relaxed),
            atomic_hits: self.atomic_hits.load(Ordering::Relaxed),
            broadcast_sends: self.broadcast_sends.load(Ordering::Relaxed),
            channel_sends: self.channel_sends.load(Ordering::Relaxed),
        }
    }
}

impl ProbeSnapshot {
    pub fn delta(&self, base: &ProbeSnapshot) -> ProbeSnapshot {
        ProbeSnapshot {
            publish_calls: self.publish_calls.saturating_sub(base.publish_calls),
            lock_hits: self.lock_hits.saturating_sub(base.lock_hits),
            atomic_hits: self.atomic_hits.saturating_sub(base.atomic_hits),
            broadcast_sends: self.broadcast_sends.saturating_sub(base.broadcast_sends),
            channel_sends: self.channel_sends.saturating_sub(base.channel_sends),
        }
    }
}

#[cfg(test)]
#[path = "probe_tests.rs"]
mod probe_tests;
