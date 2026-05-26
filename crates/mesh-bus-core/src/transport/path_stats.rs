use crate::FlowId;

#[derive(Clone, Default, Debug)]
pub struct PathStats {
    pub rtt_us: Option<u32>,
    pub rttvar_us: Option<u32>,
    pub snd_cwnd: Option<u32>,
    pub send_buf_used_bytes: Option<u32>,
    pub send_buf_capacity_bytes: Option<u32>,
    pub retransmits: Option<u32>,
    /// Datagrams drained by the most recent receive batch (one recvmmsg run on
    /// Linux, one per-datagram fallback otherwise).
    pub recv_batch_size: Option<u32>,
    /// Last successful per-message UDP_SEGMENT size. `None` means the current
    /// path is using plain sendmmsg/per-datagram send, or GSO was disabled after
    /// a kernel fallback.
    pub gso_segment_size: Option<u16>,
    /// Software pacing delay applied to the last release; `Some(0)` when the
    /// loop is unpaced.
    pub pacing_delay_us: Option<u32>,
    /// Conservative path MTU guard the substrate clamps oversize sends to.
    pub pmtu: Option<u16>,
    /// Cumulative datagram send failures observed on the loop.
    pub send_errors: u32,
    /// Cumulative datagrams dropped before send (e.g. clamped past the PMTU
    /// guard).
    pub drops: u32,
    /// Cumulative datagrams refused because the bounded outbound queue was full.
    pub queue_full_drops: u32,
    pub sampled_at_ms: u64,
}

pub trait PathStatsProvider: Send + Sync {
    fn path_stats(&self, flow_id: &FlowId) -> Option<PathStats>;
}

#[cfg(test)]
#[path = "path_stats_tests.rs"]
mod path_stats_tests;
