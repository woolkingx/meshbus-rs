use super::DatagramState;
use std::collections::{HashMap, VecDeque};

pub(super) type PendingDatagramSeqs = HashMap<String, VecDeque<u64>>;

pub(super) fn datagram_key(endpoint: &mb_endpoint::Endpoint) -> String {
    endpoint.to_string()
}

pub(super) async fn pop_pending_seq(
    state: &DatagramState,
    source: &mb_endpoint::Endpoint,
) -> Option<u64> {
    let mut pending = state.pending_by_source.lock().await;
    let key = datagram_key(source);
    let seq = pending.get_mut(&key)?.pop_front();
    if matches!(pending.get(&key), Some(queue) if queue.is_empty()) {
        pending.remove(&key);
    }
    seq
}

pub(super) async fn remove_pending_seq(
    state: &DatagramState,
    target: &mb_endpoint::Endpoint,
    seq: u64,
) {
    let mut pending = state.pending_by_source.lock().await;
    let key = datagram_key(target);
    if let Some(queue) = pending.get_mut(&key) {
        if let Some(pos) = queue.iter().position(|pending_seq| *pending_seq == seq) {
            queue.remove(pos);
        }
        if queue.is_empty() {
            pending.remove(&key);
        }
    }
}
