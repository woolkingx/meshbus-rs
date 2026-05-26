use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use futures::stream::{FuturesUnordered, StreamExt};
use tokio::sync::mpsc;

use super::{
    event_type::EventTypeId,
    ids::ScopeId,
    subscriber::{SubKey, SubscriberStatus, SubscriberStatusTable},
};

#[derive(Clone, Debug)]
pub struct EventEnvelope {
    pub type_id: EventTypeId,
    pub payload: EventPayload,
    pub at_ns: u64,
}

#[derive(Clone, Debug, Default)]
pub struct EventPayload(pub Arc<EventPayloadInner>);

#[derive(Debug, Default)]
pub struct EventPayloadInner {
    pub flow_id: Option<u64>,
    pub flow_id_text: Option<String>,
    pub session_id_text: Option<String>,
    pub sink_id: Option<u32>,
    pub exit_id: Option<String>,
    pub selected_exit: Option<String>,
    pub route_group: Option<String>,
    pub target_sink: Option<String>,
    pub packet_id: Option<u64>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub payload_bytes: u64,
    pub rtt_ms: u64,
    pub success: Option<bool>,
    pub close_reason: Option<String>,
    pub io_err_kind: Option<std::io::ErrorKind>,
    pub direction: Option<u8>,
    pub terminal: bool,
    pub shape: Option<u8>,
    pub at_ms: u64,
    pub peer_id: Option<String>,
    pub source_addr: Option<String>,
    pub reason: Option<String>,
    pub reason_code: Option<u16>,
    pub transport_mode: Option<String>,
    pub secure: Option<bool>,
}

impl EventPayload {
    pub fn empty() -> Self {
        Self::default()
    }
}

#[derive(Default, Debug)]
pub struct DeliveryReport {
    pub delivered: u32,
    pub timed_out: u32,
    pub closed: u32,
}

#[derive(Clone)]
struct ScopedSender {
    tx: mpsc::Sender<EventEnvelope>,
    scope: ScopeId,
}

const INITIAL_SLOTS: usize = 64;

/// Sentinel scope used by callers that have not adopted scoped wiring.
/// `unwire_scope` never targets `ScopeId(0)`.
pub const UNSCOPED: ScopeId = ScopeId(0);

pub struct ObservationBus {
    routing: ArcSwap<Vec<Arc<[ScopedSender]>>>,
    status: Mutex<SubscriberStatusTable>,
    origin: Instant,
}

impl Default for ObservationBus {
    fn default() -> Self {
        Self::new()
    }
}

impl ObservationBus {
    pub fn new() -> Self {
        let empty: Vec<Arc<[ScopedSender]>> = (0..INITIAL_SLOTS).map(|_| Arc::from([])).collect();
        Self {
            routing: ArcSwap::from_pointee(empty),
            status: Mutex::new(SubscriberStatusTable::new()),
            origin: Instant::now(),
        }
    }

    fn now_ns(&self) -> u64 {
        self.origin.elapsed().as_nanos() as u64
    }

    pub fn wire_subscriber(&self, type_id: EventTypeId, tx: mpsc::Sender<EventEnvelope>) {
        self.wire_subscriber_scoped(type_id, tx, UNSCOPED);
    }

    pub fn wire_subscriber_scoped(
        &self,
        type_id: EventTypeId,
        tx: mpsc::Sender<EventEnvelope>,
        scope: ScopeId,
    ) {
        let mut next = (**self.routing.load()).clone();
        let slot_idx = type_id.as_u32() as usize;
        if slot_idx >= next.len() {
            next.resize(slot_idx + 8, Arc::from([]));
        }
        let mut v: Vec<ScopedSender> = (*next[slot_idx]).to_vec();
        v.push(ScopedSender { tx, scope });
        next[slot_idx] = Arc::from(v.into_boxed_slice());
        self.routing.store(Arc::new(next));
    }

    pub fn unwire_scope(&self, scope: ScopeId) {
        if scope == UNSCOPED {
            return;
        }
        let mut next = (**self.routing.load()).clone();
        let now_ns = self.now_ns();
        let mut status = self.status.lock().unwrap();
        for (slot_idx, slot) in next.iter_mut().enumerate() {
            if slot.is_empty() {
                continue;
            }
            let type_u32 = slot_idx as u32;
            let mut kept: Vec<ScopedSender> = Vec::with_capacity(slot.len());
            for (i, s) in slot.iter().enumerate() {
                if s.scope == scope {
                    let key: SubKey = (decode_type(type_u32), i);
                    status.record_scope_revoked(key, now_ns);
                } else {
                    kept.push(s.clone());
                }
            }
            if kept.len() != slot.len() {
                *slot = Arc::from(kept.into_boxed_slice());
            }
        }
        drop(status);
        self.routing.store(Arc::new(next));
    }

    pub fn publish(&self, type_id: EventTypeId, payload: EventPayload) {
        let routing = self.routing.load();
        let Some(senders) = routing.get(type_id.as_u32() as usize) else {
            return;
        };
        if senders.is_empty() {
            return;
        }
        let env = EventEnvelope {
            type_id,
            payload,
            at_ns: self.now_ns(),
        };
        for s in senders.iter() {
            let _ = s.tx.try_send(env.clone());
        }
    }

    pub async fn publish_reliable(
        &self,
        type_id: EventTypeId,
        payload: EventPayload,
        total_deadline: Duration,
    ) -> DeliveryReport {
        let mut report = DeliveryReport::default();
        let senders: Vec<ScopedSender> = {
            let routing = self.routing.load();
            match routing.get(type_id.as_u32() as usize) {
                Some(slot) => (**slot).to_vec(),
                None => return report,
            }
        };
        if senders.is_empty() {
            return report;
        }

        let env = EventEnvelope {
            type_id,
            payload,
            at_ns: self.now_ns(),
        };
        let n = senders.len();
        let deadline_at = tokio::time::Instant::now() + total_deadline;

        let mut pending: FuturesUnordered<_> = senders
            .iter()
            .enumerate()
            .map(|(idx, s)| {
                let tx = s.tx.clone();
                let env = env.clone();
                async move { (idx, tx.send(env).await) }
            })
            .collect();

        let mut completed = bitvec::bitvec![0; n];
        loop {
            if completed.all() {
                break;
            }
            match tokio::time::timeout_at(deadline_at, pending.next()).await {
                Ok(Some((idx, Ok(())))) => {
                    completed.set(idx, true);
                    report.delivered += 1;
                    self.status.lock().unwrap().record_success((type_id, idx));
                }
                Ok(Some((idx, Err(_closed)))) => {
                    completed.set(idx, true);
                    report.closed += 1;
                    self.status
                        .lock()
                        .unwrap()
                        .record_closed((type_id, idx), env.at_ns);
                }
                Ok(None) => break,
                Err(_elapsed) => {
                    let mut unwired_indices: Vec<usize> = Vec::new();
                    {
                        let mut s = self.status.lock().unwrap();
                        for idx in 0..n {
                            if !completed[idx] {
                                report.timed_out += 1;
                                let unwired_now = s.record_timeout((type_id, idx), env.at_ns);
                                if unwired_now {
                                    unwired_indices.push(idx);
                                }
                            }
                        }
                    }
                    for idx in &unwired_indices {
                        tracing::warn!(
                            event = "observation.subscriber_unwired",
                            type_id = ?type_id,
                            subscriber_idx = *idx,
                            reason = "LifecycleTimeoutThresholdExceeded",
                        );
                    }
                    if !unwired_indices.is_empty() {
                        self.drop_indices(type_id, &unwired_indices);
                    }
                    break;
                }
            }
        }
        report
    }

    fn drop_indices(&self, type_id: EventTypeId, drop: &[usize]) {
        let mut next = (**self.routing.load()).clone();
        let slot_idx = type_id.as_u32() as usize;
        if let Some(slot) = next.get_mut(slot_idx) {
            let mut v: Vec<ScopedSender> = (*slot).to_vec();
            // Drop in descending index order so earlier indices stay valid.
            let mut sorted = drop.to_vec();
            sorted.sort_unstable_by(|a, b| b.cmp(a));
            for i in sorted {
                if i < v.len() {
                    v.remove(i);
                }
            }
            *slot = Arc::from(v.into_boxed_slice());
        }
        self.routing.store(Arc::new(next));
    }

    pub fn subscriber_status_snapshot(
        &self,
    ) -> std::collections::BTreeMap<SubKey, SubscriberStatus> {
        self.status.lock().unwrap().snapshot()
    }
}

fn decode_type(packed: u32) -> EventTypeId {
    use super::event_type::CORE_RANGE_END;
    use super::event_type::{CoreEventId, ObsEventId};
    match packed {
        0 => EventTypeId::Core(CoreEventId::FlowOpened),
        1 => EventTypeId::Core(CoreEventId::FlowPathChanged),
        2 => EventTypeId::Core(CoreEventId::FlowClosed),
        3 => EventTypeId::Core(CoreEventId::PathIoError),
        n => EventTypeId::Obs(ObsEventId(n - CORE_RANGE_END)),
    }
}

#[cfg(test)]
#[path = "bus_tests.rs"]
mod bus_tests;
