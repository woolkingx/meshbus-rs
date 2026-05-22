use crate::kernel::health_snapshot::{HealthPublisher, HealthSnapshot};
use crate::kernel::observation::{CoreEventId, EventEnvelope, EventTypeId};
use crate::{BusEvent, ObserverPlugin};
use mb_health::{ExitHealthTable, HealthPolicy};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::mpsc;
#[cfg(test)]
use tokio::sync::oneshot;

enum Sample {
    Success {
        exit_id: String,
        at_ms: u64,
    },
    Failure {
        exit_id: String,
        at_ms: u64,
    },
    #[cfg(test)]
    Flush(oneshot::Sender<()>),
}

pub struct ExitHealthObserver {
    tx: mpsc::Sender<Sample>,
}

impl ExitHealthObserver {
    pub fn new(
        publisher: Arc<HealthPublisher>,
        policy: HealthPolicy,
        exit_ids: Vec<String>,
    ) -> Arc<Self> {
        let (tx, rx) = mpsc::channel::<Sample>(4096);
        tokio::spawn(_drainer(rx, publisher, policy, exit_ids));
        Arc::new(Self { tx })
    }

    #[cfg(test)]
    pub async fn flush_for_test(&self) {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = self.tx.send(Sample::Flush(reply_tx)).await;
        let _ = reply_rx.await;
    }

    pub fn on_core_event(&self, env: &EventEnvelope) {
        let payload = &env.payload.0;
        let Some(exit_id) = payload.selected_exit.as_ref().or(payload.exit_id.as_ref()) else {
            return;
        };
        let at_ms = payload.at_ms;
        let sample = match env.type_id {
            EventTypeId::Core(CoreEventId::FlowClosed) if payload.success.unwrap_or(true) => {
                Sample::Success {
                    exit_id: exit_id.clone(),
                    at_ms,
                }
            }
            EventTypeId::Core(CoreEventId::FlowClosed)
            | EventTypeId::Core(CoreEventId::PathIoError) => Sample::Failure {
                exit_id: exit_id.clone(),
                at_ms,
            },
            _ => return,
        };
        let _ = self.tx.try_send(sample);
    }
}

async fn _drainer(
    mut rx: mpsc::Receiver<Sample>,
    publisher: Arc<HealthPublisher>,
    policy: HealthPolicy,
    exit_ids: Vec<String>,
) {
    let mut table = ExitHealthTable::new(policy);

    while let Some(sample) = rx.recv().await {
        match sample {
            Sample::Success { exit_id, at_ms } => {
                table.record(&exit_id, true, at_ms);
                _publish(&publisher, &table, &exit_ids, at_ms);
            }
            Sample::Failure { exit_id, at_ms } => {
                table.record(&exit_id, false, at_ms);
                _publish(&publisher, &table, &exit_ids, at_ms);
            }
            #[cfg(test)]
            Sample::Flush(reply) => {
                let _ = reply.send(());
            }
        }
    }
}

fn _publish(
    publisher: &HealthPublisher,
    table: &ExitHealthTable,
    exit_ids: &[String],
    now_ms: u64,
) {
    let unhealthy: HashSet<String> = exit_ids
        .iter()
        .filter(|id| !table.can_dispatch(id, now_ms))
        .cloned()
        .collect();
    publisher.publish(HealthSnapshot { unhealthy });
}

impl ObserverPlugin for ExitHealthObserver {
    fn on_event(&self, event: &BusEvent) {
        if let BusEvent::Core(env) = event {
            self.on_core_event(env);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::observation::{EventPayload, EventPayloadInner};
    use mb_health::HealthPolicy;

    fn strict_policy() -> HealthPolicy {
        HealthPolicy {
            failure_threshold: 2,
            recovery_window_ms: 60_000,
            probe_after_ms: 30_000,
        }
    }

    #[tokio::test]
    async fn three_failures_mark_exit_unhealthy() {
        let publisher = Arc::new(HealthPublisher::new());
        let obs =
            ExitHealthObserver::new(publisher.clone(), strict_policy(), vec!["e1".to_string()]);
        for i in 0..5 {
            obs.on_core_event(&EventEnvelope {
                type_id: EventTypeId::Core(CoreEventId::PathIoError),
                payload: EventPayload(Arc::new(EventPayloadInner {
                    selected_exit: Some("e1".into()),
                    at_ms: i * 100,
                    success: Some(false),
                    ..Default::default()
                })),
                at_ns: 0,
            });
        }
        obs.flush_for_test().await;
        let snap = publisher.load();
        assert!(
            snap.unhealthy.contains("e1"),
            "e1 should be unhealthy after consecutive failures"
        );
    }

    #[tokio::test]
    async fn success_recovers_exit() {
        let publisher = Arc::new(HealthPublisher::new());
        let obs =
            ExitHealthObserver::new(publisher.clone(), strict_policy(), vec!["e1".to_string()]);
        for i in 0..5 {
            obs.on_core_event(&EventEnvelope {
                type_id: EventTypeId::Core(CoreEventId::PathIoError),
                payload: EventPayload(Arc::new(EventPayloadInner {
                    selected_exit: Some("e1".into()),
                    at_ms: i * 100,
                    success: Some(false),
                    ..Default::default()
                })),
                at_ns: 0,
            });
        }
        obs.flush_for_test().await;
        assert!(publisher.load().unhealthy.contains("e1"));

        // hammer success; use at_ms far enough past probe_after_ms so can_dispatch returns true
        for i in 0..10 {
            obs.on_core_event(&EventEnvelope {
                type_id: EventTypeId::Core(CoreEventId::FlowClosed),
                payload: EventPayload(Arc::new(EventPayloadInner {
                    selected_exit: Some("e1".into()),
                    at_ms: 100_000 + i * 100,
                    success: Some(true),
                    ..Default::default()
                })),
                at_ns: 0,
            });
        }
        obs.flush_for_test().await;
        assert!(
            !publisher.load().unhealthy.contains("e1"),
            "e1 should recover after success"
        );
    }
}
