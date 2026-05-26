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
#[path = "health_observer_tests.rs"]
mod health_observer_tests;
