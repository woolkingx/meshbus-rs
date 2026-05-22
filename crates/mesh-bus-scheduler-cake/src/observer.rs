use mesh_bus_core::kernel::observation::{CoreEventId, EventEnvelope, EventTypeId};
use mesh_bus_core::{BusEvent, ExitId, ExitResult, ObserverPlugin, ReturnEvent, SchedulerPlugin};
use std::sync::Arc;
use tokio::sync::mpsc;

enum Sample {
    Feedback {
        result: ExitResult,
        payload_bytes: u64,
        at_ms: u64,
    },
    Flush(tokio::sync::oneshot::Sender<()>),
}

pub struct CakeFeedbackObserver {
    tx: mpsc::Sender<Sample>,
}

impl CakeFeedbackObserver {
    pub fn new<S: SchedulerPlugin + Send + Sync + 'static>(scheduler: Arc<S>) -> Arc<Self> {
        let (tx, mut rx) = mpsc::channel(4096);
        tokio::spawn(async move {
            while let Some(s) = rx.recv().await {
                match s {
                    Sample::Feedback {
                        result,
                        payload_bytes,
                        at_ms,
                    } => {
                        scheduler.feedback(&result, payload_bytes, at_ms);
                    }
                    Sample::Flush(reply) => {
                        let _ = reply.send(());
                    }
                }
            }
        });
        Arc::new(Self { tx })
    }

    pub fn on_core_event(&self, env: &EventEnvelope) {
        if !matches!(
            env.type_id,
            EventTypeId::Core(CoreEventId::FlowClosed)
                | EventTypeId::Core(CoreEventId::PathIoError)
        ) {
            return;
        }
        let payload = &env.payload.0;
        let Some(exit_id) = payload
            .selected_exit
            .as_ref()
            .or(payload.exit_id.as_ref())
            .cloned()
        else {
            return;
        };
        let success = payload.success.unwrap_or(matches!(
            env.type_id,
            EventTypeId::Core(CoreEventId::FlowClosed)
        ));
        let result = ExitResult {
            exit_id: ExitId(exit_id),
            success,
            rtt_ms: payload.rtt_ms,
            local_endpoint: None,
            return_event: ReturnEvent::Idle,
        };
        let _ = self.tx.try_send(Sample::Feedback {
            result,
            payload_bytes: payload.bytes_out.max(payload.payload_bytes),
            at_ms: payload.at_ms,
        });
    }

    pub async fn flush_for_test(&self) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let _ = self.tx.send(Sample::Flush(tx)).await;
        let _ = rx.await;
    }
}

impl ObserverPlugin for CakeFeedbackObserver {
    fn on_event(&self, event: &BusEvent) {
        if let BusEvent::Core(env) = event {
            self.on_core_event(env);
        }
    }
}
