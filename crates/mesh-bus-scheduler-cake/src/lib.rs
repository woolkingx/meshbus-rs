//! CAKE-based scheduler: sliding-window health stats + mb-cake ranking.

pub mod observer;
pub use observer::CakeFeedbackObserver;

use arc_swap::ArcSwap;
use mb_cake::{ExitMetric, RankConfig, rank};
use mb_cost::{Score, ScoreInputs};
use mb_health::HealthWindow;
use mesh_bus_core::kernel::observation::{CoreEventId, EventEnvelope, EventTypeId};
use mesh_bus_core::{
    ExitId, ExitResult, RankContext, ReturnEvent, ScheduleDecision, SchedulerPlugin, TrafficClass,
};
use std::collections::HashMap;
use std::sync::Mutex;

const UNKNOWN_RTT_MS: u64 = 10;

#[derive(Clone)]
struct MetricSnapshot {
    rtt_ms: u64,
    jitter_ms: u64,
    success_rate: f64,
    goodput_bps: Option<u64>,
}

pub struct CakeScheduler {
    windows: Mutex<HashMap<ExitId, HealthWindow>>,
    snapshot: ArcSwap<HashMap<ExitId, MetricSnapshot>>,
}

impl CakeScheduler {
    pub fn new() -> Self {
        Self {
            windows: Mutex::new(HashMap::new()),
            snapshot: ArcSwap::from_pointee(HashMap::new()),
        }
    }

    fn metric_for(&self, id: &ExitId) -> ExitMetric {
        let snap = self.snapshot.load();
        let m = snap.get(id);
        ExitMetric {
            id: id.0.clone(),
            rtt_ms: m.map(|m| m.rtt_ms).unwrap_or(UNKNOWN_RTT_MS),
            jitter_ms: m.map(|m| m.jitter_ms).unwrap_or(0),
            success_rate: m.map(|m| m.success_rate).unwrap_or(1.0),
            weight: 1,
            goodput_bps: m.and_then(|m| m.goodput_bps).filter(|v| *v > 0),
            capacity_bps: None,
        }
    }

    fn republish_snapshot(
        windows: &HashMap<ExitId, HealthWindow>,
    ) -> HashMap<ExitId, MetricSnapshot> {
        windows
            .iter()
            .map(|(id, w)| {
                let g = w.goodput_bps();
                (
                    id.clone(),
                    MetricSnapshot {
                        rtt_ms: w.mean_rtt_ms(),
                        jitter_ms: w.jitter_ms(),
                        success_rate: w.success_rate(),
                        goodput_bps: if g > 0 { Some(g) } else { None },
                    },
                )
            })
            .collect()
    }

    fn rank_config(ctx: &RankContext) -> RankConfig {
        match ctx.traffic_class {
            TrafficClass::Bulk => RankConfig { price_weight: 2 },
            _ => RankConfig { price_weight: 1 },
        }
    }
}

impl Default for CakeScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl SchedulerPlugin for CakeScheduler {
    fn schedule(&self, candidates: &[ExitId], ctx: &RankContext) -> ScheduleDecision {
        let metrics: Vec<ExitMetric> = candidates.iter().map(|id| self.metric_for(id)).collect();
        let cfg = Self::rank_config(ctx);
        let order_ids = rank(&metrics, &ctx.flow_id.0, cfg);
        let order = order_ids
            .iter()
            .filter_map(|oid| candidates.iter().position(|c| &c.0 == oid))
            .collect();
        ScheduleDecision::ordered(order)
    }

    fn feedback(&self, result: &ExitResult, payload_bytes: u64, at_ms: u64) {
        let mut windows = self.windows.lock().unwrap();
        let w = windows
            .entry(result.exit_id.clone())
            .or_insert_with(|| HealthWindow::new(64));
        w.record_rtt(result.rtt_ms);
        w.record_outcome(result.success);
        if payload_bytes > 0 {
            w.record_payload(payload_bytes, at_ms);
        }
        let snap = Self::republish_snapshot(&windows);
        drop(windows);
        self.snapshot.store(std::sync::Arc::new(snap));
    }

    fn on_observation(&self, event: &EventEnvelope) {
        if !matches!(
            event.type_id,
            EventTypeId::Core(CoreEventId::FlowOpened)
                | EventTypeId::Core(CoreEventId::FlowClosed)
                | EventTypeId::Core(CoreEventId::PathIoError)
        ) {
            return;
        }
        let payload = &event.payload.0;
        let Some(exit_id) = payload
            .selected_exit
            .as_ref()
            .or(payload.exit_id.as_ref())
            .cloned()
        else {
            return;
        };
        let result = ExitResult {
            exit_id: ExitId(exit_id),
            success: payload.success.unwrap_or(!matches!(
                event.type_id,
                EventTypeId::Core(CoreEventId::PathIoError)
            )),
            rtt_ms: payload.rtt_ms,
            local_endpoint: None,
            return_event: ReturnEvent::Idle,
        };
        self.feedback(
            &result,
            payload.bytes_out.max(payload.payload_bytes),
            payload.at_ms,
        );
    }

    fn score_for(&self, exit_id: &ExitId, _candidates: &[ExitId], ctx: &RankContext) -> u64 {
        let m = self.metric_for(exit_id);
        let cfg = Self::rank_config(ctx);
        let inputs = ScoreInputs {
            rtt_ms: m.rtt_ms,
            jitter_ms: m.jitter_ms,
            success_rate: m.success_rate,
            price_weight: cfg.price_weight.max(1),
            goodput_bps: m.goodput_bps,
            capacity_bps: m.capacity_bps,
        };
        Score::compute(&inputs).value()
    }

    fn goodput_bps_for(&self, exit_id: &ExitId) -> Option<u64> {
        self.snapshot
            .load()
            .get(exit_id)
            .and_then(|m| m.goodput_bps)
            .filter(|v| *v > 0)
    }
}
