//! transport.pick_sink_cake hook.
//!
//! Filters SharedHookCtx.candidates by event.meta.net.protocol as an L4
//! transport-family hint (tcp -> stream, udp -> datagram) and by
//! event.meta.policy.route_group, then ranks via mb_cake::rank against a
//! per-candidate ExitMetric. Returns
//! Verdict::Accept(SinkId) for the winning sink, or Reject("no_usable_exit")
//! when no candidate survives the filter.
//!
//! cost_bias (zigzag-encoded u64 written by policy.rule_chain) is decoded to
//! a signed milli-units value and applied uniformly to effective rtt: bias > 0
//! reduces rtt (promotes), bias < 0 inflates rtt (demotes). The uniform shift
//! moves the absolute cost level for observability and downstream batching;
//! it does not change relative ordering between candidates.

use crate::context::{ExitCandidate, current};
use mb_cake::{ExitMetric, RankConfig, rank};
use mesh_bus_core::kernel::{Event, KernelCtx, MetaValue, Reason, SinkId, Verdict};

pub fn pick_sink_cake(event: &mut Event, _ctx: &mut KernelCtx) -> Verdict {
    let Some(shared) = current() else {
        return Verdict::Reject(Reason::code("hook_ctx_missing"));
    };

    let route_group = event.meta.policy.route_group.clone();
    let transport_family = event.meta.net.protocol.as_deref();
    let bias = read_cost_bias(event);
    let dns_rtt = read_dns_rtt(event);

    match transport_family {
        Some("tcp" | "udp") => {}
        Some(_) => return Verdict::Reject(Reason::code("invalid_transport_family")),
        None => return Verdict::Reject(Reason::code("missing_transport_family")),
    }

    let filtered: Vec<&ExitCandidate> = shared
        .candidates
        .iter()
        .filter(|c| match transport_family {
            Some("tcp") => c.supports_stream,
            Some("udp") => c.supports_datagram,
            _ => false,
        })
        .filter(|c| match &route_group {
            None => true,
            Some(g) => c.route_groups.iter().any(|cg| cg == g),
        })
        .collect();
    if filtered.is_empty() {
        return Verdict::Reject(Reason::code("no_usable_exit"));
    }

    let multiplier = bias_multiplier(bias);
    let metrics: Vec<ExitMetric> = filtered
        .iter()
        .map(|c| {
            let base_rtt = if c.rtt_ms == 0 && dns_rtt > 0 {
                dns_rtt
            } else {
                c.rtt_ms
            };
            // bias > 0 → multiplier > 1.0 → divide → lower effective rtt (promote)
            // bias < 0 → multiplier < 1.0 → divide → higher effective rtt (demote)
            let effective_rtt = if multiplier > 0.0 {
                (base_rtt as f64 / multiplier as f64).round() as u64
            } else {
                base_rtt
            };
            ExitMetric {
                id: c.sink_id.clone(),
                rtt_ms: effective_rtt,
                jitter_ms: c.jitter_ms,
                success_rate: c.success_rate,
                weight: 1,
                goodput_bps: None,
                capacity_bps: None,
            }
        })
        .collect();
    let flow = event.meta.trace.flow_id.as_deref().unwrap_or("flow:anon");
    let ranked = rank(&metrics, flow, RankConfig::default());
    match ranked.first() {
        Some(top) => Verdict::Accept(SinkId::new(top.as_str())),
        None => Verdict::Reject(Reason::code("no_usable_exit")),
    }
}

fn read_cost_bias(event: &Event) -> i32 {
    let raw = event
        .meta
        .ext
        .iter()
        .find(|(k, _)| *k == "cost_bias")
        .and_then(|(_, v)| match v {
            MetaValue::U64(n) => Some(*n),
            _ => None,
        })
        .unwrap_or(0);
    decode_bias(raw)
}

fn read_dns_rtt(event: &Event) -> u64 {
    event
        .meta
        .ext
        .iter()
        .find(|(k, _)| *k == "dns_rtt_ms")
        .and_then(|(_, v)| match v {
            MetaValue::U64(n) => Some(*n),
            _ => None,
        })
        .unwrap_or(0)
}

fn decode_bias(raw: u64) -> i32 {
    let sign = (raw >> 63) & 1;
    let mag = (raw & ((1u64 << 63) - 1)) as i64;
    if sign == 0 { mag as i32 } else { (-mag) as i32 }
}

fn bias_multiplier(bias_milli: i32) -> f32 {
    let m = 1.0 + (bias_milli as f32) / 1000.0;
    m.clamp(0.1, 10.0)
}
