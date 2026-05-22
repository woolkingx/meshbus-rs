//! policy.rule_chain hook.
//!
//! Projects pipeline metadata into RuleCtx, evaluates against the operator's
//! RuleChain with full match-trace, and projects Action back into pipeline
//! metadata. Deny short-circuits to Reject; cost bias is zigzag-encoded so
//! downstream pick_sink can read it as a u64 (sign-bit-prefixed magnitude).

use crate::context::current;
use crate::ext_meta::write_ext;
use mb_rule::data_handle::evaluate_with_trace;
use mb_rule::types::{Action, RuleCtx, RuleNetwork, RuleScheduleHint};
use mesh_bus_core::kernel::{Event, KernelCtx, MetaValue, Reason, ScheduleHintLabel, Verdict};
use std::net::IpAddr;

pub fn rule_chain(event: &mut Event, _ctx: &mut KernelCtx) -> Verdict {
    let Some(shared) = current() else {
        return Verdict::Reject(Reason::code("hook_ctx_missing"));
    };
    let rctx = match build_rule_ctx(event) {
        Ok(rctx) => rctx,
        Err(reason) => return Verdict::Reject(reason),
    };
    let decision = evaluate_with_trace(&shared.rule_chain, &rctx, &shared.rule_sets);
    apply_action(event, &decision.action)
}

fn build_rule_ctx(event: &Event) -> Result<RuleCtx, Reason> {
    let mut c = RuleCtx::empty();
    c.src_ip = match event.meta.net.src_ip.as_deref() {
        Some(s) => Some(
            s.parse::<IpAddr>()
                .map_err(|_| Reason::code("invalid_src_ip"))?,
        ),
        None => None,
    };
    c.dst_port = event.meta.net.dst_port;
    c.network = match event.meta.net.protocol.as_deref() {
        Some("tcp") => Some(RuleNetwork::Tcp),
        Some("udp") => Some(RuleNetwork::Udp),
        Some(_) => return Err(Reason::code("invalid_transport_family")),
        None => return Err(Reason::code("missing_transport_family")),
    };
    c.hostname = event.meta.net.dst_host.clone();
    c.authenticated_user = event.meta.auth.user.clone();
    for (k, v) in &event.meta.ext {
        match (*k, v) {
            ("dst_ip_primary", MetaValue::String(s)) => {
                c.dst_ip = Some(
                    s.parse()
                        .map_err(|_| Reason::code("invalid_dst_ip_primary"))?,
                );
            }
            ("operation", MetaValue::String(s)) => {
                c.operation = Some(s.clone());
            }
            ("geo_country", MetaValue::String(s)) => {
                c.dst_geo = Some(s.clone());
            }
            ("asn", MetaValue::U64(n)) => {
                c.asn = Some(*n as u32);
            }
            ("geosite_tags", MetaValue::Bytes(b)) => {
                c.geosite_tags = b
                    .split(|x| *x == 0)
                    .filter(|s| !s.is_empty())
                    .filter_map(|s| std::str::from_utf8(s).ok())
                    .map(|s| s.to_string())
                    .collect();
            }
            _ => {}
        }
    }
    Ok(c)
}

fn apply_action(event: &mut Event, action: &Action) -> Verdict {
    match action {
        Action::Allow => Verdict::Continue,
        Action::Deny => Verdict::Reject(Reason::code("denied_by_rule")),
        Action::SetRouteGroup(g) => {
            event.meta.policy.route_group = Some(g.clone());
            Verdict::Continue
        }
        Action::SetCostBias(b) => {
            write_ext(event, "cost_bias", MetaValue::U64(encode_bias(*b)));
            Verdict::Continue
        }
        Action::SetScheduleHint(h) => {
            event.meta.transport.schedule_hint = match h {
                RuleScheduleHint::Auto => {
                    event.meta.transport.schedule_fanout_k = None;
                    None
                }
                RuleScheduleHint::FanOut { fanout } => {
                    event.meta.transport.schedule_fanout_k = Some(fanout.k);
                    Some(ScheduleHintLabel::FanOut)
                }
            };
            Verdict::Continue
        }
        Action::SetTransform(_) | Action::SetResolverPool(_) => {
            Verdict::Reject(Reason::code("unsupported_forward_rule_action"))
        }
        Action::Compose(items) => {
            for sub in items {
                match apply_action(event, sub) {
                    Verdict::Continue => {}
                    other => return other,
                }
            }
            Verdict::Continue
        }
        _ => Verdict::Reject(Reason::code("unsupported_forward_rule_action")),
    }
}

fn encode_bias(v: i32) -> u64 {
    let clamped = v.clamp(-9000, 9000);
    if clamped >= 0 {
        clamped as u64
    } else {
        (1u64 << 63) | ((-(clamped as i64)) as u64)
    }
}
