use crate::types::ResolutionSignals;
use mb_rule::types::{Action, RuleDecision, RuleScheduleHint};

/// Build a zero-state ResolutionSignals with qname_key and pool populated.
/// All numeric fields start at 0; action defaults to "allow".
pub fn fresh_signals(qname_lower: &str, pool_name: &str) -> ResolutionSignals {
    ResolutionSignals {
        qname_key: qname_lower.to_string(),
        pool: pool_name.to_string(),
        action: "allow".to_string(),
        schedule_hint: "ordered".to_string(),
        ..ResolutionSignals::default()
    }
}

/// Copy decision-trace fields from a `RuleDecision` into a mutable signals struct.
pub fn record_rule_decision(sig: &mut ResolutionSignals, decision: &RuleDecision) {
    sig.matched_rule_id = decision.trace.rule_id.clone();
    sig.matched_rule_index = decision.trace.rule_index.map(|i| i as u32);
    sig.default_used = decision.trace.default_used;
    sig.action = action_label(&decision.action);
}

/// Emit a structured tracing access log with all ResolutionSignals fields.
/// `target` should be "mesh_bus.resolver.open" or "mesh_bus.resolver.denied".
/// `tracing::info!` requires a literal for target:, so we branch on the two
/// canonical values; anything else falls through to the open target.
pub fn emit_access_log(sig: &ResolutionSignals, target: &str) {
    macro_rules! emit {
        ($tgt:literal) => {
            tracing::info!(
                target: $tgt,
                qname_key = %sig.qname_key,
                pool = %sig.pool,
                resolver_rtt_ms = sig.resolver_rtt_ms,
                attempted = sig.attempted,
                answer_count = sig.answer_count,
                truncated = sig.truncated,
                matched_rule_id = ?sig.matched_rule_id,
                matched_rule_index = ?sig.matched_rule_index,
                default_used = sig.default_used,
                action = %sig.action,
                schedule_hint = %sig.schedule_hint,
            )
        };
    }
    match target {
        "mesh_bus.resolver.denied" => emit!("mesh_bus.resolver.denied"),
        _ => emit!("mesh_bus.resolver.open"),
    }
}

/// Pure label for an `mb_rule::Action`.
pub fn action_label(action: &Action) -> String {
    match action {
        Action::Allow => "allow".into(),
        Action::Deny => "deny".into(),
        Action::SetResolverPool(p) => format!("set_resolver_pool:{p}"),
        Action::SetRouteGroup(g) => format!("set_route_group:{g}"),
        Action::SetScheduleHint(RuleScheduleHint::Auto) => "set_schedule_hint:auto".into(),
        Action::SetScheduleHint(RuleScheduleHint::FanOut { fanout }) => {
            format!("set_schedule_hint:fanout:k={}", fanout.k)
        }
        Action::SetTransform(_) => "set_transform".into(),
        Action::Compose(_) => "compose".into(),
        _ => "unknown".into(),
    }
}
