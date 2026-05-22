//! Projects an `mb_rule::Action` onto a `BusSessionRequest`.
//!
//! L7 stitcher hook: rule engine speaks rule-side DTOs; this module is the
//! single place that maps them onto the canonical Bus* session request.

use mb_rule::{Action, RuleDecision, RuleScheduleHint};
use mesh_bus_core::{BusSessionRequest, ScheduleHint};

#[derive(Debug, Clone)]
pub enum ApplyOutcome {
    Allow(BusSessionRequest),
    Deny,
}

pub fn apply_action(action: Action, request: BusSessionRequest) -> ApplyOutcome {
    apply_one(action, request)
}

pub fn apply_decision(decision: RuleDecision, request: BusSessionRequest) -> ApplyOutcome {
    apply_one(decision.action, request)
}

pub fn validate_rule_policy_actions(chain: &mb_rule::RuleChain) -> Result<(), String> {
    for rule in &chain.rules {
        validate_projectable_action(&rule.action)?;
    }
    validate_projectable_action(&chain.default)
}

fn validate_projectable_action(action: &Action) -> Result<(), String> {
    match action {
        Action::Allow | Action::Deny | Action::SetRouteGroup(_) | Action::SetScheduleHint(_) => {
            Ok(())
        }
        Action::Compose(actions) => {
            for inner in actions {
                validate_projectable_action(inner)?;
            }
            Ok(())
        }
        Action::SetResolverPool(_) | Action::SetTransform(_) | Action::SetCostBias(_) => Err(
            "unsupported legacy rule action: action cannot be projected onto BusSessionRequest"
                .into(),
        ),
        _ => Err(
            "unsupported legacy rule action: action cannot be projected onto BusSessionRequest"
                .into(),
        ),
    }
}

fn apply_one(action: Action, request: BusSessionRequest) -> ApplyOutcome {
    match action {
        Action::Allow => ApplyOutcome::Allow(request),
        Action::Deny => ApplyOutcome::Deny,
        Action::SetRouteGroup(group) => ApplyOutcome::Allow(request.with_route_group(group)),
        Action::SetScheduleHint(hint) => {
            ApplyOutcome::Allow(request.with_schedule_hint(map_schedule_hint(hint)))
        }
        Action::SetTransform(descriptor) => {
            tracing::warn!(
                target: "mesh_bus.ingress.socks5",
                transform = ?descriptor.kind,
                "set_transform_unsupported_at_socks5_ingress"
            );
            ApplyOutcome::Deny
        }
        Action::Compose(actions) => {
            let mut current = request;
            for inner in actions {
                match apply_one(inner, current) {
                    ApplyOutcome::Allow(next) => current = next,
                    ApplyOutcome::Deny => return ApplyOutcome::Deny,
                }
            }
            ApplyOutcome::Allow(current)
        }
        other => {
            tracing::warn!(
                target: "mesh_bus.ingress.socks5",
                action = ?other,
                "unsupported_action_variant_denied"
            );
            ApplyOutcome::Deny
        }
    }
}

fn map_schedule_hint(hint: RuleScheduleHint) -> ScheduleHint {
    match hint {
        RuleScheduleHint::Auto => ScheduleHint::Auto,
        RuleScheduleHint::FanOut { fanout } => ScheduleHint::FanOut {
            k: fanout.k as usize,
        },
    }
}

pub fn action_label(action: &Action) -> String {
    match action {
        Action::Allow => "allow".into(),
        Action::Deny => "deny".into(),
        Action::SetRouteGroup(group) => format!("set_route_group:{group}"),
        Action::SetScheduleHint(RuleScheduleHint::Auto) => "set_schedule_hint:auto".into(),
        Action::SetScheduleHint(RuleScheduleHint::FanOut { fanout }) => {
            format!("set_schedule_hint:fanout:k={}", fanout.k)
        }
        Action::SetTransform(_) => "set_transform".into(),
        Action::Compose(_) => "compose".into(),
        _ => "unknown".into(),
    }
}

pub fn schedule_hint_label(hint: &ScheduleHint) -> String {
    match hint {
        ScheduleHint::Auto => "auto".into(),
        ScheduleHint::SinglePath => "ordered".into(),
        ScheduleHint::FanOut { k } => format!("fanout:k={k}"),
        ScheduleHint::Stripe { n } => format!("stripe:n={n}"),
        _ => "unknown".into(),
    }
}
