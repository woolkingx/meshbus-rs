//! Verifies that `apply_action` projects an `mb_rule::Action` onto a
//! `BusSessionRequest` (or short-circuits to `Deny`) without exposing any
//! bus-core L4 internals.

use mb_endpoint::Endpoint;
use mb_rule::{Action, FanOutParams, RuleScheduleHint, RuleTransformDescriptor, RuleTransformKind};
use mesh_bus_core::{BusSessionRequest, ScheduleHint};
use mesh_bus_ingress_socks5::action_apply::{ApplyOutcome, apply_action};

fn req() -> BusSessionRequest {
    let target = Endpoint::new("example.com", 443).expect("endpoint");
    BusSessionRequest::stream(target)
}

#[test]
fn allow_passes_request_through_unchanged() {
    let base = req();
    let outcome = apply_action(Action::Allow, base.clone());
    match outcome {
        ApplyOutcome::Allow(r) => assert_eq!(r, base),
        ApplyOutcome::Deny => panic!("expected allow"),
    }
}

#[test]
fn deny_short_circuits() {
    match apply_action(Action::Deny, req()) {
        ApplyOutcome::Deny => {}
        ApplyOutcome::Allow(_) => panic!("expected deny"),
    }
}

#[test]
fn set_route_group_writes_field() {
    let outcome = apply_action(Action::SetRouteGroup("cn".into()), req());
    let ApplyOutcome::Allow(r) = outcome else {
        panic!("expected allow");
    };
    assert_eq!(r.route_group.as_deref(), Some("cn"));
}

#[test]
fn set_schedule_hint_fanout_maps_to_bus_fanout() {
    let outcome = apply_action(
        Action::SetScheduleHint(RuleScheduleHint::FanOut {
            fanout: FanOutParams { k: 3 },
        }),
        req(),
    );
    let ApplyOutcome::Allow(r) = outcome else {
        panic!("expected allow");
    };
    assert!(matches!(r.schedule_hint, ScheduleHint::FanOut { k: 3 }));
}

#[test]
fn set_schedule_hint_auto_maps_to_auto() {
    let mut base = req();
    base.schedule_hint = ScheduleHint::FanOut { k: 5 };
    let outcome = apply_action(Action::SetScheduleHint(RuleScheduleHint::Auto), base);
    let ApplyOutcome::Allow(r) = outcome else {
        panic!("expected allow");
    };
    assert!(matches!(r.schedule_hint, ScheduleHint::Auto));
}

#[test]
fn set_transform_fails_closed_at_l7_socks5_ingress_for_v1() {
    let outcome = apply_action(
        Action::SetTransform(RuleTransformDescriptor {
            kind: RuleTransformKind::Fragment,
            params: Default::default(),
        }),
        req(),
    );
    assert!(matches!(outcome, ApplyOutcome::Deny));
}

#[test]
fn set_resolver_pool_fails_closed_at_l7_socks5_ingress() {
    let outcome = apply_action(Action::SetResolverPool("dns-cn".into()), req());
    assert!(matches!(outcome, ApplyOutcome::Deny));
}

#[test]
fn compose_applies_in_order_with_deny_short_circuit() {
    let outcome = apply_action(
        Action::Compose(vec![
            Action::SetRouteGroup("us".into()),
            Action::Deny,
            Action::SetRouteGroup("cn".into()), // never reached
        ]),
        req(),
    );
    assert!(matches!(outcome, ApplyOutcome::Deny));
}

#[test]
fn compose_later_setter_overrides_earlier() {
    let outcome = apply_action(
        Action::Compose(vec![
            Action::SetRouteGroup("us".into()),
            Action::SetRouteGroup("cn".into()),
        ]),
        req(),
    );
    let ApplyOutcome::Allow(r) = outcome else {
        panic!("expected allow");
    };
    assert_eq!(r.route_group.as_deref(), Some("cn"));
}
