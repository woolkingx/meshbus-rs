use crate::types::*;
use mb_rule::types::*;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Projection {
    pub pool: Option<String>,
    pub route_group: Option<String>,
    pub schedule_hint_label: String,
    pub action_label: String,
    pub denied: bool,
}

pub fn build_rule_ctx(req: &ResolveRequest) -> RuleCtx {
    let hostname = {
        let mut s = req.qname.to_ascii_lowercase();
        while s.ends_with('.') {
            s.pop();
        }
        if s.is_empty() { None } else { Some(s) }
    };
    let qtype_str = match req.qtype {
        QType::A => "A",
        QType::Aaaa => "AAAA",
        QType::Ptr => "PTR",
        QType::Cname => "CNAME",
        QType::Txt => "TXT",
    }
    .to_string();
    RuleCtx {
        hostname,
        dns_qtype: Some(qtype_str),
        consumer: Some(req.consumer.0.clone()),
        ..RuleCtx::default()
    }
}

pub fn project_decision(dec: &RuleDecision) -> Projection {
    let mut p = Projection {
        schedule_hint_label: "ordered".to_string(),
        ..Projection::default()
    };
    walk(&dec.action, &mut p);
    if p.action_label.is_empty() {
        p.action_label = "allow".to_string();
    }
    p
}

fn walk(a: &Action, p: &mut Projection) {
    match a {
        Action::Allow => {
            if p.action_label.is_empty() {
                p.action_label = "allow".to_string();
            }
        }
        Action::Deny => {
            p.denied = true;
            p.action_label = "deny".to_string();
        }
        Action::SetRouteGroup(g) => {
            p.route_group = Some(g.clone());
            if p.action_label.is_empty() {
                p.action_label = format!("set_route_group:{g}");
            }
        }
        Action::SetScheduleHint(h) => {
            p.schedule_hint_label = match h {
                RuleScheduleHint::Auto => "ordered".to_string(),
                RuleScheduleHint::FanOut { fanout } => format!("fanout:k={}", fanout.k),
            };
        }
        Action::SetResolverPool(pl) => {
            p.pool = Some(pl.clone());
            p.action_label = format!("set_resolver_pool:{pl}");
        }
        Action::SetTransform(_) => {}
        Action::Compose(list) => {
            for x in list {
                walk(x, p);
                if p.denied {
                    return;
                }
            }
        }
        _ => {} // mb_rule::Action is #[non_exhaustive]
    }
}
