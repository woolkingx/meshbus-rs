use mb_rule::{
    data_handle::{RuleSetRegistry, evaluate_with_trace},
    types::{Action, MatchExpr, Predicate, Rule, RuleChain, RuleCtx},
};

fn act(chain: &RuleChain, ctx: &RuleCtx, reg: &RuleSetRegistry) -> Action {
    evaluate_with_trace(chain, ctx, reg).action
}

#[test]
fn asn_eq_matches_exact() {
    let chain = RuleChain {
        rules: vec![Rule {
            id: None,
            r#match: MatchExpr::Term(Predicate::AsnEq(13335)),
            action: Action::Allow,
        }],
        default: Action::Deny,
    };
    let mut ctx = RuleCtx::empty();
    ctx.asn = Some(13335);
    assert_eq!(act(&chain, &ctx, &RuleSetRegistry::empty()), Action::Allow);
    ctx.asn = Some(15169);
    assert_eq!(act(&chain, &ctx, &RuleSetRegistry::empty()), Action::Deny);
    ctx.asn = None;
    assert_eq!(act(&chain, &ctx, &RuleSetRegistry::empty()), Action::Deny);
}

#[test]
fn asn_any_matches_set() {
    let chain = RuleChain {
        rules: vec![Rule {
            id: None,
            r#match: MatchExpr::Term(Predicate::AsnAny(vec![13335, 15169])),
            action: Action::Allow,
        }],
        default: Action::Deny,
    };
    let mut ctx = RuleCtx::empty();
    ctx.asn = Some(15169);
    assert_eq!(act(&chain, &ctx, &RuleSetRegistry::empty()), Action::Allow);
    ctx.asn = Some(7922);
    assert_eq!(act(&chain, &ctx, &RuleSetRegistry::empty()), Action::Deny);
}
