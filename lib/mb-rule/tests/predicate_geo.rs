use mb_rule::{
    data_handle::{RuleSetRegistry, evaluate_with_trace},
    types::{Action, MatchExpr, Predicate, Rule, RuleChain, RuleCtx},
};

fn act(chain: &RuleChain, ctx: &RuleCtx, reg: &RuleSetRegistry) -> Action {
    evaluate_with_trace(chain, ctx, reg).action
}

#[test]
fn dst_geo_eq_matches_country() {
    let chain = RuleChain {
        rules: vec![Rule {
            id: None,
            r#match: MatchExpr::Term(Predicate::DstGeoEq("CN".into())),
            action: Action::Allow,
        }],
        default: Action::Deny,
    };
    let mut ctx = RuleCtx::empty();
    ctx.dst_geo = Some("CN".into());
    assert_eq!(act(&chain, &ctx, &RuleSetRegistry::empty()), Action::Allow);

    ctx.dst_geo = Some("US".into());
    assert_eq!(act(&chain, &ctx, &RuleSetRegistry::empty()), Action::Deny);

    ctx.dst_geo = None;
    assert_eq!(act(&chain, &ctx, &RuleSetRegistry::empty()), Action::Deny);
}
