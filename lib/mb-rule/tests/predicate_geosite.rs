use mb_rule::{
    data_handle::{RuleSetRegistry, evaluate_with_trace},
    types::{Action, MatchExpr, Predicate, Rule, RuleChain, RuleCtx},
};

fn act(chain: &RuleChain, ctx: &RuleCtx, reg: &RuleSetRegistry) -> Action {
    evaluate_with_trace(chain, ctx, reg).action
}

#[test]
fn geosite_tag_matches_membership() {
    let chain = RuleChain {
        rules: vec![Rule {
            id: None,
            r#match: MatchExpr::Term(Predicate::GeositeTag("ad".into())),
            action: Action::Deny,
        }],
        default: Action::Allow,
    };
    let mut ctx = RuleCtx::empty();
    ctx.geosite_tags = vec!["cn".into(), "ad".into()];
    assert_eq!(act(&chain, &ctx, &RuleSetRegistry::empty()), Action::Deny);

    ctx.geosite_tags = vec!["cn".into()];
    assert_eq!(act(&chain, &ctx, &RuleSetRegistry::empty()), Action::Allow);

    ctx.geosite_tags.clear();
    assert_eq!(act(&chain, &ctx, &RuleSetRegistry::empty()), Action::Allow);
}
