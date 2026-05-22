use mb_rule::{
    data_handle::{RuleSetRegistry, ValidateError, evaluate_with_trace, validate},
    types::{Action, MatchExpr, Predicate, Rule, RuleChain, RuleCtx},
};

#[test]
fn set_cost_bias_returns_action() {
    let chain = RuleChain {
        rules: vec![Rule {
            id: None,
            r#match: MatchExpr::Term(Predicate::AsnEq(13335)),
            action: Action::SetCostBias(500),
        }],
        default: Action::Allow,
    };
    let mut ctx = RuleCtx::empty();
    ctx.asn = Some(13335);
    assert_eq!(
        evaluate_with_trace(&chain, &ctx, &RuleSetRegistry::empty()).action,
        Action::SetCostBias(500)
    );
}

#[test]
fn compose_duplicate_set_cost_bias_rejected_by_validate() {
    let chain = RuleChain {
        rules: vec![Rule {
            id: None,
            r#match: MatchExpr::Term(Predicate::AsnEq(13335)),
            action: Action::Compose(vec![Action::SetCostBias(500), Action::SetCostBias(-200)]),
        }],
        default: Action::Allow,
    };
    let err = validate(&chain, &[]).unwrap_err();
    assert!(matches!(err, ValidateError::ComposeMultipleCostBias));
}
