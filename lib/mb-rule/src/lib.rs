//! mb-rule — bus-mesh rule engine. See docs/handbook/system-architecture.html.
//!
//! Boundary: this crate MUST NOT depend on the bus core crate or any adapter crate.
//! All RuleCtx / Action types are rule-side DTOs owned here.

pub mod data_handle;
pub mod types;

pub use data_handle::{
    ParseError, RuleSetRegistry, ValidateError, evaluate_with_trace, parse_chain_and_rulesets_yaml,
    parse_chain_yaml, validate,
};
pub use types::*;
