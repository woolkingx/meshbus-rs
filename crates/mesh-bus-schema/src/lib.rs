//! Cross-module type definitions generated from schemas/*.schema.json.

use serde::{Deserialize, Serialize};

#[allow(
    clippy::disallowed_methods,
    clippy::len_zero,
    clippy::clone_on_copy,
    clippy::to_string_trait_impl
)]
mod generated {
    use super::*;
    include!(concat!(env!("OUT_DIR"), "/types.rs"));
}

pub use generated::*;
