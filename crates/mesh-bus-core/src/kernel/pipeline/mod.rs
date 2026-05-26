pub(crate) mod data_handle;
pub(crate) mod types;

#[allow(unused_imports)]
pub(crate) use data_handle::{PipelineRunError, run_pipeline};
#[allow(unused_imports)]
pub(crate) use types::{Pipeline, Wiring};

#[cfg(test)]
mod tests;
