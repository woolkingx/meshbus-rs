pub(crate) mod data_handle;
pub(crate) mod types;

#[allow(unused_imports)]
pub(crate) use data_handle::{event_empty, event_new, hook_trace_record};
#[allow(unused_imports)]
pub(crate) use types::{Event, HookTrace};

#[cfg(test)]
mod tests;
