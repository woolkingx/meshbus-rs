pub(crate) mod data_handle;
pub(crate) mod types;

#[allow(unused_imports)]
pub(crate) use data_handle::{ext_get, ext_set, is_valid_ext_key_tail};
#[allow(unused_imports)]
pub(crate) use types::{
    AuthMeta, MetaValue, NetMeta, PolicyMeta, ScheduleHintLabel, SmallMap, TraceMeta,
    TransportMeta, TypedMap,
};

#[cfg(test)]
mod tests;
