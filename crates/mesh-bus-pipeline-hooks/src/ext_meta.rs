use mesh_bus_core::kernel::{Event, MetaValue, is_valid_ext_key_tail};

pub(crate) fn write_ext(event: &mut Event, key: &'static str, val: MetaValue) {
    debug_assert!(is_valid_ext_key_tail(key), "invalid ext key tail: {key}");
    if let Some(slot) = event.meta.ext.iter_mut().find(|(k, _)| *k == key) {
        slot.1 = val;
    } else {
        event.meta.ext.push((key, val));
    }
}

#[cfg(test)]
#[path = "ext_meta_tests.rs"]
mod ext_meta_tests;
