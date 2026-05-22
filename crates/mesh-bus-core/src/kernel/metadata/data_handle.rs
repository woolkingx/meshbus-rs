use super::types::{MetaValue, SmallMap};

/// Insert or update a key in the extension map.
#[allow(dead_code)]
pub fn ext_set(ext: &mut SmallMap, key: &'static str, value: MetaValue) {
    debug_assert!(is_valid_ext_key_tail(key), "invalid ext key tail: {key}");
    if let Some(slot) = ext.iter_mut().find(|(k, _)| *k == key) {
        slot.1 = value;
    } else {
        ext.push((key, value));
    }
}

/// Look up a key in the extension map.
#[allow(dead_code)]
pub fn ext_get<'a>(ext: &'a SmallMap, key: &str) -> Option<&'a MetaValue> {
    ext.iter().find(|(k, _)| *k == key).map(|(_, v)| v)
}

#[allow(dead_code)]
pub fn is_valid_ext_key_tail(key: &str) -> bool {
    if matches!(
        key.split_once('.').map(|(head, _)| head),
        Some("net" | "transport" | "policy" | "auth" | "trace" | "ext")
    ) {
        return false;
    }
    !key.is_empty()
        && key.split('.').all(|part| {
            !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
}
