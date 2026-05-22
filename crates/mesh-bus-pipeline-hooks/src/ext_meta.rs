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
mod tests {
    use super::write_ext;
    use mesh_bus_core::kernel::{Event, MetaValue, is_valid_ext_key_tail};

    #[test]
    fn write_ext_inserts_and_updates_without_duplicates() {
        let mut event = Event::default();

        write_ext(&mut event, "operation", MetaValue::String("connect".into()));
        write_ext(
            &mut event,
            "operation",
            MetaValue::String("datagram_send".into()),
        );

        assert_eq!(event.meta.ext.len(), 1);
        assert_eq!(
            event.meta.ext[0],
            ("operation", MetaValue::String("datagram_send".into()))
        );
    }

    #[test]
    fn ext_key_tail_shape_matches_metadata_schema() {
        for key in ["operation", "dst_ip_primary", "geo.country"] {
            assert!(is_valid_ext_key_tail(key), "{key} should be valid");
        }
        for key in [
            "",
            "ext.operation",
            "net.dst_host",
            "bad-key",
            "bad key",
            "bad/key",
        ] {
            assert!(!is_valid_ext_key_tail(key), "{key} should be invalid");
        }
    }
}
