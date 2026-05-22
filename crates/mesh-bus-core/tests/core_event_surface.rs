use mesh_bus_core::kernel::observation::{
    CoreEventId, DeliveryPolicy, EventTypeId, OBS_MESHSEC_DROP, OBS_NATIVE_DROP,
    default_event_type_specs,
};

#[test]
fn core_event_surface_is_exactly_four_variants() {
    fn assert_exhaustive(id: CoreEventId) -> &'static str {
        match id {
            CoreEventId::FlowOpened => "FlowOpened",
            CoreEventId::FlowPathChanged => "FlowPathChanged",
            CoreEventId::FlowClosed => "FlowClosed",
            CoreEventId::PathIoError => "PathIoError",
        }
    }
    assert_eq!(assert_exhaustive(CoreEventId::FlowOpened), "FlowOpened");
    assert_eq!(
        assert_exhaustive(CoreEventId::FlowPathChanged),
        "FlowPathChanged"
    );
    assert_eq!(assert_exhaustive(CoreEventId::FlowClosed), "FlowClosed");
    assert_eq!(assert_exhaustive(CoreEventId::PathIoError), "PathIoError");
}

#[test]
fn event_type_id_packs_core_in_low_bits() {
    assert!(EventTypeId::Core(CoreEventId::FlowOpened).as_u32() < 16);
    assert!(EventTypeId::Core(CoreEventId::PathIoError).as_u32() < 16);
    assert_eq!(OBS_MESHSEC_DROP.as_u32(), 16);
    assert_eq!(OBS_NATIVE_DROP.as_u32(), 17);
}

#[test]
fn default_catalog_keeps_core_and_obs_ranges_separate() {
    let specs = default_event_type_specs();
    assert_eq!(specs.len(), 6);
    assert_eq!(specs[0].id.as_u32(), 0);
    assert_eq!(specs[3].id.as_u32(), 3);
    assert_eq!(specs[4].id, OBS_MESHSEC_DROP);
    assert_eq!(specs[4].delivery, DeliveryPolicy::Lossy);
    assert_eq!(specs[5].id, OBS_NATIVE_DROP);
}
