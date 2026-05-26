use crate::kernel::data_handle::Registry;

#[test]
fn registry_starts_empty() {
    let r = Registry::new();
    assert!(r.egresses.is_empty());
    assert!(r.observers.is_empty());
    assert!(r.scheduler.is_none());
}
