use mesh_bus_core::{BusEvent, ObserverPlugin, SessionId};

struct Probe;
impl ObserverPlugin for Probe {
    fn on_event(&self, _event: &BusEvent) {}
}

#[test]
fn observer_plugin_on_event_is_sync() {
    let p: Box<dyn ObserverPlugin> = Box::new(Probe);
    p.on_event(&BusEvent::SessionOpened(SessionId("s".into())));
}
