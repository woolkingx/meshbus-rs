use crate::{
    Capabilities, EgressPlugin, ExitId, ExitResult, Frame, Measurement, Registry, ReturnEvent,
    SessionId,
};
use async_trait::async_trait;

struct StubExit {
    id: ExitId,
}

#[async_trait]
impl EgressPlugin for StubExit {
    fn id(&self) -> &ExitId {
        &self.id
    }
    fn capabilities(&self) -> &Capabilities {
        panic!("stub")
    }
    async fn send(&self, _f: Frame) -> ExitResult {
        panic!("stub")
    }
    async fn poll(&self, _s: &SessionId) -> ReturnEvent {
        panic!("stub")
    }
    async fn probe(&self, _t: &mb_endpoint::Endpoint) -> Measurement {
        panic!("stub")
    }
    async fn close(&self, _s: &SessionId) {}
}

#[test]
fn registry_holds_egress() {
    let mut r = Registry::new();
    r.add_egress(Box::new(StubExit {
        id: ExitId("stub".into()),
    }));
    assert_eq!(r.egress_count(), 1);
}
