use super::*;
use crate::FlowId;

struct Mock;
impl PathStatsProvider for Mock {
    fn path_stats(&self, flow_id: &FlowId) -> Option<PathStats> {
        if flow_id.0 == "known" {
            Some(PathStats {
                rtt_us: Some(2_500),
                sampled_at_ms: 1,
                ..Default::default()
            })
        } else {
            None
        }
    }
}

#[test]
fn provider_returns_some_for_known_flow() {
    let p: Box<dyn PathStatsProvider> = Box::new(Mock);
    assert!(p.path_stats(&FlowId("known".into())).is_some());
    assert!(p.path_stats(&FlowId("other".into())).is_none());
}
