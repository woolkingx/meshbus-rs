use super::types::{Event, HookTrace};
use crate::kernel::metadata::types::TypedMap;
use crate::kernel::verdict::data_handle::verdict_label;
use crate::kernel::verdict::types::{HookId, Verdict};
use bytes::Bytes;

#[allow(dead_code)]
pub fn event_new(payload: Bytes) -> Event {
    Event {
        payload,
        meta: TypedMap::default(),
    }
}

#[allow(dead_code)]
pub fn event_empty() -> Event {
    Event::default()
}

#[allow(dead_code)]
pub fn hook_trace_record(hook_id: &HookId, verdict: &Verdict) -> HookTrace {
    HookTrace {
        hook_id: hook_id.clone(),
        verdict: verdict_label(verdict),
    }
}
