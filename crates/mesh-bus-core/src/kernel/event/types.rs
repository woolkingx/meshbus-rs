use crate::kernel::metadata::types::TypedMap;
use crate::kernel::verdict::types::HookId;
use bytes::Bytes;

#[derive(Debug, Clone, Default)]
pub struct Event {
    pub payload: Bytes,
    pub meta: TypedMap,
}

/// One entry in a pipeline execution trace — one per hook invocation.
#[derive(Debug, Clone)]
pub struct HookTrace {
    pub hook_id: HookId,
    /// VerdictLabel string: "Continue" | "Jump" | "Accept" | "Reject" | "Drop"
    pub verdict: &'static str,
}
