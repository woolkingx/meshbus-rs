use super::dispatch::DispatchRuntime;

#[derive(Debug, Clone, Default)]
pub(super) struct SourceActivityState {
    pub active_flows: u32,
    pub idle_since_ms: Option<u64>,
}

pub(super) fn snapshot(
    runtime: &DispatchRuntime,
    source_key: Option<&str>,
) -> Option<crate::SourceActivity> {
    let key = source_key?;
    runtime
        .source_activity
        .get(key)
        .map(|entry| crate::SourceActivity {
            active_flows: entry.active_flows,
            idle_since_ms: entry.idle_since_ms,
        })
}

pub(super) fn mark_open(runtime: &DispatchRuntime, source_key: Option<&str>) {
    let Some(source_key) = source_key else {
        return;
    };
    let mut entry = runtime
        .source_activity
        .entry(source_key.to_string())
        .or_default();
    entry.active_flows = entry.active_flows.saturating_add(1);
    entry.idle_since_ms = None;
}

pub(super) fn mark_closed(runtime: &DispatchRuntime, source_key: Option<&str>) {
    let Some(source_key) = source_key else {
        return;
    };
    mark_closed_in_table(
        &runtime.source_activity,
        source_key.to_string(),
        (runtime.clock)(),
    );
}

pub(super) fn mark_closed_in_table(
    source_activity: &dashmap::DashMap<String, SourceActivityState>,
    source_key: String,
    now_ms: u64,
) {
    let mut entry = source_activity.entry(source_key).or_default();
    entry.active_flows = entry.active_flows.saturating_sub(1);
    if entry.active_flows == 0 {
        entry.idle_since_ms = Some(now_ms);
    }
}
