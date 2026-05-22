use mb_geoip::GeoIpDb;
use mb_geosite::GeositeDb;
use mesh_bus_resolver::cache::DnsCache;
use mesh_bus_resolver::data_handle::ResolverHandle;
use std::sync::Arc;

/// One exit candidate as seen by the pick_sink hook. Sourced from the bus
/// runtime's operator egress set plus its capability labels; health metrics are
/// seeded here and can later be replaced by a live snapshot.
#[derive(Clone, Debug)]
pub struct ExitCandidate {
    /// Matches BusSessionRequest target sink_id.
    pub sink_id: String,
    /// Empty = no route_group membership; otherwise all accepted group labels.
    pub route_groups: Vec<String>,
    pub supports_stream: bool,
    pub supports_datagram: bool,
    pub rtt_ms: u64,
    pub success_rate: f64,
    pub jitter_ms: u64,
}

/// Shared state every hook needs. Built once at boot; the ingress installs
/// it into a thread-local before each pipeline run so sync HookFn pointers
/// can reach the Tokio runtime handle + cache handles.
#[derive(Clone)]
pub struct SharedHookCtx {
    pub resolver: Arc<dyn ResolverHandle>,
    pub cache: Arc<DnsCache>,
    pub geoip: Arc<GeoIpDb>,
    pub geosite: Arc<GeositeDb>,
    pub rule_chain: Arc<mb_rule::RuleChain>,
    pub rule_sets: Arc<mb_rule::RuleSetRegistry>,
    pub candidates: Arc<Vec<ExitCandidate>>,
    pub tokio: tokio::runtime::Handle,
}

thread_local! {
    static SHARED: std::cell::RefCell<Option<SharedHookCtx>> =
        const { std::cell::RefCell::new(None) };
}

pub fn install(ctx: SharedHookCtx) {
    SHARED.with(|c| *c.borrow_mut() = Some(ctx));
}

pub struct InstalledHookCtx;

impl Drop for InstalledHookCtx {
    fn drop(&mut self) {
        clear();
    }
}

pub fn install_scoped(ctx: SharedHookCtx) -> InstalledHookCtx {
    install(ctx);
    InstalledHookCtx
}

pub fn current() -> Option<SharedHookCtx> {
    SHARED.with(|c| c.borrow().clone())
}

pub fn clear() {
    SHARED.with(|c| *c.borrow_mut() = None);
}
