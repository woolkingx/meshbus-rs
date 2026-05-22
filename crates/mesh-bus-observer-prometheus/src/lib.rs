//! Prometheus textfile observer for per-exit dispatch telemetry.

use mesh_bus_core::kernel::observation::{
    CoreEventId, EventTypeId, OBS_MESHSEC_DROP, OBS_NATIVE_DROP,
};
use mesh_bus_core::{BusEvent, Measurement, ObserverPlugin};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, Semaphore, mpsc};
use tokio::time::{Duration, timeout};

const METRICS_READ_TIMEOUT: Duration = Duration::from_millis(500);
const MAX_METRICS_CONNECTIONS: usize = 64;
const DRAIN_CHANNEL_CAPACITY: usize = 256;

#[derive(Debug, Clone, Default)]
struct ExitStats {
    dispatch_total: u64,
    success_total: u64,
    failure_total: u64,
    payload_bytes_total: u64,
    last_rtt_ms: u64,
}

#[derive(Debug, Clone, Default)]
struct DropStats {
    meshsec_by_reason: BTreeMap<String, u64>,
    native_by_reason: BTreeMap<String, u64>,
}

// Shared label maps — written by builder methods, read by the drainer.
type LabelMap = Arc<RwLock<HashMap<String, String>>>;
// Per-exit static label set (exit_id -> ordered {label -> value}).
type PerExitLabels = Arc<RwLock<HashMap<String, BTreeMap<String, String>>>>;

#[derive(Clone)]
pub struct PrometheusTextfileObserver {
    path: Option<PathBuf>,
    stats: Arc<Mutex<BTreeMap<String, ExitStats>>>,
    drop_stats: Arc<std::sync::Mutex<DropStats>>,
    wan_labels: LabelMap,
    peer_labels: PerExitLabels,
    static_labels: LabelMap,
    drain_tx: mpsc::Sender<Measurement>,
}

impl PrometheusTextfileObserver {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let stats = Arc::new(Mutex::new(BTreeMap::new()));
        let drop_stats = Arc::new(std::sync::Mutex::new(DropStats::default()));
        let wan_labels: LabelMap = Arc::new(RwLock::new(HashMap::new()));
        let peer_labels: PerExitLabels = Arc::new(RwLock::new(HashMap::new()));
        let static_labels: LabelMap = Arc::new(RwLock::new(HashMap::new()));
        let (drain_tx, drain_rx) = mpsc::channel(DRAIN_CHANNEL_CAPACITY);
        let obs = Self {
            path: Some(path),
            stats,
            drop_stats,
            wan_labels,
            peer_labels,
            static_labels,
            drain_tx,
        };
        obs.spawn_drainer(drain_rx);
        obs
    }

    pub fn http() -> Self {
        let stats = Arc::new(Mutex::new(BTreeMap::new()));
        let drop_stats = Arc::new(std::sync::Mutex::new(DropStats::default()));
        let wan_labels: LabelMap = Arc::new(RwLock::new(HashMap::new()));
        let peer_labels: PerExitLabels = Arc::new(RwLock::new(HashMap::new()));
        let static_labels: LabelMap = Arc::new(RwLock::new(HashMap::new()));
        let (drain_tx, drain_rx) = mpsc::channel(DRAIN_CHANNEL_CAPACITY);
        let obs = Self {
            path: None,
            stats,
            drop_stats,
            wan_labels,
            peer_labels,
            static_labels,
            drain_tx,
        };
        obs.spawn_drainer(drain_rx);
        obs
    }

    pub fn with_wan_labels(self, wan_labels: HashMap<String, String>) -> Self {
        *self.wan_labels.write().expect("wan_labels lock") = wan_labels;
        self
    }

    pub fn with_peer_labels(self, peer_labels: HashMap<String, BTreeMap<String, String>>) -> Self {
        *self.peer_labels.write().expect("peer_labels lock") = peer_labels;
        self
    }

    pub fn with_static_labels(self, static_labels: HashMap<String, String>) -> Self {
        *self.static_labels.write().expect("static_labels lock") = static_labels;
        self
    }

    pub async fn snapshot_text(&self) -> String {
        let stats = self.stats.lock().await;
        let drop_stats = self.drop_stats.lock().expect("drop_stats lock").clone();
        let wan = self.wan_labels.read().expect("wan_labels lock");
        let peer = self.peer_labels.read().expect("peer_labels lock");
        let sta = self.static_labels.read().expect("static_labels lock");
        render_metrics(&stats, &drop_stats, &wan, &peer, &sta)
    }

    pub async fn serve_http(self, listener: TcpListener) -> std::io::Result<()> {
        let permits = Arc::new(Semaphore::new(MAX_METRICS_CONNECTIONS));
        loop {
            let Ok(permit) = permits.clone().acquire_owned().await else {
                return Ok(());
            };
            let (mut socket, _) = listener.accept().await?;
            let observer = self.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let Some(request) = read_http_request(&mut socket).await else {
                    let _ = socket.shutdown().await;
                    return;
                };
                let response = if request.starts_with("GET /metrics ") {
                    let body = observer.snapshot_text().await;
                    format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: text/plain; version=0.0.4\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                } else {
                    let body = "not found\n";
                    format!(
                        "HTTP/1.1 404 Not Found\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                };
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    }

    fn spawn_drainer(&self, mut rx: mpsc::Receiver<Measurement>) {
        let stats = self.stats.clone();
        let drop_stats = self.drop_stats.clone();
        let path = self.path.clone();
        let wan_labels = self.wan_labels.clone();
        let peer_labels = self.peer_labels.clone();
        let static_labels = self.static_labels.clone();
        tokio::spawn(async move {
            while let Some(measurement) = rx.recv().await {
                let text = {
                    let mut s = stats.lock().await;
                    let entry = s.entry(measurement.exit_id.0.clone()).or_default();
                    entry.dispatch_total = entry.dispatch_total.saturating_add(1);
                    entry.payload_bytes_total = entry
                        .payload_bytes_total
                        .saturating_add(measurement.payload_bytes);
                    entry.last_rtt_ms = measurement.rtt_ms;
                    if measurement.success {
                        entry.success_total = entry.success_total.saturating_add(1);
                    } else {
                        entry.failure_total = entry.failure_total.saturating_add(1);
                    }
                    let wan = wan_labels.read().expect("wan_labels lock");
                    let peer = peer_labels.read().expect("peer_labels lock");
                    let sta = static_labels.read().expect("static_labels lock");
                    let drops = drop_stats.lock().expect("drop_stats lock").clone();
                    render_metrics(&s, &drops, &wan, &peer, &sta)
                };
                if let Some(p) = &path {
                    if let Err(err) = write_textfile(p, &text).await {
                        tracing::warn!(path = %p.display(), error = %err, "prometheus textfile write failed");
                    }
                }
            }
        });
    }
}

impl ObserverPlugin for PrometheusTextfileObserver {
    fn on_event(&self, event: &BusEvent) {
        match event {
            BusEvent::Core(env) => {
                // dispatch_total counts dispatch ATTEMPTS. A flow that opens then
                // closes is one attempt: FlowClosed is the terminal lifecycle of an
                // already-counted FlowOpened and carries no new bytes/RTT, so it
                // must not be forwarded or dispatch_total double-counts.
                if !matches!(
                    env.type_id,
                    EventTypeId::Core(CoreEventId::FlowOpened)
                        | EventTypeId::Core(CoreEventId::PathIoError)
                ) {
                    return;
                }
                let payload = &env.payload.0;
                let Some(exit_id) = payload
                    .selected_exit
                    .as_ref()
                    .or(payload.exit_id.as_ref())
                    .cloned()
                else {
                    return;
                };
                let measurement = Measurement {
                    exit_id: mesh_bus_core::ExitId(exit_id),
                    at_ms: payload.at_ms,
                    rtt_ms: payload.rtt_ms,
                    payload_bytes: payload.bytes_out.max(payload.payload_bytes),
                    jitter_ms: None,
                    throughput_bps: None,
                    success: payload.success.unwrap_or(matches!(
                        env.type_id,
                        EventTypeId::Core(CoreEventId::FlowOpened)
                    )),
                };
                // Lossy on full — side-channel contract; emit path must not block.
                let _ = self.drain_tx.try_send(measurement);
            }
            BusEvent::Observation(env) => {
                let reason = env.payload.0.reason.as_deref().unwrap_or("unknown");
                let mut stats = self.drop_stats.lock().expect("drop_stats lock");
                match env.type_id {
                    OBS_MESHSEC_DROP => {
                        *stats
                            .meshsec_by_reason
                            .entry(reason.to_string())
                            .or_insert(0) += 1;
                    }
                    OBS_NATIVE_DROP => {
                        *stats
                            .native_by_reason
                            .entry(reason.to_string())
                            .or_insert(0) += 1;
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    fn subscribed_events(&self) -> &'static [EventTypeId] {
        &[OBS_MESHSEC_DROP, OBS_NATIVE_DROP]
    }
}

async fn read_http_request(socket: &mut tokio::net::TcpStream) -> Option<String> {
    let mut request = Vec::with_capacity(1024);
    timeout(METRICS_READ_TIMEOUT, async {
        let mut buf = [0u8; 256];
        loop {
            let n = socket.read(&mut buf).await.ok()?;
            if n == 0 {
                return None;
            }
            request.extend_from_slice(&buf[..n]);
            if request.windows(4).any(|w| w == b"\r\n\r\n") {
                return Some(());
            }
            if request.len() >= 4096 {
                return None;
            }
        }
    })
    .await
    .ok()??;
    Some(String::from_utf8_lossy(&request).into_owned())
}

fn render_metrics(
    stats: &BTreeMap<String, ExitStats>,
    drop_stats: &DropStats,
    wan_labels: &HashMap<String, String>,
    peer_labels: &HashMap<String, BTreeMap<String, String>>,
    static_labels: &HashMap<String, String>,
) -> String {
    let mut out = String::new();
    out.push_str("# HELP mesh_bus_dispatch_total Total dispatch attempts by exit.\n");
    out.push_str("# TYPE mesh_bus_dispatch_total counter\n");
    for (exit, stat) in stats {
        out.push_str(&format!(
            "mesh_bus_dispatch_total{{{}}} {}\n",
            labels(exit, wan_labels, peer_labels, static_labels),
            stat.dispatch_total
        ));
    }
    out.push_str("# HELP mesh_bus_dispatch_success_total Successful dispatch attempts by exit.\n");
    out.push_str("# TYPE mesh_bus_dispatch_success_total counter\n");
    for (exit, stat) in stats {
        out.push_str(&format!(
            "mesh_bus_dispatch_success_total{{{}}} {}\n",
            labels(exit, wan_labels, peer_labels, static_labels),
            stat.success_total
        ));
    }
    out.push_str("# HELP mesh_bus_dispatch_failure_total Failed dispatch attempts by exit.\n");
    out.push_str("# TYPE mesh_bus_dispatch_failure_total counter\n");
    for (exit, stat) in stats {
        out.push_str(&format!(
            "mesh_bus_dispatch_failure_total{{{}}} {}\n",
            labels(exit, wan_labels, peer_labels, static_labels),
            stat.failure_total
        ));
    }
    out.push_str("# HELP mesh_bus_dispatch_payload_bytes_total Payload bytes sent by exit.\n");
    out.push_str("# TYPE mesh_bus_dispatch_payload_bytes_total counter\n");
    for (exit, stat) in stats {
        out.push_str(&format!(
            "mesh_bus_dispatch_payload_bytes_total{{{}}} {}\n",
            labels(exit, wan_labels, peer_labels, static_labels),
            stat.payload_bytes_total
        ));
    }
    out.push_str("# HELP mesh_bus_dispatch_rtt_ms_last Last observed dispatch RTT by exit.\n");
    out.push_str("# TYPE mesh_bus_dispatch_rtt_ms_last gauge\n");
    for (exit, stat) in stats {
        out.push_str(&format!(
            "mesh_bus_dispatch_rtt_ms_last{{{}}} {}\n",
            labels(exit, wan_labels, peer_labels, static_labels),
            stat.last_rtt_ms
        ));
    }
    out.push_str("# HELP mesh_bus_dispatch_success_rate Dispatch success ratio by exit.\n");
    out.push_str("# TYPE mesh_bus_dispatch_success_rate gauge\n");
    for (exit, stat) in stats {
        let rate = if stat.dispatch_total == 0 {
            0.0
        } else {
            stat.success_total as f64 / stat.dispatch_total as f64
        };
        out.push_str(&format!(
            "mesh_bus_dispatch_success_rate{{{}}} {:.6}\n",
            labels(exit, wan_labels, peer_labels, static_labels),
            rate
        ));
    }
    out.push_str("# HELP mesh_bus_meshsec_drop_total MeshSec packet drops by reason.\n");
    out.push_str("# TYPE mesh_bus_meshsec_drop_total counter\n");
    for (reason, count) in &drop_stats.meshsec_by_reason {
        out.push_str(&format!(
            "mesh_bus_meshsec_drop_total{{{}}} {}\n",
            reason_labels(reason, static_labels),
            count
        ));
    }
    out.push_str("# HELP mesh_bus_native_drop_total Native mesh packet drops by reason.\n");
    out.push_str("# TYPE mesh_bus_native_drop_total counter\n");
    for (reason, count) in &drop_stats.native_by_reason {
        out.push_str(&format!(
            "mesh_bus_native_drop_total{{{}}} {}\n",
            reason_labels(reason, static_labels),
            count
        ));
    }
    out
}

fn reason_labels(reason: &str, static_labels: &HashMap<String, String>) -> String {
    let mut labels = format!("reason=\"{}\"", escape_label(reason));
    let mut static_labels: Vec<_> = static_labels.iter().collect();
    static_labels.sort_by(|a, b| a.0.cmp(b.0));
    for (key, value) in static_labels {
        labels.push_str(&format!(
            ",{}=\"{}\"",
            escape_label(key),
            escape_label(value)
        ));
    }
    labels
}

fn labels(
    exit_id: &str,
    wan_labels: &HashMap<String, String>,
    peer_labels: &HashMap<String, BTreeMap<String, String>>,
    static_labels: &HashMap<String, String>,
) -> String {
    let mut labels = format!("exit_id=\"{}\"", escape_label(exit_id));
    if let Some(wan_id) = wan_labels.get(exit_id) {
        labels.push_str(&format!(",wan_id=\"{}\"", escape_label(wan_id)));
    }
    if let Some(per) = peer_labels.get(exit_id) {
        for (key, value) in per {
            labels.push_str(&format!(
                ",{}=\"{}\"",
                escape_label(key),
                escape_label(value)
            ));
        }
    }
    let mut static_labels: Vec<_> = static_labels.iter().collect();
    static_labels.sort_by(|a, b| a.0.cmp(b.0));
    for (key, value) in static_labels {
        labels.push_str(&format!(
            ",{}=\"{}\"",
            escape_label(key),
            escape_label(value)
        ));
    }
    labels
}

fn escape_label(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

async fn write_textfile(path: &Path, text: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let tmp = path.with_extension("tmp");
    tokio::fs::write(&tmp, text).await?;
    tokio::fs::rename(tmp, path).await
}
