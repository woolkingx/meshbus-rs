use super::dispatch::{DispatchRuntime, ExitRuntimeStats, FlowState};
use super::observation_wiring::{
    verify_observer_declarations, wire_core_observers, wire_scheduler_observer, wire_user_observers,
};
use super::port::BusPort;
use super::registry::Registry;
use super::types::BusError;
use crate::kernel::forwarder::{
    DatagramForwarderProbeOutcome, FlowCounters, ForwarderDatagramState, ForwarderStreamState,
};
use crate::kernel::observation::ObservationBus;
use crate::{
    BusSnapshot, EgressPlugin, ExitSnapshot, FlowId, Frame, PacketId, ReturnEvent, SchedulerPlugin,
    SessionId,
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::sync::{Mutex, Notify, Semaphore, mpsc, oneshot};

const DISPATCH_CONCURRENCY_LIMIT: usize = 512;

type SubmitTuple = (
    Frame,
    SessionId,
    mpsc::Sender<ReturnEvent>,
    oneshot::Sender<()>,
);

enum RuntimeCommand {
    Snapshot(oneshot::Sender<BusSnapshot>),
}

pub struct Bus {
    port: BusPort,
    submit_rx: Mutex<Option<mpsc::Receiver<SubmitTuple>>>,
    command_tx: mpsc::Sender<RuntimeCommand>,
    command_rx: Mutex<Option<mpsc::Receiver<RuntimeCommand>>>,
    egresses: Arc<Vec<Box<dyn EgressPlugin>>>,
    compiled_candidates: Arc<crate::kernel::compiled::CompiledCandidates>,
    scheduler: Arc<dyn SchedulerPlugin>,
    flow_pins: Arc<Mutex<HashMap<FlowId, usize>>>,
    packet_returns: Arc<Mutex<HashSet<(FlowId, PacketId)>>>,
    active_stream_polls: Arc<Mutex<HashMap<(SessionId, usize), tokio::task::JoinHandle<()>>>>,
    forwarder_streams: Arc<dashmap::DashMap<SessionId, ForwarderStreamState>>,
    forwarder_datagrams: Arc<dashmap::DashMap<SessionId, ForwarderDatagramState>>,
    probe_channels: Arc<
        dashmap::DashMap<SessionId, tokio::sync::oneshot::Sender<DatagramForwarderProbeOutcome>>,
    >,
    health_snapshot: Arc<crate::kernel::health_snapshot::HealthPublisher>,
    exit_stats: Arc<dashmap::DashMap<String, ExitRuntimeStats>>,
    metrics: Arc<crate::kernel::metrics_observer::MetricsObserver>,
    observation_bus: Arc<ObservationBus>,
    flow_counters: Arc<dashmap::DashMap<FlowId, Arc<FlowCounters>>>,
    flow_states: Arc<dashmap::DashMap<FlowId, FlowState>>,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    shutdown: Arc<AtomicBool>,
    in_flight: Arc<AtomicU64>,
    drain_notify: Arc<Notify>,
    dispatch_sem: Arc<Semaphore>,
}

pub struct BusHandle {
    shutdown: Arc<AtomicBool>,
    in_flight: Arc<AtomicU64>,
    drain_notify: Arc<Notify>,
    egresses: Arc<Vec<Box<dyn EgressPlugin>>>,
    exit_stats: Arc<dashmap::DashMap<String, ExitRuntimeStats>>,
    metrics: Arc<crate::kernel::metrics_observer::MetricsObserver>,
    flow_counters: Arc<dashmap::DashMap<FlowId, Arc<FlowCounters>>>,
    command_tx: mpsc::Sender<RuntimeCommand>,
    join: tokio::task::JoinHandle<()>,
}

#[derive(Clone)]
pub struct BusSnapshotClient {
    egresses: Arc<Vec<Box<dyn EgressPlugin>>>,
    exit_stats: Arc<dashmap::DashMap<String, ExitRuntimeStats>>,
    metrics: Arc<crate::kernel::metrics_observer::MetricsObserver>,
    flow_counters: Arc<dashmap::DashMap<FlowId, Arc<FlowCounters>>>,
    command_tx: mpsc::Sender<RuntimeCommand>,
}

impl BusSnapshotClient {
    pub async fn snapshot(&self) -> BusSnapshot {
        let (tx, rx) = oneshot::channel();
        if self
            .command_tx
            .send(RuntimeCommand::Snapshot(tx))
            .await
            .is_ok()
        {
            if let Ok(snap) = rx.await {
                return snap;
            }
        }
        collect_snapshot(
            &self.egresses,
            &self.exit_stats,
            &self.metrics,
            &self.flow_counters,
        )
        .await
    }
}

impl BusHandle {
    pub async fn shutdown(self) {
        self.shutdown.store(true, Ordering::SeqCst);
        while self.in_flight.load(Ordering::SeqCst) != 0 {
            self.drain_notify.notified().await;
        }
        let _ = self.join.await;
    }

    pub async fn shutdown_with_timeout(self, timeout: std::time::Duration) -> Result<(), BusError> {
        self.shutdown.store(true, Ordering::SeqCst);
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if self.in_flight.load(Ordering::SeqCst) == 0 {
                break;
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                self.join.abort();
                return Err(BusError::DrainTimeout);
            }
            if tokio::time::timeout(remaining, self.drain_notify.notified())
                .await
                .is_err()
            {
                self.join.abort();
                return Err(BusError::DrainTimeout);
            }
        }
        let _ = self.join.await;
        Ok(())
    }

    pub async fn snapshot(&self) -> BusSnapshot {
        self.snapshot_client().snapshot().await
    }

    pub fn snapshot_client(&self) -> BusSnapshotClient {
        BusSnapshotClient {
            egresses: self.egresses.clone(),
            exit_stats: self.exit_stats.clone(),
            metrics: self.metrics.clone(),
            flow_counters: self.flow_counters.clone(),
            command_tx: self.command_tx.clone(),
        }
    }
}

impl Bus {
    pub fn port(&self) -> BusPort {
        self.port.clone()
    }

    pub async fn snapshot(&self) -> BusSnapshot {
        collect_snapshot(
            &self.egresses,
            &self.exit_stats,
            &self.metrics,
            &self.flow_counters,
        )
        .await
    }

    pub fn spawn(self) -> BusHandle {
        let shutdown = self.shutdown.clone();
        let in_flight = self.in_flight.clone();
        let drain_notify = self.drain_notify.clone();
        let egresses = self.egresses.clone();
        let exit_stats = self.exit_stats.clone();
        let metrics = self.metrics.clone();
        let flow_counters = self.flow_counters.clone();
        let command_tx = self.command_tx.clone();
        let join = tokio::spawn(async move { self.run().await });
        BusHandle {
            shutdown,
            in_flight,
            drain_notify,
            egresses,
            exit_stats,
            metrics,
            flow_counters,
            command_tx,
            join,
        }
    }

    async fn run(self) {
        let mut rx = self
            .submit_rx
            .lock()
            .await
            .take()
            .expect("run called twice");
        let mut command_rx = self
            .command_rx
            .lock()
            .await
            .take()
            .expect("run called twice");
        loop {
            tokio::select! {
                cmd = command_rx.recv() => {
                    if let Some(RuntimeCommand::Snapshot(reply)) = cmd {
                        let _ = reply.send(collect_snapshot(&self.egresses, &self.exit_stats, &self.metrics, &self.flow_counters).await);
                    }
                }
                msg = rx.recv() => {
                    match msg {
                        Some((frame, _sid, return_tx, done_tx)) => {
                            let permit = loop {
                                tokio::select! {
                                    permit = self.dispatch_sem.clone().acquire_owned() => {
                                        match permit {
                                            Ok(p) => break p,
                                            Err(_) => return,
                                        }
                                    }
                                    cmd = command_rx.recv() => {
                                        match cmd {
                                            Some(RuntimeCommand::Snapshot(reply)) => {
                                                let _ = reply.send(collect_snapshot(&self.egresses, &self.exit_stats, &self.metrics, &self.flow_counters).await);
                                            }
                                            None => {
                                                match self.dispatch_sem.clone().acquire_owned().await {
                                                    Ok(p) => break p,
                                                    Err(_) => return,
                                                }
                                            }
                                        }
                                    }
                                }
                            };
                            self.in_flight.fetch_add(1, Ordering::SeqCst);
                            let runtime = DispatchRuntime {
                                egresses: self.egresses.clone(),
                                compiled_candidates: self.compiled_candidates.clone(),
                                scheduler: self.scheduler.clone(),
                                observation_bus: self.observation_bus.clone(),
                                flow_counters: self.flow_counters.clone(),
                                flow_states: self.flow_states.clone(),
                                flow_pins: self.flow_pins.clone(),
                                packet_returns: self.packet_returns.clone(),
                                active_stream_polls: self.active_stream_polls.clone(),
                                forwarder_streams: self.forwarder_streams.clone(),
                                forwarder_datagrams: self.forwarder_datagrams.clone(),
                                probe_channels: self.probe_channels.clone(),
                                health_snapshot: self.health_snapshot.clone(),
                                exit_stats: self.exit_stats.clone(),
                                clock: self.clock.clone(),
                                shutdown: self.shutdown.clone(),
                            };
                            let in_flight = self.in_flight.clone();
                            let drain_notify = self.drain_notify.clone();
                            tokio::spawn(async move {
                                super::dispatch::dispatch(frame, return_tx, runtime).await;
                                let _ = done_tx.send(());
                                if in_flight.fetch_sub(1, Ordering::SeqCst) == 1 {
                                    drain_notify.notify_waiters();
                                }
                                drop(permit);
                            });
                        }
                        None => break,
                    }
                }
                _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {
                    if self.shutdown.load(Ordering::SeqCst) { break; }
                }
            }
        }
    }
}

pub(crate) fn build(reg: Registry) -> Result<Bus, BusError> {
    let scheduler = reg.scheduler.ok_or(BusError::NoScheduler)?;
    if reg.egresses.is_empty() {
        return Err(BusError::NoEgress);
    }
    verify_observer_declarations(&reg.observers)?;
    let (submit_tx, submit_rx) = mpsc::channel(256);
    let (command_tx, command_rx) = mpsc::channel(16);
    let observation_bus = Arc::new(ObservationBus::new());
    let forwarder_streams = Arc::new(dashmap::DashMap::new());
    let forwarder_datagrams: Arc<dashmap::DashMap<SessionId, ForwarderDatagramState>> =
        Arc::new(dashmap::DashMap::new());
    let probe_channels: Arc<
        dashmap::DashMap<SessionId, tokio::sync::oneshot::Sender<DatagramForwarderProbeOutcome>>,
    > = Arc::new(dashmap::DashMap::new());

    let supports_stream = reg
        .egresses
        .iter()
        .any(|e| e.capabilities().supports_stream);
    let supports_datagram = reg
        .egresses
        .iter()
        .any(|e| e.capabilities().supports_datagram);
    let port = BusPort {
        submit_tx,
        next_session_id: Arc::new(AtomicU64::new(1)),
        supports_stream,
        supports_datagram,
        forwarder_streams: forwarder_streams.clone(),
        forwarder_datagrams: forwarder_datagrams.clone(),
        probe_channels: probe_channels.clone(),
        observation_bus: observation_bus.clone(),
    };

    // Build always-on observers
    let metrics: Arc<crate::kernel::metrics_observer::MetricsObserver> =
        crate::kernel::metrics_observer::MetricsObserver::new();
    let health_publisher = Arc::new(crate::kernel::health_snapshot::HealthPublisher::new());
    let exit_ids: Vec<String> = reg.egresses.iter().map(|e| e.id().0.clone()).collect();
    let health_observer = crate::kernel::health_observer::ExitHealthObserver::new(
        health_publisher.clone(),
        reg.health_policy,
        exit_ids,
    );

    let scheduler_arc: Arc<dyn SchedulerPlugin> = Arc::from(scheduler);
    wire_scheduler_observer(&observation_bus, scheduler_arc.clone());
    wire_core_observers(&observation_bus, metrics.clone(), health_observer.clone());
    wire_user_observers(&observation_bus, reg.observers);

    let compiled_candidates = Arc::new(crate::kernel::compiled::CompiledCandidates::from_egresses(
        &reg.egresses,
    ));

    Ok(Bus {
        port,
        submit_rx: Mutex::new(Some(submit_rx)),
        command_tx,
        command_rx: Mutex::new(Some(command_rx)),
        egresses: Arc::new(reg.egresses),
        compiled_candidates,
        scheduler: scheduler_arc,
        flow_pins: Arc::new(Mutex::new(HashMap::new())),
        packet_returns: Arc::new(Mutex::new(HashSet::new())),
        active_stream_polls: Arc::new(Mutex::new(HashMap::new())),
        forwarder_streams,
        forwarder_datagrams,
        probe_channels: probe_channels.clone(),
        health_snapshot: health_publisher,
        exit_stats: Arc::new(dashmap::DashMap::new()),
        metrics,
        observation_bus,
        flow_counters: Arc::new(dashmap::DashMap::new()),
        flow_states: Arc::new(dashmap::DashMap::new()),
        clock: Arc::new(monotonic_ms),
        shutdown: Arc::new(AtomicBool::new(false)),
        in_flight: Arc::new(AtomicU64::new(0)),
        drain_notify: Arc::new(Notify::new()),
        dispatch_sem: Arc::new(Semaphore::new(DISPATCH_CONCURRENCY_LIMIT)),
    })
}

async fn collect_snapshot(
    egresses: &Arc<Vec<Box<dyn EgressPlugin>>>,
    exit_stats: &Arc<dashmap::DashMap<String, ExitRuntimeStats>>,
    metrics: &Arc<crate::kernel::metrics_observer::MetricsObserver>,
    flow_counters: &Arc<dashmap::DashMap<FlowId, Arc<FlowCounters>>>,
) -> BusSnapshot {
    let exits = egresses
        .iter()
        .map(|egress| {
            let caps = egress.capabilities();
            let stat = exit_stats
                .get(&egress.id().0)
                .map(|r| r.clone())
                .unwrap_or_default();
            ExitSnapshot {
                exit_id: egress.id().clone(),
                protocol: caps.protocol.clone(),
                supports_stream: caps.supports_stream,
                supports_datagram: caps.supports_datagram,
                send_count: stat.send_count,
                success_count: stat.success_count,
                failure_count: stat.failure_count,
                last_rtt_ms: stat.last_rtt_ms,
                payload_bytes_total: stat.payload_bytes_total,
            }
        })
        .collect();
    let m = metrics.snapshot();
    BusSnapshot {
        exits,
        dispatch_success: m.dispatch_success,
        dispatch_failure: m.dispatch_failure,
        bytes_sent: m.bytes_sent,
        meshsec_drop_total: m.meshsec_drop_total,
        meshsec_auth_drop_total: m.meshsec_auth_drop_total,
        meshsec_replay_drop_total: m.meshsec_replay_drop_total,
        native_drop_total: m.native_drop_total,
        native_queue_overflow_drop_total: m.native_queue_overflow_drop_total,
        flows: flow_counters
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().snapshot()))
            .collect(),
    }
}

fn monotonic_ms() -> u64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_millis() as u64
}
