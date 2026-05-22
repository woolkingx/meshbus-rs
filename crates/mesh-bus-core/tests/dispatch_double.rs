//! Shared test doubles for the dispatch SERVICE composition tests.
//!
//! Dispatch is a SERVICE: it crosses Frame (L4 data-plane owned), the scheduler
//! decision, EgressPlugin behavior, ExitHealthTable, and the ObservationBus. It
//! is not a single-schema data owner, so its owner-contract tests drive the REAL
//! public `BusBuilder` dispatch boundary (no second mock runtime). This module
//! holds the ONE parameterized test egress + the reused scheduler/observer/
//! forwarder-half doubles so each case stays a thin composition assertion
//! instead of re-typing ~40 lines of EgressPlugin boilerplate per case
//! (DDTR D-M7.3 — collapses the 14 copy-pasted fakes from 383b81d).
//!
//! Published owner-test boundary per decision 0.4.39 (DDTR D-M7.2): Frame,
//! EgressPlugin, BusBuilder::add_egress, BusPort::open_session are public so
//! these owner-contract tests can drive the dispatch service directly. Runtime
//! application participants must NOT implement EgressPlugin for routing/wiring;
//! they use StreamEgress/DatagramEgress.

#![allow(dead_code)] // each tests/ file compiles this module; not all use every door

use async_trait::async_trait;
use bytes::Bytes;
use mb_endpoint::Endpoint;
use mesh_bus_core::{
    Capabilities, CloseReason, EgressPlugin, ExitId, ExitResult, Frame, Measurement, RankContext,
    ReturnEvent, ScheduleDecision, SchedulerPlugin, SessionId,
    kernel::forwarder::{ForwarderDatagramTransport, OpenedForwarderDatagram},
};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use tokio::sync::Mutex;

// ── Capabilities builders ────────────────────────────────────────────────────

pub fn stream_caps() -> Capabilities {
    Capabilities {
        protocol: "test".into(),
        supports_stream: true,
        supports_datagram: false,
        max_payload_bytes: None,
        groups: Vec::new(),
    }
}

pub fn datagram_caps() -> Capabilities {
    Capabilities {
        protocol: "udp-test".into(),
        supports_stream: false,
        supports_datagram: true,
        max_payload_bytes: Some(1200),
        groups: Vec::new(),
    }
}

pub fn caps(protocol: &str, supports_stream: bool, supports_datagram: bool) -> Capabilities {
    Capabilities {
        protocol: protocol.into(),
        supports_stream,
        supports_datagram,
        max_payload_bytes: None,
        groups: Vec::new(),
    }
}

// ── One parameterized test egress (replaces 14 copy-pasted fakes) ────────────

/// Behavior the dispatch service observes at the egress boundary. The case
/// selects one; the egress itself is a thin recording sink, never a runtime.
pub enum Behavior {
    /// success, returns Data{seq,payload}; counts sends.
    Echo { sends: Arc<AtomicU64> },
    /// success=false, returns Closed(Other); counts sends (health filtering).
    Fail { sends: Arc<AtomicU64> },
    /// success, returns Idle (no data); counts sends.
    Idle { sends: Arc<AtomicU64> },
    /// success, returns Data; records the Frame.path_trace dispatch appended.
    TraceCapture {
        sends: Arc<AtomicU64>,
        seen: Arc<Mutex<Vec<String>>>,
    },
    /// send returns Idle; poll() drains queued ReturnEvents (bytestream poll).
    PollQueue {
        rx: Mutex<tokio::sync::mpsc::Receiver<ReturnEvent>>,
    },
    /// send returns Idle + counts; open_forwarder_datagram yields a direct half.
    Forwarder {
        frame_sends: Arc<AtomicUsize>,
        direct_sends: Arc<AtomicUsize>,
    },
}

pub struct TestEgress {
    pub id: ExitId,
    pub caps: Capabilities,
    pub behavior: Behavior,
}

impl TestEgress {
    pub fn boxed(id: &str, caps: Capabilities, behavior: Behavior) -> Box<dyn EgressPlugin> {
        Box::new(TestEgress {
            id: ExitId(id.into()),
            caps,
            behavior,
        })
    }
}

#[async_trait]
impl EgressPlugin for TestEgress {
    fn id(&self) -> &ExitId {
        &self.id
    }
    fn capabilities(&self) -> &Capabilities {
        &self.caps
    }
    async fn send(&self, frame: Frame) -> ExitResult {
        let base = |success, return_event| ExitResult {
            exit_id: self.id.clone(),
            success,
            rtt_ms: 1,
            local_endpoint: None,
            return_event,
        };
        match &self.behavior {
            Behavior::Echo { sends } => {
                sends.fetch_add(1, Ordering::SeqCst);
                base(
                    true,
                    ReturnEvent::Data {
                        seq: frame.seq,
                        payload: frame.payload,
                    },
                )
            }
            Behavior::Fail { sends } => {
                sends.fetch_add(1, Ordering::SeqCst);
                base(
                    false,
                    ReturnEvent::Closed {
                        reason: CloseReason::Other("forced failure".into()),
                    },
                )
            }
            Behavior::Idle { sends } => {
                sends.fetch_add(1, Ordering::SeqCst);
                base(true, ReturnEvent::Idle)
            }
            Behavior::TraceCapture { sends, seen } => {
                sends.fetch_add(1, Ordering::SeqCst);
                *seen.lock().await = frame.path_trace.clone();
                base(
                    true,
                    ReturnEvent::Data {
                        seq: frame.seq,
                        payload: frame.payload,
                    },
                )
            }
            Behavior::PollQueue { .. } => base(true, ReturnEvent::Idle),
            Behavior::Forwarder { frame_sends, .. } => {
                frame_sends.fetch_add(1, Ordering::SeqCst);
                base(true, ReturnEvent::Idle)
            }
        }
    }
    async fn open_forwarder_datagram(
        &self,
        _frame: &Frame,
    ) -> Option<Result<OpenedForwarderDatagram, mesh_bus_core::DisconnectReason>> {
        match &self.behavior {
            Behavior::Forwarder { direct_sends, .. } => Some(Ok(OpenedForwarderDatagram {
                local_endpoint: None,
                rtt_ms: 1,
                transport: ForwarderDatagramTransport {
                    send: Mutex::new(Box::new(MockSendHalf {
                        send_count: direct_sends.clone(),
                    })),
                    recv: Mutex::new(Box::new(MockRecvHalf)),
                },
            })),
            _ => None,
        }
    }
    async fn poll(&self, _: &SessionId) -> ReturnEvent {
        match &self.behavior {
            Behavior::PollQueue { rx } => {
                rx.lock().await.recv().await.unwrap_or(ReturnEvent::Closed {
                    reason: CloseReason::ReaderClosed,
                })
            }
            _ => ReturnEvent::Idle,
        }
    }
    async fn probe(&self, _: &Endpoint) -> Measurement {
        Measurement {
            exit_id: self.id.clone(),
            at_ms: 0,
            rtt_ms: 1,
            payload_bytes: 0,
            jitter_ms: None,
            throughput_bps: None,
            success: !matches!(self.behavior, Behavior::Fail { .. }),
        }
    }
    async fn close(&self, _: &SessionId) {}
}

// ── Reused scheduler / observer / forwarder-half doubles ─────────────────────

pub struct First;
impl SchedulerPlugin for First {
    fn schedule(&self, candidates: &[ExitId], _: &RankContext) -> ScheduleDecision {
        ScheduleDecision::ordered((0..candidates.len()).collect())
    }
    fn feedback(&self, _: &ExitResult, _: u64, _: u64) {}
}

pub struct RecordingScheduler {
    pub seen: Arc<std::sync::Mutex<Vec<RankContext>>>,
}
impl SchedulerPlugin for RecordingScheduler {
    fn schedule(&self, candidates: &[ExitId], ctx: &RankContext) -> ScheduleDecision {
        self.seen.lock().expect("lock").push(ctx.clone());
        ScheduleDecision::ordered((0..candidates.len()).collect())
    }
    fn feedback(&self, _: &ExitResult, _: u64, _: u64) {}
}

pub struct MockSendHalf {
    pub send_count: Arc<AtomicUsize>,
}
#[async_trait]
impl mesh_bus_core::BusDatagramSendHalf for MockSendHalf {
    async fn send_to(&mut self, _: Endpoint, _: Bytes) -> Result<(), mesh_bus_core::SendError> {
        self.send_count.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn close(&mut self) {}
}

pub struct MockRecvHalf;
#[async_trait]
impl mesh_bus_core::BusDatagramRecvHalf for MockRecvHalf {
    async fn recv_from(&mut self) -> Option<(Endpoint, Bytes)> {
        std::future::pending().await
    }
    fn last_error(&self) -> Option<&mesh_bus_core::DisconnectReason> {
        None
    }
}
