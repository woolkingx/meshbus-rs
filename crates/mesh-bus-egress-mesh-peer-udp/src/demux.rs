use crate::{
    DeliveryCoord, EgressPolicy, MeshSecRecv, now_unix_secs, sender::MeshPeerSender,
    wire_close_to_disconnect,
};
use bytes::{Bytes, BytesMut};
use mb_endpoint::Endpoint;
use mb_proto_mesh::{
    CloseReasonWire, EventSemantic, MESHSEC_ACCEPTED_EPOCH_SKEW_SLOTS, MeshFrame, NativeEventMode,
    decode_event, decode_frame, decode_mesh_frame_clear, event_frame_payload, meshsec_epoch_number,
    open_bytes, open_mesh_frame,
};
use mb_reorder::{FamilyPushOutcome, FamilyReorderState};
use mesh_bus_core::DisconnectReason;
use mesh_bus_core::transport::udp_loop::UdpPacketLoop;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

const STREAM_CONTROL_BOUND: usize = 32;
const STREAM_DATA_BOUND: usize = 256;
const STREAM_EVENT_BOUND: usize = 16;
const DATAGRAM_BOUND: usize = 256;
const REPAIR_CONTROL_BOUND: usize = 64;
const NATIVE_REORDER_WINDOW: u16 = 64;

type FamilyKey = (SocketAddr, String);

#[derive(Debug)]
pub(crate) enum StreamControl {
    OpenAccepted {
        open_token: u64,
    },
    OpenRejected {
        open_token: u64,
        close_reason: CloseReasonWire,
    },
}

#[derive(Debug)]
pub(crate) enum StreamEvent {
    ShutdownWrite,
    Close(CloseReasonWire),
    QueueFull,
}

pub(crate) struct StreamDemuxHandle {
    pub(crate) control_inbox: mpsc::Receiver<StreamControl>,
    pub(crate) data_inbox: mpsc::Receiver<Bytes>,
    pub(crate) event_inbox: mpsc::Receiver<StreamEvent>,
    pub(crate) driver: DriverGuard,
}

pub(crate) struct DatagramDemuxHandle {
    pub(crate) datagram_inbox: mpsc::Receiver<(Endpoint, Bytes)>,
    pub(crate) error_inbox: mpsc::Receiver<DisconnectReason>,
    pub(crate) driver: DriverGuard,
}

pub(crate) struct DriverGuard {
    handles: Vec<JoinHandle<()>>,
}

impl DriverGuard {
    fn new_pair(driver: JoinHandle<()>, control: JoinHandle<()>) -> Self {
        Self {
            handles: vec![driver, control],
        }
    }
}

impl Drop for DriverGuard {
    fn drop(&mut self) {
        for handle in &self.handles {
            handle.abort();
        }
    }
}

fn spawn_repair_control_worker(
    sender: MeshPeerSender,
    mut repair_rx: mpsc::Receiver<Vec<Vec<u8>>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(resend) = repair_rx.recv().await {
            let _ = sender.send_repair_bytes(resend).await;
        }
    })
}

pub(crate) fn spawn_stream_driver(
    packet_loop: Arc<UdpPacketLoop>,
    coord: Arc<DeliveryCoord>,
    policy: Arc<EgressPolicy>,
    sender: MeshPeerSender,
    native_event_mode: NativeEventMode,
    meshsec: Option<MeshSecRecv>,
    session_id: String,
) -> StreamDemuxHandle {
    let (control_tx, control_inbox) = mpsc::channel(STREAM_CONTROL_BOUND);
    let (data_tx, data_inbox) = mpsc::channel(STREAM_DATA_BOUND);
    let (event_tx, event_inbox) = mpsc::channel(STREAM_EVENT_BOUND);
    let (repair_tx, repair_rx) = mpsc::channel(REPAIR_CONTROL_BOUND);
    let control = spawn_repair_control_worker(sender, repair_rx);
    let driver = tokio::spawn(async move {
        let mut driver = Driver {
            packet_loop,
            coord,
            policy,
            native_event_mode,
            meshsec,
            family_states: HashMap::new(),
            repair_tx,
        };
        loop {
            if control_tx.is_closed() && data_tx.is_closed() && event_tx.is_closed() {
                break;
            }
            if driver.packet_loop.poll_recv().await.is_err() {
                break;
            }
            let frames = driver.drain_frames().await;
            for frame in frames {
                if driver.handle_common_frame(&frame) {
                    continue;
                }
                match frame {
                    MeshFrame::StreamOpenAccepted {
                        session_id: frame_session_id,
                        open_token,
                    } if frame_session_id == session_id => {
                        if control_tx
                            .try_send(StreamControl::OpenAccepted { open_token })
                            .is_err()
                        {
                            return;
                        }
                    }
                    MeshFrame::StreamOpenReject {
                        session_id: frame_session_id,
                        open_token,
                        close_reason,
                        ..
                    } if frame_session_id == session_id => {
                        if control_tx
                            .try_send(StreamControl::OpenRejected {
                                open_token,
                                close_reason,
                            })
                            .is_err()
                        {
                            return;
                        }
                    }
                    MeshFrame::StreamData {
                        session_id: frame_session_id,
                        payload,
                        ..
                    } if frame_session_id == session_id => {
                        if data_tx.try_send(payload).is_err() {
                            let _ = event_tx.try_send(StreamEvent::QueueFull);
                        }
                    }
                    MeshFrame::StreamShutdownWrite {
                        session_id: frame_session_id,
                    } if frame_session_id == session_id => {
                        let _ = event_tx.try_send(StreamEvent::ShutdownWrite);
                    }
                    MeshFrame::StreamClose {
                        session_id: frame_session_id,
                        close_reason,
                    } if frame_session_id == session_id => {
                        let _ = event_tx.try_send(StreamEvent::Close(close_reason));
                    }
                    _ => {}
                }
            }
        }
    });
    StreamDemuxHandle {
        control_inbox,
        data_inbox,
        event_inbox,
        driver: DriverGuard::new_pair(driver, control),
    }
}

pub(crate) fn spawn_datagram_driver(
    packet_loop: Arc<UdpPacketLoop>,
    coord: Arc<DeliveryCoord>,
    policy: Arc<EgressPolicy>,
    sender: MeshPeerSender,
    native_event_mode: NativeEventMode,
    meshsec: Option<MeshSecRecv>,
    session_id: String,
) -> DatagramDemuxHandle {
    let (datagram_tx, datagram_inbox) = mpsc::channel(DATAGRAM_BOUND);
    let (error_tx, error_inbox) = mpsc::channel(1);
    let (repair_tx, repair_rx) = mpsc::channel(REPAIR_CONTROL_BOUND);
    let control = spawn_repair_control_worker(sender, repair_rx);
    let driver = tokio::spawn(async move {
        let mut driver = Driver {
            packet_loop,
            coord,
            policy,
            native_event_mode,
            meshsec,
            family_states: HashMap::new(),
            repair_tx,
        };
        loop {
            if datagram_tx.is_closed() {
                break;
            }
            if driver.packet_loop.poll_recv().await.is_err() {
                break;
            }
            let frames = driver.drain_frames().await;
            for frame in frames {
                if driver.handle_common_frame(&frame) {
                    continue;
                }
                match frame {
                    MeshFrame::DatagramReturn {
                        session_id: frame_session_id,
                        source,
                        payload,
                        ..
                    } if frame_session_id == session_id => {
                        if datagram_tx.try_send((source, payload)).is_err() {
                            let _ = error_tx.try_send(DisconnectReason::QueueFull);
                            return;
                        }
                    }
                    MeshFrame::DatagramClose {
                        session_id: frame_session_id,
                        ..
                    } if frame_session_id == session_id => {
                        return;
                    }
                    _ => {}
                }
            }
        }
    });
    DatagramDemuxHandle {
        datagram_inbox,
        error_inbox,
        driver: DriverGuard::new_pair(driver, control),
    }
}

struct Driver {
    packet_loop: Arc<UdpPacketLoop>,
    coord: Arc<DeliveryCoord>,
    policy: Arc<EgressPolicy>,
    native_event_mode: NativeEventMode,
    meshsec: Option<MeshSecRecv>,
    family_states: HashMap<FamilyKey, FamilyReorderState>,
    repair_tx: mpsc::Sender<Vec<Vec<u8>>>,
}

impl Driver {
    async fn drain_frames(&mut self) -> Vec<MeshFrame> {
        let mut frames = Vec::new();
        for inbound in self.packet_loop.drain_inbound() {
            frames.extend(self.decode_datagram(inbound.source, &inbound.payload).await);
        }
        frames
    }

    async fn decode_datagram(&mut self, peer: SocketAddr, payload: &[u8]) -> Vec<MeshFrame> {
        let clear = match self.meshsec.as_mut() {
            Some(mc) => match self.native_event_mode {
                NativeEventMode::MeshFrame => {
                    let epoch = meshsec_epoch_number(now_unix_secs());
                    return match open_mesh_frame(
                        payload,
                        &mc.keys,
                        &mc.local_node_id,
                        epoch.saturating_sub(MESHSEC_ACCEPTED_EPOCH_SKEW_SLOTS)
                            ..=epoch + MESHSEC_ACCEPTED_EPOCH_SKEW_SLOTS,
                        &mut mc.replay,
                    ) {
                        Ok((_, frame)) => vec![frame],
                        Err(_) => Vec::new(),
                    };
                }
                NativeEventMode::SecureUdpNative => {
                    let epoch = meshsec_epoch_number(now_unix_secs());
                    match open_bytes(
                        payload,
                        &mc.keys,
                        &mc.local_node_id,
                        epoch.saturating_sub(MESHSEC_ACCEPTED_EPOCH_SKEW_SLOTS)
                            ..=epoch + MESHSEC_ACCEPTED_EPOCH_SKEW_SLOTS,
                        &mut mc.replay,
                    ) {
                        Ok((_, clear)) => clear,
                        Err(_) => return Vec::new(),
                    }
                }
            },
            None => payload.to_vec(),
        };

        match self.native_event_mode {
            NativeEventMode::MeshFrame => decode_legacy_frame(&clear).into_iter().collect(),
            NativeEventMode::SecureUdpNative => {
                if let Ok(event) = decode_event(&mut BytesMut::from(&clear[..])) {
                    self.decode_native_event(peer, event).await
                } else {
                    decode_legacy_frame(&clear).into_iter().collect()
                }
            }
        }
    }

    async fn decode_native_event(
        &mut self,
        peer: SocketAddr,
        event: mb_proto_mesh::MeshEvent,
    ) -> Vec<MeshFrame> {
        match event.semantic {
            EventSemantic::Control | EventSemantic::Observation => event_frame_payload(&event)
                .and_then(decode_legacy_frame)
                .into_iter()
                .collect(),
            EventSemantic::Stream | EventSemantic::Datagram => {
                let Some(package) = event.package else {
                    return Vec::new();
                };
                let family_id = event.family_id.clone();
                let fam_key = (peer, family_id.clone());
                let outcome = self
                    .family_states
                    .entry(fam_key.clone())
                    .or_insert_with(|| {
                        FamilyReorderState::new(family_id, 1, NATIVE_REORDER_WINDOW, 0)
                    })
                    .push_package(package);
                match outcome {
                    FamilyPushOutcome::Deliver(packages) => packages
                        .into_iter()
                        .filter_map(|pkg| decode_legacy_frame(&pkg.payload))
                        .collect(),
                    FamilyPushOutcome::Gap(ack) => {
                        self.enqueue_retransmit(&ack);
                        Vec::new()
                    }
                    FamilyPushOutcome::WindowOverflow(_) => {
                        self.family_states.remove(&fam_key);
                        Vec::new()
                    }
                    FamilyPushOutcome::Buffered | FamilyPushOutcome::Duplicate => Vec::new(),
                }
            }
        }
    }

    fn enqueue_retransmit(&self, ack: &mb_proto_mesh::AckNack) {
        let resend = self.policy.to_retransmit(ack);
        if resend.is_empty() {
            return;
        }
        let _ = self.repair_tx.try_send(resend);
    }

    fn handle_common_frame(&self, frame: &MeshFrame) -> bool {
        match frame {
            MeshFrame::PortOpen(mouth) => {
                self.coord.apply_port_open(mouth);
                true
            }
            MeshFrame::PortClose { .. } => true,
            MeshFrame::AckNack(ack) => {
                self.enqueue_retransmit(ack);
                true
            }
            _ => false,
        }
    }
}

fn decode_legacy_frame(payload: &[u8]) -> Option<MeshFrame> {
    decode_frame(&mut BytesMut::from(payload))
        .or_else(|_| decode_mesh_frame_clear(payload))
        .ok()
}

pub(crate) fn control_result(
    control: StreamControl,
    open_token: u64,
) -> Option<Result<(), DisconnectReason>> {
    match control {
        StreamControl::OpenAccepted {
            open_token: frame_token,
        } if frame_token == open_token => Some(Ok(())),
        StreamControl::OpenRejected {
            open_token: frame_token,
            close_reason,
        } if frame_token == open_token => Some(Err(wire_close_to_disconnect(close_reason))),
        _ => None,
    }
}

#[cfg(test)]
#[path = "demux_tests.rs"]
mod demux_tests;
