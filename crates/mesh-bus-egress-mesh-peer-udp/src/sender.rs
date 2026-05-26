use crate::{DeliveryCoord, EgressPolicy, MeshSecEgress, now_unix_secs};
use bytes::Bytes;
use mb_proto_mesh::{
    EventSemantic, MeshFrame, NativeEventMode, encode_event, encode_frame, frame_event_meta,
    meshsec_epoch_number, seal_bytes, seal_mesh_frame, wrap_frame_event,
};
use mesh_bus_core::SendError;
use mesh_bus_core::transport::udp_loop::{OutboundDatagram, UdpPacketLoop};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

const CONTROL_QUEUE_BOUND: usize = 128;
const DATA_QUEUE_BOUND: usize = 1024;
const DATA_FLUSH_BATCH_DATAGRAMS: usize = 32;
const DATA_FLUSH_MAX_DELAY: Duration = Duration::from_micros(250);
const MAX_UDP_PAYLOAD_BYTES: usize = 65_507;

#[derive(Clone)]
pub(crate) struct MeshPeerSender {
    control_tx: mpsc::Sender<SenderRequest>,
    data_tx: mpsc::Sender<SenderRequest>,
}

enum SenderRequest {
    Frame {
        frame: MeshFrame,
        done: oneshot::Sender<Result<(), SendError>>,
    },
    Frames {
        frames: Vec<MeshFrame>,
        done: oneshot::Sender<Result<(), SendError>>,
    },
    RepairBytes {
        datagrams: Vec<Vec<u8>>,
        done: oneshot::Sender<Result<(), SendError>>,
    },
}

struct PendingSend {
    datagrams: Vec<OutboundDatagram>,
    done: oneshot::Sender<Result<(), SendError>>,
}

struct SenderDriver {
    packet_loop: Arc<UdpPacketLoop>,
    coord: Arc<DeliveryCoord>,
    policy: Arc<EgressPolicy>,
    timeout: Duration,
    native_event_mode: NativeEventMode,
    seal: Option<MeshSecEgress>,
    control_rx: mpsc::Receiver<SenderRequest>,
    data_rx: mpsc::Receiver<SenderRequest>,
    pending_data: Vec<PendingSend>,
}

impl MeshPeerSender {
    pub(crate) fn spawn(
        packet_loop: Arc<UdpPacketLoop>,
        coord: Arc<DeliveryCoord>,
        policy: Arc<EgressPolicy>,
        timeout: Duration,
        native_event_mode: NativeEventMode,
        seal: Option<MeshSecEgress>,
    ) -> Self {
        let (control_tx, control_rx) = mpsc::channel(CONTROL_QUEUE_BOUND);
        let (data_tx, data_rx) = mpsc::channel(DATA_QUEUE_BOUND);
        let driver = SenderDriver {
            packet_loop,
            coord,
            policy,
            timeout,
            native_event_mode,
            seal,
            control_rx,
            data_rx,
            pending_data: Vec::new(),
        };
        tokio::spawn(driver.run());
        Self {
            control_tx,
            data_tx,
        }
    }

    pub(crate) async fn send_frame(&self, frame: MeshFrame) -> Result<(), SendError> {
        let (done, wait) = oneshot::channel();
        let tx = if is_control_frame(&frame) {
            &self.control_tx
        } else {
            &self.data_tx
        };
        tx.try_send(SenderRequest::Frame { frame, done })
            .map_err(|_| SendError::BufferFull)?;
        wait.await.unwrap_or(Err(SendError::Closed))
    }

    pub(crate) async fn send_data_frames(&self, frames: Vec<MeshFrame>) -> Result<(), SendError> {
        if frames.is_empty() {
            return Ok(());
        }
        if frames.iter().any(is_control_frame) {
            for frame in frames {
                self.send_frame(frame).await?;
            }
            return Ok(());
        }
        let (done, wait) = oneshot::channel();
        self.data_tx
            .try_send(SenderRequest::Frames { frames, done })
            .map_err(|_| SendError::BufferFull)?;
        wait.await.unwrap_or(Err(SendError::Closed))
    }

    pub(crate) async fn send_repair_bytes(&self, datagrams: Vec<Vec<u8>>) -> Result<(), SendError> {
        if datagrams.is_empty() {
            return Ok(());
        }
        let (done, wait) = oneshot::channel();
        self.control_tx
            .try_send(SenderRequest::RepairBytes { datagrams, done })
            .map_err(|_| SendError::BufferFull)?;
        wait.await.unwrap_or(Err(SendError::Closed))
    }
}

impl SenderDriver {
    async fn run(mut self) {
        loop {
            tokio::select! {
                biased;
                Some(request) = self.control_rx.recv() => {
                    self.handle_control(request).await;
                }
                Some(request) = self.data_rx.recv() => {
                    self.push_data(request);
                    self.collect_data_until_flush().await;
                }
                else => {
                    self.complete_pending_data(Err(SendError::Closed));
                    break;
                }
            }
        }
    }

    async fn collect_data_until_flush(&mut self) {
        let delay = tokio::time::sleep(DATA_FLUSH_MAX_DELAY);
        tokio::pin!(delay);
        loop {
            if self.pending_data_datagrams() >= DATA_FLUSH_BATCH_DATAGRAMS {
                self.flush_pending_data().await;
                return;
            }
            tokio::select! {
                biased;
                Some(request) = self.control_rx.recv() => {
                    self.handle_control(request).await;
                }
                Some(request) = self.data_rx.recv() => {
                    self.push_data(request);
                }
                _ = &mut delay => {
                    self.flush_pending_data().await;
                    return;
                }
                else => {
                    self.flush_pending_data().await;
                    return;
                }
            }
        }
    }

    async fn handle_control(&mut self, request: SenderRequest) {
        let mut pending = Vec::new();
        self.push_request(request, &mut pending);
        while let Ok(request) = self.control_rx.try_recv() {
            self.push_request(request, &mut pending);
        }
        flush_pending(&self.packet_loop, self.timeout, pending).await;
    }

    fn push_data(&mut self, request: SenderRequest) {
        let mut encoded = Vec::new();
        self.push_request(request, &mut encoded);
        self.pending_data.extend(encoded);
    }

    fn push_request(&self, request: SenderRequest, out: &mut Vec<PendingSend>) {
        match request {
            SenderRequest::Frame { frame, done } => match self.encode_frame_datagrams(&frame) {
                Ok(datagrams) => out.push(PendingSend { datagrams, done }),
                Err(err) => {
                    let _ = done.send(Err(err));
                }
            },
            SenderRequest::Frames { frames, done } => {
                let mut datagrams = Vec::new();
                for frame in frames {
                    match self.encode_frame_datagrams(&frame) {
                        Ok(mut next) => datagrams.append(&mut next),
                        Err(err) => {
                            let _ = done.send(Err(err));
                            return;
                        }
                    }
                }
                out.push(PendingSend { datagrams, done });
            }
            SenderRequest::RepairBytes { datagrams, done } => {
                let destination = self.coord.addr();
                let mut outbound = Vec::with_capacity(datagrams.len());
                for payload in datagrams {
                    outbound.push(OutboundDatagram {
                        destination,
                        payload: Bytes::from(payload),
                    });
                }
                out.push(PendingSend {
                    datagrams: outbound,
                    done,
                });
            }
        }
    }

    fn encode_frame_datagrams(
        &self,
        frame: &MeshFrame,
    ) -> Result<Vec<OutboundDatagram>, SendError> {
        let peer = self.coord.addr();
        let (_, frame_seq, frame_semantic) = frame_event_meta(frame);
        let encoded = match (self.native_event_mode, self.seal.as_ref()) {
            (NativeEventMode::MeshFrame, Some(s)) => seal_mesh_frame(
                frame,
                &s.ctx,
                meshsec_epoch_number(now_unix_secs()),
                s.counter.fetch_add(1, Ordering::Relaxed),
            )
            .map_err(|_| SendError::Closed)?,
            (NativeEventMode::MeshFrame, None) => {
                encode_frame(frame).map_err(|_| SendError::Closed)?
            }
            (NativeEventMode::SecureUdpNative, seal) => {
                let frame_clear = encode_frame(frame).map_err(|_| SendError::Closed)?;
                let (family_id, seq, semantic) = frame_event_meta(frame);
                let event = wrap_frame_event(
                    family_id,
                    seq,
                    semantic,
                    self.policy.policy_id(),
                    &frame_clear,
                );
                let event_bytes = encode_event(&event).map_err(|_| SendError::Closed)?;
                match seal {
                    Some(s) => seal_bytes(
                        &event_bytes,
                        &s.ctx,
                        meshsec_epoch_number(now_unix_secs()),
                        s.counter.fetch_add(1, Ordering::Relaxed),
                    )
                    .map_err(|_| SendError::Closed)?,
                    None => event_bytes,
                }
            }
        };
        if encoded.len() > MAX_UDP_PAYLOAD_BYTES {
            return Err(SendError::PayloadTooLarge);
        }
        if matches!(
            frame_semantic,
            EventSemantic::Datagram | EventSemantic::Stream
        ) {
            self.policy.remember(frame_seq, &encoded);
        }
        let mut datagrams = Vec::with_capacity(self.policy.send_copies());
        for _ in 0..self.policy.send_copies() {
            datagrams.push(OutboundDatagram {
                destination: peer,
                payload: Bytes::from(encoded.clone()),
            });
        }
        Ok(datagrams)
    }

    fn pending_data_datagrams(&self) -> usize {
        self.pending_data
            .iter()
            .map(|pending| pending.datagrams.len())
            .sum()
    }

    async fn flush_pending_data(&mut self) {
        let pending = std::mem::take(&mut self.pending_data);
        flush_pending(&self.packet_loop, self.timeout, pending).await;
    }

    fn complete_pending_data(&mut self, result: Result<(), SendError>) {
        for pending in self.pending_data.drain(..) {
            let _ = pending.done.send(result.clone());
        }
    }
}

async fn flush_pending(packet_loop: &UdpPacketLoop, timeout: Duration, pending: Vec<PendingSend>) {
    if pending.is_empty() {
        return;
    }
    let mut completions = Vec::with_capacity(pending.len());
    for pending in pending {
        let mut result = Ok(());
        for datagram in pending.datagrams {
            if packet_loop.try_enqueue(datagram).is_err() {
                result = Err(SendError::BufferFull);
                break;
            }
        }
        match result {
            Ok(()) => completions.push(pending.done),
            Err(err) => {
                let _ = pending.done.send(Err(err));
            }
        }
    }
    if completions.is_empty() {
        return;
    }
    let result = match tokio::time::timeout(timeout, packet_loop.flush()).await {
        Ok(Ok(outcome)) if outcome.sent == 0 && outcome.pmtu_dropped > 0 => {
            Err(SendError::PayloadTooLarge)
        }
        Ok(Ok(_)) => Ok(()),
        Ok(Err(_)) | Err(_) => Err(SendError::Closed),
    };
    for done in completions {
        let _ = done.send(result.clone());
    }
}

pub(crate) fn is_control_frame(frame: &MeshFrame) -> bool {
    !matches!(
        frame_event_meta(frame).2,
        EventSemantic::Datagram | EventSemantic::Stream
    )
}

#[cfg(test)]
#[path = "sender_tests.rs"]
mod sender_tests;
