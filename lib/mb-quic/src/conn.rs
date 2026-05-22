//! Sans-I/O QUIC connection state machine (RFC 9000 §7, RFC 9001 §4).
//!
//! No socket ownership: feed datagrams in with [`Conn::recv`], poll datagrams
//! out with [`Conn::poll_transmit`], poll timers with [`Conn::poll_timeout`].
//! M4 scope is the handshake to the 1-RTT keys; M5 adds streams, recovery,
//! flow control and datagrams onto this skeleton.

use std::collections::BTreeMap;

use crate::crypto::{PacketKeys, RustlsKeys};
use crate::datagram::DatagramQueue;
use crate::flow_control::FlowController;
use crate::frame::{Frame, decode_all};
use crate::packet::{
    ConnectionId, LongHeader, LongType, decode_packet_number, decode_varint, encode_packet_number,
    encode_varint, packet_number_len, parse_long_header, parse_short_header_dcid, varint_len,
    write_long_header,
};
use crate::recovery::{LossRecovery, SentPacket};
use crate::stream::{StreamId, StreamMap};
use crate::tls::{TlsSession, initial_suite};
use crate::transport_params::TransportParameters;
use crate::{Error, Result, Version, crypto};

/// Largest STREAM/DATAGRAM payload placed in one 1-RTT packet (leaves room
/// for header + AEAD tag inside a 1200-byte datagram).
const APP_FRAME_BUDGET: usize = 1100;

/// Coalesced QUIC packets accepted from one UDP datagram before the datagram
/// is rejected (defense against peer-driven split_packets blow-up).
const MAX_PACKETS_PER_DATAGRAM: usize = 64;

/// Bytes a single per-level CRYPTO stream may hold out-of-order before further
/// inserts are dropped (defense against peer-driven rx_buf blow-up).
const MAX_STREAM_RX_BYTES: u64 = 8 << 20; // 8 MiB

/// QUIC endpoint role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// Connection initiator.
    Client,
    /// Connection responder.
    Server,
}

/// Encryption levels / packet-number spaces (RFC 9001 §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Level {
    Initial = 0,
    Handshake = 1,
    Data = 2,
}

/// Direction-oriented packet protection: native AES-GCM for Initial,
/// `rustls::quic` keys for Handshake / 1-RTT.
enum PktCrypto {
    Native(PacketKeys),
    Rustls(RustlsKeys),
}

impl PktCrypto {
    fn seal(&self, pn: u64, header: &[u8], payload: &mut Vec<u8>) -> Result<()> {
        match self {
            PktCrypto::Native(k) => k.seal(pn, header, payload),
            PktCrypto::Rustls(k) => k.seal(pn, header, payload),
        }
    }

    fn open(&self, pn: u64, header: &[u8], payload: &mut [u8]) -> Result<usize> {
        match self {
            PktCrypto::Native(k) => k.open(pn, header, payload).map(|p| p.len()),
            PktCrypto::Rustls(k) => k.open(pn, header, payload),
        }
    }

    fn header_mask(&self, sample: &[u8]) -> Result<[u8; 5]> {
        match self {
            PktCrypto::Native(k) => k.header_mask(sample),
            PktCrypto::Rustls(k) => k.header_mask(sample),
        }
    }
}

/// Per-level CRYPTO stream (TLS handshake bytes).
#[derive(Default)]
struct CryptoStream {
    tx: Vec<u8>,
    tx_off: u64,
    rx_next: u64,
    rx_buf: BTreeMap<u64, Vec<u8>>,
}

impl CryptoStream {
    fn push_tx(&mut self, data: &[u8]) {
        self.tx.extend_from_slice(data);
    }

    fn take_tx(&mut self, max: usize) -> Option<(u64, Vec<u8>)> {
        if self.tx.is_empty() {
            return None;
        }
        let n = self.tx.len().min(max);
        let chunk: Vec<u8> = self.tx.drain(..n).collect();
        let off = self.tx_off;
        self.tx_off += n as u64;
        Some((off, chunk))
    }

    fn recv(&mut self, off: u64, data: Vec<u8>) {
        if off + data.len() as u64 <= self.rx_next {
            return;
        }
        let buffered: u64 = self.rx_buf.values().map(|v| v.len() as u64).sum();
        if buffered + data.len() as u64 > MAX_STREAM_RX_BYTES {
            return;
        }
        self.rx_buf.insert(off, data);
    }

    fn read_in_order(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        while let Some((&off, _)) = self.rx_buf.iter().next() {
            if off > self.rx_next {
                break;
            }
            let data = self.rx_buf.remove(&off).unwrap();
            let skip = (self.rx_next - off) as usize;
            if skip < data.len() {
                out.extend_from_slice(&data[skip..]);
                self.rx_next += (data.len() - skip) as u64;
            }
        }
        out
    }
}

/// One packet-number space.
#[derive(Default)]
struct Space {
    next_pn: u64,
    largest_recv: Option<u64>,
    recv_count: u64,
    ack_pending: bool,
    crypto: CryptoStream,
}

/// A QUIC connection (one peer).
pub struct Conn {
    side: Side,
    version: Version,
    dcid: ConnectionId,
    scid: ConnectionId,
    tls: TlsSession,
    write_level: Level,
    spaces: [Space; 3],
    tx_keys: [Option<PktCrypto>; 3],
    rx_keys: [Option<PktCrypto>; 3],
    initial_sent: bool,
    handshake_confirmed: bool,
    send_handshake_done: bool,
    closed: bool,
    peer_params: Option<Vec<u8>>,
    streams: StreamMap,
    datagrams: DatagramQueue,
    recovery: LossRecovery,
    send_fc: FlowController,
    recv_fc: FlowController,
    recv_window: u64,
    peer_stream_data: u64,
    sent_frames: BTreeMap<(usize, u64), Vec<Frame>>,
    retransmit: Vec<Frame>,
    close_pending: Option<(bool, u64, Vec<u8>)>,
    now: u64,
    last_activity: u64,
    idle_timeout_us: u64,
}

/// Connection configuration.
pub struct ConnConfig {
    /// QUIC version.
    pub version: Version,
    /// Local transport parameters, already encoded (RFC 9000 §18).
    pub transport_params: Vec<u8>,
    /// Optional caller-supplied client TLS config (e.g. an SPKI-pinned
    /// verifier owned by an L7 peer binding). `None` uses the engine default.
    pub tls_client: Option<std::sync::Arc<rustls::ClientConfig>>,
    /// Optional caller-supplied server TLS config (e.g. an operator
    /// certificate/key owned by an L7 peer binding). `None` uses the engine
    /// default self-signed certificate.
    pub tls_server: Option<std::sync::Arc<rustls::ServerConfig>>,
}

impl Default for ConnConfig {
    fn default() -> Self {
        ConnConfig {
            version: Version::V1,
            transport_params: TransportParameters::default().encode(),
            tls_client: None,
            tls_server: None,
        }
    }
}

impl Conn {
    /// Create a client connection (generates Initial keys from a fresh DCID).
    pub fn client(cfg: ConnConfig) -> Result<Conn> {
        let dcid = ConnectionId::random(8);
        let scid = ConnectionId::random(8);
        let tls = match cfg.tls_client {
            Some(tls) => TlsSession::client_with(cfg.version, cfg.transport_params, tls)?,
            None => TlsSession::client(cfg.version, cfg.transport_params)?,
        };
        let mut c = Conn::new(Side::Client, cfg.version, dcid.clone(), scid, tls)?;
        c.install_initial_keys(dcid.as_slice())?;
        Ok(c)
    }

    /// Create a server connection. Initial keys are derived once the client's
    /// first Initial packet reveals the destination connection ID.
    pub fn server(cfg: ConnConfig) -> Result<Conn> {
        let scid = ConnectionId::random(8);
        let tls = match cfg.tls_server {
            Some(tls) => TlsSession::server_with(cfg.version, cfg.transport_params, tls)?,
            None => TlsSession::server(cfg.version, cfg.transport_params)?,
        };
        Conn::new(
            Side::Server,
            cfg.version,
            ConnectionId::default(),
            scid,
            tls,
        )
    }

    fn new(
        side: Side,
        version: Version,
        dcid: ConnectionId,
        scid: ConnectionId,
        tls: TlsSession,
    ) -> Result<Conn> {
        let local = TransportParameters::default();
        Ok(Conn {
            side,
            version,
            dcid,
            scid,
            tls,
            write_level: Level::Initial,
            spaces: Default::default(),
            tx_keys: [None, None, None],
            rx_keys: [None, None, None],
            initial_sent: false,
            handshake_confirmed: false,
            send_handshake_done: false,
            closed: false,
            peer_params: None,
            streams: StreamMap::new(side, 0, 0),
            datagrams: DatagramQueue::default(),
            recovery: LossRecovery::default(),
            send_fc: FlowController::new(0),
            recv_fc: FlowController::new(local.initial_max_data),
            recv_window: local.initial_max_data,
            peer_stream_data: 0,
            sent_frames: BTreeMap::new(),
            retransmit: Vec::new(),
            close_pending: None,
            now: 0,
            last_activity: 0,
            idle_timeout_us: local.max_idle_timeout_ms.saturating_mul(1000),
        })
    }

    /// Adopt the negotiated peer transport parameters: peer flow-control
    /// limits, per-stream send limit, stream counts and the effective idle
    /// timeout (min of both endpoints, RFC 9000 §10.1).
    fn adopt_peer_params(&mut self, raw: &[u8]) {
        let Ok(peer) = TransportParameters::decode(raw) else {
            return;
        };
        self.send_fc.set_limit(peer.initial_max_data);
        self.peer_stream_data = peer
            .initial_max_stream_data_bidi_remote
            .max(peer.initial_max_stream_data_uni);
        self.streams
            .set_peer_max(true, peer.initial_max_streams_bidi);
        self.streams
            .set_peer_max(false, peer.initial_max_streams_uni);
        let peer_idle = peer.max_idle_timeout_ms.saturating_mul(1000);
        self.idle_timeout_us = match (self.idle_timeout_us, peer_idle) {
            (0, p) => p,
            (l, 0) => l,
            (l, p) => l.min(p),
        };
    }

    fn install_initial_keys(&mut self, client_dcid: &[u8]) -> Result<()> {
        // Acquire the QUIC Initial cipher suite once to validate availability.
        initial_suite()?;
        let (cs, ss) = (
            crypto::initial_secret(client_dcid, true, self.version),
            crypto::initial_secret(client_dcid, false, self.version),
        );
        let (tx, rx) = match self.side {
            Side::Client => (cs, ss),
            Side::Server => (ss, cs),
        };
        self.tx_keys[0] = Some(PktCrypto::Native(PacketKeys::from_initial_secret(&tx)));
        self.rx_keys[0] = Some(PktCrypto::Native(PacketKeys::from_initial_secret(&rx)));
        Ok(())
    }

    /// True once the TLS handshake has completed and 1-RTT keys are installed.
    pub fn is_established(&self) -> bool {
        !self.tls.is_handshaking() && self.tx_keys[2].is_some() && self.rx_keys[2].is_some()
    }

    /// Negotiated peer transport parameters once available.
    pub fn peer_transport_parameters(&self) -> Option<&[u8]> {
        self.peer_params.as_deref()
    }

    /// Inject the current time (microseconds, monotonic). Sans-I/O: the caller
    /// owns the clock so recovery and idle timing stay deterministic.
    pub fn set_now(&mut self, now: u64) {
        self.now = now;
        if self.last_activity == 0 {
            self.last_activity = now;
        }
    }

    /// Earliest timer deadline (absolute microseconds): the loss/PTO timer
    /// (RFC 9002 §6.2) or the idle timeout (RFC 9000 §10.1), whichever fires
    /// first. `None` once closed or when no timer is armed.
    pub fn poll_timeout(&self) -> Option<u64> {
        if self.closed {
            return None;
        }
        let loss = self.recovery.loss_timer();
        let idle = if self.idle_timeout_us > 0 {
            Some(self.last_activity + self.idle_timeout_us)
        } else {
            None
        };
        match (loss, idle) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// Drive timers at `now`: close on idle expiry, otherwise run loss
    /// detection / PTO across spaces and re-queue lost data for retransmission.
    pub fn on_timeout(&mut self, now: u64) {
        self.now = now;
        if self.idle_timeout_us > 0 && now >= self.last_activity + self.idle_timeout_us {
            self.closed = true;
            return;
        }
        let mut any_lost = false;
        for space in 0..3 {
            let lost = self.recovery.detect_lost(space, now);
            if !lost.is_empty() {
                any_lost = true;
                self.requeue_lost(space, &lost);
            }
        }
        if !any_lost {
            if let Some(deadline) = self.recovery.loss_timer() {
                if now >= deadline {
                    self.recovery.on_pto_expired();
                }
            }
        }
    }

    /// Open the next locally initiated bidirectional stream, or `None` when
    /// the peer's stream limit is exhausted (RFC 9000 §4.6).
    pub fn open_bidi_stream(&mut self) -> Option<StreamId> {
        self.streams.open(true)
    }

    /// Open the next locally initiated unidirectional stream.
    pub fn open_uni_stream(&mut self) -> Option<StreamId> {
        self.streams.open(false)
    }

    /// Queue application bytes on a stream; `fin` finalises it.
    pub fn write_stream(&mut self, id: u64, data: &[u8], fin: bool) {
        self.streams.entry(id).send.write(data, fin);
    }

    /// Pop the in-order received prefix of a stream.
    pub fn read_stream(&mut self, id: u64) -> Vec<u8> {
        self.streams.entry(id).recv.read()
    }

    /// True once every byte through the peer's FIN has been read.
    pub fn stream_finished(&self, id: u64) -> bool {
        self.streams.get(id).is_some_and(|s| s.recv.is_finished())
    }

    /// Stream IDs with in-order inbound data or an unconsumed FIN. Lets a
    /// server discover peer-initiated streams without an `accept()` surface.
    pub fn readable_streams(&self) -> Vec<u64> {
        self.streams.readable()
    }

    /// Queue a best-effort datagram (RFC 9221). Dropped if the queue is full.
    pub fn send_datagram(&mut self, data: Vec<u8>) -> bool {
        self.datagrams.queue_outgoing(data)
    }

    /// Pop the next received datagram in arrival order.
    pub fn recv_datagram(&mut self) -> Option<Vec<u8>> {
        self.datagrams.recv()
    }

    /// Begin an immediate connection close (RFC 9000 §10.2): a
    /// CONNECTION_CLOSE frame is emitted on the next [`Conn::poll_transmit`].
    pub fn close(&mut self, application: bool, error_code: u64, reason: &[u8]) {
        if self.close_pending.is_none() && !self.closed {
            self.close_pending = Some((application, error_code, reason.to_vec()));
        }
    }

    /// True once the connection is closed (locally or by the peer).
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Feed one received UDP datagram (may contain coalesced packets).
    ///
    /// Packets that cannot yet be decrypted (the keys for their level are not
    /// installed because an earlier coalesced packet has not been fed to TLS
    /// yet) are buffered and retried after each [`Conn::pump_tls`] pass, per
    /// RFC 9001 §4.1.4.
    pub fn recv(&mut self, datagram: &[u8]) -> Result<()> {
        let mut queue = self.split_packets(datagram)?;
        loop {
            let mut deferred = Vec::new();
            let mut progressed = false;
            for pkt in queue.drain(..) {
                match self.recv_one(&pkt) {
                    Ok(()) => progressed = true,
                    Err(Error::Crypto("no rx keys for level")) => deferred.push(pkt),
                    Err(e) => return Err(e),
                }
            }
            self.pump_tls()?;
            queue = deferred;
            if queue.is_empty() || !progressed {
                break;
            }
        }
        Ok(())
    }

    /// Split a datagram into individual packet byte ranges without decrypting.
    /// Long headers carry an explicit Length; a short header is the datagram
    /// tail (RFC 9000 §12.2).
    fn split_packets(&self, datagram: &[u8]) -> Result<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        let mut off = 0usize;
        while off < datagram.len() {
            let buf = &datagram[off..];
            let first = *buf.first().ok_or(Error::ShortBuffer)?;
            // QUIC v1 sets the fixed bit (0x40) on every valid packet's first
            // byte (RFC 9000 §17.2/§17.3). A cleared fixed bit marks trailing
            // datagram padding (0x00); stop parsing here (RFC 9000 §12.2).
            if first & 0x40 == 0 {
                break;
            }
            let plen = if first & 0x80 == 0 {
                buf.len()
            } else {
                let (hdr, _lo, hdr_end) = parse_long_header(buf)?;
                match hdr.ty {
                    LongType::Initial | LongType::Handshake | LongType::ZeroRtt => {
                        let (len, n) = decode_varint(&buf[hdr_end..])?;
                        hdr_end + n + len as usize
                    }
                    LongType::Retry => buf.len(),
                }
            };
            if plen == 0 || off + plen > datagram.len() {
                return Err(Error::ShortBuffer);
            }
            if out.len() >= MAX_PACKETS_PER_DATAGRAM {
                return Err(Error::Malformed("too many coalesced packets"));
            }
            out.push(buf[..plen].to_vec());
            off += plen;
        }
        Ok(out)
    }

    fn recv_one(&mut self, buf: &[u8]) -> Result<()> {
        let first = *buf.first().ok_or(Error::ShortBuffer)?;
        if first & 0x80 != 0 {
            self.recv_long(buf)?;
        } else {
            self.recv_short(buf)?;
        }
        Ok(())
    }

    fn recv_long(&mut self, buf: &[u8]) -> Result<usize> {
        let (hdr, _lo, hdr_end) = parse_long_header(buf)?;
        if hdr.version != self.version.to_u32() {
            return Err(Error::UnsupportedVersion(hdr.version));
        }
        let level = match hdr.ty {
            LongType::Initial => Level::Initial,
            LongType::Handshake => Level::Handshake,
            _ => return Err(Error::Transport("unsupported long packet")),
        };
        if self.side == Side::Server && level == Level::Initial && self.rx_keys[0].is_none() {
            self.dcid = hdr.scid.clone();
            let client_dcid = hdr.dcid.as_slice().to_vec();
            self.install_initial_keys(&client_dcid)?;
        }
        let (len, n) = decode_varint(&buf[hdr_end..])?;
        let len_off = hdr_end + n;
        let pkt_end = len_off + len as usize;
        if pkt_end > buf.len() {
            return Err(Error::ShortBuffer);
        }
        self.decrypt_and_handle(level, buf, len_off, pkt_end)?;
        Ok(pkt_end)
    }

    fn recv_short(&mut self, buf: &[u8]) -> Result<usize> {
        let (_dcid, pn_off) = parse_short_header_dcid(buf, self.scid.len())?;
        let level = Level::Data;
        self.decrypt_and_handle(level, buf, pn_off, buf.len())?;
        Ok(buf.len())
    }

    fn decrypt_and_handle(
        &mut self,
        level: Level,
        buf: &[u8],
        pn_off: usize,
        pkt_end: usize,
    ) -> Result<()> {
        let idx = level as usize;
        let rx = self.rx_keys[idx]
            .as_ref()
            .ok_or(Error::Crypto("no rx keys for level"))?;
        let mut pkt = buf[..pkt_end].to_vec();
        // Header protection: sample starts 4 bytes after the pn offset.
        let sample_off = pn_off + 4;
        if sample_off + 16 > pkt.len() {
            return Err(Error::ShortBuffer);
        }
        let mask = rx.header_mask(&pkt[sample_off..sample_off + 16])?;
        let long = pkt[0] & 0x80 != 0;
        pkt[0] ^= mask[0] & if long { 0x0f } else { 0x1f };
        let pn_len = ((pkt[0] & 0x03) + 1) as usize;
        for i in 0..pn_len {
            pkt[pn_off + i] ^= mask[1 + i];
        }
        let mut truncated = 0u64;
        for i in 0..pn_len {
            truncated = (truncated << 8) | u64::from(pkt[pn_off + i]);
        }
        let largest = self.spaces[idx].largest_recv.unwrap_or(0);
        let pn = decode_packet_number(largest, truncated, (pn_len * 8) as u32);
        let header = pkt[..pn_off + pn_len].to_vec();
        let mut payload = pkt[pn_off + pn_len..].to_vec();
        let ptlen = rx.open(pn, &header, &mut payload)?;
        payload.truncate(ptlen);
        self.spaces[idx].largest_recv =
            Some(self.spaces[idx].largest_recv.map_or(pn, |l| l.max(pn)));
        self.spaces[idx].recv_count += 1;
        self.spaces[idx].ack_pending = true;
        for frame in decode_all(&payload)? {
            self.handle_frame(level, frame)?;
        }
        Ok(())
    }

    fn handle_frame(&mut self, level: Level, frame: Frame) -> Result<()> {
        match frame {
            Frame::Padding(_) | Frame::Ping => {}
            Frame::Ack {
                largest,
                delay,
                first_range,
                ranges,
            } => {
                let space = level as usize;
                let acked =
                    self.recovery
                        .on_ack(space, largest, first_range, &ranges, delay, self.now);
                for p in &acked {
                    self.sent_frames.remove(&(space, p.pn));
                }
                let lost = self.recovery.detect_lost(space, self.now);
                self.requeue_lost(space, &lost);
            }
            Frame::Crypto { offset, data } => {
                self.spaces[level as usize].crypto.recv(offset, data);
            }
            Frame::ResetStream { stream_id, .. } => {
                self.streams.entry(stream_id).recv.stop();
            }
            Frame::StopSending { .. } => {}
            Frame::Stream {
                id,
                offset,
                fin,
                data,
            } => {
                if !self.recv_fc.consume(data.len() as u64) {
                    return Err(Error::Transport("connection flow control exceeded"));
                }
                if self.streams.would_exceed_cap(id) {
                    return Err(Error::Transport("stream count cap"));
                }
                self.streams.entry(id).recv.ingest(offset, &data, fin);
            }
            Frame::MaxData { max } => self.send_fc.set_limit(max),
            Frame::MaxStreamData { max, .. } => {
                if max > self.peer_stream_data {
                    self.peer_stream_data = max;
                }
            }
            Frame::MaxStreams { bidi, max } => self.streams.set_peer_max(bidi, max),
            Frame::DataBlocked { .. }
            | Frame::StreamDataBlocked { .. }
            | Frame::StreamsBlocked { .. } => {}
            Frame::ConnectionClose { .. } => {
                self.closed = true;
            }
            Frame::HandshakeDone => {
                if self.side == Side::Client {
                    self.handshake_confirmed = true;
                }
            }
            Frame::Datagram { data } => self.datagrams.ingest(data),
        }
        Ok(())
    }

    /// Re-queue retransmittable frames from lost packets (RFC 9002 §6); a lost
    /// DATAGRAM is never retransmitted (RFC 9221 §5).
    fn requeue_lost(&mut self, space: usize, lost: &[SentPacket]) {
        for p in lost {
            if let Some(frames) = self.sent_frames.remove(&(space, p.pn)) {
                for f in frames {
                    if matches!(f, Frame::Crypto { .. } | Frame::Stream { .. }) {
                        self.retransmit.push(f);
                    }
                }
            }
        }
    }

    fn pump_tls(&mut self) -> Result<()> {
        for lvl in [Level::Initial, Level::Handshake, Level::Data] {
            let pending = self.spaces[lvl as usize].crypto.read_in_order();
            if !pending.is_empty() {
                self.tls.read_handshake(&pending)?;
            }
        }
        loop {
            let mut buf = Vec::new();
            let change = self.tls.write_handshake(&mut buf);
            if !buf.is_empty() {
                self.spaces[self.write_level as usize].crypto.push_tx(&buf);
            }
            match change {
                Some(rustls::quic::KeyChange::Handshake { keys }) => {
                    self.tx_keys[1] =
                        Some(PktCrypto::Rustls(RustlsKeys::from_directional(keys.local)));
                    self.rx_keys[1] =
                        Some(PktCrypto::Rustls(RustlsKeys::from_directional(keys.remote)));
                    self.write_level = Level::Handshake;
                }
                Some(rustls::quic::KeyChange::OneRtt { keys, next: _ }) => {
                    self.tx_keys[2] =
                        Some(PktCrypto::Rustls(RustlsKeys::from_directional(keys.local)));
                    self.rx_keys[2] =
                        Some(PktCrypto::Rustls(RustlsKeys::from_directional(keys.remote)));
                    self.write_level = Level::Data;
                }
                None => break,
            }
        }
        if self.peer_params.is_none() {
            if let Some(raw) = self.tls.peer_transport_parameters() {
                self.adopt_peer_params(&raw);
                self.peer_params = Some(raw);
            }
        }
        if self.side == Side::Server && !self.tls.is_handshaking() && !self.handshake_confirmed {
            self.handshake_confirmed = true;
            self.send_handshake_done = true;
        }
        Ok(())
    }

    /// Poll one datagram to transmit, coalescing levels into one datagram.
    pub fn poll_transmit(&mut self) -> Option<Vec<u8>> {
        if self.closed {
            return None;
        }
        if self.side == Side::Client && !self.initial_sent {
            let _ = self.pump_tls();
        }
        let mut datagram = Vec::new();
        for lvl in [Level::Initial, Level::Handshake, Level::Data] {
            if let Some(pkt) = self.build_packet(lvl) {
                datagram.extend_from_slice(&pkt);
            }
        }
        if datagram.is_empty() {
            return None;
        }
        if self.side == Side::Client && !self.initial_sent {
            self.initial_sent = true;
            if datagram.len() < 1200 {
                datagram.resize(1200, 0x00);
            }
        }
        Some(datagram)
    }

    fn build_packet(&mut self, level: Level) -> Option<Vec<u8>> {
        let idx = level as usize;
        self.tx_keys[idx].as_ref()?;
        let mut frames: Vec<Frame> = Vec::new();
        if self.spaces[idx].ack_pending {
            if let Some(largest) = self.spaces[idx].largest_recv {
                frames.push(Frame::Ack {
                    largest,
                    delay: 0,
                    first_range: largest,
                    ranges: Vec::new(),
                });
                self.spaces[idx].ack_pending = false;
            }
        }
        let mut closing = false;
        if level == Level::Data {
            if let Some((application, error_code, reason)) = self.close_pending.take() {
                frames.push(Frame::ConnectionClose {
                    application,
                    error_code,
                    reason,
                });
                closing = true;
            } else {
                if let Some(max) = self.recv_fc.maybe_extend(self.recv_window) {
                    frames.push(Frame::MaxData { max });
                }
                for f in std::mem::take(&mut self.retransmit) {
                    frames.push(f);
                }
                self.collect_stream_frames(&mut frames);
                while self.datagrams.has_outgoing() {
                    match self.datagrams.take_outgoing(APP_FRAME_BUDGET) {
                        Some(d) => frames.push(Frame::Datagram { data: d }),
                        None => break,
                    }
                }
            }
        }
        if !closing {
            while let Some((offset, data)) = self.spaces[idx].crypto.take_tx(APP_FRAME_BUDGET) {
                frames.push(Frame::Crypto { offset, data });
            }
            if level == Level::Data && self.side == Side::Server && self.send_handshake_done {
                frames.push(Frame::HandshakeDone);
                self.send_handshake_done = false;
            }
        }
        if frames.is_empty() {
            return None;
        }
        let mut body = Vec::new();
        for f in &frames {
            f.encode(&mut body);
        }
        let ack_eliciting = frames.iter().any(|f| {
            !matches!(
                f,
                Frame::Padding(_) | Frame::Ack { .. } | Frame::ConnectionClose { .. }
            )
        });
        let pn = self.spaces[idx].next_pn;
        let pkt = self.protect(level, body);
        self.recovery.on_packet_sent(
            idx,
            SentPacket {
                pn,
                time_sent: self.now,
                size: pkt.len() as u64,
                ack_eliciting,
            },
        );
        let keep: Vec<Frame> = frames
            .into_iter()
            .filter(|f| matches!(f, Frame::Crypto { .. } | Frame::Stream { .. }))
            .collect();
        if !keep.is_empty() {
            self.sent_frames.insert((idx, pn), keep);
        }
        if ack_eliciting {
            self.last_activity = self.now;
        }
        if closing {
            self.closed = true;
        }
        Some(pkt)
    }

    /// Drain pending stream bytes into STREAM frames, bounded by connection
    /// send flow control (RFC 9000 §4.1) and the congestion window
    /// (RFC 9002 §7).
    fn collect_stream_frames(&mut self, frames: &mut Vec<Frame>) {
        let cong = self.recovery.congestion().available();
        let mut remaining = self.send_fc.available().min(cong) as usize;
        for id in self.streams.sendable() {
            while remaining > 0 {
                let take = remaining.min(APP_FRAME_BUDGET);
                let Some((offset, data, fin)) = self.streams.entry(id).send.take(take) else {
                    break;
                };
                let n = data.len() as u64;
                self.send_fc.consume(n);
                remaining -= n as usize;
                frames.push(Frame::Stream {
                    id,
                    offset,
                    fin,
                    data,
                });
                if fin {
                    break;
                }
            }
        }
    }

    fn protect(&mut self, level: Level, mut body: Vec<u8>) -> Vec<u8> {
        let idx = level as usize;
        let pn = self.spaces[idx].next_pn;
        self.spaces[idx].next_pn += 1;
        let pn_len = packet_number_len(pn, None).max(2);
        let mut out = Vec::new();
        if level == Level::Data {
            out.push(0x40 | (pn_len as u8 - 1));
            out.extend_from_slice(self.dcid.as_slice());
        } else {
            let ty = if level == Level::Initial {
                LongType::Initial
            } else {
                LongType::Handshake
            };
            let hdr = LongHeader {
                ty,
                version: self.version.to_u32(),
                dcid: self.dcid.clone(),
                scid: self.scid.clone(),
                token: Vec::new(),
            };
            write_long_header(&mut out, &hdr, pn_len as u8 - 1);
            let length = pn_len + body.len() + crypto::tag_len();
            encode_varint(&mut out, length as u64);
        }
        let pn_off = out.len();
        encode_packet_number(&mut out, pn, pn_len);
        let header = out.clone();
        let tx = self.tx_keys[idx].as_ref().unwrap();
        tx.seal(pn, &header, &mut body).expect("seal");
        out.extend_from_slice(&body);
        // Header protection: sample 4 bytes past the packet number start.
        let sample_off = pn_off + 4;
        let sample = out[sample_off..sample_off + 16].to_vec();
        let mask = tx.header_mask(&sample).expect("hp mask");
        let long = out[0] & 0x80 != 0;
        out[0] ^= mask[0] & if long { 0x0f } else { 0x1f };
        for i in 0..pn_len {
            out[pn_off + i] ^= mask[1 + i];
        }
        let _ = varint_len(0);
        out
    }

    /// Source connection ID this endpoint advertises.
    pub fn scid(&self) -> &ConnectionId {
        &self.scid
    }
}
