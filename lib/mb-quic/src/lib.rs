//! Own IETF QUIC transport library (sans-I/O).
//!
//! Architecture and acceptance gates: see
//! `docs/handbook/transport.html`.
//!
//! This crate implements real RFC 9000 / RFC 9001 QUIC packet framing and
//! packet protection. TLS 1.3 + Handshake/1-RTT key schedule is delegated to
//! the proven `rustls::quic` API; RFC 9001 Initial secret / AEAD /
//! header-protection is implemented natively over `ring` and asserted against
//! the RFC 9001 Appendix A.1 published vectors.
//!
//! The public API is sans-I/O: feed UDP datagrams in, poll UDP datagrams out,
//! poll timers. This crate never owns a socket and never names a Mesh Protocol
//! concept; it is a QUIC transport library only.

pub mod conn;
pub mod crypto;
pub mod datagram;
pub mod flow_control;
pub mod frame;
pub mod packet;
pub mod recovery;
pub mod stream;
pub mod tls;
pub mod transport_params;

pub use conn::{Conn, ConnConfig, Side};
pub use packet::ConnectionId;
pub use tls::ALPN;
pub use transport_params::TransportParameters;

/// QUIC protocol version governed by this crate (RFC 9000 §15).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version {
    /// First stable RFC (RFC 9000), wire value `0x00000001`.
    V1,
}

impl Version {
    /// Wire encoding of the version field.
    pub const fn to_u32(self) -> u32 {
        match self {
            Version::V1 => 0x0000_0001,
        }
    }

    /// Parse a wire version value.
    pub const fn from_u32(v: u32) -> Option<Version> {
        match v {
            0x0000_0001 => Some(Version::V1),
            _ => None,
        }
    }

    /// Map to the `rustls::quic` version selector.
    pub(crate) fn rustls(self) -> rustls::quic::Version {
        match self {
            Version::V1 => rustls::quic::Version::V1,
        }
    }
}

/// Errors surfaced by the QUIC engine.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Buffer ended before a full field could be read.
    #[error("short buffer")]
    ShortBuffer,
    /// A varint or field was malformed.
    #[error("malformed: {0}")]
    Malformed(&'static str),
    /// Unsupported or unknown QUIC version on the wire.
    #[error("unsupported version {0:#010x}")]
    UnsupportedVersion(u32),
    /// AEAD seal/open or header-protection failure.
    #[error("crypto failure: {0}")]
    Crypto(&'static str),
    /// TLS 1.3 handshake failure surfaced by rustls.
    #[error("tls: {0}")]
    Tls(String),
    /// Peer violated a transport invariant.
    #[error("transport: {0}")]
    Transport(&'static str),
}

/// Convenience result alias.
pub type Result<T> = core::result::Result<T, Error>;
