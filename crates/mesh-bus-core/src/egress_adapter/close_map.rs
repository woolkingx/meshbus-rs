use crate::{CloseReason, DisconnectReason};

pub(super) fn close_from_disconnect(reason: DisconnectReason) -> CloseReason {
    match reason {
        DisconnectReason::ConnectionRefused => CloseReason::ConnectionRefused,
        DisconnectReason::NetworkUnreachable => CloseReason::NetworkUnreachable,
        DisconnectReason::HostUnreachable => CloseReason::HostUnreachable,
        DisconnectReason::TtlExpired => CloseReason::TtlExpired,
        DisconnectReason::TimedOut => CloseReason::TimedOut,
        DisconnectReason::UpstreamEof => CloseReason::UpstreamEof,
        DisconnectReason::ConnectionReset => CloseReason::ConnectionReset,
        DisconnectReason::NotConnected => CloseReason::NotConnected,
        DisconnectReason::NoUsableExit => CloseReason::NoUsableExit,
        DisconnectReason::SessionClosed => CloseReason::SessionClosed,
        DisconnectReason::ReaderClosed => CloseReason::ReaderClosed,
        DisconnectReason::AddressNotSupported => CloseReason::AddressNotSupported,
        DisconnectReason::Other(s) => CloseReason::Other(s),
    }
}
