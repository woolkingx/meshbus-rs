//! Receiver-mouth delivery-coordinate registry.

use mb_proto_mesh::ReceiverMouth;
use std::collections::HashMap;
use std::net::SocketAddr;

/// Soft TTL for a receiver mouth entry. A mouth not re-advertised within this
/// window is pruned on the next PortOpen for its peer. The registry holds
/// delivery coordinates only; expiry never tears down a bus session.
pub(crate) const MOUTH_SOFT_TTL_SECS: u64 = 30;

pub(crate) type MouthKey = (SocketAddr, String);

/// One receiver-mouth registry entry. Delivery coordinate only — it carries no
/// session, route, or channel truth and never owns a bus session. `epoch` and
/// `last_seen` drive rotation/TTL; the remaining fields are the recorded
/// delivery-coordinate evidence consumed by M6 LinkEvidence / M7 DeliveryPolicy.
pub(crate) struct MouthEntry {
    pub(crate) epoch: u64,
    #[allow(dead_code)]
    pub(crate) udp_addr: String,
    #[allow(dead_code)]
    pub(crate) family_filter: Vec<String>,
    #[allow(dead_code)]
    pub(crate) advertised_capacity: u32,
    pub(crate) last_seen: u64,
}

/// Apply a PortOpen advertisement to the receiver-mouth registry. Pure
/// delivery-coordinate bookkeeping: it never opens, closes, or mutates a bus
/// session, family-reorder state, or route. Soft-TTL-expired entries for the
/// peer are pruned first. A stale-epoch advertisement (older than the recorded
/// epoch for the same mouth) is ignored. Make-before-break: a fresh or rotated
/// mouth is eligible immediately on upsert. Returns true when the registry now
/// reflects this mouth, false when the advertisement was ignored as stale.
pub(crate) fn apply_port_open(
    mouths: &mut HashMap<MouthKey, MouthEntry>,
    peer: SocketAddr,
    mouth: &ReceiverMouth,
    now: u64,
) -> bool {
    mouths.retain(|(p, _), e| *p != peer || now.saturating_sub(e.last_seen) <= MOUTH_SOFT_TTL_SECS);
    let key = (peer, mouth.mouth_id.clone());
    if let Some(existing) = mouths.get(&key) {
        if existing.epoch > mouth.epoch {
            return false;
        }
    }
    mouths.insert(
        key,
        MouthEntry {
            epoch: mouth.epoch,
            udp_addr: mouth.udp_addr.clone(),
            family_filter: mouth.family_filter.clone(),
            advertised_capacity: mouth.advertised_capacity,
            last_seen: now,
        },
    );
    true
}

/// Apply a PortClose to the registry. A stale-epoch close (older than the
/// recorded epoch) is ignored so a late close cannot retract a rotated mouth.
/// Pure registry bookkeeping — never touches a bus session. Returns true when
/// an entry was removed.
pub(crate) fn apply_port_close(
    mouths: &mut HashMap<MouthKey, MouthEntry>,
    peer: SocketAddr,
    mouth_id: &str,
    epoch: u64,
) -> bool {
    let key = (peer, mouth_id.to_string());
    match mouths.get(&key) {
        Some(existing) if existing.epoch > epoch => false,
        Some(_) => mouths.remove(&key).is_some(),
        None => false,
    }
}
