//! net.enrich_geo_asn hook.
//!
//! Reads packed `dst_ips` Bytes (tag-prefixed: 4=v4 with 4 octets, 16=v6 with
//! 16 octets), decodes the first record, and looks up country/asn via GeoIpDb.
//! Empty MMDB returns ("XX", 0). Missing `dst_ips` is a no-op Continue so this
//! hook never blocks a flow on its own. Geosite tags are looked up by
//! `net.dst_host` from the operator-installed in-memory geosite DB and packed
//! as NUL-separated UTF-8 bytes for downstream rule_chain readers.

use crate::context::current;
use crate::ext_meta::write_ext;
use bytes::Bytes;
use mesh_bus_core::kernel::{Event, KernelCtx, MetaValue, Reason, Verdict};
use std::net::IpAddr;

pub fn enrich_geo_asn(event: &mut Event, _ctx: &mut KernelCtx) -> Verdict {
    let Some(shared) = current() else {
        return Verdict::Continue;
    };

    let dst_ips = event
        .meta
        .ext
        .iter()
        .find(|(k, _)| *k == "dst_ips")
        .and_then(|(_, v)| match v {
            MetaValue::Bytes(b) => Some(b.clone()),
            _ => None,
        });
    let Some(buf) = dst_ips else {
        return Verdict::Continue;
    };
    let Some(first_ip) = decode_first_ip(&buf) else {
        return Verdict::Reject(Reason::code("invalid_dst_ips"));
    };

    let result = shared.geoip.lookup(first_ip);
    let geosite_tags = event
        .meta
        .net
        .dst_host
        .as_deref()
        .map(|host| shared.geosite.lookup_packed(host))
        .unwrap_or_default();
    write_ext(event, "geo_country", MetaValue::String(result.country));
    write_ext(event, "asn", MetaValue::U64(result.asn as u64));
    write_ext(
        event,
        "geosite_tags",
        MetaValue::Bytes(Bytes::from(geosite_tags)),
    );
    Verdict::Continue
}

fn decode_first_ip(buf: &[u8]) -> Option<IpAddr> {
    match buf.first().copied()? {
        4 if buf.len() >= 5 => {
            let octets = [buf[1], buf[2], buf[3], buf[4]];
            Some(IpAddr::V4(octets.into()))
        }
        16 if buf.len() >= 17 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(&buf[1..17]);
            Some(IpAddr::V6(o.into()))
        }
        _ => None,
    }
}
