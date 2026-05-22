//! net.resolve_or_recover hook.
//!
//! Forward path: dst_host -> ResolverHandle (M1/M2/M3) -> pack dst_ips + write
//! dst_ip_primary / dns_rtt_ms / resolution_mode.
//!
//! Recovery path: only dst_ip_primary known -> consult DnsCache reverse-map for
//! qname/geo/asn; on miss, write resolution_mode = "passthrough_ip".
//!
//! Neither side known -> Verdict::Reject("no_target").

use crate::context::current;
use crate::ext_meta::write_ext;
use bytes::Bytes;
use mesh_bus_core::kernel::{Event, KernelCtx, MetaValue, Reason, Verdict};
use mesh_bus_resolver::types::{
    AnswerRecord, ConsumerId, QType, ResolveError, ResolveRequest, ResolverSource,
};
use std::net::IpAddr;

pub fn resolve_or_recover(event: &mut Event, _ctx: &mut KernelCtx) -> Verdict {
    let shared = match current() {
        Some(s) => s,
        None => return Verdict::Reject(Reason::code("hook_ctx_missing")),
    };

    let dst_host = event.meta.net.dst_host.clone();
    let dst_ip_primary = event
        .meta
        .ext
        .iter()
        .find(|(k, _)| *k == "dst_ip_primary")
        .and_then(|(_, v)| match v {
            MetaValue::String(s) => Some(s.clone()),
            _ => None,
        });

    if let Some(host) = dst_host {
        if host.is_empty() {
            return Verdict::Reject(Reason::code("invalid_dst_host"));
        }
        let req = ResolveRequest {
            qname: ensure_trailing_dot(&host),
            qtype: QType::A,
            consumer: ConsumerId("forward_pipeline".into()),
        };
        let (ans, sig) = match shared.tokio.block_on(shared.resolver.resolve(req)) {
            Ok(pair) => pair,
            Err((e, _)) => {
                return match e {
                    ResolveError::NxDomain => Verdict::Reject(Reason::code("nxdomain")),
                    ResolveError::Denied => Verdict::Reject(Reason::code("denied")),
                    _ => Verdict::Reject(Reason::with_detail("resolve_failure", e.to_string())),
                };
            }
        };

        let mut buf: Vec<u8> = Vec::new();
        let mut first_ip: Option<IpAddr> = None;
        for r in &ans.records {
            match r {
                AnswerRecord::A(v4) => {
                    buf.push(4);
                    buf.extend_from_slice(&v4.octets());
                    if first_ip.is_none() {
                        first_ip = Some(IpAddr::V4(*v4));
                    }
                }
                AnswerRecord::Aaaa(v6) => {
                    buf.push(16);
                    buf.extend_from_slice(&v6.octets());
                    if first_ip.is_none() {
                        first_ip = Some(IpAddr::V6(*v6));
                    }
                }
                _ => {}
            }
        }
        let first_ip = match first_ip {
            Some(ip) => ip,
            None => return Verdict::Reject(Reason::code("nxdomain")),
        };
        write_ext(event, "dst_ips", MetaValue::Bytes(Bytes::from(buf)));
        write_ext(
            event,
            "dst_ip_primary",
            MetaValue::String(first_ip.to_string()),
        );
        write_ext(event, "dns_rtt_ms", MetaValue::U64(sig.resolver_rtt_ms));
        let mode = match ans.source {
            ResolverSource::System => "m3",
            ResolverSource::MeshDirect { .. } => "m2",
            ResolverSource::Tunneled { .. } => "m1",
        };
        write_ext(event, "resolution_mode", MetaValue::String(mode.into()));
        return Verdict::Continue;
    }

    if let Some(ip_str) = dst_ip_primary {
        let ip = match ip_str.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => return Verdict::Reject(Reason::code("dst_ip_primary_unparseable")),
        };
        if let Some(entry) = shared.cache.lookup_reverse(ip) {
            event.meta.net.dst_host = Some(entry.qname.clone());
            if let Some(geo) = entry.geo {
                write_ext(event, "geo_country", MetaValue::String(geo));
            }
            if let Some(asn) = entry.asn {
                write_ext(event, "asn", MetaValue::U64(asn as u64));
            }
            write_ext(
                event,
                "resolution_mode",
                MetaValue::String("reverse_map".into()),
            );
        } else {
            write_ext(
                event,
                "resolution_mode",
                MetaValue::String("passthrough_ip".into()),
            );
        }
        let mut buf: Vec<u8> = Vec::new();
        match ip {
            IpAddr::V4(v4) => {
                buf.push(4);
                buf.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                buf.push(16);
                buf.extend_from_slice(&v6.octets());
            }
        }
        write_ext(event, "dst_ips", MetaValue::Bytes(Bytes::from(buf)));
        return Verdict::Continue;
    }

    Verdict::Reject(Reason::code("no_target"))
}

fn ensure_trailing_dot(s: &str) -> String {
    if s.ends_with('.') {
        s.into()
    } else {
        format!("{s}.")
    }
}
