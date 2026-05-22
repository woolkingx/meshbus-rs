use crate::types::*;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;
use tokio::task;

pub(crate) async fn resolve_system(
    qname: &str,
    qtype: QType,
) -> Result<ResolveAnswer, ResolveError> {
    let start = Instant::now();
    // IP literal fast path
    if let Ok(ip) = qname.trim_end_matches('.').parse::<IpAddr>() {
        let rec = match ip {
            IpAddr::V4(v4) => AnswerRecord::A(v4),
            IpAddr::V6(v6) => AnswerRecord::Aaaa(v6),
        };
        return Ok(ResolveAnswer {
            records: vec![rec],
            source: ResolverSource::System,
            truncated: false,
            rtt: start.elapsed(),
            min_rr_ttl: 60,
        });
    }
    let host = qname.trim_end_matches('.').to_string();
    let want_v4 = matches!(qtype, QType::A);
    let want_v6 = matches!(qtype, QType::Aaaa);
    let result = task::spawn_blocking(move || {
        use std::net::ToSocketAddrs;
        let probe = format!("{host}:0");
        probe
            .to_socket_addrs()
            .map(|it| it.collect::<Vec<SocketAddr>>())
    })
    .await
    .map_err(|e| ResolveError::Io(format!("spawn_blocking: {e}")))?;
    let addrs = match result {
        Ok(v) => v,
        Err(e) => return Err(ResolveError::Io(format!("getaddrinfo: {e}"))),
    };
    if addrs.is_empty() {
        return Err(ResolveError::NxDomain);
    }
    let records = addrs
        .into_iter()
        .filter_map(|sa| match sa.ip() {
            IpAddr::V4(v4) if want_v4 || !want_v6 => Some(AnswerRecord::A(v4)),
            IpAddr::V6(v6) if want_v6 || !want_v4 => Some(AnswerRecord::Aaaa(v6)),
            _ => None,
        })
        .collect::<Vec<_>>();
    if records.is_empty() {
        return Err(ResolveError::NxDomain);
    }
    Ok(ResolveAnswer {
        records,
        source: ResolverSource::System,
        truncated: false,
        rtt: start.elapsed(),
        min_rr_ttl: 60,
    })
}
