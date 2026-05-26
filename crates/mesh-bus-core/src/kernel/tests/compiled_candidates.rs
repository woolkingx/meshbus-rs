use super::helpers::DevNullEgress;
use crate::Capabilities;
use crate::kernel::compiled::{CompiledCandidate, CompiledCandidates};
use crate::transport::forwarding::data_handle::capability_matches_flow;
use crate::transport::forwarding::types::FlowSemantics;
use crate::{EgressPlugin, ExitId};

fn egress(id: &str, stream: bool, datagram: bool, groups: &[&str]) -> Box<dyn EgressPlugin> {
    Box::new(DevNullEgress {
        id: ExitId(id.into()),
        caps: Capabilities {
            protocol: "test".into(),
            supports_stream: stream,
            supports_datagram: datagram,
            max_payload_bytes: None,
            groups: groups.iter().map(|g| (*g).to_string()).collect(),
        },
    })
}

/// Pre-M4 reference: a full `dyn EgressPlugin` scan in index order applying
/// the canonical capability predicate plus the route-group/target-sink
/// filter and the fail-closed rule. No health filter (empty unhealthy set),
/// so the both-`None` fallback equals the first pass.
fn reference_scan(
    egresses: &[Box<dyn EgressPlugin>],
    want: FlowSemantics,
    route_group: Option<&str>,
    target_sink: Option<&str>,
) -> (Vec<ExitId>, Vec<usize>) {
    let keep = |caps: &Capabilities, id: &ExitId| -> bool {
        if !capability_matches_flow(caps, want) {
            return false;
        }
        if let Some(sink) = target_sink {
            if id.0 != sink {
                return false;
            }
        }
        match route_group {
            Some(g) => caps.groups.iter().any(|x| x == g),
            None => true,
        }
    };
    let mut cands = Vec::new();
    let mut map = Vec::new();
    for (idx, e) in egresses.iter().enumerate() {
        if keep(e.capabilities(), e.id()) {
            cands.push(e.id().clone());
            map.push(idx);
        }
    }
    if cands.is_empty() && (route_group.is_some() || target_sink.is_some()) {
        return (Vec::new(), Vec::new());
    }
    (cands, map)
}

/// Faithful copy of `dispatch::healthy_candidates` minus the health
/// snapshot: bucket the compiled table, apply the same group/sink filter,
/// and the same empty → fail-closed / both-`None` fallback branches.
fn compiled_path(
    cc: &CompiledCandidates,
    want: FlowSemantics,
    route_group: Option<&str>,
    target_sink: Option<&str>,
) -> (Vec<ExitId>, Vec<usize>) {
    let bucket = cc.bucket(want);
    let keep = |c: &CompiledCandidate| -> bool {
        if let Some(sink) = target_sink {
            if c.exit_id.0 != sink {
                return false;
            }
        }
        match route_group {
            Some(g) => c.groups.iter().any(|x| x == g),
            None => true,
        }
    };
    let mut cands = Vec::new();
    let mut map = Vec::new();
    for c in bucket.iter() {
        if keep(c) {
            cands.push(c.exit_id.clone());
            map.push(c.egress_idx);
        }
    }
    if cands.is_empty() {
        if route_group.is_some() || target_sink.is_some() {
            return (Vec::new(), Vec::new());
        }
        return bucket
            .iter()
            .filter(|c| keep(c))
            .map(|c| (c.exit_id.clone(), c.egress_idx))
            .collect::<Vec<_>>()
            .into_iter()
            .unzip();
    }
    (cands, map)
}

#[test]
fn compiled_candidates_match_healthy_candidates_for_all_groups() {
    let egresses: Vec<Box<dyn EgressPlugin>> = vec![
        egress("e0", true, false, &["alpha"]),
        egress("e1", false, true, &["beta"]),
        egress("e2", true, true, &["gamma"]),
        egress("e3", true, false, &["alpha", "gamma"]),
        egress("e4", false, true, &[]),
        egress("e5", true, true, &["beta", "gamma"]),
    ];
    let cc = CompiledCandidates::from_egresses(&egresses);
    let semantics = [
        FlowSemantics::ByteStream,
        FlowSemantics::Datagram,
        FlowSemantics::Message,
    ];
    let groups = [
        None,
        Some("alpha"),
        Some("beta"),
        Some("gamma"),
        Some("delta"),
    ];
    for &want in &semantics {
        for &g in &groups {
            assert_eq!(
                compiled_path(&cc, want, g, None),
                reference_scan(&egresses, want, g, None),
                "compiled candidate set diverged for semantics {want:?} group {g:?}"
            );
        }
    }
}

#[test]
fn compiled_candidates_fail_closed_for_unknown_target_sink() {
    let egresses: Vec<Box<dyn EgressPlugin>> = vec![
        egress("e0", true, false, &["alpha"]),
        egress("e1", true, true, &["beta"]),
        egress("e2", false, true, &[]),
    ];
    let cc = CompiledCandidates::from_egresses(&egresses);
    for &want in &[
        FlowSemantics::ByteStream,
        FlowSemantics::Datagram,
        FlowSemantics::Message,
    ] {
        let (cands, map) = compiled_path(&cc, want, None, Some("ghost-exit"));
        assert!(
            cands.is_empty() && map.is_empty(),
            "unknown target sink must fail closed for {want:?}, got {cands:?}"
        );
        assert_eq!(
            compiled_path(&cc, want, None, Some("ghost-exit")),
            reference_scan(&egresses, want, None, Some("ghost-exit")),
            "fail-closed path diverged from reference scan for {want:?}"
        );
    }
    // A real sink still resolves — proves the empty sets above are the
    // unknown-sink fail-closed, not a blanket empty bucket.
    let (cands, _) = compiled_path(&cc, FlowSemantics::ByteStream, None, Some("e1"));
    assert_eq!(cands, vec![ExitId("e1".into())]);
}
