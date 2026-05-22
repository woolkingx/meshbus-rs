use super::id_shape::check_id_shapes;
use super::types::{HookKind, HookSpec, KernelRegistry};
use super::verify_error::VerifyError;
use crate::kernel::verdict::types::{HookId, PipelineId};
use std::collections::{HashMap, HashSet};

const VERDICT_NAMESPACES: &[&str] = &["policy", "auth"];
const METADATA_NAMESPACES: &[&str] = &["net", "transport", "policy", "auth", "trace", "ext"];

pub fn verify(reg: &KernelRegistry) -> Result<(), VerifyError> {
    _check_registry_identities(reg)?;
    check_id_shapes(reg)?;
    _check_spec_kinds(reg)?;
    _check_wirings_exist(reg)?;
    _check_hooks_exist(reg)?;
    _check_accept_declarations(reg)?;
    _check_sink_targets(reg)?;
    _check_jump_declarations(reg)?;
    _check_jump_targets(reg)?;
    _check_jump_dag(reg)?;
    _check_pipeline_terminates(reg)?;
    _check_metadata_keys(reg)?;
    _check_namespace_patterns(reg)?;
    _check_namespace_rules(reg)?;
    _check_hook_fns(reg)?;
    Ok(())
}

fn _check_spec_kinds(reg: &KernelRegistry) -> Result<(), VerifyError> {
    for (id, source) in &reg.sources {
        if source.kind != "application/source" {
            return Err(VerifyError::InvalidSourceKind {
                source_id: id.as_str().into(),
                kind: source.kind.clone(),
            });
        }
    }
    for (id, sink) in &reg.sinks {
        if !matches!(sink.kind.as_str(), "stream_egress" | "datagram_egress") {
            return Err(VerifyError::InvalidSinkKind {
                sink_id: id.as_str().into(),
                kind: sink.kind.clone(),
            });
        }
    }
    Ok(())
}

fn _check_registry_identities(reg: &KernelRegistry) -> Result<(), VerifyError> {
    for (id, source) in &reg.sources {
        if source.id != *id {
            return Err(VerifyError::RegistryIdentityMismatch {
                kind: "source",
                key: id.as_str().into(),
                id: source.id.as_str().into(),
            });
        }
    }
    for (id, sink) in &reg.sinks {
        if sink.id != *id {
            return Err(VerifyError::RegistryIdentityMismatch {
                kind: "sink",
                key: id.as_str().into(),
                id: sink.id.as_str().into(),
            });
        }
    }
    for (id, hook) in &reg.hooks {
        if hook.id != *id {
            return Err(VerifyError::RegistryIdentityMismatch {
                kind: "hook",
                key: id.as_str().into(),
                id: hook.id.as_str().into(),
            });
        }
    }
    for (id, pipeline) in &reg.pipelines {
        if pipeline.id != *id {
            return Err(VerifyError::RegistryIdentityMismatch {
                kind: "pipeline",
                key: id.as_str().into(),
                id: pipeline.id.as_str().into(),
            });
        }
    }
    Ok(())
}

fn _check_wirings_exist(reg: &KernelRegistry) -> Result<(), VerifyError> {
    let mut wired_sources = HashSet::new();
    for wiring in &reg.wirings {
        if !wired_sources.insert(wiring.source.as_str()) {
            return Err(VerifyError::DuplicateWiringSource {
                source_id: wiring.source.as_str().into(),
            });
        }
        if !reg.sources.contains_key(&wiring.source) {
            return Err(VerifyError::UnknownSource {
                source_id: wiring.source.as_str().into(),
            });
        }
        if !reg.pipelines.contains_key(&wiring.pipeline) {
            return Err(VerifyError::UnknownWiringPipeline {
                source_id: wiring.source.as_str().into(),
                pipeline: wiring.pipeline.as_str().into(),
            });
        }
    }
    for source_id in reg.sources.keys() {
        if !wired_sources.contains(source_id.as_str()) {
            return Err(VerifyError::MissingSourceWiring {
                source_id: source_id.as_str().into(),
            });
        }
    }
    Ok(())
}

fn _check_hooks_exist(reg: &KernelRegistry) -> Result<(), VerifyError> {
    for (pid, pipeline) in &reg.pipelines {
        for hook_id in &pipeline.hooks {
            if !reg.hooks.contains_key(hook_id) {
                return Err(VerifyError::UnknownHook(
                    pid.as_str().into(),
                    hook_id.as_str().into(),
                ));
            }
        }
    }
    Ok(())
}

fn _check_hook_fns(reg: &KernelRegistry) -> Result<(), VerifyError> {
    for hook_id in reg.fns.keys() {
        if !reg.hooks.contains_key(hook_id) {
            return Err(VerifyError::UnknownHookFn {
                hook: hook_id.as_str().into(),
            });
        }
    }
    for (pid, pipeline) in &reg.pipelines {
        for hook_id in &pipeline.hooks {
            if !reg.fns.contains_key(hook_id) {
                return Err(VerifyError::MissingHookFn {
                    pipeline: pid.as_str().into(),
                    hook: hook_id.as_str().into(),
                });
            }
        }
    }
    Ok(())
}

fn _check_accept_declarations(reg: &KernelRegistry) -> Result<(), VerifyError> {
    for (hook_id, spec) in &reg.hooks {
        if !spec.may_terminate && !spec.may_accept_to.is_empty() {
            return Err(VerifyError::InvalidAcceptDeclaration {
                hook: hook_id.as_str().into(),
            });
        }
    }
    Ok(())
}

fn _check_sink_targets(reg: &KernelRegistry) -> Result<(), VerifyError> {
    // `may_accept_to` enumerates every SinkId a Verdict::Accept may name. Empty is
    // legal: it marks a hook that terminates only via Reject/Drop (e.g. resolve or
    // rule_chain). The runtime cannot emit Accept without a SinkId, so empty list
    // means Accept is not in this hook's verdict set.
    for (hid, spec) in &reg.hooks {
        for sink in &spec.may_accept_to {
            if !reg.sinks.contains_key(sink) {
                return Err(VerifyError::UnknownSink {
                    hook: hid.as_str().into(),
                    sink: sink.as_str().into(),
                });
            }
        }
    }
    Ok(())
}

fn _check_jump_declarations(reg: &KernelRegistry) -> Result<(), VerifyError> {
    for (hook_id, spec) in &reg.hooks {
        if !spec.may_jump && !spec.may_jump_to.is_empty() {
            return Err(VerifyError::InvalidJumpDeclaration {
                hook: hook_id.as_str().into(),
            });
        }
    }
    Ok(())
}

fn _check_jump_targets(reg: &KernelRegistry) -> Result<(), VerifyError> {
    for (pid, pipeline) in &reg.pipelines {
        for hook_id in &pipeline.hooks {
            if let Some(spec) = reg.hooks.get(hook_id) {
                for target in &spec.may_jump_to {
                    if !reg.pipelines.contains_key(target) {
                        return Err(VerifyError::UnknownPipelineJumpTarget {
                            from: pid.as_str().into(),
                            hook: hook_id.as_str().into(),
                            to: target.as_str().into(),
                        });
                    }
                }
            }
        }
    }
    Ok(())
}

fn _check_jump_dag(reg: &KernelRegistry) -> Result<(), VerifyError> {
    let mut adj: HashMap<&PipelineId, Vec<&PipelineId>> = HashMap::new();
    for (pid, pipeline) in &reg.pipelines {
        let targets = pipeline
            .hooks
            .iter()
            .filter_map(|hid| reg.hooks.get(hid))
            .flat_map(|spec| &spec.may_jump_to)
            .collect::<Vec<_>>();
        adj.insert(pid, targets);
    }

    let mut color: HashMap<&PipelineId, u8> = HashMap::new();
    for start in reg.pipelines.keys() {
        if color.get(start).copied().unwrap_or(0) == 0 {
            _dfs_cycle(start, &adj, &mut color)?;
        }
    }
    Ok(())
}

fn _dfs_cycle<'a>(
    node: &'a PipelineId,
    adj: &HashMap<&'a PipelineId, Vec<&'a PipelineId>>,
    color: &mut HashMap<&'a PipelineId, u8>,
) -> Result<(), VerifyError> {
    color.insert(node, 1);
    for &neighbor in adj.get(node).map(|v| v.as_slice()).unwrap_or(&[]) {
        match color.get(neighbor).copied().unwrap_or(0) {
            0 => _dfs_cycle(neighbor, adj, color)?,
            1 => return Err(VerifyError::JumpCycle(node.as_str().into())),
            _ => {}
        }
    }
    color.insert(node, 2);
    Ok(())
}

fn _check_pipeline_terminates(reg: &KernelRegistry) -> Result<(), VerifyError> {
    for (pid, pipeline) in &reg.pipelines {
        let can_terminate = pipeline.hooks.iter().any(|hid| {
            reg.hooks
                .get(hid)
                .map(|s| s.may_terminate || (s.may_jump && !s.may_jump_to.is_empty()))
                .unwrap_or(false)
        });
        if !can_terminate {
            return Err(VerifyError::PipelineDoesNotTerminate(pid.as_str().into()));
        }
    }
    Ok(())
}

/// Extract the leading namespace head from a metadata key (`"net.dst_host"` → `"net"`).
fn _head(key: &str) -> &str {
    key.split('.').next().unwrap_or("")
}

/// Glob match: pattern is `<head>.*`; matches when key's leading head equals pattern's head.
fn _ns_covers(patterns: &[String], key: &str) -> bool {
    patterns.iter().any(|p| {
        let Some(p_head) = p.strip_suffix(".*") else {
            return false;
        };
        key.strip_prefix(p_head)
            .is_some_and(|rest| rest.starts_with('.'))
    })
}

fn _is_valid_namespace_pattern(pattern: &str) -> bool {
    let Some(head) = pattern.strip_suffix(".*") else {
        return false;
    };
    METADATA_NAMESPACES.contains(&head)
}

fn _is_valid_metadata_key(key: &str) -> bool {
    let Some((head, rest)) = key.split_once('.') else {
        return false;
    };
    METADATA_NAMESPACES.contains(&head)
        && rest.split('.').all(|part| {
            !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
}

fn _check_metadata_keys(reg: &KernelRegistry) -> Result<(), VerifyError> {
    for (source_id, source) in &reg.sources {
        for key in &source.initial_writes {
            if !_is_valid_metadata_key(key) {
                return Err(VerifyError::InvalidMetadataKey {
                    owner: format!("source:{}", source_id.as_str()),
                    key: key.clone(),
                });
            }
        }
    }

    for (hook_id, spec) in &reg.hooks {
        for key in spec.reads.iter().chain(spec.writes.iter()) {
            if !_is_valid_metadata_key(key) {
                return Err(VerifyError::InvalidMetadataKey {
                    owner: format!("hook:{}", hook_id.as_str()),
                    key: key.clone(),
                });
            }
        }
    }
    Ok(())
}

fn _check_namespace_patterns(reg: &KernelRegistry) -> Result<(), VerifyError> {
    for (hook_id, spec) in &reg.hooks {
        for pattern in &spec.allowed_namespaces {
            if !_is_valid_namespace_pattern(pattern) {
                return Err(VerifyError::InvalidNamespacePattern {
                    hook: hook_id.as_str().into(),
                    pattern: pattern.clone(),
                });
            }
        }
    }
    Ok(())
}

fn _check_namespace_rules(reg: &KernelRegistry) -> Result<(), VerifyError> {
    for (pid, pipeline) in &reg.pipelines {
        let pid_str = pid.as_str();
        let mut available: HashSet<String> = reg
            .wirings
            .iter()
            .filter(|w| w.pipeline == *pid)
            .filter_map(|w| reg.sources.get(&w.source))
            .flat_map(|src| src.initial_writes.iter().cloned())
            .collect();

        for hook_id in &pipeline.hooks {
            let spec = match reg.hooks.get(hook_id) {
                Some(s) => s,
                None => continue,
            };
            let hook_str = hook_id.as_str();

            if spec.kind == HookKind::Policy && spec.reads.iter().any(|r| r == "net.payload") {
                return Err(VerifyError::PolicyReadsPayload {
                    pipeline: pid_str.into(),
                    hook: hook_str.into(),
                });
            }

            for write in &spec.writes {
                if !_ns_covers(&spec.allowed_namespaces, write) {
                    return Err(VerifyError::NamespaceViolation {
                        pipeline: pid_str.into(),
                        hook: hook_str.into(),
                        key: write.clone(),
                        side: "write",
                    });
                }
            }
            for read in &spec.reads {
                if !_ns_covers(&spec.allowed_namespaces, read) {
                    return Err(VerifyError::NamespaceViolation {
                        pipeline: pid_str.into(),
                        hook: hook_str.into(),
                        key: read.clone(),
                        side: "read",
                    });
                }
            }

            if spec.side_effect_only {
                for write in &spec.writes {
                    let ns = _head(write);
                    if VERDICT_NAMESPACES.contains(&ns) {
                        return Err(VerifyError::SideEffectMutatesVerdict {
                            pipeline: pid_str.into(),
                            hook: hook_str.into(),
                            key: write.clone(),
                        });
                    }
                }
            }

            for read in &spec.reads {
                if !available.contains(read.as_str()) {
                    return Err(VerifyError::UnsatisfiedRead {
                        pipeline: pid_str.into(),
                        hook: hook_str.into(),
                        key: read.clone(),
                    });
                }
            }

            for write in &spec.writes {
                available.insert(write.clone());
            }
        }
    }
    Ok(())
}
