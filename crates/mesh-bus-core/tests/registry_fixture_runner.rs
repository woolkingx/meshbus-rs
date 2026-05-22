//! Registry-layer fixture runner. Legal operator over
//! tests/fixtures/registry/*.json for layer="registry". Drives the REAL
//! mesh_bus_core::kernel::kernel_registry_verify; no mock registry.
//!
//! Each fixture describes a KernelRegistry shape (sources/sinks/hooks/
//! pipelines/wirings) and an expected result (ok or error_contains substring).
//! The runner builds the real KernelRegistry, optionally registers a no-op
//! HookFn for every hook (for positive ok=true cases), then calls
//! kernel_registry_verify and asserts the result matches the fixture expectation.

use mesh_bus_core::kernel::{
    HookId, HookKind, HookSpec, KernelRegistry, Pipeline, PipelineId, SinkId, SinkSpec, SourceId,
    SourceSpec, Wiring, kernel_registry_verify,
};
use serde::Deserialize;
use std::path::Path;

// --- Fixture schema types ---

#[derive(Deserialize)]
struct Case {
    name: String,
    params: Params,
    input: Input,
    expect: Expect,
}

#[derive(Deserialize, Default)]
struct Params {
    #[serde(default)]
    auto_register_fns: bool,
}

#[derive(Deserialize)]
struct Input {
    json: RegistryDesc,
}

#[derive(Deserialize)]
struct Expect {
    ok: bool,
    #[serde(default)]
    error_contains: Option<String>,
}

// --- Registry description types (JSON fixture shape) ---

#[derive(Deserialize)]
struct RegistryDesc {
    sources: Vec<SourceDesc>,
    sinks: Vec<SinkDesc>,
    hooks: Vec<HookDesc>,
    pipelines: Vec<PipelineDesc>,
    wirings: Vec<WiringDesc>,
}

#[derive(Deserialize)]
struct SourceDesc {
    id: String,
    kind: String,
    #[serde(default)]
    initial_writes: Vec<String>,
}

#[derive(Deserialize)]
struct SinkDesc {
    id: String,
    kind: String,
}

/// Hook descriptor. `map_key` is the BTreeMap key (defaults to `id` when absent).
/// `spec_id` is the HookSpec embedded id (defaults to `id`). Setting `map_key`
/// and `spec_id` to different values exercises RegistryIdentityMismatch.
#[derive(Deserialize)]
struct HookDesc {
    /// map key used in KernelRegistry.hooks; if absent, falls back to `id`.
    #[serde(default)]
    map_key: Option<String>,
    /// embedded HookSpec.id; if absent, falls back to `id`.
    #[serde(default)]
    spec_id: Option<String>,
    /// canonical id (also used as map_key and spec_id when those fields are absent).
    #[serde(default)]
    id: String,
    kind: String,
    #[serde(default)]
    allowed_namespaces: Vec<String>,
    #[serde(default)]
    reads: Vec<String>,
    #[serde(default)]
    writes: Vec<String>,
    #[serde(default)]
    may_terminate: bool,
    #[serde(default)]
    may_jump: bool,
    #[serde(default)]
    may_jump_to: Vec<String>,
    #[serde(default)]
    may_accept_to: Vec<String>,
    #[serde(default)]
    side_effect_only: bool,
}

#[derive(Deserialize)]
struct PipelineDesc {
    id: String,
    hooks: Vec<String>,
}

#[derive(Deserialize)]
struct WiringDesc {
    source: String,
    pipeline: String,
}

// --- Registry builder ---

fn _parse_hook_kind(s: &str) -> HookKind {
    match s {
        "Net" => HookKind::Net,
        "Transport" => HookKind::Transport,
        "Policy" => HookKind::Policy,
        "Auth" => HookKind::Auth,
        "SideEffect" => HookKind::SideEffect,
        other => panic!("unknown HookKind: {other:?}"),
    }
}

fn _noop_fn(
    _e: &mut mesh_bus_core::kernel::Event,
    _ctx: &mut mesh_bus_core::kernel::KernelCtx,
) -> mesh_bus_core::kernel::Verdict {
    mesh_bus_core::kernel::Verdict::Continue
}

fn _build_registry(desc: &RegistryDesc, auto_fns: bool) -> KernelRegistry {
    let mut reg = KernelRegistry::default();

    for s in &desc.sources {
        let id = SourceId::new(&s.id);
        reg.sources.insert(
            id.clone(),
            SourceSpec {
                id,
                kind: s.kind.clone(),
                initial_writes: s.initial_writes.clone(),
            },
        );
    }

    for s in &desc.sinks {
        let id = SinkId::new(&s.id);
        reg.sinks.insert(
            id.clone(),
            SinkSpec {
                id,
                kind: s.kind.clone(),
            },
        );
    }

    for h in &desc.hooks {
        let map_key = HookId::new(h.map_key.as_deref().unwrap_or(&h.id));
        let spec_id = HookId::new(h.spec_id.as_deref().unwrap_or(&h.id));
        let spec = HookSpec {
            id: spec_id,
            kind: _parse_hook_kind(&h.kind),
            allowed_namespaces: h.allowed_namespaces.clone(),
            reads: h.reads.clone(),
            writes: h.writes.clone(),
            may_terminate: h.may_terminate,
            may_jump: h.may_jump,
            may_jump_to: h.may_jump_to.iter().map(|s| PipelineId::new(s)).collect(),
            may_accept_to: h.may_accept_to.iter().map(|s| SinkId::new(s)).collect(),
            side_effect_only: h.side_effect_only,
        };
        reg.hooks.insert(map_key.clone(), spec);
        if auto_fns {
            reg.fns.insert(map_key, _noop_fn);
        }
    }

    for p in &desc.pipelines {
        let id = PipelineId::new(&p.id);
        reg.pipelines.insert(
            id.clone(),
            Pipeline {
                id,
                hooks: p.hooks.iter().map(|h| HookId::new(h)).collect(),
            },
        );
    }

    for w in &desc.wirings {
        reg.wirings.push(Wiring {
            source: SourceId::new(&w.source),
            pipeline: PipelineId::new(&w.pipeline),
        });
    }

    reg
}

// --- Test runner ---

fn _load_cases() -> Vec<Case> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/registry");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("fixtures/registry dir") {
        let p = entry.unwrap().path();
        if p.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let txt = std::fs::read_to_string(&p).unwrap();
        let c: Case = serde_json::from_str(&txt).unwrap_or_else(|e| panic!("fixture {p:?}: {e}"));
        out.push(c);
    }
    out
}

#[test]
fn registry_contract_fixtures() {
    let cases = _load_cases();
    assert!(
        !cases.is_empty(),
        "no fixtures found in tests/fixtures/registry/"
    );
    for c in &cases {
        let reg = _build_registry(&c.input.json, c.params.auto_register_fns);
        let result = kernel_registry_verify(&reg);
        if c.expect.ok {
            result.unwrap_or_else(|e| panic!("[{}] expected Ok, got Err: {e}", c.name));
        } else {
            let err = match result {
                Err(e) => e,
                Ok(_) => panic!(
                    "[{}] expected Err but got Ok (set auto_register_fns: true for positive cases)",
                    c.name
                ),
            };
            if let Some(sub) = &c.expect.error_contains {
                let msg = format!("{err}");
                assert!(
                    msg.contains(sub.as_str()),
                    "[{}] error {msg:?} does not contain {sub:?}",
                    c.name
                );
            }
        }
    }
    println!("registry_contract_fixtures: {} cases passed", cases.len());
}
