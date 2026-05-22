//! Imperative residue for `KernelRegistry::verify()` error classes that require
//! an actual `HookFn` function-pointer to be inserted into `reg.fns`.
//!
//! Structural error classes (triggered before the HookFn check) are covered by
//! data fixtures in `crates/mesh-bus-core/tests/fixtures/registry/*.json` driven
//! by `tests/registry_fixture_runner.rs`. Only `UnknownHookFn` requires a real
//! function-pointer registration and therefore stays here as imperative residue.

use super::data_handle::verify;
use super::types::{HookKind, HookSpec, KernelRegistry, SinkSpec, SourceSpec};
use super::verify_error::VerifyError;
use crate::kernel::event::types::Event;
use crate::kernel::pipeline::types::{Pipeline, Wiring};
use crate::kernel::verdict::types::{HookId, PipelineId, SinkId, SourceId, Verdict};

fn minimal_spec(id: &str, kind: HookKind, may_terminate: bool) -> HookSpec {
    HookSpec {
        id: HookId::new(id),
        kind,
        allowed_namespaces: vec![],
        reads: vec![],
        writes: vec![],
        may_terminate,
        may_jump: false,
        may_jump_to: vec![],
        may_accept_to: vec![],
        side_effect_only: false,
    }
}

fn source_spec(id: &str) -> SourceSpec {
    SourceSpec {
        id: SourceId::new(id),
        kind: "application/source".into(),
        initial_writes: vec![],
    }
}

fn sink_spec(id: &str) -> SinkSpec {
    SinkSpec {
        id: SinkId::new(id),
        kind: "stream_egress".into(),
    }
}

fn continue_fn(_event: &mut Event, _ctx: &mut super::types::KernelCtx) -> Verdict {
    Verdict::Continue
}

fn pipeline(id: &str, hooks: &[&str]) -> Pipeline {
    Pipeline {
        id: PipelineId::new(id),
        hooks: hooks.iter().map(|h| HookId::new(*h)).collect(),
    }
}

fn base_registry() -> KernelRegistry {
    let mut r = KernelRegistry::default();
    r.sources.insert(SourceId::new("src"), source_spec("src"));
    r.sinks.insert(SinkId::new("direct"), sink_spec("direct"));
    r
}

// --- HookFn residue: UnknownHookFn ---
// Error class: UnknownHookFn — fires when reg.fns contains a HookId with no
// corresponding HookSpec. Requires inserting an actual fn pointer into reg.fns,
// which cannot be expressed as JSON data; this case stays imperative.

#[test]
fn verify_rejects_registered_fn_without_hook_spec() {
    let mut reg = base_registry();
    reg.hooks.insert(
        HookId::new("allow"),
        minimal_spec("allow", HookKind::Net, true),
    );
    reg.fns.insert(HookId::new("allow"), continue_fn);
    reg.fns.insert(HookId::new("orphan"), continue_fn);
    reg.pipelines
        .insert(PipelineId::new("main"), pipeline("main", &["allow"]));
    reg.wirings.push(Wiring {
        source: SourceId::new("src"),
        pipeline: PipelineId::new("main"),
    });

    let err = verify(&reg).expect_err("HookFn requires HookSpec");
    assert!(
        matches!(err, VerifyError::UnknownHookFn { .. }),
        "{:?}",
        err
    );
}
