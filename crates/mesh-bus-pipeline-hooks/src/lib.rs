//! mesh-bus-pipeline-hooks — the four hooks specified by
//! 2026-05-12-dns-enrichment-pipeline-design.md.
//!
//! Each hook registers a sync HookFn + declarative HookSpec with the
//! KernelRegistry. Async work (DNS resolution, blocking I/O) is bridged
//! through SharedHookCtx.

pub mod context;
mod ext_meta;
pub mod geo;
pub mod pick_sink;
pub mod resolve;
pub mod rule;
pub mod runtime;
pub mod specs;

pub use context::SharedHookCtx;
pub use runtime::PipelineRuntime;
