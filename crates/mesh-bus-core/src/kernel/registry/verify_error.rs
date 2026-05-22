use thiserror::Error;

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("pipeline `{0}` references unknown hook `{1}`")]
    UnknownHook(String, String),
    #[error("pipeline `{pipeline}` hook `{hook}` has no registered HookFn")]
    MissingHookFn { pipeline: String, hook: String },
    #[error("HookFn `{hook}` has no HookSpec")]
    UnknownHookFn { hook: String },
    #[error("registry {kind} key `{key}` disagrees with embedded id `{id}`")]
    RegistryIdentityMismatch {
        kind: &'static str,
        key: String,
        id: String,
    },
    #[error("invalid SourceId `{source_id}`")]
    InvalidSourceId { source_id: String },
    #[error("invalid SinkId `{sink_id}`")]
    InvalidSinkId { sink_id: String },
    #[error("invalid PipelineId `{pipeline_id}`")]
    InvalidPipelineId { pipeline_id: String },
    #[error("invalid HookId `{hook_id}`")]
    InvalidHookId { hook_id: String },
    #[error("invalid SourceSpec.kind `{kind}` for source `{source_id}`")]
    InvalidSourceKind { source_id: String, kind: String },
    #[error("invalid SinkSpec.kind `{kind}` for sink `{sink_id}`")]
    InvalidSinkKind { sink_id: String, kind: String },
    #[error("wiring references unknown source `{source_id}`")]
    UnknownSource { source_id: String },
    #[error("wiring from source `{source_id}` references unknown pipeline `{pipeline}`")]
    UnknownWiringPipeline { source_id: String, pipeline: String },
    #[error("source `{source_id}` has more than one wiring")]
    DuplicateWiringSource { source_id: String },
    #[error("source `{source_id}` has no wiring")]
    MissingSourceWiring { source_id: String },
    #[error("hook `{hook}` may_accept_to lists unknown sink `{sink}`")]
    UnknownSink { hook: String, sink: String },
    #[error("hook `{hook}` declares may_accept_to targets while may_terminate=false")]
    InvalidAcceptDeclaration { hook: String },
    #[error("pipeline `{from}` hook `{hook}` jumps to unknown pipeline `{to}`")]
    UnknownPipelineJumpTarget {
        from: String,
        hook: String,
        to: String,
    },
    #[error("hook `{hook}` declares may_jump_to targets while may_jump=false")]
    InvalidJumpDeclaration { hook: String },
    #[error("pipeline jump graph contains cycle at `{0}`")]
    JumpCycle(String),
    #[error(
        "pipeline `{pipeline}` hook `{hook}` reads `{key}` not satisfied by source or prior write"
    )]
    UnsatisfiedRead {
        pipeline: String,
        hook: String,
        key: String,
    },
    #[error(
        "pipeline `{pipeline}` hook `{hook}` violates namespace restriction (key=`{key}`, side=`{side}`)"
    )]
    NamespaceViolation {
        pipeline: String,
        hook: String,
        key: String,
        side: &'static str,
    },
    #[error("invalid metadata key `{key}` declared by `{owner}`")]
    InvalidMetadataKey { owner: String, key: String },
    #[error("invalid namespace pattern `{pattern}` declared by hook `{hook}`")]
    InvalidNamespacePattern { hook: String, pattern: String },
    #[error("pipeline `{pipeline}` policy hook `{hook}` reads `net.payload` (forbidden)")]
    PolicyReadsPayload { pipeline: String, hook: String },
    #[error(
        "pipeline `{pipeline}` side-effect hook `{hook}` writes verdict-driving metadata `{key}`"
    )]
    SideEffectMutatesVerdict {
        pipeline: String,
        hook: String,
        key: String,
    },
    #[error(
        "pipeline `{0}` cannot terminate: no hook has may_terminate=true or may_jump=true with at least one target"
    )]
    PipelineDoesNotTerminate(String),
}
