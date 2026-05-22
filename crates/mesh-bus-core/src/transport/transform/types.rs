use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransformKind {
    None,
    Fragment,
    Compress,
    Encrypt,
    Checksum,
    Parity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransformDescriptor {
    pub kind: TransformKind,
    pub policy_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentMetadata {
    pub group_id: String,
    pub fragment_id: String,
    pub seq: u64,
    pub total: u64,
    pub offset: u64,
    pub deadline_ms: Option<u64>,
    pub checksum: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReassemblyMode {
    None,
    Dedup,
    Reorder,
    Reassemble,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReassemblyPolicy {
    pub mode: ReassemblyMode,
    pub policy_ref: Option<String>,
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransformError {
    #[error("fragment total must be greater than zero")]
    InvalidTotal,
    #[error("fragment seq must be less than total")]
    SeqOutOfRange,
    #[error("fragment group_id must be non-empty")]
    EmptyGroupId,
    #[error("fragment fragment_id must be non-empty")]
    EmptyFragmentId,
}
