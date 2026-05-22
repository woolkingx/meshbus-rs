use super::data_handle::validate_fragment;
use super::types::{
    FragmentMetadata, ReassemblyMode, ReassemblyPolicy, TransformDescriptor, TransformError,
    TransformKind,
};

fn meta() -> FragmentMetadata {
    FragmentMetadata {
        group_id: "g1".into(),
        fragment_id: "f1".into(),
        seq: 0,
        total: 1,
        offset: 0,
        deadline_ms: None,
        checksum: "deadbeef".into(),
    }
}

#[test]
fn descriptor_carries_opaque_policy_ref() {
    let d = TransformDescriptor {
        kind: TransformKind::Encrypt,
        policy_ref: Some("noise://wan20".into()),
    };
    assert_eq!(d.kind, TransformKind::Encrypt);
    assert_eq!(d.policy_ref.as_deref(), Some("noise://wan20"));
}

#[test]
fn reassembly_policy_carries_mode_and_ref() {
    let p = ReassemblyPolicy {
        mode: ReassemblyMode::Reorder,
        policy_ref: None,
    };
    assert_eq!(p.mode, ReassemblyMode::Reorder);
    assert!(p.policy_ref.is_none());
}

#[test]
fn validate_fragment_accepts_valid_metadata() {
    assert!(validate_fragment(&meta()).is_ok());
}

#[test]
fn validate_fragment_rejects_zero_total() {
    let mut m = meta();
    m.total = 0;
    assert_eq!(validate_fragment(&m), Err(TransformError::InvalidTotal));
}

#[test]
fn validate_fragment_rejects_seq_at_or_above_total() {
    let mut m = meta();
    m.total = 2;
    m.seq = 2;
    assert_eq!(validate_fragment(&m), Err(TransformError::SeqOutOfRange));
}

#[test]
fn validate_fragment_rejects_empty_group_id() {
    let mut m = meta();
    m.group_id.clear();
    assert_eq!(validate_fragment(&m), Err(TransformError::EmptyGroupId));
}
