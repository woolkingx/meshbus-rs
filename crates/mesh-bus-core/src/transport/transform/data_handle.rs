use super::types::{FragmentMetadata, TransformError};

pub fn validate_fragment(meta: &FragmentMetadata) -> Result<(), TransformError> {
    if meta.group_id.is_empty() {
        return Err(TransformError::EmptyGroupId);
    }
    if meta.fragment_id.is_empty() {
        return Err(TransformError::EmptyFragmentId);
    }
    if meta.total == 0 {
        return Err(TransformError::InvalidTotal);
    }
    if meta.seq >= meta.total {
        return Err(TransformError::SeqOutOfRange);
    }
    Ok(())
}
