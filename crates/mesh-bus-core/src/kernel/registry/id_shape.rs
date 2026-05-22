use super::types::KernelRegistry;
use super::verify_error::VerifyError;

pub(super) fn check_id_shapes(reg: &KernelRegistry) -> Result<(), VerifyError> {
    for source_id in reg.sources.keys() {
        if !is_valid_id_shape(source_id.as_str()) {
            return Err(VerifyError::InvalidSourceId {
                source_id: source_id.as_str().into(),
            });
        }
    }
    for wiring in &reg.wirings {
        if !is_valid_id_shape(wiring.source.as_str()) {
            return Err(VerifyError::InvalidSourceId {
                source_id: wiring.source.as_str().into(),
            });
        }
    }
    for sink_id in reg.sinks.keys() {
        if !is_valid_id_shape(sink_id.as_str()) {
            return Err(VerifyError::InvalidSinkId {
                sink_id: sink_id.as_str().into(),
            });
        }
    }
    for pipeline_id in reg.pipelines.keys() {
        check_pipeline_id(pipeline_id.as_str())?;
    }
    for wiring in &reg.wirings {
        check_pipeline_id(wiring.pipeline.as_str())?;
    }
    for hook_id in reg.hooks.keys().chain(reg.fns.keys()) {
        check_hook_id(hook_id.as_str())?;
    }
    for pipeline in reg.pipelines.values() {
        check_pipeline_id(pipeline.id.as_str())?;
        for hook_id in &pipeline.hooks {
            check_hook_id(hook_id.as_str())?;
        }
    }
    for spec in reg.hooks.values() {
        check_hook_id(spec.id.as_str())?;
        for pipeline_id in &spec.may_jump_to {
            check_pipeline_id(pipeline_id.as_str())?;
        }
    }
    for spec in reg.hooks.values() {
        for sink_id in &spec.may_accept_to {
            if !is_valid_id_shape(sink_id.as_str()) {
                return Err(VerifyError::InvalidSinkId {
                    sink_id: sink_id.as_str().into(),
                });
            }
        }
    }
    Ok(())
}

fn check_pipeline_id(id: &str) -> Result<(), VerifyError> {
    if !is_valid_id_shape(id) {
        return Err(VerifyError::InvalidPipelineId {
            pipeline_id: id.into(),
        });
    }
    Ok(())
}

fn check_hook_id(id: &str) -> Result<(), VerifyError> {
    if !is_valid_id_shape(id) {
        return Err(VerifyError::InvalidHookId { hook_id: id.into() });
    }
    Ok(())
}

fn is_valid_id_shape(id: &str) -> bool {
    !id.is_empty()
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-'))
}
