use super::types::Verdict;

#[allow(dead_code)]
pub fn verdict_label(v: &Verdict) -> &'static str {
    match v {
        Verdict::Continue => "Continue",
        Verdict::Jump(_) => "Jump",
        Verdict::Accept(_) => "Accept",
        Verdict::Reject(_) => "Reject",
        Verdict::Drop => "Drop",
    }
}
