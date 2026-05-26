use mb_loadbalance::{
    Candidate, ConsistentHash, MaxAgePolicy, SourceLeaseActivity, SourceLeaseReason,
    SourceLeaseRotate, SourceLeaseRotateConfig, StickyTable, Swrr, Wrr,
};

fn cands() -> Vec<Candidate> {
    vec![
        Candidate {
            id: "a".into(),
            weight: 5,
        },
        Candidate {
            id: "b".into(),
            weight: 3,
        },
        Candidate {
            id: "c".into(),
            weight: 2,
        },
    ]
}

fn equal_cands() -> Vec<Candidate> {
    vec![
        Candidate {
            id: "a".into(),
            weight: 1,
        },
        Candidate {
            id: "b".into(),
            weight: 1,
        },
    ]
}

#[test]
fn wrr_distributes_by_weight() {
    let mut wrr = Wrr::new(cands());
    let mut counts = std::collections::HashMap::new();
    for _ in 0..1000 {
        let pick = wrr.pick().expect("should have candidate");
        *counts.entry(pick).or_insert(0) += 1;
    }
    assert!(counts["a"] > counts["b"]);
    assert!(counts["b"] > counts["c"]);
}

#[test]
fn swrr_distributes_by_weight() {
    // SWRR should respect weight ratios over many picks.
    // weights: a=5, b=3, c=2  →  a:b:c should be 5:3:2 over 100 picks
    let mut swrr = Swrr::new(cands());
    let mut counts = std::collections::HashMap::new();
    for _ in 0..100 {
        let pick = swrr.pick().expect("should have candidate");
        *counts.entry(pick).or_insert(0) += 1;
    }
    assert!(counts["a"] > counts["b"], "a should be picked more than b");
    assert!(counts["b"] > counts["c"], "b should be picked more than c");
}

#[test]
fn consistent_hash_stable_for_same_key() {
    let ch = ConsistentHash::new(cands());
    let p1 = ch.pick("session-42");
    let p2 = ch.pick("session-42");
    assert_eq!(p1, p2);
}

#[test]
fn consistent_hash_uses_fxhash_not_defaulthasher() {
    // Same key produces the same exit across rebuilds (stable hash).
    let ch1 = ConsistentHash::new(cands());
    let ch2 = ConsistentHash::new(cands());
    assert_eq!(ch1.pick("x"), ch2.pick("x"));
}

#[test]
fn sticky_table_keeps_key_until_ttl_expires() {
    let mut sticky = StickyTable::new(100);
    let first = sticky
        .pick("flow-a", &equal_cands(), 1_000)
        .expect("first pick");
    let before_expiry = sticky
        .pick("flow-a", &equal_cands(), 1_050)
        .expect("sticky pick");
    let after_expiry = sticky
        .pick("flow-a", &equal_cands(), 1_101)
        .expect("repick");

    assert_eq!(first, before_expiry);
    assert_ne!(first, after_expiry);
}

#[test]
fn sticky_table_repicks_when_candidate_disappears() {
    let mut sticky = StickyTable::new(1_000);
    let first = sticky.pick("flow-a", &cands(), 1).expect("first pick");
    let remaining: Vec<Candidate> = cands().into_iter().filter(|c| c.id != first).collect();

    let repicked = sticky
        .pick("flow-a", &remaining, 2)
        .expect("repick from remaining candidates");

    assert_ne!(first, repicked);
}

fn source_lease_config(
    idle_timeout_ms: u64,
    max_age_ms: u64,
    max_age_policy: MaxAgePolicy,
    switch_cooldown_ms: u64,
) -> SourceLeaseRotateConfig {
    SourceLeaseRotateConfig {
        idle_timeout_ms,
        max_age_ms,
        max_age_policy,
        switch_cooldown_ms,
    }
}

#[test]
fn source_lease_keeps_source_until_idle_timeout() {
    let mut table = SourceLeaseRotate::new(source_lease_config(600, 3_600, MaxAgePolicy::Off, 60));

    let first = table
        .pick("client-a", &equal_cands(), 1_000)
        .expect("first source lease");
    let hit = table
        .pick("client-a", &equal_cands(), 1_500)
        .expect("active source lease");
    let expired = table
        .pick("client-a", &equal_cands(), 2_101)
        .expect("idle-expired source lease");

    assert_eq!(hit.candidate_id, first.candidate_id);
    assert_eq!(hit.reason, SourceLeaseReason::Hit);
    assert_eq!(expired.reason, SourceLeaseReason::IdleExpired);
    assert_eq!(expired.generation, first.generation + 1);
}

#[test]
fn source_lease_off_max_age_keeps_active_source_until_idle() {
    let mut table =
        SourceLeaseRotate::new(source_lease_config(10_000, 1_000, MaxAgePolicy::Off, 60));

    let first = table
        .pick("client-a", &equal_cands(), 1_000)
        .expect("first source lease");
    let active_after_max_age = table
        .pick("client-a", &equal_cands(), 2_001)
        .expect("active source lease after max age");

    assert_eq!(active_after_max_age.candidate_id, first.candidate_id);
    assert_eq!(active_after_max_age.reason, SourceLeaseReason::Hit);
    assert_eq!(active_after_max_age.generation, first.generation);
}

#[test]
fn source_lease_activity_blocks_idle_expiry_while_source_has_active_flows() {
    let mut table = SourceLeaseRotate::new(source_lease_config(600, 3_600, MaxAgePolicy::Off, 60));

    let first = table
        .pick_with_activity("client-a", &equal_cands(), 1_000, None)
        .expect("first source lease");
    let active_after_timeout = table
        .pick_with_activity(
            "client-a",
            &equal_cands(),
            2_000,
            Some(SourceLeaseActivity {
                active_flows: 1,
                idle_since_ms: None,
            }),
        )
        .expect("active source lease");
    let idle_expired = table
        .pick_with_activity(
            "client-a",
            &equal_cands(),
            3_000,
            Some(SourceLeaseActivity {
                active_flows: 0,
                idle_since_ms: Some(2_300),
            }),
        )
        .expect("true idle-expired source lease");

    assert_eq!(active_after_timeout.candidate_id, first.candidate_id);
    assert_eq!(active_after_timeout.reason, SourceLeaseReason::Hit);
    assert_eq!(active_after_timeout.generation, first.generation);
    assert_eq!(idle_expired.reason, SourceLeaseReason::IdleExpired);
    assert_eq!(idle_expired.generation, first.generation + 1);
}

#[test]
fn source_lease_invalid_half_idle_activity_uses_unknown_fallback() {
    let mut table = SourceLeaseRotate::new(source_lease_config(600, 3_600, MaxAgePolicy::Off, 60));

    let first = table
        .pick("client-a", &equal_cands(), 1_000)
        .expect("first source lease");
    let expired = table
        .pick_with_activity(
            "client-a",
            &equal_cands(),
            2_000,
            Some(SourceLeaseActivity {
                active_flows: 0,
                idle_since_ms: None,
            }),
        )
        .expect("fallback idle-expired source lease");

    assert_eq!(expired.reason, SourceLeaseReason::IdleExpired);
    assert_eq!(expired.generation, first.generation + 1);
}

#[test]
fn source_lease_soft_max_age_advances_generation_without_forcing_different_exit() {
    let mut table =
        SourceLeaseRotate::new(source_lease_config(10_000, 1_000, MaxAgePolicy::Soft, 60));

    let first = table
        .pick("client-a", &equal_cands(), 1_000)
        .expect("first source lease");
    let aged = table
        .pick("client-a", &equal_cands(), 2_001)
        .expect("soft max-age source lease");

    assert_eq!(aged.reason, SourceLeaseReason::MaxAgeSoft);
    assert_eq!(aged.generation, first.generation + 1);
}

#[test]
fn source_lease_hard_max_age_switches_when_alternative_exists() {
    let mut table =
        SourceLeaseRotate::new(source_lease_config(10_000, 1_000, MaxAgePolicy::Hard, 60));

    let first = table
        .pick("client-a", &equal_cands(), 1_000)
        .expect("first source lease");
    let aged = table
        .pick("client-a", &equal_cands(), 2_001)
        .expect("hard max-age source lease");

    assert_eq!(aged.reason, SourceLeaseReason::MaxAgeHard);
    assert_ne!(aged.candidate_id, first.candidate_id);
}

#[test]
fn source_lease_repicks_when_leased_candidate_disappears() {
    let mut table =
        SourceLeaseRotate::new(source_lease_config(10_000, 3_600, MaxAgePolicy::Off, 60));

    let first = table
        .pick("client-a", &cands(), 1_000)
        .expect("first source lease");
    let remaining: Vec<Candidate> = cands()
        .into_iter()
        .filter(|candidate| candidate.id != first.candidate_id)
        .collect();
    let repicked = table
        .pick("client-a", &remaining, 1_001)
        .expect("repick without missing candidate");

    assert_eq!(repicked.reason, SourceLeaseReason::Unhealthy);
    assert_ne!(repicked.candidate_id, first.candidate_id);
}
