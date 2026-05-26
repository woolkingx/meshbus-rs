use mb_endpoint::Endpoint;
use mesh_bus_core::{
    ExitId, ExitResult, FlowId, FlowSemantics, PacketId, RankContext, ReturnEvent, ReturnSemantics,
    ScheduleHint, SchedulerPlugin, SessionId, SourceActivity, TrafficClass,
};
use mesh_bus_scheduler_loadbalance::{
    LoadBalanceMode, LoadBalanceScheduler, SourceLeaseReason, SourceLeaseRotateSettings,
};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

fn ctx(flow: &str) -> RankContext {
    ctx_with_keys(flow, None, None)
}

fn ctx_with_keys(flow: &str, source: Option<&str>, target: Option<&str>) -> RankContext {
    RankContext {
        packet_id: PacketId(0),
        flow_id: FlowId(flow.into()),
        session_id: SessionId("s-1".into()),
        target: Endpoint::new("example.com", 443).expect("endpoint"),
        traffic_class: TrafficClass::Bulk,
        policy_ref: None,
        deadline_ms: None,
        schedule_hint: ScheduleHint::Auto,
        flow_semantics: FlowSemantics::ByteStream,
        return_semantics: ReturnSemantics::Direct,
        source_key: source.map(|s| s.to_string()),
        target_key: target.map(|s| s.to_string()),
        source_activity: None,
    }
}

fn cands() -> Vec<ExitId> {
    vec![ExitId("a".into()), ExitId("b".into()), ExitId("c".into())]
}

#[test]
fn round_robin_rotates_first_candidate() {
    let s = LoadBalanceScheduler::new(LoadBalanceMode::RoundRobin);
    let cands = cands();
    let picks: Vec<usize> = (0..6)
        .map(|_| s.schedule(&cands, &ctx("flow")).indices()[0])
        .collect();
    assert_eq!(picks, vec![0, 1, 2, 0, 1, 2]);
}

#[test]
fn round_robin_respects_configured_weights() {
    let s = LoadBalanceScheduler::new(LoadBalanceMode::RoundRobin).with_weights([
        ("a".to_string(), 2),
        ("b".to_string(), 1),
        ("c".to_string(), 1),
    ]);
    let cands = cands();
    let picks: Vec<usize> = (0..8)
        .map(|_| s.schedule(&cands, &ctx("flow")).indices()[0])
        .collect();
    assert_eq!(picks, vec![0, 0, 1, 2, 0, 0, 1, 2]);
}

#[test]
fn consistent_hashing_is_stable_for_same_target_key() {
    let s = LoadBalanceScheduler::new(LoadBalanceMode::ConsistentHashing);
    let cands = cands();
    let target = Some("example.com");
    let first = s
        .schedule(&cands, &ctx_with_keys("flow-1", Some("10.0.0.1"), target))
        .indices()[0];
    for i in 0..20 {
        let pick = s
            .schedule(
                &cands,
                &ctx_with_keys(
                    &format!("flow-{}", i + 2),
                    Some(&format!("10.0.0.{}", i + 2)),
                    target,
                ),
            )
            .indices()[0];
        assert_eq!(
            pick, first,
            "consistent-hashing must ignore flow_id and source_key"
        );
    }
}

#[test]
fn consistent_hashing_falls_back_to_flow_id_when_target_absent() {
    let s = LoadBalanceScheduler::new(LoadBalanceMode::ConsistentHashing);
    let cands = cands();
    let first = s.schedule(&cands, &ctx("flow-a")).indices()[0];
    for _ in 0..20 {
        assert_eq!(s.schedule(&cands, &ctx("flow-a")).indices()[0], first);
    }
}

#[test]
fn consistent_hashing_distributes_across_target_keys() {
    let s = LoadBalanceScheduler::new(LoadBalanceMode::ConsistentHashing);
    let cands = cands();
    let mut seen = std::collections::HashSet::new();
    for i in 0..50 {
        let tgt = format!("host-{}.example.com", i);
        let pick = s
            .schedule(&cands, &ctx_with_keys("flow", None, Some(&tgt)))
            .indices()[0];
        seen.insert(pick);
    }
    assert!(seen.len() >= 2, "fxhash should distribute across exits");
}

#[test]
fn sticky_sessions_pins_by_source_and_target_across_flow_ids() {
    let s = LoadBalanceScheduler::new(LoadBalanceMode::StickySessions);
    let cands = cands();
    let source = Some("10.0.0.1");
    let target = Some("example.com");
    let first = s
        .schedule(&cands, &ctx_with_keys("flow-1", source, target))
        .indices()[0];
    for i in 0..20 {
        let pick = s
            .schedule(
                &cands,
                &ctx_with_keys(&format!("flow-{}", i + 2), source, target),
            )
            .indices()[0];
        assert_eq!(pick, first, "sticky-sessions must pin by (source, target)");
    }
}

#[test]
fn sticky_sessions_separates_different_sources_for_same_target() {
    let s = LoadBalanceScheduler::new(LoadBalanceMode::StickySessions);
    let cands = cands();
    let target = Some("example.com");
    let mut seen = std::collections::HashSet::new();
    for i in 0..50 {
        let src = format!("10.0.0.{}", i);
        let pick = s
            .schedule(&cands, &ctx_with_keys("flow", Some(&src), target))
            .indices()[0];
        seen.insert(pick);
    }
    assert!(
        seen.len() >= 2,
        "different sources must spread across exits even for one target"
    );
}

#[test]
fn sticky_sessions_falls_back_to_flow_id_when_keys_absent() {
    let s = LoadBalanceScheduler::new(LoadBalanceMode::StickySessions);
    let cands = cands();
    let first = s.schedule(&cands, &ctx("flow-b")).indices()[0];
    for _ in 0..20 {
        assert_eq!(s.schedule(&cands, &ctx("flow-b")).indices()[0], first);
    }
}

#[test]
fn sticky_sessions_reselects_after_ttl() {
    let now = Arc::new(AtomicU64::new(1_000));
    let clock_now = now.clone();
    let s = LoadBalanceScheduler::with_sticky_ttl_ms(LoadBalanceMode::StickySessions, 100)
        .with_clock(Arc::new(move || clock_now.load(Ordering::SeqCst)));
    let cands = cands();

    let first = s.schedule(&cands, &ctx("flow-c")).indices()[0];
    now.store(1_050, Ordering::SeqCst);
    let before_expiry = s.schedule(&cands, &ctx("flow-c")).indices()[0];
    now.store(1_101, Ordering::SeqCst);
    let after_expiry = s.schedule(&cands, &ctx("flow-c")).indices()[0];

    assert_eq!(first, before_expiry);
    assert_ne!(first, after_expiry);
}

#[test]
fn sticky_key_is_injective_for_distinct_pairs() {
    let k1 = mesh_bus_scheduler_loadbalance::sticky_key_for_test(Some("ab"), Some("c"));
    let k2 = mesh_bus_scheduler_loadbalance::sticky_key_for_test(Some("a"), Some("bc"));
    assert_ne!(k1, k2, "distinct (src,tgt) must not collide");
    let k3 = mesh_bus_scheduler_loadbalance::sticky_key_for_test(Some("a|b"), Some("c"));
    let k4 = mesh_bus_scheduler_loadbalance::sticky_key_for_test(Some("a"), Some("b|c"));
    assert_ne!(k3, k4, "pipe in opaque key must not cause collision");
}

#[test]
fn feedback_is_accepted_without_state_change() {
    let s = LoadBalanceScheduler::new(LoadBalanceMode::RoundRobin);
    s.feedback(
        &ExitResult {
            exit_id: ExitId("a".into()),
            success: true,
            rtt_ms: 1,
            local_endpoint: None,
            return_event: ReturnEvent::Idle,
        },
        0,
        0,
    );
}

fn source_lease_scheduler(now: Arc<AtomicU64>) -> LoadBalanceScheduler {
    let clock_now = now.clone();
    LoadBalanceScheduler::with_source_lease_rotate(SourceLeaseRotateSettings {
        idle_timeout_ms: 600_000,
        max_age_ms: 3_600_000,
        max_age_policy: mesh_bus_scheduler_loadbalance::MaxAgePolicy::Off,
        switch_cooldown_ms: 60_000,
    })
    .with_clock(Arc::new(move || clock_now.load(Ordering::SeqCst)))
}

#[test]
fn source_lease_rotate_default_keeps_active_source_after_max_age() {
    let now = Arc::new(AtomicU64::new(1_000));
    let clock_now = now.clone();
    let s = LoadBalanceScheduler::new(LoadBalanceMode::SourceLeaseRotate)
        .with_clock(Arc::new(move || clock_now.load(Ordering::SeqCst)));
    let cands = cands();
    let source = Some("10.0.0.8");
    let first = s
        .schedule(
            &cands,
            &ctx_with_keys("flow-a", source, Some("api.example")),
        )
        .indices()[0];

    let mut active_after_max_age = first;
    for (idx, at_ms) in [
        591_000, 1_181_000, 1_771_000, 2_361_000, 2_951_000, 3_541_000, 4_131_000,
    ]
    .into_iter()
    .enumerate()
    {
        now.store(at_ms, Ordering::SeqCst);
        active_after_max_age = s
            .schedule(
                &cands,
                &ctx_with_keys(&format!("flow-active-{idx}"), source, Some("cdn.example")),
            )
            .indices()[0];
    }

    assert_eq!(
        active_after_max_age, first,
        "default source-lease-rotate must not age-switch an active source"
    );
}

#[test]
fn source_lease_rotate_uses_active_source_activity_for_idle() {
    let now = Arc::new(AtomicU64::new(1_000));
    let clock_now = now.clone();
    let s = LoadBalanceScheduler::with_source_lease_rotate(SourceLeaseRotateSettings {
        idle_timeout_ms: 600,
        max_age_ms: 3_600,
        max_age_policy: mesh_bus_scheduler_loadbalance::MaxAgePolicy::Off,
        switch_cooldown_ms: 0,
    })
    .with_clock(Arc::new(move || clock_now.load(Ordering::SeqCst)));
    let cands = cands();
    let mut first_ctx = ctx_with_keys("flow-a", Some("10.0.0.8"), Some("api.example"));
    first_ctx.source_activity = None;
    let first = s
        .source_lease_decision_for_test(&cands, &first_ctx)
        .expect("first source lease");
    assert_eq!(first.reason, SourceLeaseReason::New);

    now.store(2_000, Ordering::SeqCst);
    let mut active_ctx = ctx_with_keys("flow-b", Some("10.0.0.8"), Some("cdn.example"));
    active_ctx.source_activity = Some(SourceActivity {
        active_flows: 1,
        idle_since_ms: None,
    });
    let active_after_timeout = s
        .source_lease_decision_for_test(&cands, &active_ctx)
        .expect("active source lease");

    assert_eq!(
        active_after_timeout.candidate_id, first.candidate_id,
        "source lease must not idle-expire while core reports active flows"
    );
    assert_eq!(active_after_timeout.reason, SourceLeaseReason::Hit);
    assert_eq!(active_after_timeout.generation, first.generation);

    now.store(3_000, Ordering::SeqCst);
    let mut idle_ctx = ctx_with_keys("flow-c", Some("10.0.0.8"), Some("media.example"));
    idle_ctx.source_activity = Some(SourceActivity {
        active_flows: 0,
        idle_since_ms: Some(2_300),
    });
    let idle_after_timeout = s
        .source_lease_decision_for_test(&cands, &idle_ctx)
        .expect("idle-expired source lease");

    assert_eq!(
        idle_after_timeout.reason,
        SourceLeaseReason::IdleExpired,
        "source lease may rotate only after core reports true source idle"
    );
    assert_eq!(idle_after_timeout.generation, first.generation + 1);
}

#[test]
fn source_lease_rotate_pins_by_source_not_target() {
    let now = Arc::new(AtomicU64::new(1_000));
    let s = source_lease_scheduler(now);
    let cands = cands();
    let source = Some("10.0.0.8");
    let first = s
        .schedule(
            &cands,
            &ctx_with_keys("flow-a", source, Some("api.example")),
        )
        .indices()[0];

    for (idx, target) in ["cdn.example", "assets.example", "telemetry.example"]
        .iter()
        .enumerate()
    {
        let pick = s
            .schedule(
                &cands,
                &ctx_with_keys(&format!("flow-target-{idx}"), source, Some(target)),
            )
            .indices()[0];
        assert_eq!(pick, first, "source lease rotate must ignore target_key");
    }
}

#[test]
fn source_lease_rotate_spreads_distinct_sources() {
    let now = Arc::new(AtomicU64::new(1_000));
    let s = source_lease_scheduler(now);
    let cands = cands();
    let mut seen = std::collections::HashSet::new();
    for i in 0..50 {
        let source = format!("10.0.0.{i}");
        let pick = s
            .schedule(
                &cands,
                &ctx_with_keys("flow", Some(&source), Some("same.example")),
            )
            .indices()[0];
        seen.insert(pick);
    }

    assert!(
        seen.len() >= 2,
        "source lease rotate must distribute different sources across exits"
    );
}
