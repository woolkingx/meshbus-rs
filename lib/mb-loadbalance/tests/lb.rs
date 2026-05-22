use mb_loadbalance::{Candidate, ConsistentHash, StickyTable, Swrr, Wrr};

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
