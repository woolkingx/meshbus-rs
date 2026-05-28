use super::*;
use mb_proto_mesh::SeqRange;

#[test]
fn replicate_count_is_bounded_duplicate_send() {
    assert_eq!(replicate_count(0), 1, "0 fanout is meaningless -> 1");
    assert_eq!(replicate_count(1), 1);
    assert_eq!(replicate_count(2), 2);
    assert_eq!(replicate_count(4), 4);
    assert_eq!(
        replicate_count(255),
        4,
        "fanout is clamped, no amplification"
    );
}

#[test]
fn send_copies_only_replicate_fans_out() {
    let steer = EgressPolicy::new(DeliveryMode::Steer, 3, 4);
    assert_eq!(steer.send_copies(), 1, "Steer sends exactly once");
    let rep = EgressPolicy::new(DeliveryMode::Replicate, 3, 4);
    assert_eq!(
        rep.send_copies(),
        3,
        "Replicate fans out the configured count"
    );
    let repair = EgressPolicy::new(DeliveryMode::Repair, 3, 4);
    assert_eq!(
        repair.send_copies(),
        1,
        "Repair sends once, retransmits on AckNack"
    );
}

#[test]
fn stripe_index_round_robins_across_mouths_and_degrades_to_steer_at_one() {
    // One mouth: Stripe == Steer.
    for seq in 0..5u64 {
        assert_eq!(stripe_index(seq, 1), 0);
        assert_eq!(stripe_index(seq, 0), 0);
    }
    // Multiple mouths: consecutive packages spread round-robin.
    assert_eq!(stripe_index(0, 3), 0);
    assert_eq!(stripe_index(1, 3), 1);
    assert_eq!(stripe_index(2, 3), 2);
    assert_eq!(stripe_index(3, 3), 0);
}

#[test]
fn repair_remembers_only_data_seqs_and_retransmits_missing_ranges() {
    let policy = EgressPolicy::new(DeliveryMode::Repair, 2, 4);
    policy.remember(0, b"control-no-seq"); // seq 0 (control) is not buffered
    policy.remember(1, b"data-seq-1");
    policy.remember(2, b"data-seq-2");
    policy.remember(3, b"data-seq-3");

    let ack = AckNack {
        family_id: "fam".into(),
        cumulative_seq: 0,
        received_bitmap: "0".repeat(32),
        missing_ranges: vec![SeqRange { start: 2, end: 3 }],
    };
    let resend = policy.to_retransmit(&ack);
    assert_eq!(
        resend,
        vec![b"data-seq-2".to_vec(), b"data-seq-3".to_vec()],
        "only the seqs the peer reports missing are retransmitted"
    );

    // Steer never buffers, so a stray AckNack retransmits nothing.
    let steer = EgressPolicy::new(DeliveryMode::Steer, 2, 4);
    steer.remember(1, b"x");
    assert!(steer.to_retransmit(&ack).is_empty());
}

#[test]
fn steer_does_not_repair_missing_stream_seq_but_repair_does() {
    let ack = AckNack {
        family_id: "stream-session".into(),
        cumulative_seq: 1,
        received_bitmap: "0".repeat(32),
        missing_ranges: vec![SeqRange { start: 1, end: 1 }],
    };

    let steer = EgressPolicy::new(DeliveryMode::Steer, 1, 0);
    steer.remember(1, b"stream-seq-1");
    assert!(
        steer.to_retransmit(&ack).is_empty(),
        "steer must not pretend to repair an ordered stream gap"
    );

    let repair = EgressPolicy::new(DeliveryMode::Repair, 1, 0);
    repair.remember(1, b"stream-seq-1");
    assert_eq!(
        repair.to_retransmit(&ack),
        vec![b"stream-seq-1".to_vec()],
        "repair must retain stream data packages for AckNack retransmit"
    );
}

#[test]
fn probe_budget_caps_low_rate_samples() {
    let policy = EgressPolicy::new(DeliveryMode::Probe, 2, 3);
    assert!(policy.take_probe_token(), "1st probe within budget");
    assert!(policy.take_probe_token(), "2nd probe within budget");
    assert!(policy.take_probe_token(), "3rd probe within budget");
    assert!(
        !policy.take_probe_token(),
        "4th probe exceeds budget -> skipped"
    );
    assert!(!policy.take_probe_token(), "budget stays exhausted");
}

#[test]
fn outbound_queue_full_maps_to_l5_queue_full() {
    assert_eq!(
        send_error_to_disconnect(SendError::BufferFull),
        DisconnectReason::QueueFull
    );
}
