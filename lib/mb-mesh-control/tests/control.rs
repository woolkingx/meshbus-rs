use mb_mesh_control::{InflightPackage, MeshPathController};
use mb_proto_mesh::{AckNack, SeqRange};

fn ack(missing_ranges: Vec<SeqRange>) -> AckNack {
    AckNack {
        family_id: "fam-a".into(),
        cumulative_seq: 0,
        received_bitmap: "0".repeat(32),
        missing_ranges,
    }
}

#[test]
fn ack_frees_inflight_bytes_and_restores_send_budget() {
    let mut ctl = MeshPathController::default();
    let initial = ctl.send_budget();
    ctl.on_sent(InflightPackage {
        seq: 7,
        sent_at_us: 10,
        size: 900,
        ack_eliciting: true,
    });

    assert!(ctl.send_budget() < initial);
    let update = ctl.on_ack(&ack(Vec::new()), 0, 60_000);

    assert_eq!(update.acked_seqs, vec![7]);
    assert_eq!(ctl.bytes_in_flight(), 0);
    assert!(ctl.send_budget() >= initial);
}

#[test]
fn missing_range_marks_only_matching_inflight_packages_lost() {
    let mut ctl = MeshPathController::default();
    for seq in 1..=4 {
        ctl.on_sent(InflightPackage {
            seq,
            sent_at_us: seq * 1_000,
            size: 800,
            ack_eliciting: true,
        });
    }

    let update = ctl.on_ack(&ack(vec![SeqRange { start: 2, end: 3 }]), 0, 80_000);

    assert_eq!(update.lost_seqs, vec![2, 3]);
    assert_eq!(ctl.bytes_in_flight(), 0);
}

#[test]
fn pto_backoff_is_timer_state_not_fixed_chunk_sleep() {
    let mut ctl = MeshPathController::default();
    assert_eq!(ctl.loss_timer(), None);
    ctl.on_sent(InflightPackage {
        seq: 1,
        sent_at_us: 1_000,
        size: 900,
        ack_eliciting: true,
    });
    let first = ctl.loss_timer().expect("timer after ack-eliciting send");
    ctl.on_pto_expired();
    let second = ctl.loss_timer().expect("backed off timer remains armed");

    assert!(second > first);
    assert_eq!(ctl.pto_count(), 1);
}
