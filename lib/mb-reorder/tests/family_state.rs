use bytes::Bytes;
use mb_proto_mesh::{CloseReasonWire, DataPackage, SeqRange};
use mb_reorder::{FamilyPushOutcome, FamilyReorderState};

fn pkg(seq: u64) -> DataPackage {
    let body = format!("payload-{seq}").into_bytes();
    DataPackage {
        package_id: format!("pkg-{seq:06}"),
        seq,
        offset: seq * 1452,
        len: body.len() as u32,
        fragment_id: 0,
        fragment_count: 1,
        payload: Bytes::from(body),
    }
}

fn delivered_seqs(outcome: &FamilyPushOutcome) -> Vec<u64> {
    match outcome {
        FamilyPushOutcome::Deliver(v) => v.iter().map(|p| p.seq).collect(),
        other => panic!("expected Deliver, got {other:?}"),
    }
}

#[test]
fn in_order_delivery_advances_frontier_each_package() {
    let mut fam = FamilyReorderState::new("fam-7".into(), 0, 64, 200);
    for seq in 0..5 {
        assert_eq!(delivered_seqs(&fam.push_package(pkg(seq))), vec![seq]);
    }
    assert_eq!(fam.next_expected_seq, 5);
    assert!(fam.close_reason().is_none());
    assert!(fam.ack_snapshot().missing_ranges.is_empty());
}

#[test]
fn out_of_order_delivery_cascades_on_gap_fill() {
    let mut fam = FamilyReorderState::new("fam-7".into(), 0, 64, 200);
    assert_eq!(delivered_seqs(&fam.push_package(pkg(0))), vec![0]);
    assert!(matches!(
        fam.push_package(pkg(2)),
        FamilyPushOutcome::Gap(_)
    ));
    // 4 extends the gap frontier above 2, still gapped.
    assert!(matches!(
        fam.push_package(pkg(4)),
        FamilyPushOutcome::Gap(_)
    ));
    // 3 fills interior of the already-known gap region (below highest_seen 4).
    assert_eq!(fam.push_package(pkg(3)), FamilyPushOutcome::Buffered);
    // 1 lands on the frontier and cascades 1,2,3,4.
    assert_eq!(delivered_seqs(&fam.push_package(pkg(1))), vec![1, 2, 3, 4]);
    assert_eq!(fam.next_expected_seq, 5);
}

#[test]
fn duplicate_below_frontier_and_already_buffered_are_suppressed() {
    let mut fam = FamilyReorderState::new("fam-7".into(), 0, 64, 200);
    fam.push_package(pkg(0));
    assert_eq!(fam.push_package(pkg(0)), FamilyPushOutcome::Duplicate);
    assert!(matches!(
        fam.push_package(pkg(2)),
        FamilyPushOutcome::Gap(_)
    ));
    assert_eq!(fam.push_package(pkg(2)), FamilyPushOutcome::Duplicate);
}

#[test]
fn missing_range_generation_reports_contiguous_holes() {
    let mut fam = FamilyReorderState::new("fam-7".into(), 0, 64, 200);
    assert_eq!(delivered_seqs(&fam.push_package(pkg(0))), vec![0]);
    let FamilyPushOutcome::Gap(ack) = fam.push_package(pkg(5)) else {
        panic!("expected Gap");
    };
    assert_eq!(ack.family_id, "fam-7");
    assert_eq!(ack.cumulative_seq, 1);
    assert_eq!(ack.missing_ranges, vec![SeqRange { start: 1, end: 4 }]);

    fam.push_package(pkg(3));
    let split = fam.ack_snapshot();
    assert_eq!(
        split.missing_ranges,
        vec![SeqRange { start: 1, end: 2 }, SeqRange { start: 4, end: 4 }]
    );
}

#[test]
fn bounded_window_overflow_closes_family_protocol_error() {
    let mut fam = FamilyReorderState::new("fam-7".into(), 0, 8, 200);
    assert_eq!(delivered_seqs(&fam.push_package(pkg(0))), vec![0]);
    let FamilyPushOutcome::WindowOverflow(ack) = fam.push_package(pkg(100)) else {
        panic!("expected WindowOverflow");
    };
    assert_eq!(ack.cumulative_seq, 1);
    assert_eq!(fam.close_reason(), Some(CloseReasonWire::ProtocolError));
    // Family stays terminal: further packages keep returning WindowOverflow.
    assert!(matches!(
        fam.push_package(pkg(1)),
        FamilyPushOutcome::WindowOverflow(_)
    ));
}

#[test]
fn family_window_overflows_when_frontier_gap_exceeds_window() {
    let mut state = FamilyReorderState::new("session-a".into(), 1, 64, 0);

    assert!(matches!(state.push_package(pkg(2)), FamilyPushOutcome::Gap(_)));

    for seq in 3..65 {
        assert!(
            matches!(
                state.push_package(pkg(seq)),
                FamilyPushOutcome::Buffered | FamilyPushOutcome::Gap(_)
            ),
            "seq {seq} should remain inside the reorder window"
        );
    }

    assert!(
        matches!(
            state.push_package(pkg(65)),
            FamilyPushOutcome::WindowOverflow(_)
        ),
        "seq 65 is 64 ahead of missing seq 1 and must close the family"
    );
}
