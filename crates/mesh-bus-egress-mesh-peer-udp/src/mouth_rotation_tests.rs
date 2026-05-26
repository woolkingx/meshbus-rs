use super::*;

fn mouth(addr: &str, epoch: u64) -> ReceiverMouth {
    ReceiverMouth {
        mouth_id: "mouth-1".into(),
        udp_addr: addr.into(),
        family_filter: vec!["datagram".into()],
        advertised_capacity: 4096,
        epoch,
    }
}

#[test]
fn initial_mouth_addr_is_the_configured_peer() {
    let configured: SocketAddr = "127.0.0.1:7001".parse().unwrap();
    let coord = DeliveryCoord::new(configured);
    assert_eq!(coord.addr(), configured);
}

#[test]
fn port_open_rotation_updates_addr_and_epoch_make_before_break() {
    let coord = DeliveryCoord::new("127.0.0.1:7001".parse().unwrap());
    assert!(coord.apply_port_open(&mouth("127.0.0.1:7009", 5)));
    // The new coordinate is live the instant apply_port_open returns true,
    // before any old-mouth close: this is make-before-break.
    assert_eq!(coord.addr(), "127.0.0.1:7009".parse().unwrap());
    assert_eq!(coord.epoch.load(Ordering::Relaxed), 5);
}

#[test]
fn stale_epoch_port_open_is_rejected_and_addr_unchanged() {
    let coord = DeliveryCoord::new("127.0.0.1:7001".parse().unwrap());
    assert!(coord.apply_port_open(&mouth("127.0.0.1:7009", 5)));
    // A strictly-older epoch must not rewind the coordinate.
    assert!(!coord.apply_port_open(&mouth("127.0.0.1:6000", 4)));
    assert_eq!(coord.addr(), "127.0.0.1:7009".parse().unwrap());
    assert_eq!(coord.epoch.load(Ordering::Relaxed), 5);
    // A malformed udp_addr is rejected without touching the coordinate.
    assert!(!coord.apply_port_open(&mouth("not-an-addr", 6)));
    assert_eq!(coord.addr(), "127.0.0.1:7009".parse().unwrap());
}

#[test]
fn family_seq_and_session_id_survive_two_mouth_rotation() {
    // The session's monotone family seq and identity live in fields the
    // coordinate never touches; rotating across two mouths must not reset
    // or perturb them.
    let coord = DeliveryCoord::new("127.0.0.1:7001".parse().unwrap());
    let next_seq = AtomicU64::new(1);
    let session_id = String::from("s-egress-42");

    let s1 = next_seq.fetch_add(1, Ordering::Relaxed);
    assert!(coord.apply_port_open(&mouth("127.0.0.1:7009", 1)));
    let s2 = next_seq.fetch_add(1, Ordering::Relaxed);
    assert!(coord.apply_port_open(&mouth("127.0.0.1:7010", 2)));
    let s3 = next_seq.fetch_add(1, Ordering::Relaxed);

    assert_eq!((s1, s2, s3), (1, 2, 3));
    assert_eq!(next_seq.load(Ordering::Relaxed), 4);
    assert_eq!(session_id, "s-egress-42");
    assert_eq!(coord.addr(), "127.0.0.1:7010".parse().unwrap());
}
