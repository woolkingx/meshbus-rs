use super::*;

fn mouth(id: &str, addr: &str, epoch: u64) -> ReceiverMouth {
    ReceiverMouth {
        mouth_id: id.into(),
        udp_addr: addr.into(),
        family_filter: vec!["datagram".into()],
        advertised_capacity: 1024,
        epoch,
    }
}

fn peer() -> SocketAddr {
    "127.0.0.1:9100".parse().unwrap()
}

#[test]
fn initial_mouth_is_recorded() {
    let mut mouths: HashMap<MouthKey, MouthEntry> = HashMap::new();
    assert!(apply_port_open(
        &mut mouths,
        peer(),
        &mouth("m1", "10.0.0.1:7001", 1),
        100
    ));
    let e = mouths.get(&(peer(), "m1".into())).unwrap();
    assert_eq!(e.epoch, 1);
    assert_eq!(e.udp_addr, "10.0.0.1:7001");
    assert_eq!(e.last_seen, 100);
}

#[test]
fn mouth_rotation_make_before_break_keeps_old_until_close() {
    let mut mouths: HashMap<MouthKey, MouthEntry> = HashMap::new();
    apply_port_open(&mut mouths, peer(), &mouth("m1", "10.0.0.1:7001", 1), 100);
    // New mouth becomes eligible immediately; old mouth still present.
    assert!(apply_port_open(
        &mut mouths,
        peer(),
        &mouth("m2", "10.0.0.1:7002", 2),
        101
    ));
    assert!(mouths.contains_key(&(peer(), "m1".into())));
    assert!(mouths.contains_key(&(peer(), "m2".into())));
    // Old mouth closes only after the new one is live (break).
    assert!(apply_port_close(&mut mouths, peer(), "m1", 1));
    assert!(!mouths.contains_key(&(peer(), "m1".into())));
    assert!(mouths.contains_key(&(peer(), "m2".into())));
}

#[test]
fn stale_epoch_mouth_open_and_close_are_ignored() {
    let mut mouths: HashMap<MouthKey, MouthEntry> = HashMap::new();
    apply_port_open(&mut mouths, peer(), &mouth("m1", "10.0.0.1:7002", 5), 100);
    // Stale-epoch re-open does not regress the coordinate.
    assert!(!apply_port_open(
        &mut mouths,
        peer(),
        &mouth("m1", "10.0.0.1:7001", 3),
        101
    ));
    assert_eq!(
        mouths.get(&(peer(), "m1".into())).unwrap().udp_addr,
        "10.0.0.1:7002"
    );
    // Stale-epoch close cannot retract a rotated mouth.
    assert!(!apply_port_close(&mut mouths, peer(), "m1", 4));
    assert!(mouths.contains_key(&(peer(), "m1".into())));
    // Current-or-newer-epoch close removes it.
    assert!(apply_port_close(&mut mouths, peer(), "m1", 5));
    assert!(!mouths.contains_key(&(peer(), "m1".into())));
}

#[test]
fn soft_ttl_expired_mouth_is_pruned_on_next_open() {
    let mut mouths: HashMap<MouthKey, MouthEntry> = HashMap::new();
    apply_port_open(&mut mouths, peer(), &mouth("m1", "10.0.0.1:7001", 1), 100);
    // A later PortOpen for a different mouth, past the soft TTL, prunes m1.
    apply_port_open(
        &mut mouths,
        peer(),
        &mouth("m2", "10.0.0.1:7002", 1),
        100 + MOUTH_SOFT_TTL_SECS + 1,
    );
    assert!(!mouths.contains_key(&(peer(), "m1".into())));
    assert!(mouths.contains_key(&(peer(), "m2".into())));
}
