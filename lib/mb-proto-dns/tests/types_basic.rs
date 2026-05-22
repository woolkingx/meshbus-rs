use mb_proto_dns::*;

#[test]
fn name_round_trips_through_ascii_lower() {
    let n = Name::from_ascii("WWW.Example.COM.").expect("valid ascii name");
    assert_eq!(n.as_ascii_lower(), "www.example.com.");
}

#[test]
fn qtype_well_known() {
    assert_eq!(QType::A as u16, 1);
    assert_eq!(QType::Aaaa as u16, 28);
    assert_eq!(QType::Ptr as u16, 12);
    assert_eq!(QType::Cname as u16, 5);
    assert_eq!(QType::Txt as u16, 16);
    assert_eq!(QType::Opt as u16, 41);
}

#[test]
fn message_default_is_empty_query() {
    let m = Message::default();
    assert_eq!(m.questions.len(), 0);
    assert_eq!(m.answers.len(), 0);
    assert_eq!(m.header.qdcount(), 0);
}
