use bytes::BytesMut;
use mb_proto_dns::framing::*;

#[test]
fn writes_two_byte_length_prefix() {
    let mut out = BytesMut::new();
    write_tcp_frame(&mut out, &[0xAA; 17]);
    assert_eq!(&out[..2], &[0x00, 0x11]);
    assert_eq!(out.len(), 19);
}

#[test]
fn reads_one_full_frame() {
    let mut buf = BytesMut::new();
    write_tcp_frame(&mut buf, &[1, 2, 3, 4]);
    let frame = try_read_tcp_frame(&mut buf).expect("frame");
    assert_eq!(frame.as_ref(), &[1, 2, 3, 4]);
    assert!(buf.is_empty());
}

#[test]
fn returns_none_until_complete() {
    let mut buf = BytesMut::new();
    buf.extend_from_slice(&[0x00, 0x05, 0x01, 0x02]);
    assert!(try_read_tcp_frame(&mut buf).is_none());
    buf.extend_from_slice(&[0x03, 0x04, 0x05]);
    let frame = try_read_tcp_frame(&mut buf).expect("frame");
    assert_eq!(frame.as_ref(), &[1, 2, 3, 4, 5]);
}

#[test]
fn handles_back_to_back_frames() {
    let mut buf = BytesMut::new();
    write_tcp_frame(&mut buf, &[0xAA]);
    write_tcp_frame(&mut buf, &[0xBB, 0xCC]);
    let f1 = try_read_tcp_frame(&mut buf).expect("f1");
    let f2 = try_read_tcp_frame(&mut buf).expect("f2");
    assert_eq!(f1.as_ref(), &[0xAA]);
    assert_eq!(f2.as_ref(), &[0xBB, 0xCC]);
    assert!(buf.is_empty());
}
