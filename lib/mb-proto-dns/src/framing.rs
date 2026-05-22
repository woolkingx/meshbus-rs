use bytes::{Buf, Bytes, BytesMut};

pub fn write_tcp_frame(out: &mut BytesMut, msg: &[u8]) {
    debug_assert!(msg.len() <= u16::MAX as usize);
    out.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    out.extend_from_slice(msg);
}

pub fn try_read_tcp_frame(buf: &mut BytesMut) -> Option<Bytes> {
    if buf.len() < 2 {
        return None;
    }
    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if buf.len() < 2 + len {
        return None;
    }
    buf.advance(2);
    Some(buf.split_to(len).freeze())
}
