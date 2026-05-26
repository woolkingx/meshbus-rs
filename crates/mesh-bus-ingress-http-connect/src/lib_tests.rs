use super::base64_encode;

#[test]
fn base64_basic_vector() {
    assert_eq!(base64_encode(b"alice:secret"), "YWxpY2U6c2VjcmV0");
}
