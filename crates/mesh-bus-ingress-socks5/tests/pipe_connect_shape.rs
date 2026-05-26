#[test]
fn connect_relay_uses_owned_spawned_direction_tasks() {
    let src = std::fs::read_to_string("src/connect.rs").expect("read SOCKS5 CONNECT source");
    let start = src
        .find("async fn pipe_connect")
        .expect("pipe_connect exists");
    let end = src[start..]
        .find("fn reply_for_disconnect")
        .map(|offset| start + offset)
        .expect("reply_for_disconnect follows pipe_connect");
    let body = &src[start..end];

    assert!(
        body.contains(".into_split()"),
        "pipe_connect must own TCP halves so each direction can be spawned"
    );
    assert!(
        body.matches("tokio::spawn").count() >= 2,
        "pipe_connect must spawn independent upload and download direction tasks"
    );
    assert!(
        !body.contains("sock.split()") && !body.contains("tokio::pin!"),
        "pipe_connect must not drive borrowed direction futures from one task"
    );
}

#[test]
fn connect_relay_attempts_splice_before_async_halves() {
    let src = std::fs::read_to_string("src/connect.rs").expect("read SOCKS5 CONNECT source");
    let start = src
        .find("async fn pipe_connect")
        .expect("pipe_connect exists");
    let end = src[start..]
        .find("fn reply_for_disconnect")
        .map(|offset| start + offset)
        .expect("reply_for_disconnect follows pipe_connect");
    let body = &src[start..end];

    assert!(
        body.contains("try_splice_tcp_connect("),
        "pipe_connect must try the TCP splice path before falling back to userspace copy"
    );
    assert!(
        body.find("try_splice_tcp_connect(") < body.find("session.split()"),
        "splice must be attempted before splitting into abstract send/recv halves"
    );
}

#[test]
fn splice_error_path_has_explicit_close_reason() {
    let src = std::fs::read_to_string("src/connect.rs").expect("read SOCKS5 CONNECT source");
    let start = src
        .find("async fn try_splice_tcp_connect")
        .expect("try_splice_tcp_connect exists");
    let end = src[start..]
        .find("fn join_close_reason")
        .map(|offset| start + offset)
        .expect("join_close_reason follows splice helper");
    let body = &src[start..end];

    assert!(
        body.contains("close_reason: \"splice_error\""),
        "splice errors must surface an explicit close reason"
    );
    assert!(
        !body.contains("Completed(mb_splice::SpliceStats::default())"),
        "splice errors must not be reported as a clean completed splice"
    );
}
