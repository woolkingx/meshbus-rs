use super::*;
use tokio::net::{TcpListener, UdpSocket};

#[tokio::test]
async fn applies_udp_socket_buffers() {
    let config = SocketBufferConfig::new(Some(16 * 1024), Some(16 * 1024));
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    apply_udp_socket_buffers(&socket, config).unwrap();

    let sock = socket2::SockRef::from(&socket);
    assert!(sock.recv_buffer_size().unwrap() >= config.recv_bytes.unwrap());
    assert!(sock.send_buffer_size().unwrap() >= config.send_bytes.unwrap());
}

#[tokio::test]
async fn connect_tcp_applies_socket_buffers() {
    let config = SocketBufferConfig::new(Some(16 * 1024), Some(16 * 1024));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accept = tokio::spawn(async move {
        let _ = listener.accept().await.unwrap();
    });

    let stream = connect_tcp(&addr.to_string(), config).await.unwrap();

    let sock = socket2::SockRef::from(&stream);
    assert!(sock.recv_buffer_size().unwrap() >= config.recv_bytes.unwrap());
    assert!(sock.send_buffer_size().unwrap() >= config.send_bytes.unwrap());
    drop(stream);
    accept.await.unwrap();
}
