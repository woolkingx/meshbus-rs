//! Shared socket-level tuning for ingress and egress plugins.

use std::io;
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SocketBufferConfig {
    pub recv_bytes: Option<usize>,
    pub send_bytes: Option<usize>,
}

impl SocketBufferConfig {
    pub fn new(recv_bytes: Option<usize>, send_bytes: Option<usize>) -> Self {
        Self {
            recv_bytes,
            send_bytes,
        }
    }

    pub fn is_disabled(self) -> bool {
        self.recv_bytes.is_none() && self.send_bytes.is_none()
    }
}

pub fn apply_tcp_stream_buffers(stream: &TcpStream, config: SocketBufferConfig) -> io::Result<()> {
    if config.is_disabled() {
        return Ok(());
    }
    apply_sock_ref(socket2::SockRef::from(stream), config)
}

pub fn apply_udp_socket_buffers(socket: &UdpSocket, config: SocketBufferConfig) -> io::Result<()> {
    if config.is_disabled() {
        return Ok(());
    }
    apply_sock_ref(socket2::SockRef::from(socket), config)
}

pub async fn connect_tcp(addr: &str, config: SocketBufferConfig) -> io::Result<TcpStream> {
    let mut last_error = None;
    for peer in tokio::net::lookup_host(addr).await? {
        let socket = if peer.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        apply_tcp_socket_buffers(&socket, config)?;
        match socket.connect(peer).await {
            Ok(stream) => return Ok(stream),
            Err(err) => last_error = Some(err),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "address resolved to no endpoints",
        )
    }))
}

fn apply_sock_ref(sock: socket2::SockRef<'_>, config: SocketBufferConfig) -> io::Result<()> {
    if let Some(bytes) = config.recv_bytes {
        sock.set_recv_buffer_size(bytes)?;
    }
    if let Some(bytes) = config.send_bytes {
        sock.set_send_buffer_size(bytes)?;
    }
    Ok(())
}

fn apply_tcp_socket_buffers(socket: &TcpSocket, config: SocketBufferConfig) -> io::Result<()> {
    if let Some(bytes) = config.recv_bytes {
        socket.set_recv_buffer_size(u32_buffer_size(bytes)?)?;
    }
    if let Some(bytes) = config.send_bytes {
        socket.set_send_buffer_size(u32_buffer_size(bytes)?)?;
    }
    Ok(())
}

fn u32_buffer_size(bytes: usize) -> io::Result<u32> {
    u32::try_from(bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket buffer size exceeds u32::MAX",
        )
    })
}

#[cfg(test)]
mod tests {
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
}
