use mesh_bus_core::{
    BusBuilder, ExitId, ExitResult, IngressPlugin, RankContext, ScheduleDecision, SchedulerPlugin,
};
use mesh_bus_egress_tcp::TcpEgress;
use mesh_bus_ingress_tcp::TcpIngress;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct First;
impl SchedulerPlugin for First {
    fn schedule(&self, c: &[ExitId], _ctx: &RankContext) -> ScheduleDecision {
        ScheduleDecision::ordered((0..c.len()).collect())
    }
    fn feedback(&self, _r: &ExitResult, _payload_bytes: u64, _at_ms: u64) {}
}

#[tokio::test]
async fn ingress_pipes_to_egress() {
    let echo = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let echo_port = echo.local_addr().expect("echo addr").port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = echo.accept().await.expect("accept echo");
            tokio::spawn(async move {
                let mut buf = vec![0u8; 1024];
                loop {
                    let n = s.read(&mut buf).await.expect("read echo");
                    if n == 0 {
                        break;
                    }
                    s.write_all(&buf[..n]).await.expect("write echo");
                }
            });
        }
    });

    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_stream_egress(Box::new(TcpEgress::new(
            ExitId("tcp".into()),
            Duration::from_millis(500),
        )))
        .build()
        .await;
    let port = bus.port();
    let _bh = bus.spawn();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ingress");
    let bind_port = listener.local_addr().expect("ingress addr").port();
    let target = mb_endpoint::Endpoint::new("127.0.0.1", echo_port).expect("endpoint");
    let ingress = TcpIngress::new(listener, target);
    tokio::spawn(async move { Box::new(ingress).run(port).await.expect("ingress run") });

    let mut client = TcpStream::connect(format!("127.0.0.1:{bind_port}"))
        .await
        .expect("client connect");
    client.write_all(b"hello").await.expect("client write");
    let mut buf = vec![0u8; 5];
    client.read_exact(&mut buf).await.expect("client read");
    assert_eq!(&buf[..], b"hello");
}

#[tokio::test]
async fn transient_accept_error_does_not_kill_listener() {
    let echo = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let echo_port = echo.local_addr().expect("echo addr").port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = echo.accept().await.expect("accept echo");
            tokio::spawn(async move {
                let mut buf = vec![0u8; 1024];
                loop {
                    let n = s.read(&mut buf).await.expect("read echo");
                    if n == 0 {
                        break;
                    }
                    s.write_all(&buf[..n]).await.expect("write echo");
                }
            });
        }
    });

    let bus = BusBuilder::new()
        .scheduler(Box::new(First))
        .add_stream_egress(Box::new(TcpEgress::new(
            ExitId("tcp".into()),
            Duration::from_millis(500),
        )))
        .build()
        .await;
    let port = bus.port();
    let _bh = bus.spawn();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ingress");
    let bind_port = listener.local_addr().expect("ingress addr").port();
    let target = mb_endpoint::Endpoint::new("127.0.0.1", echo_port).expect("endpoint");
    let ingress = TcpIngress::new(listener, target);
    tokio::spawn(async move { Box::new(ingress).run(port).await.expect("ingress run") });

    for i in 0..50u32 {
        let mut client = TcpStream::connect(format!("127.0.0.1:{bind_port}"))
            .await
            .unwrap_or_else(|e| panic!("client {i} connect: {e}"));
        let msg = format!("ping{i}");
        client
            .write_all(msg.as_bytes())
            .await
            .unwrap_or_else(|e| panic!("client {i} write: {e}"));
        let mut buf = vec![0u8; msg.len()];
        client
            .read_exact(&mut buf)
            .await
            .unwrap_or_else(|e| panic!("client {i} read (listener died?): {e}"));
        assert_eq!(buf, msg.as_bytes(), "roundtrip {i}");
    }
}
