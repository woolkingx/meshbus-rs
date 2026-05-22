use mesh_bus_core::kernel::observation::{
    CoreEventId, EventEnvelope, EventPayload, EventPayloadInner, EventTypeId, OBS_MESHSEC_DROP,
    OBS_NATIVE_DROP,
};
use mesh_bus_core::{BusEvent, ObserverPlugin};
use mesh_bus_observer_prometheus::PrometheusTextfileObserver;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Duration, timeout};

fn flow_event(
    type_id: EventTypeId,
    exit_id: &str,
    rtt_ms: u64,
    payload_bytes: u64,
    success: bool,
) -> BusEvent {
    BusEvent::Core(EventEnvelope {
        type_id,
        payload: EventPayload(Arc::new(EventPayloadInner {
            selected_exit: Some(exit_id.into()),
            rtt_ms,
            payload_bytes,
            success: Some(success),
            ..Default::default()
        })),
        at_ns: 0,
    })
}

fn obs_drop(type_id: EventTypeId, reason: &str) -> BusEvent {
    BusEvent::Observation(EventEnvelope {
        type_id,
        payload: EventPayload(Arc::new(EventPayloadInner {
            reason: Some(reason.into()),
            ..Default::default()
        })),
        at_ns: 0,
    })
}

#[tokio::test]
async fn writes_prometheus_textfile_metrics() {
    let path = std::env::temp_dir().join(format!(
        "mesh-bus-prom-{}-{}.prom",
        std::process::id(),
        "writes"
    ));
    let _ = tokio::fs::remove_file(&path).await;
    let observer = PrometheusTextfileObserver::new(&path)
        .with_wan_labels(HashMap::from([("wan20".to_string(), "wan-a".to_string())]))
        .with_static_labels(HashMap::from([("node".to_string(), "lab-1".to_string())]));

    observer.on_event(&flow_event(
        EventTypeId::Core(CoreEventId::FlowOpened),
        "wan20",
        12,
        512,
        true,
    ));
    observer.on_event(&flow_event(
        EventTypeId::Core(CoreEventId::PathIoError),
        "wan20",
        30,
        256,
        false,
    ));

    // Drainer task writes the file asynchronously after each event.
    // Poll until both events have been flushed (dispatch_total == 2).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let text = loop {
        if path.exists() {
            if let Ok(t) = std::fs::read_to_string(&path) {
                // The second event sets dispatch_total to 2; wait for that write.
                if t.contains(
                    "mesh_bus_dispatch_total{exit_id=\"wan20\",wan_id=\"wan-a\",node=\"lab-1\"} 2",
                ) {
                    break t;
                }
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "drainer did not flush both events within 2 s"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    };

    assert!(
        text.contains(
            "mesh_bus_dispatch_total{exit_id=\"wan20\",wan_id=\"wan-a\",node=\"lab-1\"} 2"
        )
    );
    assert!(text.contains(
        "mesh_bus_dispatch_success_total{exit_id=\"wan20\",wan_id=\"wan-a\",node=\"lab-1\"} 1"
    ));
    assert!(text.contains(
        "mesh_bus_dispatch_failure_total{exit_id=\"wan20\",wan_id=\"wan-a\",node=\"lab-1\"} 1"
    ));
    assert!(
        text.contains(
            "mesh_bus_dispatch_payload_bytes_total{exit_id=\"wan20\",wan_id=\"wan-a\",node=\"lab-1\"} 768"
        )
    );
    assert!(text.contains(
        "mesh_bus_dispatch_rtt_ms_last{exit_id=\"wan20\",wan_id=\"wan-a\",node=\"lab-1\"} 30"
    ));
    assert!(text.contains(
        "mesh_bus_dispatch_success_rate{exit_id=\"wan20\",wan_id=\"wan-a\",node=\"lab-1\"} 0.500000"
    ));

    let _ = tokio::fs::remove_file(&path).await;
}

#[tokio::test]
async fn exports_observation_drop_families_by_reason() {
    let observer = PrometheusTextfileObserver::http();
    observer.on_event(&obs_drop(OBS_MESHSEC_DROP, "auth"));
    observer.on_event(&obs_drop(OBS_MESHSEC_DROP, "replay"));
    observer.on_event(&obs_drop(OBS_NATIVE_DROP, "queue_overflow"));

    let text = observer.snapshot_text().await;
    assert!(text.contains("mesh_bus_meshsec_drop_total{reason=\"auth\"} 1"));
    assert!(text.contains("mesh_bus_meshsec_drop_total{reason=\"replay\"} 1"));
    assert!(text.contains("mesh_bus_native_drop_total{reason=\"queue_overflow\"} 1"));
    assert!(!text.contains("decrypted"));
}

#[tokio::test]
async fn emits_per_sink_peer_labels() {
    let observer = PrometheusTextfileObserver::http()
        .with_wan_labels(HashMap::from([("peer-a".to_string(), "wan-a".to_string())]))
        .with_peer_labels(HashMap::from([
            (
                "peer-a".to_string(),
                BTreeMap::from([
                    ("node_id".to_string(), "local-1".to_string()),
                    ("peer_id".to_string(), "up-1".to_string()),
                    ("path_id".to_string(), "peer-a".to_string()),
                    ("hop_count".to_string(), "1".to_string()),
                ]),
            ),
            (
                "direct".to_string(),
                BTreeMap::from([("node_id".to_string(), "local-1".to_string())]),
            ),
        ]));

    observer.on_event(&flow_event(
        EventTypeId::Core(CoreEventId::FlowOpened),
        "peer-a",
        9,
        64,
        true,
    ));
    observer.on_event(&flow_event(
        EventTypeId::Core(CoreEventId::FlowOpened),
        "direct",
        4,
        32,
        true,
    ));

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let text = loop {
        let snap = observer.snapshot_text().await;
        if snap.contains("exit_id=\"peer-a\"") && snap.contains("exit_id=\"direct\"") {
            break snap;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "drainer did not record both events within 2 s"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    };

    // Mesh-peer sink: wan_id + sorted peer labels (hop_count,node_id,path_id,peer_id).
    assert!(text.contains(
        "mesh_bus_dispatch_total{exit_id=\"peer-a\",wan_id=\"wan-a\",hop_count=\"1\",node_id=\"local-1\",path_id=\"peer-a\",peer_id=\"up-1\"} 1"
    ));
    // Direct sink: node_id only, no peer_id/path_id/hop_count.
    assert!(text.contains("mesh_bus_dispatch_total{exit_id=\"direct\",node_id=\"local-1\"} 1"));
    assert!(!text.contains("exit_id=\"direct\",node_id=\"local-1\",peer_id"));
}

#[tokio::test]
async fn dispatch_total_does_not_double_count_flow_open_and_close() {
    // mesh_bus_dispatch_total is HELP'd "Total dispatch attempts by exit".
    // A single flow that opens then closes is ONE dispatch attempt, not two.
    // FlowClosed is the terminal lifecycle of an already-counted attempt and
    // must not increment dispatch_total.
    let observer = PrometheusTextfileObserver::http();

    observer.on_event(&flow_event(
        EventTypeId::Core(CoreEventId::FlowOpened),
        "wan30",
        5,
        100,
        true,
    ));

    // Wait until the open attempt is recorded (dispatch_total == 1).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        let snap = observer.snapshot_text().await;
        if snap.contains("mesh_bus_dispatch_total{exit_id=\"wan30\"} 1") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "open attempt not recorded within 2 s"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    observer.on_event(&flow_event(
        EventTypeId::Core(CoreEventId::FlowClosed),
        "wan30",
        5,
        0,
        true,
    ));

    // Give the drainer ample time to process the close. dispatch_total must
    // stay 1: the close is a lifecycle terminal, not a new dispatch attempt.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let snap = observer.snapshot_text().await;
    assert!(
        snap.contains("mesh_bus_dispatch_total{exit_id=\"wan30\"} 1"),
        "FlowClosed must not increment dispatch_total; snapshot was:\n{snap}"
    );
    assert!(
        !snap.contains("mesh_bus_dispatch_total{exit_id=\"wan30\"} 2"),
        "dispatch_total double-counted flow open + close; snapshot was:\n{snap}"
    );
}

#[tokio::test]
async fn serves_fragmented_prometheus_metrics_request() {
    let observer = PrometheusTextfileObserver::new(std::env::temp_dir().join(format!(
        "mesh-bus-prom-fragmented-{}-unused.prom",
        std::process::id()
    )));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind metrics listener");
    let addr = listener.local_addr().expect("metrics addr");
    let server = tokio::spawn(observer.serve_http(listener));

    let mut client = TcpStream::connect(addr).await.expect("connect metrics");
    client
        .write_all(b"GET /met")
        .await
        .expect("write first fragment");
    client
        .write_all(b"rics HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("write second fragment");
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .await
        .expect("read response");
    let response = String::from_utf8(response).expect("utf8 response");
    assert!(response.starts_with("HTTP/1.1 200 OK"));

    server.abort();
}

#[tokio::test]
async fn serves_prometheus_metrics_over_http() {
    let observer = PrometheusTextfileObserver::new(std::env::temp_dir().join(format!(
        "mesh-bus-prom-http-{}-unused.prom",
        std::process::id()
    )))
    .with_wan_labels(HashMap::from([("wan21".to_string(), "wan-b".to_string())]));

    observer.on_event(&flow_event(
        EventTypeId::Core(CoreEventId::FlowOpened),
        "wan21",
        7,
        128,
        true,
    ));

    // Let drainer process the event before serving HTTP snapshot.
    tokio::time::sleep(Duration::from_millis(20)).await;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind metrics listener");
    let addr = listener.local_addr().expect("metrics addr");
    let server = tokio::spawn(observer.clone().serve_http(listener));

    let mut client = TcpStream::connect(addr).await.expect("connect metrics");
    client
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("write request");
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .await
        .expect("read response");
    let response = String::from_utf8(response).expect("utf8 response");

    assert!(response.starts_with("HTTP/1.1 200 OK"));
    assert!(response.contains("content-type: text/plain; version=0.0.4"));
    assert!(response.contains("mesh_bus_dispatch_total{exit_id=\"wan21\",wan_id=\"wan-b\"} 1"));

    server.abort();
}

#[tokio::test]
async fn metrics_http_closes_idle_clients_after_read_timeout() {
    let observer = PrometheusTextfileObserver::http();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind metrics listener");
    let addr = listener.local_addr().expect("metrics addr");
    let server = tokio::spawn(observer.serve_http(listener));

    let mut client = TcpStream::connect(addr).await.expect("connect metrics");
    let mut buf = [0u8; 1];
    let n = timeout(Duration::from_secs(2), client.read(&mut buf))
        .await
        .expect("idle client should be closed before test timeout")
        .expect("read close");
    assert_eq!(n, 0, "idle metrics client should receive EOF");

    server.abort();
}
