//! TDD: `build_pipeline_runtime(&Config, base_dir)` assembles a verified
//! PipelineRuntime from operator YAML, with sinks projected from configured
//! egresses and the kernel registry passing verify().

use mesh_bus_core::kernel::{SinkId, SourceId, kernel_registry_verify};
use mesh_bus_resolver::cache::CacheKey;
use mesh_bus_resolver::types::{AnswerRecord, ConsumerId, QType, ResolveRequest};
use mesh_bus_runtime::{IngressCfg, build_pipeline_runtime, parse_config};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::Duration;

fn chain_yaml_minimal() -> &'static str {
    "rules: []\ndefault: allow\n"
}

struct TmpDir(PathBuf);

impl TmpDir {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "mesh-bus-runtime-pipeline-{}-{}",
            tag,
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("mkdir tmp");
        Self(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn write_chain(dir: &TmpDir, name: &str, body: &str) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, body).expect("write chain");
    path
}

fn cfg_yaml_with_chain(chain_path: &Path) -> String {
    let chain_str = chain_path.display();
    format!(
        r#"
ingresses:
  - kind: Socks5
    listen: 127.0.0.1:19500
egresses:
  - kind: Tcp
    id: direct
    timeout_ms: 3000
  - kind: Socks5
    id: cn-exit
    upstream: 127.0.0.1:1080
    timeout_ms: 3000
    groups: [cn]
pipeline:
  rule_chain_path: {chain_str}
"#
    )
}

fn cfg_yaml_with_forward_chain(chain_path: &Path) -> String {
    let chain_str = chain_path.display();
    format!(
        r#"
ingresses:
  - kind: Socks5
    listen: 127.0.0.1:19502
egresses:
  - kind: Tcp
    id: direct
    timeout_ms: 3000
pipeline:
  rule_chain_forward: {chain_str}
"#
    )
}

fn cfg_yaml_with_configured_source(chain_path: &Path) -> String {
    let chain_str = chain_path.display();
    format!(
        r#"
ingresses:
  - kind: Socks5
    listen: 127.0.0.1:19506
egresses:
  - kind: Tcp
    id: direct
    timeout_ms: 3000
pipeline:
  rule_chain_forward: {chain_str}
  source:
    ingress_index: 0
    id: edge-0
    kind: application/source
    initial_writes:
      - net.dst_host
      - net.dst_port
      - net.protocol
      - net.src_ip
      - auth.user
      - trace.flow_id
      - ext.operation
      - ext.dst_ip_primary
"#
    )
}

fn cfg_yaml_with_source_missing_protocol_write(chain_path: &Path) -> String {
    let chain_str = chain_path.display();
    format!(
        r#"
ingresses:
  - kind: Socks5
    listen: 127.0.0.1:19508
egresses:
  - kind: Tcp
    id: direct
    timeout_ms: 3000
pipeline:
  rule_chain_forward: {chain_str}
  source:
    ingress_index: 0
    initial_writes:
      - net.dst_host
      - net.dst_port
      - net.src_ip
      - auth.user
      - trace.flow_id
      - ext.operation
      - ext.dst_ip_primary
"#
    )
}

fn cfg_yaml_with_dns_cache(chain_path: &Path) -> String {
    let chain_str = chain_path.display();
    format!(
        r#"
ingresses:
  - kind: Socks5
    listen: 127.0.0.1:19503
egresses:
  - kind: Tcp
    id: direct
    timeout_ms: 3000
pipeline:
  rule_chain_forward: {chain_str}
  dns_cache:
    serve_stale_window_ms: 0
"#
    )
}

fn cfg_yaml_with_geosite(chain_path: &Path, geosite_path: &Path) -> String {
    let chain_str = chain_path.display();
    let geosite_str = geosite_path.display();
    format!(
        r#"
ingresses:
  - kind: Socks5
    listen: 127.0.0.1:19505
egresses:
  - kind: Tcp
    id: direct
    timeout_ms: 3000
pipeline:
  rule_chain_forward: {chain_str}
  geosite:
    path: {geosite_str}
"#
    )
}

fn cfg_yaml_with_geoip(chain_path: &Path, country_path: &Path, asn_path: &Path) -> String {
    let chain_str = chain_path.display();
    let country_str = country_path.display();
    let asn_str = asn_path.display();
    format!(
        r#"
ingresses:
  - kind: Socks5
    listen: 127.0.0.1:19507
egresses:
  - kind: Tcp
    id: direct
    timeout_ms: 3000
pipeline:
  rule_chain_forward: {chain_str}
  geoip:
    country_path: {country_str}
    asn_path: {asn_str}
"#
    )
}

fn cfg_yaml_with_resolver_chain(forward_chain_path: &Path, resolver_chain_path: &Path) -> String {
    let forward_chain_str = forward_chain_path.display();
    let resolver_chain_str = resolver_chain_path.display();
    format!(
        r#"
ingresses:
  - kind: Socks5
    listen: 127.0.0.1:19504
egresses:
  - kind: Tcp
    id: direct
    timeout_ms: 3000
pipeline:
  rule_chain_forward: {forward_chain_str}
  rule_chain_resolver: {resolver_chain_str}
"#
    )
}

fn cfg_yaml_with_multi_group_chain(chain_path: &Path) -> String {
    let chain_str = chain_path.display();
    format!(
        r#"
ingresses:
  - kind: Socks5
    listen: 127.0.0.1:19501
egresses:
  - kind: Tcp
    id: multi
    timeout_ms: 3000
    groups: [cn, fast]
  - kind: Udp
    id: dns
    timeout_ms: 3000
    groups: [dns]
pipeline:
  rule_chain_path: {chain_str}
"#
    )
}

fn cfg_yaml_with_mesh_peer_chain(chain_path: &Path) -> String {
    let chain_str = chain_path.display();
    format!(
        r#"
node:
  id: node-a
peers:
  - id: parent-b
    node_id: node-b
    route_groups: [remote-udp]
ingresses:
  - kind: Socks5
    listen: 127.0.0.1:19510
egresses:
  - kind: MeshPeerUdp
    id: peer-b-udp
    peer_id: parent-b
    peer: 127.0.0.1:29000
    timeout_ms: 1000
    groups: [remote-udp]
pipeline:
  rule_chain_path: {chain_str}
"#
    )
}

#[tokio::test]
async fn build_pipeline_runtime_succeeds_for_minimal_pipeline_cfg() {
    let dir = TmpDir::new("ok");
    let chain = write_chain(&dir, "chain.yaml", chain_yaml_minimal());
    let cfg = parse_config(&cfg_yaml_with_chain(&chain)).expect("parse");
    let rt = build_pipeline_runtime(&cfg, dir.path()).expect("build runtime");
    assert!(!rt.registry().hooks.is_empty(), "hooks must be registered");
    assert!(
        !rt.registry().pipelines.is_empty(),
        "at least one pipeline must be registered"
    );
}

#[tokio::test]
async fn build_pipeline_runtime_rejects_unsupported_forward_rule_action() {
    let dir = TmpDir::new("unsupported-forward-action");
    let chain = write_chain(
        &dir,
        "chain.yaml",
        r#"
rules: []
default:
  set_resolver_pool: dns-cn
"#,
    );
    let cfg = parse_config(&cfg_yaml_with_chain(&chain)).expect("parse");

    let err = build_pipeline_runtime(&cfg, dir.path())
        .err()
        .expect("unsupported forward rule action must fail startup");

    assert!(
        format!("{err:#}").contains("unsupported forward rule action"),
        "unexpected error: {err:#}"
    );
}

#[tokio::test]
async fn build_pipeline_runtime_uses_rule_chain_forward() {
    let dir = TmpDir::new("forward-chain");
    let chain = write_chain(&dir, "forward.yaml", chain_yaml_minimal());
    let cfg = parse_config(&cfg_yaml_with_forward_chain(&chain)).expect("parse");
    let rt = build_pipeline_runtime(&cfg, dir.path()).expect("build runtime");
    kernel_registry_verify(rt.registry()).expect("assembled registry must pass kernel verify()");
}

#[tokio::test]
async fn build_pipeline_runtime_applies_dns_cache_stale_window() {
    let dir = TmpDir::new("dns-cache-window");
    let chain = write_chain(&dir, "forward.yaml", chain_yaml_minimal());
    let cfg = parse_config(&cfg_yaml_with_dns_cache(&chain)).expect("parse");
    let rt = build_pipeline_runtime(&cfg, dir.path()).expect("build runtime");
    let key = CacheKey {
        qname: "stale.test.".into(),
        qtype: QType::A,
    };
    rt.shared_ctx().cache.put_positive(
        key.clone(),
        vec![AnswerRecord::A(Ipv4Addr::new(203, 0, 113, 1))],
        Duration::from_millis(1),
    );
    tokio::time::sleep(Duration::from_millis(10)).await;

    assert!(
        rt.shared_ctx().cache.lookup_stale(&key).is_none(),
        "configured zero serve_stale_window_ms must disable stale hits"
    );
}

#[tokio::test]
async fn build_pipeline_runtime_resolver_uses_shared_dns_cache() {
    let dir = TmpDir::new("dns-cache-shared");
    let chain = write_chain(&dir, "forward.yaml", chain_yaml_minimal());
    let cfg = parse_config(&cfg_yaml_with_forward_chain(&chain)).expect("parse");
    let rt = build_pipeline_runtime(&cfg, dir.path()).expect("build runtime");
    let key = CacheKey {
        qname: "cached.test.".into(),
        qtype: QType::A,
    };
    rt.shared_ctx().cache.put_positive(
        key,
        vec![AnswerRecord::A(Ipv4Addr::new(198, 51, 100, 7))],
        Duration::from_secs(60),
    );

    let (ans, sig) = rt
        .shared_ctx()
        .resolver
        .resolve(ResolveRequest {
            qname: "cached.test.".into(),
            qtype: QType::A,
            consumer: ConsumerId("runtime-test".into()),
        })
        .await
        .expect("prewarmed shared cache must satisfy resolver");

    assert_eq!(sig.pool, "cache");
    assert!(
        matches!(ans.records.as_slice(), [AnswerRecord::A(ip)] if *ip == Ipv4Addr::new(198, 51, 100, 7))
    );
}

#[tokio::test]
async fn build_pipeline_runtime_loads_geosite_datafile() {
    let dir = TmpDir::new("geosite");
    let chain = write_chain(&dir, "forward.yaml", chain_yaml_minimal());
    let geosite = dir.path().join("geosite.dat");
    std::fs::write(&geosite, "ad:ads.example.com\n").expect("write geosite");
    let cfg = parse_config(&cfg_yaml_with_geosite(&chain, &geosite)).expect("parse");
    let rt = build_pipeline_runtime(&cfg, dir.path()).expect("build runtime");

    assert_eq!(
        rt.shared_ctx().geosite.lookup("cdn.ads.example.com"),
        vec!["ad"]
    );
}

#[tokio::test]
async fn build_pipeline_runtime_fails_when_configured_geoip_cannot_open() {
    let dir = TmpDir::new("geoip-fail-closed");
    let chain = write_chain(&dir, "forward.yaml", chain_yaml_minimal());
    let country = dir.path().join("missing-country.mmdb");
    let asn = dir.path().join("missing-asn.mmdb");
    let cfg = parse_config(&cfg_yaml_with_geoip(&chain, &country, &asn)).expect("parse");

    let err = build_pipeline_runtime(&cfg, dir.path())
        .err()
        .expect("configured geoip files must fail closed when they cannot be opened");
    let msg = err.to_string();
    assert!(
        msg.contains("geoip") && msg.contains("missing-country.mmdb"),
        "error must identify the configured geoip path; got: {msg}"
    );
}

#[tokio::test]
async fn build_pipeline_runtime_wires_resolver_rule_chain() {
    let dir = TmpDir::new("resolver-chain");
    let forward_chain = write_chain(&dir, "forward.yaml", chain_yaml_minimal());
    let resolver_chain = write_chain(
        &dir,
        "resolver.yaml",
        r#"
rules:
  - hostname_suffix: ".meshbus.local"
    action: deny
default: allow
"#,
    );
    let cfg = parse_config(&cfg_yaml_with_resolver_chain(
        &forward_chain,
        &resolver_chain,
    ))
    .expect("parse");
    let rt = build_pipeline_runtime(&cfg, dir.path()).expect("build runtime");

    let result = tokio::time::timeout(
        Duration::from_secs(1),
        rt.shared_ctx().resolver.resolve(ResolveRequest {
            qname: "blocked.meshbus.local.".into(),
            qtype: QType::A,
            consumer: ConsumerId("runtime-test".into()),
        }),
    )
    .await
    .expect("resolver policy should decide before system DNS");

    let (err, sig) = result.expect_err("resolver rule chain must deny matching qname");
    assert!(
        matches!(err, mesh_bus_resolver::types::ResolveError::Denied),
        "unexpected resolver error: {err:?}",
    );
    assert_eq!(sig.action, "deny");
}

#[tokio::test]
async fn build_pipeline_runtime_registers_one_sink_per_egress() {
    let dir = TmpDir::new("sinks");
    let chain = write_chain(&dir, "chain.yaml", chain_yaml_minimal());
    let cfg = parse_config(&cfg_yaml_with_chain(&chain)).expect("parse");
    let rt = build_pipeline_runtime(&cfg, dir.path()).expect("build runtime");
    assert!(
        rt.registry().sinks.contains_key(&SinkId::new("direct")),
        "direct sink must be registered"
    );
    assert!(
        rt.registry().sinks.contains_key(&SinkId::new("cn-exit")),
        "cn-exit sink must be registered"
    );
    assert_eq!(
        rt.registry().sinks.len(),
        2,
        "exactly two sinks (one per egress)"
    );
}

#[tokio::test]
async fn build_pipeline_runtime_registers_sink_kind_from_egress_capability() {
    let dir = TmpDir::new("sink-kinds");
    let chain = write_chain(&dir, "chain.yaml", chain_yaml_minimal());
    let cfg = parse_config(&cfg_yaml_with_multi_group_chain(&chain)).expect("parse");
    let rt = build_pipeline_runtime(&cfg, dir.path()).expect("build runtime");

    let stream_sink = rt
        .registry()
        .sinks
        .get(&SinkId::new("multi"))
        .expect("stream sink registered");
    assert_eq!(stream_sink.kind, "stream_egress");

    let datagram_sink = rt
        .registry()
        .sinks
        .get(&SinkId::new("dns"))
        .expect("datagram sink registered");
    assert_eq!(datagram_sink.kind, "datagram_egress");
}

#[tokio::test]
async fn build_pipeline_runtime_derives_source_from_configured_ingress() {
    let dir = TmpDir::new("source");
    let chain = write_chain(&dir, "chain.yaml", chain_yaml_minimal());
    let cfg = parse_config(&cfg_yaml_with_chain(&chain)).expect("parse");
    let rt = build_pipeline_runtime(&cfg, dir.path()).expect("build runtime");

    assert!(
        !rt.registry().sources.contains_key(&SourceId::new("socks5")),
        "source id must be derived from configured ingress position, not hardcoded to socks5"
    );
    let source = rt
        .registry()
        .sources
        .get(&SourceId::new("ingress:0"))
        .expect("first configured pipeline-capable ingress is registered as ingress:0");
    assert_eq!(source.kind, "application/source");
}

#[tokio::test]
async fn build_pipeline_runtime_uses_configured_source_projection() {
    let dir = TmpDir::new("configured-source");
    let chain = write_chain(&dir, "chain.yaml", chain_yaml_minimal());
    let cfg = parse_config(&cfg_yaml_with_configured_source(&chain)).expect("parse");
    let rt = build_pipeline_runtime(&cfg, dir.path()).expect("build runtime");

    assert!(
        !rt.registry()
            .sources
            .contains_key(&SourceId::new("ingress:0")),
        "explicit pipeline.source.id replaces the derived source id"
    );
    let source = rt
        .registry()
        .sources
        .get(&SourceId::new("edge-0"))
        .expect("configured source id is registered");
    assert_eq!(source.kind, "application/source");
    assert_eq!(
        source.initial_writes,
        vec![
            "net.dst_host".to_string(),
            "net.dst_port".to_string(),
            "net.protocol".to_string(),
            "net.src_ip".to_string(),
            "auth.user".to_string(),
            "trace.flow_id".to_string(),
            "ext.operation".to_string(),
            "ext.dst_ip_primary".to_string(),
        ]
    );
}

#[tokio::test]
async fn build_pipeline_runtime_fails_when_source_projection_omits_required_read() {
    let dir = TmpDir::new("source-missing-read");
    let chain = write_chain(&dir, "chain.yaml", chain_yaml_minimal());
    let cfg = parse_config(&cfg_yaml_with_source_missing_protocol_write(&chain)).expect("parse");

    let err = build_pipeline_runtime(&cfg, dir.path())
        .err()
        .expect("kernel registry verify must reject unsatisfied source reads");
    let msg = err.to_string();
    assert!(
        msg.contains("kernel registry verify")
            && msg.contains("UnsatisfiedRead")
            && msg.contains("net.protocol"),
        "error must identify the unsatisfied metadata read; got: {msg}"
    );
}

#[tokio::test]
async fn build_pipeline_runtime_rejects_ambiguous_default_source_selection() {
    let dir = TmpDir::new("ambiguous-source");
    let chain = write_chain(&dir, "forward.yaml", chain_yaml_minimal());
    let mut cfg = parse_config(&cfg_yaml_with_forward_chain(&chain)).expect("parse");
    cfg.ingresses.push(IngressCfg::Socks5 {
        listen: "127.0.0.1:19509".into(),
        rule_chain_path: None,
        auth: None,
        handshake_timeout_ms: None,
        accept_backoff_ms: None,
        max_connections: None,
        udp_forward_concurrency: None,
        socket_recv_buffer_bytes: None,
        socket_send_buffer_bytes: None,
    });

    let err = build_pipeline_runtime(&cfg, dir.path())
        .err()
        .expect("runtime assembly must reject ambiguous source selection");
    assert!(
        err.to_string().contains(
            "pipeline source ingress_index is required when multiple ingresses declare pipeline source kind application/source"
        ),
        "unexpected error: {err:#}"
    );
}

#[tokio::test]
async fn build_pipeline_runtime_preserves_candidate_groups_and_capabilities() {
    let dir = TmpDir::new("candidate-caps");
    let chain = write_chain(&dir, "chain.yaml", chain_yaml_minimal());
    let cfg = parse_config(&cfg_yaml_with_multi_group_chain(&chain)).expect("parse");
    let rt = build_pipeline_runtime(&cfg, dir.path()).expect("build runtime");

    let multi = rt
        .shared_ctx()
        .candidates
        .iter()
        .find(|c| c.sink_id == "multi")
        .expect("multi candidate");
    assert!(
        multi.route_groups.iter().any(|g| g == "fast"),
        "candidate must keep all configured groups, not just the first"
    );
    assert!(
        multi.supports_stream,
        "Tcp egress candidate supports streams"
    );
    assert!(
        !multi.supports_datagram,
        "Tcp egress candidate must not be marked datagram-capable"
    );

    let dns = rt
        .shared_ctx()
        .candidates
        .iter()
        .find(|c| c.sink_id == "dns")
        .expect("dns candidate");
    assert!(!dns.supports_stream, "Udp egress must not support streams");
    assert!(
        dns.supports_datagram,
        "Udp egress candidate supports datagrams"
    );
}

#[tokio::test]
async fn build_pipeline_runtime_preserves_mesh_peer_candidate_capabilities() {
    let dir = TmpDir::new("mesh-peer-candidate-caps");
    let chain = write_chain(&dir, "chain.yaml", chain_yaml_minimal());
    let cfg = parse_config(&cfg_yaml_with_mesh_peer_chain(&chain)).expect("parse");
    let rt = build_pipeline_runtime(&cfg, dir.path()).expect("build runtime");

    let peer_udp = rt
        .shared_ctx()
        .candidates
        .iter()
        .find(|c| c.sink_id == "peer-b-udp")
        .expect("peer udp candidate");
    assert!(peer_udp.supports_datagram);
    assert!(peer_udp.supports_stream);
    assert!(peer_udp.route_groups.iter().any(|g| g == "remote-udp"));
}

#[tokio::test]
async fn build_pipeline_runtime_injects_pick_sink_may_accept_to() {
    let dir = TmpDir::new("picksink");
    let chain = write_chain(&dir, "chain.yaml", chain_yaml_minimal());
    let cfg = parse_config(&cfg_yaml_with_chain(&chain)).expect("parse");
    let rt = build_pipeline_runtime(&cfg, dir.path()).expect("build runtime");
    let pick_sink = rt
        .registry()
        .hooks
        .iter()
        .find(|(id, _)| id.as_str() == "transport.pick_sink_cake")
        .map(|(_, spec)| spec)
        .expect("pick_sink_cake hook registered");
    let mut got: Vec<String> = pick_sink
        .may_accept_to
        .iter()
        .map(|s| s.as_str().to_string())
        .collect();
    got.sort();
    let want = vec!["cn-exit".to_string(), "direct".to_string()];
    assert_eq!(
        got, want,
        "pick_sink_cake.may_accept_to must mirror configured egress ids"
    );
}

#[tokio::test]
async fn build_pipeline_runtime_passes_kernel_verify() {
    let dir = TmpDir::new("verify");
    let chain = write_chain(&dir, "chain.yaml", chain_yaml_minimal());
    let cfg = parse_config(&cfg_yaml_with_chain(&chain)).expect("parse");
    let rt = build_pipeline_runtime(&cfg, dir.path()).expect("build runtime");
    kernel_registry_verify(rt.registry()).expect("assembled registry must pass kernel verify()");
}

#[tokio::test]
async fn build_pipeline_runtime_errors_when_chain_path_missing() {
    let dir = TmpDir::new("missing");
    let missing = dir.path().join("does-not-exist.yaml");
    let cfg = parse_config(&cfg_yaml_with_chain(&missing)).expect("parse");
    let err = build_pipeline_runtime(&cfg, dir.path())
        .err()
        .expect("must error when chain file is missing");
    let msg = err.to_string();
    assert!(
        msg.contains("rule_chain_path") || msg.contains("does-not-exist"),
        "error must mention the missing chain path; got: {msg}"
    );
}
