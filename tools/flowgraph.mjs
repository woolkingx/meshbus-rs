#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";

const repo = process.cwd();
const args = parseArgs(process.argv.slice(2));
const outDir = path.resolve(repo, args.outDir);

const scanRoots = [
  "CLAUDE.md",
  "docs/handbook/mesh-protocol.html",
  "docs/handbook/transport.html",
  "docs/handbook/spec/data-control-matrix.schema.json",
  "docs/plan/2026-05-25-mesh-peer-udp-demux-rewrite.md",
  "crates/mesh-bus-egress-mesh-peer-udp",
  "crates/mesh-bus-ingress-mesh-peer-udp",
  "crates/mesh-bus-core/src/transport/udp_loop",
  "crates/mesh-bus-core/src/transport/session",
  "crates/mesh-bus-core/src/transport/forwarding",
  "crates/mesh-bus-core/src/kernel",
  "crates/mesh-bus-core/src/egress_adapter",
  "crates/mesh-bus-core/tests",
  "crates/mesh-bus-pipeline-hooks",
  "crates/mesh-bus-ingress-socks5",
  "crates/mesh-bus-runtime",
  "crates/mesh-bus-scheduler-loadbalance",
  "lib/mb-loadbalance",
  "crates/mesh-bus-bin/tests/throughput_transport.rs",
  "crates/mesh-bus-bin/tests/fixtures/topology",
  "tests/live-run2-pool-validation.mjs",
  "tests/live-run2-stream-validation.mjs",
  "deploy/run2-lab/deploy.mjs",
  "config/run2-gateway.example.yaml",
  "lib/mb-proto-mesh",
  "lib/mb-mesh-control",
  "lib/mb-reorder",
];

const components = new Map([
  ["socks5_ingress", { label: "L7 SOCKS5 ingress", layer: "L7" }],
  ["pipeline_hooks", { label: "control pipeline hooks", layer: "control" }],
  ["kernel_dispatch", { label: "kernel dispatch", layer: "L4/control" }],
  ["core_session", { label: "Bus L5 session", layer: "L5" }],
  ["egress_session", { label: "MeshPeerUdp egress session", layer: "L7 adapter" }],
  ["egress_demux", { label: "egress per-loop demux driver", layer: "L5/L6 owner" }],
  ["ingress_mesh_peer", { label: "MeshPeerUdp ingress", layer: "L7 adapter" }],
  ["mesh_peer_sender", { label: "MeshPeerUdp sender packetizer", layer: "L5/L4-sender" }],
  ["udp_loop", { label: "UdpPacketLoop", layer: "L4" }],
  ["meshsec", { label: "MeshSec open/replay", layer: "L6" }],
  ["mesh_codec", { label: "MeshFrame/MeshEvent codec", layer: "L6/L5" }],
  ["mesh_control", { label: "Mesh path controller", layer: "L5/L4-control" }],
  ["family_reorder", { label: "FamilyReorderState", layer: "L5" }],
  ["session_inbox", { label: "bounded session inboxes", layer: "L5" }],
  ["queue_backpressure", { label: "QueueFull backpressure", layer: "L5/L4" }],
  ["live_validation", { label: "systemd live validation", layer: "verify" }],
  ["lb_algorithm", { label: "mb-loadbalance algorithms", layer: "scheduler/lib" }],
  ["lb_scheduler", { label: "LoadBalanceScheduler", layer: "scheduler" }],
  ["candidate_filter", { label: "healthy candidate filter", layer: "L4/control" }],
  ["flow_pin", { label: "flow pin / hysteresis", layer: "L4 state" }],
  ["runtime_assembly", { label: "runtime scheduler assembly", layer: "runtime" }],
  ["scheduler_feedback", { label: "scheduler observation feedback", layer: "observation" }],
]);

const edgeRules = [
  {
    name: "drain_inbound",
    regex: /\.drain_inbound\s*\(/,
    to: "udp_loop",
    kind: "boundary",
    label: "drain inbound datagrams",
    allowedOwners: new Set(["egress_demux", "ingress_mesh_peer", "udp_loop", "core_udp_tests", "throughput_test"]),
    violation: "UdpPacketLoop::drain_inbound must stay behind packet-loop owners/tests",
  },
  {
    name: "restore_inbound_front",
    regex: /\brestore_inbound_front\b/,
    to: "udp_loop",
    kind: "boundary",
    label: "restore inbound datagram",
    sourceOnly: true,
    violation: "restore_inbound_front reintroduces payload-aware L4 rewind",
  },
  {
    name: "meshsec_open",
    regex: /\b(open_bytes|open_mesh_frame)\s*\(/,
    to: "meshsec",
    kind: "data",
    label: "open MeshSec once",
    allowedOwners: new Set(["egress_demux", "ingress_mesh_peer", "mesh_codec", "meshsec_tests"]),
    violation: "MeshSec open/replay mutation must be single-owner",
  },
  {
    name: "decode_event",
    regex: /\bdecode_event\s*\(/,
    to: "mesh_codec",
    kind: "data",
    label: "decode MeshEvent",
  },
  {
    name: "decode_frame",
    regex: /\b(decode_frame|decode_mesh_frame_clear)\s*\(/,
    to: "mesh_codec",
    kind: "data",
    label: "decode MeshFrame",
  },
  {
    name: "family_reorder",
    regex: /\bFamilyReorderState\b|\bpush_package\s*\(/,
    to: "family_reorder",
    kind: "data",
    label: "family order/dedup",
    allowedOwners: new Set(["egress_demux", "ingress_mesh_peer", "family_reorder", "reorder_tests"]),
    violation: "FamilyReorderState should be driven only by family owners/tests",
    violationSourceOnly: true,
  },
  {
    name: "mesh_control",
    regex: /\b(MeshPathController|InflightPackage|AckUpdate|send_budget|bytes_in_flight|loss_timer|pto_count)\b/,
    to: "mesh_control",
    kind: "control",
    label: "mesh control state",
  },
  {
    name: "mesh_peer_sender",
    regex: /\b(MeshPeerSender|MeshPeerIngressSender|send_data_frames|send_repair_bytes|DATA_FLUSH_MAX_DELAY|control_tx|data_tx)\b/,
    to: "mesh_peer_sender",
    kind: "control",
    label: "control/data packetizer",
  },
  {
    name: "stream_open_ack",
    regex: /\bStreamOpenAccepted\b|\bStreamOpenReject\b|\bopen_token\b/,
    to: "core_session",
    kind: "control",
    label: "stream open ack",
  },
  {
    name: "session_inbox",
    regex: /\b(control_inbox|data_inbox|event_inbox|datagram_inbox|error_inbox)\b/,
    to: "session_inbox",
    kind: "data",
    label: "bounded inbox",
  },
  {
    name: "queue_full",
    regex: /\bQueueFull\b|\bStreamDataPending\b|\bnative_queue_overflow_drop_total\b/,
    to: "queue_backpressure",
    kind: "backpressure",
    label: "typed overflow",
  },
  {
    name: "loadbalance_scheduler",
    regex: /\bLoadBalanceScheduler\b|\bLoadBalanceMode\b/,
    to: "lb_scheduler",
    kind: "control",
    label: "LB scheduler",
  },
  {
    name: "loadbalance_algorithm",
    regex: /\b(Wrr|Swrr|ConsistentHash|StickyTable|Candidate)\b/,
    to: "lb_algorithm",
    kind: "control",
    label: "LB algorithm",
  },
  {
    name: "candidate_filter",
    regex: /\bhealthy_candidates\b|\bcompiled_candidates\b|\btarget_sink\b|\broute_group\b/,
    to: "candidate_filter",
    kind: "control",
    label: "candidate filter",
  },
  {
    name: "flow_pin",
    regex: /\bflow_pins\b|\bapply_pin_with_hysteresis\b/,
    to: "flow_pin",
    kind: "control",
    label: "flow pin",
  },
  {
    name: "scheduler_feedback",
    regex: /\bon_observation\b|\bwire_scheduler_observer\b|\bfeedback\s*\(/,
    to: "scheduler_feedback",
    kind: "control",
    label: "feedback",
  },
  {
    name: "runtime_validation",
    regex: /\bsystemctl\b|\bExecStart\b|\bmetrics-snapshot\b|\bjournalctl\b/,
    to: "live_validation",
    kind: "runtime",
    label: "runtime readback",
  },
];

const pathContracts = [
  {
    focus: "mesh-peer-udp",
    id: "control_feedback_off_hot_path",
    kind: "control/backpressure",
    title: "AckNack repair feedback is queued off the demux hot path",
    invariant: "FamilyReorderState Gap/AckNack may enqueue bounded control intent, but demux/data delivery must not await packet_loop.flush.",
    stages: [
      stage("egress_repair_control_worker", "egress_demux", ["crates/mesh-bus-egress-mesh-peer-udp/src/demux.rs"], /\bspawn_repair_control_worker\s*\(/),
      stage("egress_repair_intent_enqueue", "egress_demux", ["crates/mesh-bus-egress-mesh-peer-udp/src/demux.rs"], /\brepair_tx\.try_send\s*\(/),
      stage("ingress_control_reply_worker", "ingress_mesh_peer", ["crates/mesh-bus-ingress-mesh-peer-udp/src/lib.rs"], /\bspawn_control_reply_worker\s*\(/),
      stage("ingress_ack_intent_enqueue", "ingress_mesh_peer", ["crates/mesh-bus-ingress-mesh-peer-udp/src/lib.rs"], /\bcontrol_reply_tx\.try_send\s*\(/),
    ],
  },
  {
    focus: "mesh-peer-udp",
    id: "mesh_peer_sender_control_data_split",
    kind: "control/data",
    title: "MeshPeer sender splits control and data before UdpPacketLoop",
    invariant: "MeshPeer adapters classify MeshFrame control/data into distinct bounded queues; only sender packetizer owns outbound flush timing.",
    stages: [
      stage("egress_sender_module", "mesh_peer_sender", ["crates/mesh-bus-egress-mesh-peer-udp/src/sender.rs"], /pub\(crate\) struct MeshPeerSender/),
      stage("ingress_sender_module", "mesh_peer_sender", ["crates/mesh-bus-ingress-mesh-peer-udp/src/sender.rs"], /pub\(crate\) struct MeshPeerIngressSender/),
      stage("control_queue", "mesh_peer_sender", ["crates/mesh-bus-egress-mesh-peer-udp/src/sender.rs", "crates/mesh-bus-ingress-mesh-peer-udp/src/sender.rs"], /\bcontrol_tx\b/),
      stage("data_queue", "mesh_peer_sender", ["crates/mesh-bus-egress-mesh-peer-udp/src/sender.rs", "crates/mesh-bus-ingress-mesh-peer-udp/src/sender.rs"], /\bdata_tx\b/),
      stage("data_microbatch_deadline", "mesh_peer_sender", ["crates/mesh-bus-egress-mesh-peer-udp/src/sender.rs", "crates/mesh-bus-ingress-mesh-peer-udp/src/sender.rs"], /DATA_FLUSH_MAX_DELAY/),
      stage("udp_loop_flush_owned_by_sender", "mesh_peer_sender", ["crates/mesh-bus-egress-mesh-peer-udp/src/sender.rs", "crates/mesh-bus-ingress-mesh-peer-udp/src/sender.rs"], /\.flush\s*\(\)\)/),
    ],
  },
  {
    focus: "mesh-peer-udp",
    id: "stream_open_control",
    kind: "control",
    title: "Stream open success is remote control truth",
    invariant: "connect() may report success only after matching StreamOpenAccepted(open_token), reject, or timeout.",
    stages: [
      stage("spawn_stream_demux", "egress_session", ["crates/mesh-bus-egress-mesh-peer-udp/src/lib.rs"], /\bspawn_stream_driver\s*\(/),
      stage("send_stream_open", "egress_session", ["crates/mesh-bus-egress-mesh-peer-udp/src/lib.rs"], /MeshFrame::StreamOpen\s*\(/),
      stage("wait_control_inbox", "egress_session", ["crates/mesh-bus-egress-mesh-peer-udp/src/lib.rs"], /\bcontrol_inbox\.recv\s*\(\)/),
      stage("token_guard", "egress_demux", ["crates/mesh-bus-egress-mesh-peer-udp/src/demux.rs"], /\bcontrol_result\s*\(|open_token:\s*frame_token/),
      stage("remote_accept", "ingress_mesh_peer", ["crates/mesh-bus-ingress-mesh-peer-udp/src/lib.rs"], /MeshFrame::StreamOpenAccepted/),
      stage("remote_reject", "ingress_mesh_peer", ["crates/mesh-bus-ingress-mesh-peer-udp/src/lib.rs"], /MeshFrame::StreamOpenReject/),
    ],
    order: [
      order("demux_before_stream_open_send", "crates/mesh-bus-egress-mesh-peer-udp/src/lib.rs", /\bspawn_stream_driver\s*\(/, /MeshFrame::StreamOpen\s*\(/),
    ],
  },
  {
    focus: "mesh-peer-udp",
    id: "stream_return_data",
    kind: "data",
    title: "Stream return bytes open once, reorder once, queue before EOF",
    invariant: "Inbound datagram is drained by the demux driver, opened by MeshSec once, routed through FamilyReorderState once, and data drains before close.",
    stages: [
      stage("drain_by_demux", "egress_demux", ["crates/mesh-bus-egress-mesh-peer-udp/src/demux.rs"], /\.drain_inbound\s*\(/),
      stage("meshsec_open_by_demux", "egress_demux", ["crates/mesh-bus-egress-mesh-peer-udp/src/demux.rs"], /\b(open_bytes|open_mesh_frame)\s*\(/),
      stage("decode_mesh_payload", "egress_demux", ["crates/mesh-bus-egress-mesh-peer-udp/src/demux.rs"], /\b(decode_event|decode_legacy_frame|decode_frame|decode_mesh_frame_clear)\b/),
      stage("family_push_once", "egress_demux", ["crates/mesh-bus-egress-mesh-peer-udp/src/demux.rs"], /\.push_package\s*\(/),
      stage("data_inbox_send", "egress_demux", ["crates/mesh-bus-egress-mesh-peer-udp/src/demux.rs"], /\bdata_tx\.try_send\s*\(/),
      stage("recv_data_before_event", "egress_session", ["crates/mesh-bus-egress-mesh-peer-udp/src/lib.rs"], /\bdata_inbox\.try_recv\s*\(/),
      stage("recv_event_after_data", "egress_session", ["crates/mesh-bus-egress-mesh-peer-udp/src/lib.rs"], /\bevent_inbox\.recv\s*\(\)/),
    ],
    order: [
      order("data_try_recv_before_event_select", "crates/mesh-bus-egress-mesh-peer-udp/src/lib.rs", /\bdata_inbox\.try_recv\s*\(/, /\bevent_inbox\.recv\s*\(\)/),
    ],
  },
  {
    focus: "mesh-peer-udp",
    id: "datagram_return_close",
    kind: "control/data",
    title: "Datagram return and remote close terminate the recv half",
    invariant: "DatagramReturn queues one return; DatagramClose ends the demux task and closes the inbox.",
    stages: [
      stage("spawn_datagram_demux", "egress_session", ["crates/mesh-bus-egress-mesh-peer-udp/src/lib.rs"], /\bspawn_datagram_driver\s*\(/),
      stage("route_datagram_return", "egress_demux", ["crates/mesh-bus-egress-mesh-peer-udp/src/demux.rs"], /MeshFrame::DatagramReturn/),
      stage("datagram_inbox_send", "egress_demux", ["crates/mesh-bus-egress-mesh-peer-udp/src/demux.rs"], /\bdatagram_tx\.try_send\s*\(/),
      stage("remote_datagram_close", "egress_demux", ["crates/mesh-bus-egress-mesh-peer-udp/src/demux.rs"], /MeshFrame::DatagramClose/),
      stageText("close_returns_from_driver", "egress_demux", ["crates/mesh-bus-egress-mesh-peer-udp/src/demux.rs"], /MeshFrame::DatagramClose[\s\S]{0,180}\breturn;/),
      stage("recv_from_inbox", "egress_session", ["crates/mesh-bus-egress-mesh-peer-udp/src/lib.rs"], /\bdatagram_inbox\.recv\s*\(\)\.await/),
    ],
  },
  {
    focus: "mesh-peer-udp",
    id: "backpressure_observability",
    kind: "backpressure",
    title: "Bounded queues surface pressure instead of growing silently",
    invariant: "Every bounded queue/full condition should be typed, counted, or close the relevant receiver.",
    stages: [
      stage("stream_queue_full_event", "egress_demux", ["crates/mesh-bus-egress-mesh-peer-udp/src/demux.rs"], /StreamEvent::QueueFull/),
      stage("datagram_queue_full_error", "egress_demux", ["crates/mesh-bus-egress-mesh-peer-udp/src/demux.rs"], /error_tx\.try_send\s*\(\s*DisconnectReason::QueueFull\s*\)/),
      stage("datagram_error_inbox", "egress_session", ["crates/mesh-bus-egress-mesh-peer-udp/src/lib.rs"], /error_inbox\.(try_recv|recv)\s*\(/),
      stage("disconnect_queue_full", "core_session", ["crates/mesh-bus-core/src/transport/session/types.rs"], /QueueFull/),
      stage("send_error_queue_full", "egress_session", ["crates/mesh-bus-egress-mesh-peer-udp/src/lib.rs"], /SendError::BufferFull\s*=>\s*DisconnectReason::QueueFull/),
      stage("ingress_pending_bound", "ingress_mesh_peer", ["crates/mesh-bus-ingress-mesh-peer-udp/src/lib.rs"], /pending_stream_data_max_bytes|StreamDataPending/),
      stage("runtime_drop_counter", "live_validation", ["tests/live-run2-pool-validation.mjs"], /native_queue_overflow_drop_total/),
    ],
  },
  {
    focus: "loadbalance",
    id: "lb_algorithm_owner",
    kind: "control",
    title: "Pure LB algorithms own candidate rows and local picker state",
    invariant: "mb-loadbalance owns weighted candidate rows, WRR/SWRR cursor state, stable hash projection, sticky table TTL/repick, and source lease rotate state; it owns no runtime health, dispatch, or sockets.",
    stages: [
      stage("candidate_row", "lb_algorithm", ["lib/mb-loadbalance/src/lib.rs"], /pub struct Candidate/),
      stage("wrr_cursor", "lb_algorithm", ["lib/mb-loadbalance/src/lib.rs"], /pub struct Wrr/),
      stage("consistent_hash", "lb_algorithm", ["lib/mb-loadbalance/src/lib.rs"], /pub struct ConsistentHash/),
      stage("sticky_table", "lb_algorithm", ["lib/mb-loadbalance/src/lib.rs"], /pub struct StickyTable/),
      stage("source_lease_rotate", "lb_algorithm", ["lib/mb-loadbalance/src/lib.rs"], /pub struct SourceLeaseRotate/),
      stage("algorithm_owner_tests", "lb_algorithm", ["lib/mb-loadbalance/tests/lb.rs"], /wrr_distributes_by_weight|consistent_hash_stable_for_same_key|source_lease_keeps_source_until_idle_timeout/),
    ],
  },
  {
    focus: "loadbalance",
    id: "lb_scheduler_plugin",
    kind: "control",
    title: "LoadBalanceScheduler maps RankContext plus candidates into ordered decision indices",
    invariant: "The scheduler chooses one candidate first and preserves remaining candidates as fallback order; source/target keys affect only modes that name them.",
    stages: [
      stage("scheduler_plugin_impl", "lb_scheduler", ["crates/mesh-bus-scheduler-loadbalance/src/lib.rs"], /impl SchedulerPlugin for LoadBalanceScheduler/),
      stage("weights_by_exit_id", "lb_scheduler", ["crates/mesh-bus-scheduler-loadbalance/src/lib.rs"], /with_weights/),
      stage("round_robin_mode", "lb_scheduler", ["crates/mesh-bus-scheduler-loadbalance/src/lib.rs"], /LoadBalanceMode::RoundRobin/),
      stage("consistent_hash_target_key", "lb_scheduler", ["crates/mesh-bus-scheduler-loadbalance/src/lib.rs"], /target_key_or_flow/),
      stage("sticky_source_target_key", "lb_scheduler", ["crates/mesh-bus-scheduler-loadbalance/src/lib.rs"], /fn sticky_key/),
      stage("source_lease_source_key", "lb_scheduler", ["crates/mesh-bus-scheduler-loadbalance/src/lib.rs"], /fn source_lease_key/),
      stage("ordered_decision", "lb_scheduler", ["crates/mesh-bus-scheduler-loadbalance/src/lib.rs"], /ScheduleDecision::ordered/),
      stage("scheduler_owner_tests", "lb_scheduler", ["crates/mesh-bus-scheduler-loadbalance/tests/loadbalance.rs"], /round_robin_rotates_first_candidate|consistent_hashing_is_stable_for_same_target_key|source_lease_rotate_pins_by_source_not_target/),
    ],
  },
  {
    focus: "loadbalance",
    id: "lb_runtime_dispatch_path",
    kind: "control/data",
    title: "Runtime config, candidate filtering, scheduler decision, and dispatch evidence stay separate",
    invariant: "Runtime builds scheduler weights from egress config; core filters candidates by capability, route_group, target_sink, and health before scheduling; dispatch records selected exit evidence after send.",
    stages: [
      stage("runtime_loadbalance_config", "runtime_assembly", ["crates/mesh-bus-runtime/src/config.rs"], /LoadBalance\s*\{/),
      stage("runtime_scheduler_build", "runtime_assembly", ["crates/mesh-bus-runtime/src/lib.rs"], /LoadBalanceScheduler::with_(sticky_ttl_ms|source_lease_rotate)/),
      stage("runtime_weight_projection", "runtime_assembly", ["crates/mesh-bus-runtime/src/lib.rs"], /fn egress_weights|\.with_weights\(weights\)/),
      stage("request_keys_to_frame", "core_session", ["crates/mesh-bus-core/src/transport/session/data_handle.rs"], /source_key\.clone_from|target_key\.clone_from/),
      stage("rank_context_from_frame", "core_session", ["crates/mesh-bus-core/src/transport/forwarding/data_handle.rs"], /impl From<&Frame> for RankContext/),
      stage("healthy_candidate_filter", "candidate_filter", ["crates/mesh-bus-core/src/kernel/dispatch.rs"], /fn healthy_candidates/),
      stage("scheduler_call", "kernel_dispatch", ["crates/mesh-bus-core/src/kernel/dispatch.rs"], /runtime\.scheduler\.schedule\(candidates, ctx\)/),
      stage("map_candidate_order", "kernel_dispatch", ["crates/mesh-bus-core/src/kernel/dispatch.rs"], /fn map_candidate_order/),
      stage("flow_pin_state", "flow_pin", ["crates/mesh-bus-core/src/kernel/dispatch.rs"], /flow_pins/),
      stage("dispatch_metric_record", "kernel_dispatch", ["crates/mesh-bus-core/src/kernel/dispatch_observation.rs"], /fn record_dispatch|update_exit_stats/),
    ],
    order: [
      order("filter_before_schedule", "crates/mesh-bus-core/src/kernel/dispatch.rs", /\bhealthy_candidates\s*\(/, /\bruntime\.scheduler\.schedule\(candidates, ctx\)/),
      order("schedule_before_dispatch", "crates/mesh-bus-core/src/kernel/dispatch.rs", /\blet decision = schedule_frame/, /\bdispatch_ordered\(frame/),
    ],
  },
  {
    focus: "loadbalance",
    id: "lb_live_distribution_evidence",
    kind: "runtime",
    title: "Live LB evidence must distinguish stable lease pinning from distribution coverage",
    invariant: "A repeated same-source live probe can prove source lease pinning and path health, but it cannot prove all exits distribute unless the probe varies the LB key, expires leases, or the mode is round-robin.",
    stages: [
      stage("run2_live_shape", "live_validation", ["tests/live-run2-pool-validation.mjs"], /run2_shape/),
      stage("moved_exits_projection", "live_validation", ["tests/live-run2-pool-validation.mjs"], /moved_exits/),
      stage("run2_source_lease_example", "runtime_assembly", ["config/run2-gateway.example.yaml"], /mode:\s*source-lease-rotate/),
      stage("socks5_source_key", "socks5_ingress", ["crates/mesh-bus-ingress-socks5/src/lib.rs"], /fn socks5_source_key/),
      stage("socks5_target_key", "socks5_ingress", ["crates/mesh-bus-ingress-socks5/src/lib.rs"], /fn socks5_target_key/),
    ],
  },
];

const sourceFiles = collectFiles(scanRoots).filter((file) => isInteresting(file));
const report = {
  kind: "mesh_bus.flowgraph.static_runtime_report",
  generated_at: new Date().toISOString(),
  focus: args.focus,
  roots: scanRoots,
  nodes: [],
  edges: [],
  findings: [],
  runtime: {},
  path_contracts: [],
};

for (const [id, data] of components) {
  report.nodes.push({ id, ...data });
}

for (const file of sourceFiles) {
  scanFile(file, report);
}

scanHeuristics(sourceFiles, report);
overlayRuntime(report);
analyzePathContracts(sourceFiles, report);
const matrix = buildDataControlMatrix(report);
validateDataControlMatrix(matrix);
dedupeReport(report);

fs.mkdirSync(outDir, { recursive: true });
const matrixFile = path.join(outDir, "data-control-matrix.json");
report.matrix = {
  artifact: path.relative(repo, matrixFile),
  families: matrix.families.length,
  layers: matrix.layers.length,
  flows: matrix.flows.length,
  cells: matrix.cells.length,
};
writeJson(path.join(outDir, "flowgraph-report.json"), report);
writeJson(matrixFile, matrix);
writeMermaid(path.join(outDir, "control-flow.mmd"), report, "control");
writeMermaid(path.join(outDir, "data-flow.mmd"), report, "data");
writeMermaid(path.join(outDir, "boundary-flow.mmd"), report, "boundary");
writeBoundaryEdgesJson(path.join(outDir, "boundary-edges.json"), report);
writePathContractsJson(path.join(outDir, "path-contracts.json"), report);
writePathContractsMarkdown(path.join(outDir, "path-contracts.md"), report);
writePathContractsMermaid(path.join(outDir, "path-contracts.mmd"), report);
writeMarkdown(path.join(outDir, "flowgraph-report.md"), report);

const summary = {
  report: path.relative(repo, path.join(outDir, "flowgraph-report.json")),
  markdown: path.relative(repo, path.join(outDir, "flowgraph-report.md")),
  mermaid: {
    control: path.relative(repo, path.join(outDir, "control-flow.mmd")),
    data: path.relative(repo, path.join(outDir, "data-flow.mmd")),
    boundary: path.relative(repo, path.join(outDir, "boundary-flow.mmd")),
    path_contracts: path.relative(repo, path.join(outDir, "path-contracts.mmd")),
  },
  boundary_edges: path.relative(repo, path.join(outDir, "boundary-edges.json")),
  matrix: path.relative(repo, matrixFile),
  path_contracts: report.path_contracts.map((contract) => ({
    id: contract.id,
    status: contract.status,
    missing: contract.stages.filter((stage) => stage.status !== "ok").map((stage) => stage.id),
  })),
  findings: report.findings.map((finding) => ({
    severity: finding.severity,
    title: finding.title,
    evidence: finding.evidence?.slice(0, 3) || [],
  })),
};
console.log(JSON.stringify(summary, null, 2));

function parseArgs(argv) {
  const out = {
    focus: "mesh-peer-udp",
    outDir: "artifacts/flowgraph",
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--focus") out.focus = needValue(argv, ++i, arg);
    else if (arg === "--out-dir") out.outDir = needValue(argv, ++i, arg);
    else if (arg === "--help" || arg === "-h") {
      console.log(`Usage: node tools/flowgraph.mjs [--focus mesh-peer-udp] [--out-dir artifacts/flowgraph]`);
      process.exit(0);
    } else {
      throw new Error(`unknown arg: ${arg}`);
    }
  }
  return out;
}

function needValue(argv, index, name) {
  const value = argv[index];
  if (!value || value.startsWith("--")) throw new Error(`${name} requires a value`);
  return value;
}

function stage(id, owner, paths, regex) {
  return { id, owner, paths, regex };
}

function stageText(id, owner, paths, regexText) {
  return { id, owner, paths, regexText };
}

function order(id, file, before, after) {
  return { id, file, before, after };
}

function collectFiles(roots) {
  const files = [];
  for (const root of roots) {
    const full = path.resolve(repo, root);
    if (!fs.existsSync(full)) continue;
    const stat = fs.statSync(full);
    if (stat.isFile()) {
      files.push(full);
      continue;
    }
    walk(full, files);
  }
  return files;
}

function walk(dir, files) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if ([".git", "target", "artifacts", ".backup", ".cleanup"].includes(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, files);
    else files.push(full);
  }
}

function isInteresting(file) {
  return /\.(rs|md|html|json|toml|mjs|yaml)$/.test(file);
}

function isCodeLike(rel) {
  return /\.(rs|json|toml|mjs|yaml)$/.test(rel);
}

function scanFile(file, out) {
  const rel = path.relative(repo, file);
  if (!isCodeLike(rel)) return;
  const owner = ownerForPath(rel);
  const lines = fs.readFileSync(file, "utf8").split(/\r?\n/);
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    if (isRustCommentOnly(rel, line)) continue;
    for (const rule of edgeRules) {
      if (!rule.regex.test(line)) continue;
      if (rule.sourceOnly && !rel.endsWith(".rs")) continue;
      addEdge(out, {
        from: owner,
        to: rule.to,
        kind: rule.kind,
        label: rule.label,
        evidence: `${rel}:${i + 1}`,
        token: rule.name,
      });
      if (rule.violation && !isAllowed(rule, owner, rel)) {
        if (rule.violationSourceOnly && !rel.endsWith(".rs")) continue;
        addFinding(out, {
          severity: rule.name === "restore_inbound_front" ? "critical" : "high",
          title: rule.violation,
          evidence: [`${rel}:${i + 1}`],
        });
      }
    }
  }
}

function scanHeuristics(files, out) {
  for (const file of files.filter((candidate) => candidate.endsWith(".rs"))) {
    const rel = path.relative(repo, file);
    const owner = ownerForPath(rel);
    const text = fs.readFileSync(file, "utf8");
    if (
      (owner === "egress_demux" || owner === "ingress_mesh_peer")
      && /FamilyPushOutcome::Gap[\s\S]{0,420}(retransmit_ack\s*\([^)]*\)\.await|send_mesh_frame\s*\([\s\S]{0,260}\)\s*\.await|packet_loop\.flush\s*\(\)\.await)/.test(text)
    ) {
      addFinding(out, {
        severity: "high",
        title: "AckNack feedback awaits send/flush in native receive hot path",
        evidence: [`${rel}:1`],
        detail: "Gap feedback must enqueue a bounded control intent; waiting on send/flush can stall data delivery and create CPU pressure.",
      });
    }
    const lines = fs.readFileSync(file, "utf8").split(/\r?\n/);
    for (let i = 0; i < lines.length; i += 1) {
      const window = lines.slice(i, i + 12).join("\n");
      if (isRustCommentOnly(rel, lines[i])) continue;
      if (/\bMeshFrame::DatagramClose\b/.test(lines[i]) && /\bbreak\s*;/.test(window)) {
        addFinding(out, {
          severity: "medium",
          title: "DatagramClose appears to break only the frame loop; verify the driver closes the receiver",
          evidence: [`${rel}:${i + 1}`],
          detail: "A break inside a per-frame loop can leave the outer receive loop alive, so recv_from may wait until timeout or local close.",
        });
      }
      if (owner === "egress_demux" && /\blet _ = control_tx\.try_send/.test(lines[i])) {
        addFinding(out, {
          severity: "low",
          title: "Stream open control inbox overflow is ignored",
          evidence: [`${rel}:${i + 1}`],
          detail: "The bound is large for one session, but control overflow would turn a real ACK into a timeout.",
        });
      }
      if (owner === "egress_demux" && /\blet _ = datagram_tx\.try_send/.test(lines[i])) {
        addFinding(out, {
          severity: "low",
          title: "Datagram return inbox overflow is silent",
          evidence: [`${rel}:${i + 1}`],
          detail: "A saturated datagram inbox currently drops a return without a typed last_error.",
        });
      }
      if (
        (owner === "egress_session" || owner === "egress_demux" || owner === "ingress_mesh_peer")
        && !rel.endsWith("/sender.rs")
        && /\bpacket_loop\.flush\s*\(\)\.await/.test(lines[i])
      ) {
        addFinding(out, {
          severity: "high",
          title: "MeshPeer outbound flush bypasses sender packetizer",
          evidence: [`${rel}:${i + 1}`],
          detail: "MeshPeer control/data separation requires outbound flush timing to live in sender.rs, not in handlers or demux hot paths.",
        });
      }
    }
  }
}

function analyzePathContracts(files, out) {
  const relFiles = files.map((file) => ({
    abs: file,
    rel: path.relative(repo, file),
    text: fs.readFileSync(file, "utf8"),
  }));
  out.path_contracts = pathContracts.filter((contract) => contractInFocus(contract, out.focus)).map((contract) => {
    const stages = contract.stages.map((item) => {
      const evidence = findStageEvidence(relFiles, item);
      return {
        id: item.id,
        owner: item.owner,
        status: evidence.length > 0 ? "ok" : "missing",
        evidence,
      };
    });
    const ordering = (contract.order || []).map((item) => checkOrder(relFiles, item));
    const missing = stages.filter((item) => item.status !== "ok");
    const failedOrder = ordering.filter((item) => item.status !== "ok");
    let status = missing.length === 0 && failedOrder.length === 0 ? "ok" : "failed";
    for (const item of missing) {
      addFinding(out, {
        severity: "high",
        title: `Path contract ${contract.id} missing stage: ${item.id}`,
        evidence: [],
      });
    }
    for (const item of failedOrder) {
      addFinding(out, {
        severity: "high",
        title: `Path contract ${contract.id} ordering failed: ${item.id}`,
        evidence: item.evidence,
        detail: item.detail,
      });
    }
    if (contract.id === "backpressure_observability") {
      const silent = out.findings.filter((finding) => /overflow is ignored|overflow is silent/.test(finding.title));
      if (silent.length > 0) {
        if (status === "ok") status = "warning";
        addFinding(out, {
          severity: "low",
          title: "Backpressure contract still has silent local queue edges",
          evidence: silent.flatMap((finding) => finding.evidence || []),
          detail: "The path is bounded, but not every local bounded queue has a typed receiver-visible failure.",
        });
      }
    }
    return {
      id: contract.id,
      kind: contract.kind,
      title: contract.title,
      invariant: contract.invariant,
      status,
      stages,
      ordering,
    };
  });
}

function contractInFocus(contract, focus) {
  return !contract.focus || contract.focus === focus;
}

function findStageEvidence(files, item) {
  const evidence = [];
  for (const file of files) {
    if (!item.paths.some((needle) => file.rel.includes(needle))) continue;
    if (item.regexText) {
      const match = file.text.match(item.regexText);
      if (!match) continue;
      const line = lineNumber(file.text, match.index || 0);
      evidence.push(`${file.rel}:${line}`);
      continue;
    }
    const lines = file.text.split(/\r?\n/);
    for (let i = 0; i < lines.length; i += 1) {
      if (item.regex.test(lines[i])) evidence.push(`${file.rel}:${i + 1}`);
    }
  }
  return evidence.slice(0, 8);
}

function checkOrder(files, item) {
  const file = files.find((candidate) => candidate.rel === item.file);
  if (!file) {
    return { id: item.id, status: "missing_file", evidence: [], detail: `missing ${item.file}` };
  }
  const lines = file.text.split(/\r?\n/);
  const before = firstLine(lines, item.before);
  const after = firstLine(lines, item.after);
  if (!before || !after) {
    return {
      id: item.id,
      status: "missing_marker",
      evidence: [`${file.rel}:${before || after || 1}`],
      detail: `before=${before || "missing"} after=${after || "missing"}`,
    };
  }
  if (before >= after) {
    return {
      id: item.id,
      status: "wrong_order",
      evidence: [`${file.rel}:${before}`, `${file.rel}:${after}`],
      detail: `expected ${before} < ${after}`,
    };
  }
  return {
    id: item.id,
    status: "ok",
    evidence: [`${file.rel}:${before}`, `${file.rel}:${after}`],
  };
}

function lineNumber(text, index) {
  return text.slice(0, index).split(/\r?\n/).length;
}

function firstLine(lines, regex) {
  const idx = lines.findIndex((line) => regex.test(line));
  return idx >= 0 ? idx + 1 : 0;
}

function overlayRuntime(out) {
  const poolArtifact = latestLiveArtifact("pool");
  const streamArtifact = latestLiveArtifact("stream");
  if (!poolArtifact && !streamArtifact) {
    out.runtime = { artifact: null, status: "missing" };
    addFinding(out, {
      severity: "info",
      title: "No live Run2 artifact found for runtime overlay",
      evidence: [],
    });
    return;
  }
  out.runtime = {
    artifact: null,
    status: "missing",
    pool: null,
    stream: null,
    max_sample_cpu: 0,
  };

  if (poolArtifact) {
    const data = JSON.parse(fs.readFileSync(poolArtifact, "utf8"));
    const validation = data.validation || data;
    const artifact = path.relative(repo, poolArtifact);
    const shape = validation.run2_shape || {};
    const delta = validation.delta || {};
    const moved = validation.moved_exits || [];
    const drops = runtimeDrops(delta);
    const pool = {
      artifact,
      status: validation.status,
      gateway: validation.gateway_ssh,
      socks5: validation.gateway_socks5,
      service: validation.gateway_service,
      dispatch_success_delta: delta.dispatch_success,
      drops,
      moved_exits: moved,
      mesh_peer_exits: shape.mesh_peer_exits || [],
      max_sample_cpu: maxRuntimeCpu(validation),
    };
    out.runtime.pool = pool;
    Object.assign(out.runtime, pool);
    addEdge(out, {
      from: "live_validation",
      to: "egress_session",
      kind: "runtime",
      label: "SOCKS5 probes through deployed gateway",
      evidence: artifact,
      token: "live_pool_artifact",
    });
    if (
      out.focus === "loadbalance"
      && shape.scheduler === "LoadBalance"
      && (shape.mesh_peer_exits || []).length > 1
      && moved.length === 1
    ) {
      addFinding(out, {
        severity: "medium",
        title: "Live LB probe proves one stable leased path, not distribution across the pool",
        evidence: [artifact],
        detail: `target=${validation.target || "-"} probes=${validation.probes || "-"} moved=${moved[0]?.exit_id || "-"} configured=${(shape.mesh_peer_exits || []).join(",")}`,
      });
    }
    addRuntimeHealthFindings(out, pool);
  }

  if (streamArtifact) {
    const validation = JSON.parse(fs.readFileSync(streamArtifact, "utf8"));
    const artifact = path.relative(repo, streamArtifact);
    const delta = validation.delta || {};
    const stream = {
      artifact,
      status: validation.status,
      target: validation.target,
      managed_origin: validation.managed_origin,
      dispatch_success_delta: delta.dispatch_success,
      drops: runtimeDrops(delta),
      moved_exits: validation.moved_exits || [],
      size_download: validation.curl?.size_download,
      time_total: validation.curl?.time_total,
      max_sample_cpu: maxRuntimeCpu(validation),
    };
    out.runtime.stream = stream;
    out.runtime.max_sample_cpu = Math.max(Number(out.runtime.max_sample_cpu || 0), Number(stream.max_sample_cpu || 0));
    if (!out.runtime.artifact) Object.assign(out.runtime, stream);
    addEdge(out, {
      from: "live_validation",
      to: "egress_session",
      kind: "runtime",
      label: "SOCKS5 long stream through deployed gateway",
      evidence: artifact,
      token: "live_stream_artifact",
    });
    addRuntimeHealthFindings(out, stream);
  }

  out.runtime.status = [out.runtime.pool?.status, out.runtime.stream?.status]
    .filter(Boolean)
    .includes("failed") ? "failed" : "ok";
}

function latestLiveArtifact(kind) {
  const dir = path.resolve(repo, "artifacts/live-acceptance");
  if (!fs.existsSync(dir)) return null;
  const prefix = kind === "stream" ? "run2-stream" : "run2-pool";
  const pattern = new RegExp(`^${prefix}-.+\\.json$`);
  const files = fs.readdirSync(dir)
    .filter((file) => pattern.test(file))
    .map((file) => path.join(dir, file))
    .sort();
  return files.at(-1) || null;
}

function runtimeDrops(delta) {
  return {
    dispatch_failure: delta.dispatch_failure,
    meshsec_drop_total: delta.meshsec_drop_total,
    meshsec_replay_drop_total: delta.meshsec_replay_drop_total,
    native_drop_total: delta.native_drop_total,
    native_queue_overflow_drop_total: delta.native_queue_overflow_drop_total,
  };
}

function addRuntimeHealthFindings(out, runtime) {
  if (runtime.status === "failed") {
    addFinding(out, {
      severity: "high",
      title: "Live Run2 validation artifact failed",
      evidence: [runtime.artifact],
    });
  }
  for (const [name, value] of Object.entries(runtime.drops || {})) {
    if (Number(value || 0) > 0) {
      addFinding(out, {
        severity: "high",
        title: `Runtime drop counter increased: ${name}`,
        evidence: [runtime.artifact],
      });
    }
  }
  if (Number(runtime.max_sample_cpu || 0) >= 25) {
    addFinding(out, {
      severity: "high",
      title: "Runtime CPU sample is elevated",
      evidence: [runtime.artifact],
      detail: `max_sample_cpu=${runtime.max_sample_cpu}`,
    });
  }
}

function maxRuntimeCpu(validation) {
  let max = 0;
  for (const sample of validation.samples || []) {
    for (const key of ["diagnostics_before", "diagnostics_after"]) {
      const process = sample[key]?.process || "";
      const parts = process.trim().split(/\s+/);
      if (parts.length >= 2) max = Math.max(max, Number(parts[1]) || 0);
    }
    const process = sample.process || "";
    const parts = process.trim().split(/\s+/);
    if (parts.length >= 2) max = Math.max(max, Number(parts[1]) || 0);
  }
  const after = validation.diagnostics?.after?.process || "";
  const parts = after.trim().split(/\s+/);
  if (parts.length >= 2) max = Math.max(max, Number(parts[1]) || 0);
  return max;
}

function ownerForPath(rel) {
  if (rel.includes("lib/mb-mesh-control/tests")) return "mesh_control_tests";
  if (rel.includes("lib/mb-mesh-control")) return "mesh_control";
  if (rel.includes("lib/mb-loadbalance")) return "lb_algorithm";
  if (rel.includes("crates/mesh-bus-scheduler-loadbalance")) return "lb_scheduler";
  if (rel.includes("crates/mesh-bus-runtime")) return "runtime_assembly";
  if (rel.includes("crates/mesh-bus-egress-mesh-peer-udp/src/demux.rs")) return "egress_demux";
  if (rel.includes("crates/mesh-bus-egress-mesh-peer-udp/src/sender.rs")) return "mesh_peer_sender";
  if (rel.includes("crates/mesh-bus-ingress-mesh-peer-udp/src/sender.rs")) return "mesh_peer_sender";
  if (rel.includes("crates/mesh-bus-egress-mesh-peer-udp")) return "egress_session";
  if (rel.includes("crates/mesh-bus-ingress-mesh-peer-udp")) return "ingress_mesh_peer";
  if (rel.includes("crates/mesh-bus-core/tests/udp_loop") || rel.includes("crates/mesh-bus-core/tests/boundary_guard")) return "core_udp_tests";
  if (rel.includes("crates/mesh-bus-bin/tests/throughput_transport.rs")) return "throughput_test";
  if (rel.includes("crates/mesh-bus-core/src/transport/udp_loop")) return "udp_loop";
  if (rel.includes("crates/mesh-bus-core/src/transport/session")) return "core_session";
  if (rel.includes("crates/mesh-bus-core/src/kernel")) return "kernel_dispatch";
  if (rel.includes("crates/mesh-bus-pipeline-hooks")) return "pipeline_hooks";
  if (rel.includes("crates/mesh-bus-runtime")) return "kernel_dispatch";
  if (rel.includes("lib/mb-proto-mesh/tests") || rel.includes("lib/mb-proto-mesh/src/meshsec")) return "meshsec_tests";
  if (rel.includes("lib/mb-proto-mesh")) return "mesh_codec";
  if (rel.includes("lib/mb-reorder/tests")) return "reorder_tests";
  if (rel.includes("lib/mb-reorder")) return "family_reorder";
  if (rel.includes("tests/live-run2") || rel.includes("deploy/run2")) return "live_validation";
  if (rel.includes("ingress-socks5")) return "socks5_ingress";
  return "kernel_dispatch";
}

function isAllowed(rule, owner, rel) {
  if (rel.includes("/tests/") || rel.endsWith("_tests.rs")) return true;
  if (!rule.allowedOwners) return false;
  return rule.allowedOwners.has(owner);
}

function isRustCommentOnly(rel, line) {
  return rel.endsWith(".rs") && /^\s*(\/\/|\/\*|\*)/.test(line);
}

function addEdge(out, edge) {
  if (edge.from === edge.to) return;
  out.edges.push(edge);
}

function addFinding(out, finding) {
  out.findings.push({ ...finding, evidence: finding.evidence || [] });
}

function buildDataControlMatrix(out) {
  const layerRows = out.nodes.map((node) => ({
    id: node.id,
    layer: normalizeLayerKind(node.layer),
    owner: node.id,
    pdu: node.label,
    pci: pciForOwner(node.id),
    sdu_boundary: sduBoundaryForOwner(node.id),
    forbidden_reads: forbiddenReadsForOwner(node.id),
  }));
  const layerIds = new Set(layerRows.map((row) => row.id));
  const flowRows = out.edges.map((edge, index) => ({
    id: flowIdForEdge(edge, index),
    kind: normalizeFlowKind(edge.kind),
    from_owner: edge.from,
    to_owner: edge.to,
    input_shape: edge.token || edge.label,
    output_shape: edge.label,
    legal_crossing: `${edge.from} -> ${edge.to}`,
    failure_shape: edge.kind === "boundary" ? "boundary violation finding" : "",
  }));
  const cellRows = out.edges.map((edge, index) => ({
    family_id: familyForOwner(edge.from, edge.to),
    layer_id: layerIds.has(edge.to) ? edge.to : edge.from,
    flow_id: flowIdForEdge(edge, index),
    owned_pci: [edge.token || edge.label],
    carried_sdu: carriedSduForEdge(edge),
    schema_ref: schemaRefForOwner(edge.to, edge.from),
    code_owner: edge.from,
    proof_gate: edge.evidence || "flowgraph static scan",
    invalid_state: invalidStatesForEdge(edge),
  }));
  return {
    kind: "mesh_bus.data_control_matrix",
    families: familyRows(),
    layers: layerRows,
    flows: flowRows,
    cells: cellRows,
  };
}

function validateDataControlMatrix(matrix) {
  const errors = [];
  if (matrix.kind !== "mesh_bus.data_control_matrix") errors.push("wrong matrix kind");
  for (const key of ["families", "layers", "flows", "cells"]) {
    if (!Array.isArray(matrix[key]) || matrix[key].length === 0) errors.push(`${key} must be non-empty`);
  }
  const familyIds = uniqueIds(matrix.families, "families", errors);
  const layerIds = uniqueIds(matrix.layers, "layers", errors);
  const flowIds = uniqueIds(matrix.flows, "flows", errors);
  const legalFamilyKinds = new Set(["tcp-family", "udp-family", "mesh-protocol-family", "socks5-family", "http-connect-family", "scheduler-family", "live-evidence-family"]);
  const legalLayerKinds = new Set(["L7", "L6", "L5", "L4", "substrate", "carrier", "verify"]);
  const legalFlowKinds = new Set(["data", "control", "evidence", "lifecycle", "backpressure"]);
  for (const family of matrix.families || []) {
    if (!legalFamilyKinds.has(family.kind)) errors.push(`invalid family kind ${family.kind}`);
  }
  for (const layer of matrix.layers || []) {
    if (!legalLayerKinds.has(layer.layer)) errors.push(`invalid layer kind ${layer.layer}`);
  }
  for (const flow of matrix.flows || []) {
    if (!legalFlowKinds.has(flow.kind)) errors.push(`invalid flow kind ${flow.kind}`);
  }
  for (const cell of matrix.cells || []) {
    if (!familyIds.has(cell.family_id)) errors.push(`cell references missing family ${cell.family_id}`);
    if (!layerIds.has(cell.layer_id)) errors.push(`cell references missing layer ${cell.layer_id}`);
    if (!flowIds.has(cell.flow_id)) errors.push(`cell references missing flow ${cell.flow_id}`);
    for (const key of ["schema_ref", "code_owner", "proof_gate", "carried_sdu"]) {
      if (!cell[key]) errors.push(`cell ${cell.flow_id || "?"} missing ${key}`);
    }
  }
  if ((matrix.cells || []).length !== (matrix.flows || []).length) {
    errors.push(`matrix cells must cover every flow: flows=${matrix.flows.length} cells=${matrix.cells.length}`);
  }
  if (errors.length > 0) {
    throw new Error(`data/control matrix validation failed:\n${errors.join("\n")}`);
  }
}

function uniqueIds(rows, label, errors) {
  const ids = new Set();
  for (const row of rows || []) {
    if (!row.id) {
      errors.push(`${label} row missing id`);
      continue;
    }
    if (!/^[A-Za-z0-9_.:-]+$/.test(row.id)) errors.push(`${label} id has illegal shape: ${row.id}`);
    if (ids.has(row.id)) errors.push(`${label} duplicate id ${row.id}`);
    ids.add(row.id);
  }
  return ids;
}

function familyRows() {
  return [
    { id: "tcp-family", kind: "tcp-family", owner: "TCP ingress/egress adapters", schema_ref: "crates/mesh-bus-ingress-tcp/schema.json" },
    { id: "udp-family", kind: "udp-family", owner: "UDP ingress/egress adapters", schema_ref: "crates/mesh-bus-ingress-udp/schema.json" },
    { id: "mesh-protocol-family", kind: "mesh-protocol-family", owner: "Mesh Protocol and MeshPeerUdp owners", schema_ref: "lib/mb-proto-mesh/schema.json" },
    { id: "socks5-family", kind: "socks5-family", owner: "SOCKS5 codec and adapters", schema_ref: "lib/mb-proto-socks5/schema.json" },
    { id: "http-connect-family", kind: "http-connect-family", owner: "HTTP CONNECT adapters", schema_ref: "lib/mb-proto-http-proxy/schema.json" },
    { id: "scheduler-family", kind: "scheduler-family", owner: "Scheduler algorithms and plugins", schema_ref: "crates/mesh-bus-scheduler-loadbalance/schema.json" },
    { id: "live-evidence-family", kind: "live-evidence-family", owner: "Root tests live evidence", schema_ref: "tests/schema.json" },
  ];
}

function normalizeLayerKind(layer) {
  const text = String(layer || "");
  if (text.includes("verify")) return "verify";
  if (text.includes("L7")) return "L7";
  if (text.includes("L6")) return "L6";
  if (text.includes("L5")) return "L5";
  if (text.includes("L4") || text.includes("scheduler")) return "L4";
  if (text.includes("runtime") || text.includes("control") || text.includes("observation")) return "carrier";
  return "carrier";
}

function normalizeFlowKind(kind) {
  if (kind === "runtime") return "evidence";
  if (kind === "boundary") return "control";
  if (kind === "backpressure") return "backpressure";
  if (kind === "data") return "data";
  return "control";
}

function familyForOwner(from, to) {
  const text = `${from} ${to}`;
  if (/live_validation/.test(text)) return "live-evidence-family";
  if (/socks5/.test(text)) return "socks5-family";
  if (/udp_loop/.test(text)) return "udp-family";
  if (/lb_|candidate_filter|flow_pin|scheduler_feedback|runtime_assembly/.test(text)) return "scheduler-family";
  if (/mesh_control|mesh|demux|reorder|session_inbox|queue_backpressure|core_session/.test(text)) return "mesh-protocol-family";
  return "mesh-protocol-family";
}

function schemaRefForOwner(owner, fallback) {
  const key = `${owner} ${fallback}`;
  if (/lb_algorithm/.test(key)) return "lib/mb-loadbalance/schema.json";
  if (/lb_scheduler/.test(key)) return "crates/mesh-bus-scheduler-loadbalance/schema.json";
  if (/socks5/.test(key)) return "lib/mb-proto-socks5/schema.json";
  if (/live_validation/.test(key)) return "tests/schema.json";
  if (/mesh_control/.test(key)) return "lib/mb-mesh-control/schema.json";
  if (/mesh_codec|meshsec/.test(key)) return "lib/mb-proto-mesh/schema.json";
  if (/family_reorder/.test(key)) return "lib/mb-reorder/schema.json";
  if (/core_session|session_inbox|queue_backpressure/.test(key)) return "crates/mesh-bus-core/src/transport/session/schema.json";
  if (/udp_loop/.test(key)) return "crates/mesh-bus-core/src/transport/forwarding/schema.json";
  return "crates/mesh-bus-core/schema.json";
}

function pciForOwner(owner) {
  if (owner === "live_validation") return ["runtime evidence artifact"];
  if (owner.startsWith("lb_")) return ["candidate rows", "source lease decision"];
  if (owner === "socks5_ingress") return ["source_key", "target_key", "SOCKS5 command"];
  if (owner === "mesh_control") return ["send budget", "in-flight packages", "loss timer", "AckNack repair decision"];
  if (owner.includes("demux")) return ["family reorder cursor", "session inbox routing"];
  if (owner.includes("mesh")) return ["MeshFrame", "MeshEvent", "MeshSec envelope"];
  if (owner === "udp_loop") return ["socket endpoint", "datagram boundary"];
  return ["owner-local PCI"];
}

function sduBoundaryForOwner(owner) {
  if (owner === "kernel_dispatch" || owner === "udp_loop") return "payload stays opaque below application owners";
  if (owner === "live_validation") return "artifact records evidence only, not runtime truth";
  return "carried SDU is opaque outside the named owner";
}

function forbiddenReadsForOwner(owner) {
  if (owner === "kernel_dispatch" || owner === "udp_loop" || owner.startsWith("lb_")) {
    return ["URL", "SNI", "HTTP method", "decrypted payload"];
  }
  return [];
}

function carriedSduForEdge(edge) {
  if (edge.kind === "data") return "opaque payload/data unit carried across the owner boundary";
  if (edge.kind === "runtime") return "runtime evidence artifact";
  if (edge.kind === "backpressure") return "bounded queue state and typed failure";
  return "control metadata only; payload stays opaque";
}

function invalidStatesForEdge(edge) {
  if (edge.token === "restore_inbound_front") return ["payload-aware L4 rewind"];
  if (edge.token === "loadbalance_algorithm") return ["scheduler bypasses algorithm owner data shape"];
  if (edge.token === "runtime_validation") return ["oral completion without systemd/readback evidence"];
  return [];
}

function flowIdForEdge(edge, index) {
  return `flow.${index}.${id(`${edge.kind}.${edge.from}.${edge.to}.${edge.token || edge.label}`).toLowerCase()}`;
}

function dedupeReport(out) {
  out.edges = uniqueBy(out.edges, (edge) => `${edge.from}|${edge.to}|${edge.kind}|${edge.label}|${edge.evidence}`);
  const merged = new Map();
  for (const finding of out.findings) {
    const key = `${finding.severity}|${finding.title}|${finding.detail || ""}`;
    const prev = merged.get(key);
    if (!prev) {
      merged.set(key, { ...finding, evidence: [...finding.evidence] });
    } else {
      prev.evidence.push(...finding.evidence);
    }
  }
  out.findings = [...merged.values()]
    .map((finding) => ({ ...finding, evidence: uniqueBy(finding.evidence, (x) => x).slice(0, 20) }))
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
}

function uniqueBy(items, keyFn) {
  const seen = new Set();
  const out = [];
  for (const item of items) {
    const key = keyFn(item);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(item);
  }
  return out;
}

function severityRank(severity) {
  return { critical: 0, high: 1, medium: 2, low: 3, info: 4 }[severity] ?? 9;
}

function writeJson(file, data) {
  fs.writeFileSync(file, `${JSON.stringify(data, null, 2)}\n`);
}

function writePathContractsJson(file, data) {
  writeJson(file, {
    kind: "mesh_bus.flowgraph.path_contracts",
    generated_at: data.generated_at,
    runtime: data.runtime,
    path_contracts: data.path_contracts,
  });
}

function writeBoundaryEdgesJson(file, data) {
  const edges = uniqueBy(data.edges, (edge) => `${edge.from}|${edge.to}|${edge.kind}|${edge.token || edge.label}`)
    .map((edge, index) => ({
      id: `edge.${index}.${id(`${edge.kind}.${edge.from}.${edge.to}.${edge.token || edge.label}`).toLowerCase()}`,
      from: edge.from,
      to: edge.to,
      edge: edge.kind,
      label: edge.label,
      flow: flowKindsForBoundaryEdge(edge),
      gate: edge.evidence || "flowgraph static scan",
    }));
  writeJson(file, {
    kind: "mesh_bus.flowgraph.boundary_edges",
    generated_at: data.generated_at,
    source: "tools/flowgraph.mjs",
    edges,
  });
}

function flowKindsForBoundaryEdge(edge) {
  if (edge.kind === "runtime") return ["evidence"];
  if (edge.kind === "backpressure") return ["backpressure", "evidence"];
  if (edge.kind === "boundary") return ["data", "control", "evidence"];
  return [edge.kind];
}

function writePathContractsMarkdown(file, data) {
  const lines = [
    "# Path Contracts",
    "",
    `Generated: ${data.generated_at}`,
    "",
  ];
  for (const contract of data.path_contracts) {
    lines.push(`## ${contract.id}`);
    lines.push("");
    lines.push(`- status: \`${contract.status}\``);
    lines.push(`- kind: \`${contract.kind}\``);
    lines.push(`- title: ${contract.title}`);
    lines.push(`- invariant: ${contract.invariant}`);
    lines.push("");
    lines.push("| stage | owner | status | evidence |");
    lines.push("|---|---|---|---|");
    for (const stage of contract.stages) {
      lines.push(`| ${stage.id} | ${stage.owner} | ${stage.status} | ${stage.evidence.map((x) => `\`${x}\``).join("<br>")} |`);
    }
    if (contract.ordering.length > 0) {
      lines.push("");
      lines.push("| order | status | evidence | detail |");
      lines.push("|---|---|---|---|");
      for (const item of contract.ordering) {
        lines.push(`| ${item.id} | ${item.status} | ${item.evidence.map((x) => `\`${x}\``).join("<br>")} | ${item.detail || ""} |`);
      }
    }
    lines.push("");
  }
  fs.writeFileSync(file, `${lines.join("\n")}\n`);
}

function writePathContractsMermaid(file, data) {
  const lines = ["flowchart TD"];
  for (const contract of data.path_contracts) {
    const cluster = id(`contract_${contract.id}`);
    lines.push(`  subgraph ${cluster}["${escapeLabel(contract.id)} (${contract.status})"]`);
    for (const stage of contract.stages) {
      const node = id(`${contract.id}_${stage.id}`);
      const label = `${stage.id}\\n${stage.owner}\\n${stage.status}`;
      lines.push(`    ${node}["${escapeLabel(label)}"]`);
    }
    for (let i = 0; i < contract.stages.length - 1; i += 1) {
      lines.push(`    ${id(`${contract.id}_${contract.stages[i].id}`)} --> ${id(`${contract.id}_${contract.stages[i + 1].id}`)}`);
    }
    lines.push("  end");
  }
  fs.writeFileSync(file, `${lines.join("\n")}\n`);
}

function writeMermaid(file, data, kind) {
  const edges = [...data.edges
    .filter((edge) => edge.kind === kind || (kind === "data" && edge.kind === "backpressure"))
    .filter((edge) => !isTestOwner(edge.from))
    .reduce((acc, edge) => {
      const key = `${edge.from}|${edge.to}|${edge.label}`;
      const current = acc.get(key) || { ...edge, count: 0 };
      current.count += 1;
      acc.set(key, current);
      return acc;
    }, new Map())
    .values()];
  const lines = ["flowchart LR"];
  for (const node of data.nodes) {
    lines.push(`  ${id(node.id)}["${escapeLabel(node.label)}"]`);
  }
  for (const edge of edges) {
    const label = edge.count > 1 ? `${edge.label} x${edge.count}` : edge.label;
    lines.push(`  ${id(edge.from)} -->|"${escapeLabel(label)}"| ${id(edge.to)}`);
  }
  fs.writeFileSync(file, `${lines.join("\n")}\n`);
}

function isTestOwner(owner) {
  return owner === "core_udp_tests"
    || owner === "throughput_test"
    || owner === "meshsec_tests"
    || owner === "reorder_tests";
}

function id(value) {
  return String(value).replace(/[^A-Za-z0-9_]/g, "_");
}

function escapeLabel(value) {
  return String(value).replace(/"/g, "'");
}

function writeMarkdown(file, data) {
  const lines = [
    "# Flowgraph Report",
    "",
    `Generated: ${data.generated_at}`,
    `Focus: ${data.focus}`,
    "",
    "## Runtime",
    "",
    data.runtime.artifact ? `- artifact: \`${data.runtime.artifact}\`` : "- artifact: none",
    data.runtime.pool?.artifact ? `- pool_artifact: \`${data.runtime.pool.artifact}\`` : "",
    data.runtime.stream?.artifact ? `- stream_artifact: \`${data.runtime.stream.artifact}\`` : "",
    data.runtime.status ? `- status: \`${data.runtime.status}\`` : "- status: unknown",
    data.runtime.dispatch_success_delta !== undefined ? `- dispatch_success_delta: \`${data.runtime.dispatch_success_delta}\`` : "",
    data.runtime.max_sample_cpu !== undefined ? `- max_sample_cpu: \`${data.runtime.max_sample_cpu}\`` : "",
    "",
    "## Findings",
    "",
  ].filter(Boolean);
  if (data.findings.length === 0) {
    lines.push("- none");
  } else {
    for (const finding of data.findings) {
      lines.push(`- ${finding.severity}: ${finding.title}`);
      if (finding.detail) lines.push(`  ${finding.detail}`);
      for (const evidence of finding.evidence || []) lines.push(`  evidence: \`${evidence}\``);
    }
  }
  lines.push("", "## Edge Counts", "");
  const counts = {};
  for (const edge of data.edges) counts[edge.kind] = (counts[edge.kind] || 0) + 1;
  for (const [kind, count] of Object.entries(counts).sort()) {
    lines.push(`- ${kind}: ${count}`);
  }
  fs.writeFileSync(file, `${lines.join("\n")}\n`);
}
