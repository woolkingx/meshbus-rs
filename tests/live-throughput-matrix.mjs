#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { spawn } from "node:child_process";

const env = process.env;
const remoteSsh = required("MESH_BUS_REMOTE_SSH");
const remoteSocks5 = required("MESH_BUS_REMOTE_SOCKS5");
const remoteOperator = env.MESH_BUS_REMOTE_OPERATOR || "http://127.0.0.1:19080";
const httpTarget = env.MESH_BUS_LIVE_HTTP_TARGET || "https://example.com";
const output = env.MESH_BUS_THROUGHPUT_OUTPUT || "artifacts/live-acceptance/throughput-before.json";
const cargoTargetDir = env.CARGO_TARGET_DIR || "target/live-throughput";

const matrix = {
  kind: "mesh_bus.live_throughput_matrix",
  created_at: new Date().toISOString(),
  host: (await run("uname", ["-a"])).trim(),
  kernel: (await run("uname", ["-r"])).trim(),
  binary_sha256: await localBinarySha(),
  remote: await remoteContext(),
  sysctl: await localSysctl(),
  rows: [],
};

try {
  matrix.rows.push(await remoteSocks5HttpsRow());
  matrix.rows.push(await remoteOperatorMetricsRow());
  matrix.rows.push(await localProductTopologyReleaseRow());
  matrix.rows.push(await transportMatrixReleaseRow());

  fs.mkdirSync(path.dirname(output), { recursive: true });
  fs.writeFileSync(output, `${JSON.stringify(matrix, null, 2)}\n`);
  console.log(JSON.stringify(matrix, null, 2));
  console.log(`WROTE ${output}`);
} catch (err) {
  console.error(`LIVE_THROUGHPUT_MATRIX failed: ${err.message}`);
  if (err.stdout) console.error(err.stdout.trim());
  if (err.stderr) console.error(err.stderr.trim());
  process.exitCode = 1;
}

function required(name) {
  const value = env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

async function remoteSocks5HttpsRow() {
  const samples = [];
  for (let i = 0; i < 3; i += 1) {
    const out = await run("curl", [
      "--socks5-hostname",
      remoteSocks5,
      "-sS",
      "-o",
      "/dev/null",
      "-w",
      "http_code=%{http_code} size_download=%{size_download} time_total=%{time_total}\\n",
      httpTarget,
    ]);
    const parsed = parseFields(out);
    if (parsed.http_code !== "200") throw new Error(`remote_socks5_https got ${out.trim()}`);
    samples.push({ bytes: Number(parsed.size_download || 0), seconds: Number(parsed.time_total || 0) });
  }
  const p50 = percentile(samples.map((s) => s.seconds * 1000), 0.5);
  const p95 = percentile(samples.map((s) => s.seconds * 1000), 0.95);
  const totalBytes = samples.reduce((n, s) => n + s.bytes, 0);
  const totalSeconds = samples.reduce((n, s) => n + s.seconds, 0);
  return {
    path: "remote_socks5_https",
    transport: "tcp_stream",
    meshsec: true,
    gso: "not_applicable",
    mib_per_sec: mibPerSec(totalBytes, totalSeconds),
    p50_ms: round(p50),
    p95_ms: round(p95),
    samples,
    notes: "Small HTTPS object through deployed remote SOCKS5; latency-oriented row, not bulk transfer ceiling.",
  };
}

async function remoteOperatorMetricsRow() {
  const samples = [];
  for (let i = 0; i < 3; i += 1) {
    const start = performance.now();
    const out = await ssh(`/opt/mesh-bus/bin/mesh-bus admin metrics-snapshot --api ${shellQuote(remoteOperator)}`);
    const elapsed = performance.now() - start;
    JSON.parse(out);
    samples.push(elapsed);
  }
  return {
    path: "remote_operator_metrics",
    transport: "ssh_local_operator_http",
    meshsec: false,
    gso: "not_applicable",
    mib_per_sec: 0,
    p50_ms: round(percentile(samples, 0.5)),
    p95_ms: round(percentile(samples, 0.95)),
    samples_ms: samples.map(round),
    notes: "Operator snapshot overhead through SSH plus remote loopback Operator API.",
  };
}

async function localProductTopologyReleaseRow() {
  const start = performance.now();
  const out = await run("cargo", [
    "test",
    "-p",
    "mesh-bus-bin",
    "--test",
    "product_topology_fixture_runner",
    "--release",
    "--",
    "--nocapture",
  ], {
    CARGO_TARGET_DIR: cargoTargetDir,
    MESH_BUS_TOPOLOGY_FIXTURE: "mesh_peer_secure_udp_two_node_datagram_e2e",
  });
  return {
    path: "local_product_topology_release",
    transport: "local_process_fixture",
    meshsec: true,
    gso: "test_dependent",
    mib_per_sec: 0,
    p50_ms: round(performance.now() - start),
    p95_ms: round(performance.now() - start),
    notes: lastInterestingLines(out, /test result|running topology fixture|FAILED|ok/),
  };
}

async function transportMatrixReleaseRow() {
  const start = performance.now();
  const out = await run("cargo", [
    "test",
    "-p",
    "mesh-bus-bin",
    "--test",
    "throughput_transport",
    "--release",
    "--",
    "--ignored",
    "--nocapture",
    "--test-threads=1",
  ], {
    CARGO_TARGET_DIR: cargoTargetDir,
    MESH_BUS_TRANSPORT_BENCH: "1",
    MESH_BUS_TRANSPORT_BENCH_SECS: env.MESH_BUS_TRANSPORT_BENCH_SECS || "1",
  });
  const rows = [...out.matchAll(/THROUGHPUT_TRANSPORT_([A-Z0-9_]+)_MIB_PER_SEC\s+([0-9.]+)(.*)/g)]
    .map((m) => ({ label: m[1], mib_per_sec: Number(m[2]), raw: m[0] }));
  return {
    path: "transport_matrix_release",
    transport: "udp_packet_loop",
    meshsec: false,
    gso: "observed_in_raw_rows",
    mib_per_sec: rows.length ? round(rows.reduce((sum, row) => sum + row.mib_per_sec, 0) / rows.length) : 0,
    p50_ms: round(performance.now() - start),
    p95_ms: round(performance.now() - start),
    rows,
    notes: "Release ignored throughput_transport matrix with one-second rows.",
  };
}

async function localBinarySha() {
  if (!fs.existsSync("target/release/mesh-bus")) return "missing target/release/mesh-bus";
  return (await run("sha256sum", ["target/release/mesh-bus"])).trim().split(/\s+/)[0];
}

async function remoteContext() {
  const out = await ssh("uname -a; ss -s; sha256sum /opt/mesh-bus/bin/mesh-bus");
  return out.trim().split("\n");
}

async function localSysctl() {
  const keys = ["net.core.rmem_max", "net.core.wmem_max", "net.ipv4.tcp_congestion_control"];
  const sysctl = ["/sbin/sysctl", "/usr/sbin/sysctl", "sysctl"].find((candidate) => {
    try {
      return candidate.includes("/") ? fs.existsSync(candidate) : true;
    } catch {
      return false;
    }
  }) || "sysctl";
  const out = await run(sysctl, keys).catch((err) => err.stdout || err.message);
  return out.trim().split("\n");
}

function parseFields(out) {
  const fields = {};
  for (const token of out.trim().split(/\s+/)) {
    const idx = token.indexOf("=");
    if (idx > 0) fields[token.slice(0, idx)] = token.slice(idx + 1);
  }
  return fields;
}

function percentile(values, p) {
  const sorted = [...values].sort((a, b) => a - b);
  if (!sorted.length) return 0;
  return sorted[Math.min(sorted.length - 1, Math.floor((sorted.length - 1) * p))];
}

function mibPerSec(bytes, seconds) {
  if (!seconds) return 0;
  return round(bytes / 1024 / 1024 / seconds);
}

function round(value) {
  return Math.round(Number(value) * 100) / 100;
}

function lastInterestingLines(out, pattern) {
  return out.split("\n").filter((line) => pattern.test(line)).slice(-20);
}

async function ssh(command) {
  return run("ssh", [remoteSsh, command]);
}

function run(command, args, extraEnv = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      env: { ...process.env, ...extraEnv },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk.toString("utf8"); });
    child.stderr.on("data", (chunk) => { stderr += chunk.toString("utf8"); });
    child.on("error", reject);
    child.on("close", (code, signal) => {
      if (code === 0) {
        resolve(`${stdout}${stderr}`);
        return;
      }
      const err = new Error(`${command} exited code=${code} signal=${signal}`);
      err.stdout = stdout;
      err.stderr = stderr;
      reject(err);
    });
  });
}

function shellQuote(value) {
  return `'${String(value).replaceAll("'", "'\\''")}'`;
}
