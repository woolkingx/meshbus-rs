#!/usr/bin/env node
import { spawn } from "node:child_process";
import dgram from "node:dgram";
import fs from "node:fs";
import path from "node:path";

const env = process.env;
const remoteHost = required("MESH_BUS_REMOTE_HOST");
const remoteSocks5 = required("MESH_BUS_REMOTE_SOCKS5");
const remoteOperator = required("MESH_BUS_REMOTE_OPERATOR");
const remoteSsh = required("MESH_BUS_REMOTE_SSH");
const remoteService = env.MESH_BUS_REMOTE_SERVICE || "mesh-bus.service";
const remoteBin = env.MESH_BUS_REMOTE_BIN || "/opt/mesh-bus/bin/mesh-bus";
const remoteAdminBin = env.MESH_BUS_REMOTE_ADMIN_BIN || remoteBin;
const httpTarget = env.MESH_BUS_LIVE_HTTP_TARGET || "https://example.com";
const dnsName = env.MESH_BUS_LIVE_DNS_NAME || "example.com";
const httpProxy = env.MESH_BUS_REMOTE_HTTP_PROXY || "";
const udpClient = env.MESH_BUS_REMOTE_UDP_CLIENT || "";
const meshUdpPort = Number(env.MESH_BUS_REMOTE_MESH_UDP_PORT || "0");
const captureInterface = env.MESH_BUS_CAPTURE_INTERFACE || "any";
const captureSeconds = Number(env.MESH_BUS_CAPTURE_SECONDS || "8");
const meshsecProbeCommand = env.MESH_BUS_MESHSEC_PROBE_COMMAND || "";

const result = {
  kind: "mesh_bus.live_mvp_production_acceptance",
  remote_host: remoteHost,
  remote_service: remoteService,
  remote_bin: remoteBin,
  remote_admin_bin: remoteAdminBin,
  http_target: httpTarget,
  dns_name: dnsName,
  probes: [],
  partial_live_acceptance: false,
};

try {
  await assertRemoteServiceActive();
  const status = await remoteAdminJson("status");
  result.status = summarizeStatus(status);
  const before = await remoteAdminJson("metrics-snapshot");

  await socks5HttpsProbe();
  await optionalHttpConnectProbe();
  await optionalUdpDnsProbe();
  await optionalMeshSecCaptureProbe();
  await optionalClearFailClosedProbe();
  await journalAuditProbe();

  const after = await remoteAdminJson("metrics-snapshot");
  assertMetricsDelta(before, after);
  result.metrics_delta = {
    dispatch_success: after.dispatch_success - before.dispatch_success,
    dispatch_failure: after.dispatch_failure - before.dispatch_failure,
    stream_egress_success_delta: streamEgressSuccess(after) - streamEgressSuccess(before),
  };

  console.log(JSON.stringify(result, null, 2));
} catch (err) {
  console.error(`LIVE_MVP_PRODUCTION_ACCEPTANCE failed: ${err.message}`);
  if (err.stdout) console.error(err.stdout.trim());
  if (err.stderr) console.error(err.stderr.trim());
  process.exitCode = 1;
}

function required(name) {
  const value = env[name];
  if (!value) die(`${name} is required`);
  return value;
}

async function assertRemoteServiceActive() {
  const active = (await ssh(`systemctl is-active ${shellQuote(remoteService)}`)).trim();
  if (active !== "active") die(`${remoteService} is not active: ${active}`);
  result.probes.push({ name: "systemd_active", status: "ok" });
}

async function remoteAdminJson(command) {
  const out = await ssh(`${shellQuote(remoteAdminBin)} admin ${command} --api ${shellQuote(remoteOperator)}`);
  try {
    return JSON.parse(out);
  } catch (err) {
    err.message = `remote admin ${command} returned non-json: ${err.message}`;
    err.stdout = out;
    throw err;
  }
}

async function socks5HttpsProbe() {
  const out = await run("curl", [
    "--socks5-hostname",
    remoteSocks5,
    "-sS",
    "-o",
    "/dev/null",
    "-w",
    "http_code=%{http_code} remote_ip=%{remote_ip} time_total=%{time_total}\\n",
    httpTarget,
  ]);
  const parsed = parseCurlWriteOut(out);
  if (parsed.http_code !== "200") die(`socks5_https expected http_code=200 got ${out.trim()}`);
  result.probes.push({ name: "socks5_https", status: "ok", ...parsed });
}

async function optionalHttpConnectProbe() {
  if (!httpProxy) {
    console.log("SKIP http_connect missing MESH_BUS_REMOTE_HTTP_PROXY");
    result.partial_live_acceptance = true;
    result.probes.push({ name: "http_connect", status: "skip", reason: "missing MESH_BUS_REMOTE_HTTP_PROXY" });
    return;
  }
  const out = await run("curl", [
    "-x",
    `http://${httpProxy}`,
    "-sS",
    "-o",
    "/dev/null",
    "-w",
    "http_code=%{http_code} remote_ip=%{remote_ip} time_total=%{time_total}\\n",
    httpTarget,
  ]);
  const parsed = parseCurlWriteOut(out);
  if (parsed.http_code !== "200") die(`http_connect expected http_code=200 got ${out.trim()}`);
  result.probes.push({ name: "http_connect", status: "ok", ...parsed });
}

async function optionalUdpDnsProbe() {
  if (!udpClient) {
    console.log("SKIP udp_dns missing MESH_BUS_REMOTE_UDP_CLIENT");
    result.partial_live_acceptance = true;
    result.probes.push({ name: "udp_dns", status: "skip", reason: "missing MESH_BUS_REMOTE_UDP_CLIENT" });
    return;
  }
  const out = await runShell(udpClient, { MESH_BUS_LIVE_DNS_NAME: dnsName });
  result.probes.push({ name: "udp_dns", status: "ok", output: out.trim().split("\n").slice(-5) });
}

async function optionalMeshSecCaptureProbe() {
  if (!meshUdpPort) {
    result.probes.push({ name: "meshsec_capture", status: "skip", reason: "missing MESH_BUS_REMOTE_MESH_UDP_PORT" });
    result.partial_live_acceptance = true;
    return;
  }
  if (!meshsecProbeCommand) {
    result.probes.push({ name: "meshsec_capture", status: "skip", reason: "missing MESH_BUS_MESHSEC_PROBE_COMMAND" });
    result.partial_live_acceptance = true;
    return;
  }

  const remotePcap = `/tmp/mesh-bus-live-${Date.now()}.pcap`;
  const capture = startRemoteCapture(remotePcap);
  await sleep(1_000);
  try {
    await runShell(meshsecProbeCommand);
  } finally {
    await capture;
  }
  const pcap = await readRemoteCapture(remotePcap);
  assertNoForbiddenWireMarkers(pcap);
  const localDir = path.resolve(env.MESH_BUS_ARTIFACT_DIR || "artifacts/live-acceptance");
  fs.mkdirSync(localDir, { recursive: true });
  const localPcap = path.join(localDir, path.basename(remotePcap));
  fs.writeFileSync(localPcap, pcap);
  result.probes.push({ name: "meshsec_capture", status: "ok", bytes: pcap.length, artifact: localPcap });
}

async function optionalClearFailClosedProbe() {
  if (!meshUdpPort) {
    result.probes.push({ name: "clear_fail_closed", status: "skip", reason: "missing MESH_BUS_REMOTE_MESH_UDP_PORT" });
    result.partial_live_acceptance = true;
    return;
  }
  const before = await remoteAdminJson("metrics-snapshot");
  await sendClearUdpProbe(remoteHost, meshUdpPort);
  await sleep(500);
  const after = await remoteAdminJson("metrics-snapshot");
  if (after.dispatch_success !== before.dispatch_success) {
    die(`clear UDP probe incremented dispatch_success: before=${before.dispatch_success} after=${after.dispatch_success}`);
  }
  if (after.flows !== before.flows) {
    die(`clear UDP probe changed flows: before=${before.flows} after=${after.flows}`);
  }
  result.probes.push({ name: "clear_fail_closed", status: "ok" });
}

async function journalAuditProbe() {
  const recent = await ssh(`journalctl -u ${shellQuote(remoteService)} -n 200 --no-pager`);
  const activeSince = (await ssh(`systemctl show ${shellQuote(remoteService)} -p ActiveEnterTimestamp --value`)).trim();
  const startup = await ssh(`journalctl -u ${shellQuote(remoteService)} --since ${shellQuote(activeSince)} --no-pager`);

  const startupRequired = [
    "mesh_bus_starting",
    "config_fingerprint",
    "startup_ingress",
    "startup_egress",
  ];
  const recentRequired = [
    "connect_open",
    "flow_opened",
    "connect_close",
    "close_reason",
  ];
  const missingStartup = startupRequired.filter((needle) => !startup.includes(needle));
  if (missingStartup.length) die(`journal audit missing startup label(s): ${missingStartup.join(", ")}`);
  const missingRecent = recentRequired.filter((needle) => !recent.includes(needle));
  if (missingRecent.length) die(`journal audit missing recent label(s): ${missingRecent.join(", ")}`);

  const forbidden = [
    "static_key_hex",
    "MESH_BUS_MESHSEC_KEY_HEX",
    "password=",
  ];
  const combined = `${startup}\n${recent}`;
  const leaked = forbidden.filter((needle) => combined.includes(needle));
  if (leaked.length) die(`journal audit found forbidden label(s): ${leaked.join(", ")}`);

  result.probes.push({ name: "journal_audit", status: "ok", recent_lines_checked: 200, active_since: activeSince });
}

async function startRemoteCapture(remotePcap) {
  const check = await ssh("command -v tcpdump || true");
  if (!check.trim()) die("tcpdump is required on the remote host for meshsec_capture");
  const command = [
    "set -e",
    `rm -f ${shellQuote(remotePcap)}`,
    `timeout ${Number.isFinite(captureSeconds) ? captureSeconds : 8} tcpdump -U -i ${shellQuote(captureInterface)} -s 0 -w ${shellQuote(remotePcap)} udp port ${meshUdpPort} >/tmp/mesh-bus-live-capture.log 2>&1 & echo $!`,
  ].join("; ");
  const pid = (await ssh(command)).trim();
  return (async () => {
    await sleep((Number.isFinite(captureSeconds) ? captureSeconds : 8) * 1_000 + 500);
    await ssh(`wait ${shellQuote(pid)} || true`);
  })();
}

async function readRemoteCapture(remotePcap) {
  const encoded = await ssh(`test -s ${shellQuote(remotePcap)} && base64 -w0 ${shellQuote(remotePcap)} || true`);
  if (!encoded.trim()) die("meshsec_capture produced no packets; provide MESH_BUS_MESHSEC_PROBE_COMMAND that uses MeshPeerUdp");
  await ssh(`rm -f ${shellQuote(remotePcap)}`);
  return Buffer.from(encoded.trim(), "base64");
}

function assertNoForbiddenWireMarkers(buffer) {
  const haystack = buffer.toString("latin1");
  const forbidden = [
    "MeshFrame",
    "StreamOpen",
    "StreamData",
    "DatagramData",
    "route_group",
    "example.com",
    "static_key_hex",
  ];
  const found = forbidden.filter((marker) => haystack.includes(marker));
  if (found.length) die(`meshsec_capture exposed forbidden marker(s): ${found.join(", ")}`);
}

function sendClearUdpProbe(host, port) {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket("udp4");
    const payload = Buffer.from("MeshFrame StreamOpen example.com route_group static_key_hex");
    socket.on("error", (err) => {
      socket.close();
      reject(err);
    });
    socket.send(payload, port, host, (err) => {
      socket.close();
      if (err) reject(err);
      else resolve();
    });
  });
}

function assertMetricsDelta(before, after) {
  if (!Number.isFinite(before.dispatch_success) || !Number.isFinite(after.dispatch_success)) {
    die("operator metrics missing dispatch_success");
  }
  if (!Number.isFinite(before.dispatch_failure) || !Number.isFinite(after.dispatch_failure)) {
    die("operator metrics missing dispatch_failure");
  }
  if (after.dispatch_success <= before.dispatch_success) {
    die(`dispatch_success did not increment: before=${before.dispatch_success} after=${after.dispatch_success}`);
  }
  if (after.dispatch_failure !== before.dispatch_failure) {
    die(`dispatch_failure changed: before=${before.dispatch_failure} after=${after.dispatch_failure}`);
  }
  const streamDelta = streamEgressSuccess(after) - streamEgressSuccess(before);
  if (streamDelta < 1) {
    die(`no stream egress success_count incremented: delta=${streamDelta}`);
  }
}

function streamEgressSuccess(snapshot) {
  return (snapshot.exits || [])
    .filter((exit) => exit.supports_stream)
    .reduce((sum, exit) => sum + Number(exit.success_count || 0), 0);
}

function summarizeStatus(response) {
  const status = response.status || response;
  return {
    node_id: status.node_id,
    scheduler: status.scheduler,
    metrics: status.metrics,
    counts: status.counts,
  };
}

function parseCurlWriteOut(out) {
  const fields = {};
  for (const token of out.trim().split(/\s+/)) {
    const idx = token.indexOf("=");
    if (idx > 0) fields[token.slice(0, idx)] = token.slice(idx + 1);
  }
  return fields;
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
        resolve(stdout);
        return;
      }
      const err = new Error(`${command} exited code=${code} signal=${signal}`);
      err.stdout = stdout;
      err.stderr = stderr;
      reject(err);
    });
  });
}

function runShell(command, extraEnv = {}) {
  return run("bash", ["-lc", command], extraEnv);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function shellQuote(value) {
  return `'${String(value).replaceAll("'", "'\\''")}'`;
}

function die(message) {
  throw new Error(message);
}
