#!/usr/bin/env node
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const env = process.env;

if (process.argv.includes("--help") || process.argv.includes("-h")) {
  console.log(`Usage:
  MESH_BUS_OBSERVE_REMOTE_SSH=root@192.0.2.36 \\
  MESH_BUS_OBSERVE_REMOTE_OPERATOR=http://127.0.0.1:19081 \\
  node tests/live-observe-hooks-profile.mjs

Required:
  MESH_BUS_OBSERVE_REMOTE_SSH       SSH target for the running node.
  MESH_BUS_OBSERVE_REMOTE_OPERATOR  Operator API URL as seen from the remote node.

Optional:
  MESH_BUS_OBSERVE_ADMIN_BIN        Remote mesh-bus admin binary. Defaults to /opt/mesh-bus/bin/mesh-bus-run2.
  MESH_BUS_OBSERVE_SERVICE          systemd service name. Defaults to mesh-bus-run2.service.
  MESH_BUS_OBSERVE_PROBE            socks5-connect, http-connect, or mesh-peer. Defaults to socks5-connect.
  MESH_BUS_OBSERVE_TARGET           Probe target. Defaults to https://example.com.
  MESH_BUS_OBSERVE_ITERATIONS       Probe count. Defaults to 5.
  MESH_BUS_OBSERVE_INTERVAL_MS      Delay between probes. Defaults to 1000.
  MESH_BUS_ARTIFACT_DIR             Output directory. Defaults to artifacts/live-acceptance.
`);
  process.exit(0);
}

const remoteSsh =
  env.MESH_BUS_OBSERVE_REMOTE_SSH || env.MESH_BUS_RUN2_GATEWAY_SSH || env.MESH_BUS_REMOTE_SSH;
const remoteOperator =
  env.MESH_BUS_OBSERVE_REMOTE_OPERATOR ||
  env.MESH_BUS_RUN2_GATEWAY_OPERATOR ||
  env.MESH_BUS_REMOTE_OPERATOR;
const adminBin =
  env.MESH_BUS_OBSERVE_ADMIN_BIN ||
  env.MESH_BUS_RUN2_GATEWAY_ADMIN_BIN ||
  env.MESH_BUS_RUN2_GATEWAY_BIN ||
  "/opt/mesh-bus/bin/mesh-bus-run2";
const service = env.MESH_BUS_OBSERVE_SERVICE || env.MESH_BUS_RUN2_GATEWAY_SERVICE || "mesh-bus-run2.service";
const probe = env.MESH_BUS_OBSERVE_PROBE || "socks5-connect";
const target = env.MESH_BUS_OBSERVE_TARGET || env.MESH_BUS_RUN2_TARGET || "https://example.com";
const iterations = numberEnv("MESH_BUS_OBSERVE_ITERATIONS", 5);
const intervalMs = numberEnv("MESH_BUS_OBSERVE_INTERVAL_MS", 1000);
const artifactDir = env.MESH_BUS_ARTIFACT_DIR || "artifacts/live-acceptance";

if (!remoteSsh) dieEnv("MESH_BUS_OBSERVE_REMOTE_SSH");
if (!remoteOperator) dieEnv("MESH_BUS_OBSERVE_REMOTE_OPERATOR");
if (!["socks5-connect", "http-connect", "mesh-peer"].includes(probe)) {
  throw new Error(`MESH_BUS_OBSERVE_PROBE must be socks5-connect, http-connect, or mesh-peer; got ${probe}`);
}

const result = {
  kind: "mesh_bus.live_observe_hooks_profile",
  remote_ssh: remoteSsh,
  remote_operator: remoteOperator,
  admin_bin: adminBin,
  service,
  target,
  probe,
  iterations,
  interval_ms: intervalMs,
  samples: [],
};

try {
  result.host_before = await hostSnapshot("before");
  assertServiceActive(result.host_before, "before");
  result.status_before = await adminJson("status");
  result.metrics_before = await adminJson("metrics-snapshot");

  for (let i = 1; i <= iterations; i += 1) {
    const before = await adminJson("metrics-snapshot");
    const probeResult = await adminJson(`probe ${probe} --target ${q(target)}`);
    const after = await adminJson("metrics-snapshot");
    const sampleDelta = metricsDelta(before, after);
    const sample = {
      iteration: i,
      at: new Date().toISOString(),
      probe: probeResult,
      selected_exits: selectedExits(sampleDelta),
      dispatch_delta: {
        success: sampleDelta.dispatch_success,
        failure: sampleDelta.dispatch_failure,
      },
      drop_delta: {
        meshsec: sampleDelta.meshsec_drop_total,
        native: sampleDelta.native_drop_total,
      },
      metrics: after,
      host: await hostSample(`probe-${i}`),
    };
    result.samples.push(sample);
    assertProbeSample(sample);
    if (i < iterations) await sleep(intervalMs);
  }

  result.metrics_after = await adminJson("metrics-snapshot");
  result.delta = metricsDelta(result.metrics_before, result.metrics_after);
  result.moved_exits = Object.entries(result.delta.exits)
    .filter(([, delta]) => Number(delta.send_count || 0) > 0 || Number(delta.success_count || 0) > 0)
    .map(([exit_id, delta]) => ({ exit_id, ...delta }));
  result.host_after = await hostSnapshot("after");
  result.assertions = assertions(result);
  assertFinal(result);
  result.status = "ok";
  result.artifact = writeArtifact(result);
  result.report = writeMarkdownReport(result);
  console.log(JSON.stringify(result, null, 2));
} catch (err) {
  result.status = "failed";
  result.error = err.message;
  try {
    result.host_failure = await hostSnapshot("failure");
  } catch (snapshotErr) {
    result.host_failure_error = snapshotErr.message;
  }
  result.artifact = writeArtifact(result);
  result.report = writeMarkdownReport(result);
  console.error(`LIVE_OBSERVE_HOOKS_PROFILE failed: ${err.message}`);
  console.error(`artifact=${result.artifact}`);
  console.error(`report=${result.report}`);
  if (err.stdout) console.error(err.stdout.trim());
  if (err.stderr) console.error(err.stderr.trim());
  process.exitCode = 1;
}

function dieEnv(name) {
  throw new Error(`${name} is required`);
}

function numberEnv(name, fallback) {
  const raw = env[name];
  if (!raw) return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value) || value <= 0) throw new Error(`${name} must be a positive number`);
  return Math.floor(value);
}

async function adminJson(command) {
  const out = await ssh(`${q(adminBin)} admin ${command} --api ${q(remoteOperator)}`);
  try {
    return JSON.parse(out);
  } catch (err) {
    err.message = `remote admin ${command} returned non-json: ${err.message}`;
    err.stdout = out;
    throw err;
  }
}

async function hostSnapshot(label) {
  const systemdText = await sshText(
    `systemctl show ${q(service)} --no-pager ` +
      "-p ActiveState -p SubState -p MainPID -p ExecMainPID -p NRestarts -p ActiveEnterTimestamp -p ExecStart",
  );
  const systemd = parseKeyValues(systemdText);
  const mainPid = nonZero(systemd.MainPID || systemd.ExecMainPID);
  return {
    label,
    at: new Date().toISOString(),
    systemd,
    process: mainPid ? parseProcess(await sshText(`ps -p ${q(mainPid)} -o pid,ppid,pcpu,pmem,rss,vsz,nlwp,etime,stat,comm --no-headers || true`)) : null,
    fd_count: mainPid ? Number((await sshText(`ls /proc/${q(mainPid)}/fd 2>/dev/null | wc -l || true`)).trim() || 0) : null,
    sockets: await sshText("ss -tanup 2>/dev/null | grep -E '(mesh-bus|:1908|:1909|:2080|:1080|:909)' || true"),
  };
}

async function hostSample(label) {
  const systemdText = await sshText(
    `systemctl show ${q(service)} --no-pager -p ActiveState -p SubState -p MainPID -p ExecMainPID -p NRestarts`,
  );
  const systemd = parseKeyValues(systemdText);
  const mainPid = nonZero(systemd.MainPID || systemd.ExecMainPID);
  return {
    label,
    at: new Date().toISOString(),
    systemd,
    process: mainPid ? parseProcess(await sshText(`ps -p ${q(mainPid)} -o pid,pcpu,pmem,rss,nlwp,etime,stat,comm --no-headers || true`)) : null,
    fd_count: mainPid ? Number((await sshText(`ls /proc/${q(mainPid)}/fd 2>/dev/null | wc -l || true`)).trim() || 0) : null,
  };
}

function assertServiceActive(snapshot, label) {
  const active = snapshot.systemd?.ActiveState;
  if (active !== "active") throw new Error(`${service} not active ${label}: ${active || "unknown"}`);
}

function assertProbeSample(sample) {
  if (sample.probe?.kind !== "operator.probe_result") {
    throw new Error(`probe ${sample.iteration} did not return operator.probe_result`);
  }
  if (!sample.probe.ok) {
    throw new Error(`probe ${sample.iteration} failed: ${sample.probe.close_reason || "unknown"}`);
  }
  if (Number(sample.probe.dispatch_success_after || 0) <= Number(sample.probe.dispatch_success_before || 0)) {
    throw new Error(`probe ${sample.iteration} did not move dispatch_success through Operator probe`);
  }
  if (Number(sample.dispatch_delta.failure || 0) !== 0) {
    throw new Error(`probe ${sample.iteration} produced dispatch failure delta ${sample.dispatch_delta.failure}`);
  }
  if (Number(sample.drop_delta.meshsec || 0) !== 0 || Number(sample.drop_delta.native || 0) !== 0) {
    throw new Error(
      `probe ${sample.iteration} produced drop delta meshsec=${sample.drop_delta.meshsec} native=${sample.drop_delta.native}`,
    );
  }
}

function assertions(data) {
  return {
    observer_projection_moved:
      Number(data.delta?.dispatch_success || 0) > 0 ||
      data.moved_exits.some((exit) => Number(exit.success_count || 0) > 0 || Number(exit.send_count || 0) > 0),
    probe_used_operator_api: data.samples.every((sample) => sample.probe?.kind === "operator.probe_result"),
    no_dispatch_failure_delta: Number(data.delta?.dispatch_failure || 0) === 0,
    no_meshsec_drop_delta: Number(data.delta?.meshsec_drop_total || 0) === 0,
    no_native_drop_delta: Number(data.delta?.native_drop_total || 0) === 0,
  };
}

function assertFinal(data) {
  for (const [name, ok] of Object.entries(data.assertions)) {
    if (ok !== true) throw new Error(`assertion failed: ${name}`);
  }
}

function metricsDelta(before, after) {
  const out = {
    dispatch_success: deltaNumber(before, after, "dispatch_success"),
    dispatch_failure: deltaNumber(before, after, "dispatch_failure"),
    meshsec_drop_total: deltaNumber(before, after, "meshsec_drop_total"),
    meshsec_replay_drop_total: deltaNumber(before, after, "meshsec_replay_drop_total"),
    native_drop_total: deltaNumber(before, after, "native_drop_total"),
    native_queue_overflow_drop_total: deltaNumber(before, after, "native_queue_overflow_drop_total"),
    datagram_send_total: deltaNumber(before, after, "datagram_send_total"),
    datagram_failure_total: deltaNumber(before, after, "datagram_failure_total"),
    exits: {},
  };
  const beforeExits = new Map((before.exits || []).map((exit) => [exit.exit_id, exit]));
  for (const exit of after.exits || []) {
    const prev = beforeExits.get(exit.exit_id) || {};
    out.exits[exit.exit_id] = {
      send_count: Number(exit.send_count || 0) - Number(prev.send_count || 0),
      success_count: Number(exit.success_count || 0) - Number(prev.success_count || 0),
      failure_count: Number(exit.failure_count || 0) - Number(prev.failure_count || 0),
      payload_bytes_total: Number(exit.payload_bytes_total || 0) - Number(prev.payload_bytes_total || 0),
    };
  }
  return out;
}

function deltaNumber(before, after, key) {
  return Number(after?.[key] || 0) - Number(before?.[key] || 0);
}

function selectedExits(delta) {
  return Object.entries(delta.exits)
    .filter(([, values]) => Number(values.send_count || 0) > 0 || Number(values.success_count || 0) > 0)
    .map(([exitId]) => exitId);
}

function parseKeyValues(text) {
  const out = {};
  for (const line of String(text).split(/\r?\n/)) {
    const idx = line.indexOf("=");
    if (idx <= 0) continue;
    out[line.slice(0, idx)] = line.slice(idx + 1);
  }
  return out;
}

function parseProcess(text) {
  const parts = String(text).trim().split(/\s+/);
  if (parts.length < 7) return { raw: String(text).trim() };
  const [pid, ppidOrCpu, pcpuOrPmem, pmemOrRss, rssOrNlwp, vszOrEtime, nlwpOrStat, ...rest] = parts;
  if (parts.length >= 10) {
    const [pidText, ppid, pcpu, pmem, rss, vsz, nlwp, etime, stat, comm] = parts;
    return {
      pid: Number(pidText),
      ppid: Number(ppid),
      pcpu: Number(pcpu),
      pmem: Number(pmem),
      rss_kb: Number(rss),
      vsz_kb: Number(vsz),
      threads: Number(nlwp),
      etime,
      stat,
      comm,
    };
  }
  return {
    pid: Number(pid),
    pcpu: Number(ppidOrCpu),
    pmem: Number(pcpuOrPmem),
    rss_kb: Number(pmemOrRss),
    threads: Number(rssOrNlwp),
    etime: vszOrEtime,
    stat: nlwpOrStat,
    comm: rest[0] || "",
  };
}

function nonZero(value) {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? String(n) : null;
}

function writeArtifact(data) {
  fs.mkdirSync(artifactDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\..+/, "Z");
  const file = path.join(artifactDir, `observe-hooks-profile-${stamp}.json`);
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
  return file;
}

function writeMarkdownReport(data) {
  fs.mkdirSync(artifactDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\..+/, "Z");
  const file = path.join(artifactDir, `observe-hooks-profile-${stamp}.md`);
  const lines = [
    "# Observe Hooks Profile",
    "",
    `status: ${data.status || "unknown"}`,
    `remote: ${data.remote_ssh}`,
    `operator: ${data.remote_operator}`,
    `service: ${data.service}`,
    `probe: ${data.probe}`,
    `target: ${data.target}`,
    "",
    "## Observer Delta",
    "",
    `dispatch_success: ${data.delta?.dispatch_success ?? "-"}`,
    `dispatch_failure: ${data.delta?.dispatch_failure ?? "-"}`,
    `meshsec_drop_total: ${data.delta?.meshsec_drop_total ?? "-"}`,
    `native_drop_total: ${data.delta?.native_drop_total ?? "-"}`,
    "",
    "## Selected Exits",
    "",
    ...(data.moved_exits || []).map(
      (exit) =>
        `- ${exit.exit_id}: send=${exit.send_count || 0} success=${exit.success_count || 0} failure=${exit.failure_count || 0}`,
    ),
    "",
    "## Assertions",
    "",
    ...Object.entries(data.assertions || {}).map(([name, ok]) => `- ${name}: ${ok}`),
    "",
  ];
  fs.writeFileSync(file, lines.join("\n"));
  return file;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function ssh(command) {
  return run("ssh", [remoteSsh, command]);
}

async function sshText(command) {
  return ssh(command);
}

function run(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString("utf8");
    });
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

function q(value) {
  return `'${String(value).replaceAll("'", "'\\''")}'`;
}
