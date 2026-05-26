#!/usr/bin/env node
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const env = process.env;

if (process.argv.includes("--help") || process.argv.includes("-h")) {
  console.log(`Usage:
  MESH_BUS_PROFILE_REMOTE_SSH=root@192.0.2.36 \\
  MESH_BUS_PROFILE_REMOTE_OPERATOR=http://127.0.0.1:19081 \\
  node tests/live-observe-syscall-profile.mjs

Required:
  MESH_BUS_PROFILE_REMOTE_SSH       SSH target for the running node.
  MESH_BUS_PROFILE_REMOTE_OPERATOR  Operator API URL as seen from the remote node.

Optional:
  MESH_BUS_PROFILE_ADMIN_BIN        Remote mesh-bus admin binary. Defaults to /opt/mesh-bus/bin/mesh-bus-run2.
  MESH_BUS_PROFILE_SERVICE          systemd service name. Defaults to mesh-bus-run2.service.
  MESH_BUS_PROFILE_PROBE            socks5-connect, http-connect, or mesh-peer. Defaults to socks5-connect.
  MESH_BUS_PROFILE_TARGET           Probe target. Defaults to https://example.com.
  MESH_BUS_PROFILE_STRACE_SECONDS   Seconds per syscall phase. Defaults to 8.
  MESH_BUS_PROFILE_ACTIVE_PROBES    Operator probes during the active phase. Defaults to 3.
  MESH_BUS_PROFILE_MAX_MMAP_PER_SEC Max mmap or munmap calls per second. Defaults to 500.
  MESH_BUS_ARTIFACT_DIR             Output directory. Defaults to artifacts/live-acceptance.
`);
  process.exit(0);
}

const remoteSsh =
  env.MESH_BUS_PROFILE_REMOTE_SSH ||
  env.MESH_BUS_OBSERVE_REMOTE_SSH ||
  env.MESH_BUS_RUN2_GATEWAY_SSH ||
  env.MESH_BUS_REMOTE_SSH;
const remoteOperator =
  env.MESH_BUS_PROFILE_REMOTE_OPERATOR ||
  env.MESH_BUS_OBSERVE_REMOTE_OPERATOR ||
  env.MESH_BUS_RUN2_GATEWAY_OPERATOR ||
  env.MESH_BUS_REMOTE_OPERATOR;
const adminBin =
  env.MESH_BUS_PROFILE_ADMIN_BIN ||
  env.MESH_BUS_OBSERVE_ADMIN_BIN ||
  env.MESH_BUS_RUN2_GATEWAY_ADMIN_BIN ||
  env.MESH_BUS_RUN2_GATEWAY_BIN ||
  "/opt/mesh-bus/bin/mesh-bus-run2";
const service = env.MESH_BUS_PROFILE_SERVICE || env.MESH_BUS_OBSERVE_SERVICE || "mesh-bus-run2.service";
const probe = env.MESH_BUS_PROFILE_PROBE || env.MESH_BUS_OBSERVE_PROBE || "socks5-connect";
const target = env.MESH_BUS_PROFILE_TARGET || env.MESH_BUS_OBSERVE_TARGET || "https://example.com";
const straceSeconds = numberEnv("MESH_BUS_PROFILE_STRACE_SECONDS", 8);
const activeProbes = numberEnv("MESH_BUS_PROFILE_ACTIVE_PROBES", 3);
const maxMmapPerSec = numberEnv("MESH_BUS_PROFILE_MAX_MMAP_PER_SEC", 500);
const artifactDir = env.MESH_BUS_ARTIFACT_DIR || "artifacts/live-acceptance";

if (!remoteSsh) dieEnv("MESH_BUS_PROFILE_REMOTE_SSH");
if (!remoteOperator) dieEnv("MESH_BUS_PROFILE_REMOTE_OPERATOR");
if (!["socks5-connect", "http-connect", "mesh-peer"].includes(probe)) {
  throw new Error(`MESH_BUS_PROFILE_PROBE must be socks5-connect, http-connect, or mesh-peer; got ${probe}`);
}

const result = {
  kind: "mesh_bus.live_observe_syscall_profile",
  remote_ssh: remoteSsh,
  remote_operator: remoteOperator,
  admin_bin: adminBin,
  service,
  target,
  probe,
  strace_seconds: straceSeconds,
  active_probes: activeProbes,
  thresholds: {
    max_mmap_per_sec: maxMmapPerSec,
  },
  phases: [],
};

try {
  result.host_before = await hostSnapshot("before");
  assertServiceActive(result.host_before, "before");
  result.status_before = await adminJson("status");
  result.metrics_before = await adminJson("metrics-snapshot");

  result.phases.push(await profilePhase("idle", async () => []));
  result.phases.push(
    await profilePhase("active_probe", async () => {
      const probes = [];
      for (let i = 1; i <= activeProbes; i += 1) {
        probes.push(await adminJson(`probe ${probe} --target ${q(target)}`));
      }
      return probes;
    }),
  );

  result.metrics_after = await adminJson("metrics-snapshot");
  result.delta = metricsDelta(result.metrics_before, result.metrics_after);
  result.assertions = assertions(result);
  assertFinal(result);
  result.host_after = await hostSnapshot("after");
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
  console.error(`LIVE_OBSERVE_SYSCALL_PROFILE failed: ${err.message}`);
  console.error(`artifact=${result.artifact}`);
  console.error(`report=${result.report}`);
  if (err.stdout) console.error(err.stdout.trim());
  if (err.stderr) console.error(err.stderr.trim());
  process.exitCode = 1;
}

async function profilePhase(label, trafficFn) {
  const metricsBefore = await adminJson("metrics-snapshot");
  const hostBefore = await hostSample(`${label}-before`);
  const profilePromise = syscallProfile(label);
  await sleep(500);
  const probes = await trafficFn();
  const syscall = await profilePromise;
  const metricsAfter = await adminJson("metrics-snapshot");
  const delta = metricsDelta(metricsBefore, metricsAfter);
  const phase = {
    label,
    at: new Date().toISOString(),
    host_before: hostBefore,
    host_after: await hostSample(`${label}-after`),
    metrics_before: metricsBefore,
    metrics_after: metricsAfter,
    delta,
    probes,
    syscall,
    selected_exits: selectedExits(delta),
  };
  assertPhase(phase);
  return phase;
}

async function syscallProfile(label) {
  const script =
    `pid=$(systemctl show ${q(service)} -p MainPID --value); ` +
    `echo PROFILE_LABEL=${q(label)}; echo PID=$pid; ` +
    `timeout ${straceSeconds} strace -f -p "$pid" -c 2>&1 || true`;
  const raw = await ssh(script);
  const calls = parseStraceSummary(raw);
  const rates = {};
  for (const [name, entry] of Object.entries(calls)) {
    rates[name] = Number((entry.calls / straceSeconds).toFixed(3));
  }
  return {
    tool: "strace -f -c",
    seconds: straceSeconds,
    raw,
    calls,
    rates_per_sec: rates,
  };
}

function assertPhase(phase) {
  if (!phase.syscall || Object.keys(phase.syscall.calls || {}).length === 0) {
    throw new Error(`phase ${phase.label} did not capture syscall summary`);
  }
  const mmapRate = Number(phase.syscall.rates_per_sec.mmap || 0);
  const munmapRate = Number(phase.syscall.rates_per_sec.munmap || 0);
  if (mmapRate > maxMmapPerSec || munmapRate > maxMmapPerSec) {
    throw new Error(
      `phase ${phase.label} mmap churn too high: mmap/s=${mmapRate} munmap/s=${munmapRate} max=${maxMmapPerSec}`,
    );
  }
  if (Number(phase.delta.dispatch_failure || 0) !== 0) {
    throw new Error(`phase ${phase.label} dispatch failure delta ${phase.delta.dispatch_failure}`);
  }
  if (
    Number(phase.delta.meshsec_drop_total || 0) !== 0 ||
    Number(phase.delta.native_drop_total || 0) !== 0 ||
    Number(phase.delta.datagram_failure_total || 0) !== 0
  ) {
    throw new Error(
      `phase ${phase.label} drop/failure delta meshsec=${phase.delta.meshsec_drop_total} native=${phase.delta.native_drop_total} datagram=${phase.delta.datagram_failure_total}`,
    );
  }
  for (const [idx, probeResult] of (phase.probes || []).entries()) {
    if (probeResult?.kind !== "operator.probe_result" || probeResult.ok !== true) {
      throw new Error(`phase ${phase.label} probe ${idx + 1} failed`);
    }
  }
}

function assertions(data) {
  const phases = data.phases || [];
  return {
    service_active: data.host_before?.systemd?.ActiveState === "active",
    syscall_profiles_captured: phases.every((phase) => Object.keys(phase.syscall?.calls || {}).length > 0),
    no_mmap_churn: phases.every((phase) => {
      const rates = phase.syscall?.rates_per_sec || {};
      return Number(rates.mmap || 0) <= maxMmapPerSec && Number(rates.munmap || 0) <= maxMmapPerSec;
    }),
    no_dispatch_failure_delta: phases.every((phase) => Number(phase.delta?.dispatch_failure || 0) === 0),
    no_drop_delta: phases.every(
      (phase) =>
        Number(phase.delta?.meshsec_drop_total || 0) === 0 &&
        Number(phase.delta?.native_drop_total || 0) === 0 &&
        Number(phase.delta?.datagram_failure_total || 0) === 0,
    ),
    active_probe_moved: phases
      .filter((phase) => phase.label === "active_probe")
      .every((phase) => Number(phase.delta?.dispatch_success || 0) >= activeProbes),
  };
}

function assertFinal(data) {
  for (const [name, ok] of Object.entries(data.assertions)) {
    if (ok !== true) throw new Error(`assertion failed: ${name}`);
  }
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
    threads: mainPid ? await sshText(`ps -L -p ${q(mainPid)} -o pid,tid,psr,pcpu,stat,comm,wchan:32 --no-headers || true`) : "",
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
    threads: mainPid ? await sshText(`ps -L -p ${q(mainPid)} -o pid,tid,psr,pcpu,stat,comm,wchan:32 --no-headers || true`) : "",
    fd_count: mainPid ? Number((await sshText(`ls /proc/${q(mainPid)}/fd 2>/dev/null | wc -l || true`)).trim() || 0) : null,
  };
}

function assertServiceActive(snapshot, label) {
  const active = snapshot.systemd?.ActiveState;
  if (active !== "active") throw new Error(`${service} not active ${label}: ${active || "unknown"}`);
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

function selectedExits(delta) {
  return Object.entries(delta.exits)
    .filter(([, values]) => Number(values.send_count || 0) > 0 || Number(values.success_count || 0) > 0)
    .map(([exitId]) => exitId);
}

function parseStraceSummary(raw) {
  const calls = {};
  for (const line of String(raw).split(/\r?\n/)) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 5) continue;
    if (!/^\d+(\.\d+)?$/.test(parts[0])) continue;
    const syscall = parts[parts.length - 1];
    const callCount = Number(parts[3]);
    const maybeErrors = parts.length >= 6 ? Number(parts[4]) : 0;
    if (!Number.isFinite(callCount)) continue;
    calls[syscall] = {
      calls: callCount,
      errors: Number.isFinite(maybeErrors) ? maybeErrors : 0,
      seconds: Number(parts[1]),
      usec_per_call: Number(parts[2]),
      percent_time: Number(parts[0]),
    };
  }
  return calls;
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

function deltaNumber(before, after, key) {
  return Number(after?.[key] || 0) - Number(before?.[key] || 0);
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

function nonZero(value) {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? String(n) : null;
}

function writeArtifact(data) {
  fs.mkdirSync(artifactDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\..+/, "Z");
  const file = path.join(artifactDir, `observe-syscall-profile-${stamp}.json`);
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
  return file;
}

function writeMarkdownReport(data) {
  fs.mkdirSync(artifactDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\..+/, "Z");
  const file = path.join(artifactDir, `observe-syscall-profile-${stamp}.md`);
  const lines = [
    "# Observe Syscall Profile",
    "",
    `status: ${data.status || "unknown"}`,
    `remote: ${data.remote_ssh}`,
    `operator: ${data.remote_operator}`,
    `service: ${data.service}`,
    `probe: ${data.probe}`,
    `target: ${data.target}`,
    `max_mmap_per_sec: ${data.thresholds?.max_mmap_per_sec ?? "-"}`,
    "",
    "## Phases",
    "",
    ...phaseReportLines(data.phases || []),
    "",
    "## Assertions",
    "",
    ...Object.entries(data.assertions || {}).map(([name, ok]) => `- ${name}: ${ok}`),
    "",
  ];
  fs.writeFileSync(file, lines.join("\n"));
  return file;
}

function phaseReportLines(phases) {
  const lines = [];
  for (const phase of phases) {
    const rates = phase.syscall?.rates_per_sec || {};
    lines.push(
      `- ${phase.label}: dispatch_success_delta=${phase.delta?.dispatch_success ?? "-"} ` +
        `dispatch_failure_delta=${phase.delta?.dispatch_failure ?? "-"} ` +
        `mmap/s=${rates.mmap ?? 0} munmap/s=${rates.munmap ?? 0} ` +
        `recvmmsg/s=${rates.recvmmsg ?? 0} futex/s=${rates.futex ?? 0}`,
    );
  }
  return lines;
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
