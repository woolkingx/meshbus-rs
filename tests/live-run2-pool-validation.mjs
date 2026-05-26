#!/usr/bin/env node
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const env = process.env;
const gatewaySsh = required("MESH_BUS_RUN2_GATEWAY_SSH");
const gatewaySocks5 = required("MESH_BUS_RUN2_GATEWAY_SOCKS5");
const gatewayOperator = required("MESH_BUS_RUN2_GATEWAY_OPERATOR");
const gatewayService = env.MESH_BUS_RUN2_GATEWAY_SERVICE || "mesh-bus-run2.service";
const gatewayBin = env.MESH_BUS_RUN2_GATEWAY_BIN || "/opt/mesh-bus/bin/mesh-bus-run2";
const gatewayAdminBin = env.MESH_BUS_RUN2_GATEWAY_ADMIN_BIN || gatewayBin;
const gatewayConfig = env.MESH_BUS_RUN2_GATEWAY_CONFIG || "/etc/mesh-bus/run2.yaml";
const target = env.MESH_BUS_RUN2_TARGET || "https://example.com";
const probes = numberEnv("MESH_BUS_RUN2_PROBES", 10);
const curlMaxTimeSeconds = numberEnv("MESH_BUS_RUN2_CURL_MAX_TIME_SECONDS", 30);
const journalLines = numberEnv("MESH_BUS_RUN2_JOURNAL_LINES", 160);
const artifactDir = env.MESH_BUS_ARTIFACT_DIR || "artifacts/live-acceptance";
const allowBackgroundTraffic = boolEnv("MESH_BUS_RUN2_ALLOW_BACKGROUND_TRAFFIC");
const allowServiceMutation = boolEnv("MESH_BUS_RUN2_ALLOW_SERVICE_MUTATION");
const failoverPeerSsh = env.MESH_BUS_RUN2_FAILOVER_PEER_SSH;
const failoverExit = env.MESH_BUS_RUN2_FAILOVER_EXIT;
const failoverAllowedFailures = numberEnv("MESH_BUS_RUN2_FAILOVER_ALLOWED_FAILURES", 2);
const failoverStoppedExitSendLimit = numberEnv("MESH_BUS_RUN2_FAILOVER_STOPPED_EXIT_SEND_LIMIT", 2);

const result = {
  kind: "mesh_bus.live_run2_pool_validation",
  gateway_ssh: gatewaySsh,
  gateway_socks5: gatewaySocks5,
  gateway_operator: gatewayOperator,
  gateway_service: gatewayService,
  gateway_bin: gatewayBin,
  gateway_admin_bin: gatewayAdminBin,
  gateway_config: gatewayConfig,
  target,
  probes,
  curl_max_time_seconds: curlMaxTimeSeconds,
  journal_lines: journalLines,
  allow_background_traffic: allowBackgroundTraffic,
  failover: {
    requested: Boolean(failoverPeerSsh || failoverExit),
    peer_ssh: failoverPeerSsh || null,
    exit_id: failoverExit || null,
    service_mutation_allowed: allowServiceMutation,
    allowed_failures: failoverAllowedFailures,
    stopped_exit_send_limit: failoverStoppedExitSendLimit,
  },
  samples: [],
  diagnostics: {},
};

try {
  result.diagnostics.before = await assertGatewayService("before");
  result.status_before = await gatewayAdminJson("status");
  result.metrics_before = await gatewayAdminJson("metrics-snapshot");
  assertRun2Shape(result.status_before);

  for (let i = 1; i <= probes; i += 1) {
    const sample = {
      iteration: i,
      diagnostics_before: await collectGatewaySample(`probe-${i}-before`),
    };
    try {
      sample.curl = await socks5Curl();
      sample.metrics = summarizeMetrics(await gatewayAdminJson("metrics-snapshot"));
      sample.diagnostics_after = await collectGatewaySample(`probe-${i}-after`);
      result.samples.push(sample);
    } catch (err) {
      sample.error = err.message;
      sample.diagnostics_after = await collectGatewayFull(`probe-${i}-failed`);
      result.samples.push(sample);
      throw err;
    }
  }

  result.metrics_after = await gatewayAdminJson("metrics-snapshot");
  result.delta = metricsDelta(result.metrics_before, result.metrics_after);
  assertNormalPoolMovement(result);

  if (failoverPeerSsh || failoverExit) {
    result.failover = await runFailoverProbe();
  }

  result.status = "ok";
  result.diagnostics.after = await collectGatewayFull("after");
  result.artifact = writeArtifact(result);
  console.log(JSON.stringify(result, null, 2));
} catch (err) {
  result.status = "failed";
  result.error = err.message;
  result.diagnostics.failure = await collectGatewayFull("failure");
  result.artifact = writeArtifact(result);
  console.error(`LIVE_RUN2_POOL_VALIDATION failed: ${err.message}`);
  console.error(`artifact=${result.artifact}`);
  if (err.stdout) console.error(err.stdout.trim());
  if (err.stderr) console.error(err.stderr.trim());
  process.exitCode = 1;
}

function required(name) {
  const value = env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function numberEnv(name, fallback) {
  const raw = env[name];
  if (!raw) return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value) || value <= 0) throw new Error(`${name} must be a positive number`);
  return Math.floor(value);
}

function boolEnv(name) {
  const raw = env[name];
  return raw === "1" || raw === "true" || raw === "yes";
}

async function assertGatewayService(label) {
  const snapshot = await collectGatewayFull(label);
  result.diagnostics[label] = snapshot;
  const state = snapshot.systemd?.ActiveState || "";
  if (state !== "active") {
    throw new Error(`${gatewayService} not active ${label}: ${state || "unknown"}`);
  }
  if (snapshot.exec_path !== gatewayBin) {
    throw new Error(`${gatewayService} ExecStart mismatch: expected=${gatewayBin} actual=${snapshot.exec_path || "unknown"}`);
  }
  if (!snapshot.exec_start?.includes(gatewayConfig)) {
    throw new Error(`${gatewayService} ExecStart does not include config ${gatewayConfig}`);
  }
  if (snapshot.binary?.status !== "ok") {
    throw new Error(`gateway binary evidence missing: ${snapshot.binary?.error || gatewayBin}`);
  }
  if (snapshot.config?.status !== "ok") {
    throw new Error(`gateway config evidence missing: ${snapshot.config?.error || gatewayConfig}`);
  }
  return snapshot;
}

async function gatewayAdminJson(command) {
  const out = await ssh(gatewaySsh, `${q(gatewayAdminBin)} admin ${command} --api ${q(gatewayOperator)}`);
  try {
    return JSON.parse(out);
  } catch (err) {
    err.message = `gateway admin ${command} returned non-json: ${err.message}`;
    err.stdout = out;
    throw err;
  }
}

async function collectGatewayFull(label) {
  const systemdText = await sshText(
    gatewaySsh,
    `systemctl show ${q(gatewayService)} --no-pager ` +
      "-p ActiveState -p SubState -p MainPID -p ExecMainPID -p ExecMainCode -p ExecMainStatus " +
      "-p NRestarts -p ActiveEnterTimestamp -p FragmentPath -p ExecStart",
  );
  const systemd = parseKeyValues(systemdText);
  const mainPid = nonZero(systemd.MainPID || systemd.ExecMainPID);
  const execStart = systemd.ExecStart || "";
  const snapshot = {
    label,
    at: new Date().toISOString(),
    systemd,
    exec_start: execStart,
    exec_path: parseExecStartPath(execStart),
    exec_path_expected: gatewayBin,
    config_arg_expected: gatewayConfig,
    binary: await remoteFileEvidence(gatewayBin),
    admin_binary: gatewayAdminBin === gatewayBin ? null : await remoteFileEvidence(gatewayAdminBin),
    config: await remoteFileEvidence(gatewayConfig),
    process: mainPid ? await sshText(gatewaySsh, `ps -p ${q(mainPid)} -o pid,ppid,pcpu,pmem,rss,vsz,etime,stat,comm,args --no-headers || true`) : "",
    threads: mainPid ? await sshText(gatewaySsh, `ps -L -p ${q(mainPid)} -o pid,tid,psr,pcpu,stat,comm,wchan:32 --no-headers || true`) : "",
    proc_status: mainPid ? await sshText(gatewaySsh, `cat /proc/${q(mainPid)}/status 2>/dev/null || true`) : "",
    sockets: await sshText(gatewaySsh, "ss -tanup 2>/dev/null | grep -E '(:2080|:19081|:9092|mesh-bus)' || true"),
    journal_tail: await sshText(gatewaySsh, `journalctl -u ${q(gatewayService)} -n ${journalLines} --no-pager 2>/dev/null || true`),
  };
  snapshot.exec_path_matches = snapshot.exec_path === gatewayBin;
  snapshot.config_arg_present = execStart.includes(gatewayConfig);
  return snapshot;
}

async function collectGatewaySample(label) {
  const systemdText = await sshText(
    gatewaySsh,
    `systemctl show ${q(gatewayService)} --no-pager -p ActiveState -p SubState -p MainPID -p ExecMainPID -p NRestarts`,
  );
  const systemd = parseKeyValues(systemdText);
  const mainPid = nonZero(systemd.MainPID || systemd.ExecMainPID);
  return {
    label,
    at: new Date().toISOString(),
    systemd,
    process: mainPid ? await sshText(gatewaySsh, `ps -p ${q(mainPid)} -o pid,pcpu,pmem,rss,vsz,etime,stat,comm --no-headers || true`) : "",
    threads: mainPid ? await sshText(gatewaySsh, `ps -L -p ${q(mainPid)} -o pid,tid,psr,pcpu,stat,comm,wchan:32 --no-headers || true`) : "",
    sockets: await sshText(gatewaySsh, "ss -tanup 2>/dev/null | grep -E '(:2080|:19081|:9092|mesh-bus)' || true"),
  };
}

async function remoteFileEvidence(file) {
  const out = await sshMaybe(gatewaySsh, [
    "set -e",
    `if [ ! -e ${q(file)} ]; then echo status=missing; exit 0; fi`,
    `printf 'status=ok\\npath=%s\\n' ${q(file)}`,
    `sha256sum ${q(file)} | awk '{print "sha256="$1}'`,
    `stat -c 'size=%s mtime=%y mode=%a owner=%U:%G' ${q(file)}`,
  ].join("; "));
  if (!out.ok) {
    return { status: "error", error: out.error, stdout: out.stdout, stderr: out.stderr };
  }
  return parseKeyValues(out.stdout);
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

function parseExecStartPath(execStart) {
  const match = String(execStart).match(/path=([^ ;]+)/);
  return match ? match[1] : "";
}

function nonZero(value) {
  const text = String(value || "").trim();
  return text && text !== "0" ? text : "";
}

async function sshText(host, command) {
  const out = await sshMaybe(host, command);
  if (out.ok) return out.stdout;
  return [`error=${out.error}`, out.stdout.trim(), out.stderr.trim()].filter(Boolean).join("\n");
}

function assertRun2Shape(status) {
  const live = status.kind === "operator.live_status" ? status.status : status;
  if (!live || live.kind !== "operator.status") {
    throw new Error(`unexpected status kind ${status.kind}`);
  }
  const meshPeerExits = (live.egresses || []).filter((exit) => exit.kind === "MeshPeerUdp");
  if (meshPeerExits.length < 2) {
    throw new Error(`Run2 gateway needs at least 2 MeshPeerUdp exits, got ${meshPeerExits.length}`);
  }
  const socksIngress = (live.ingresses || []).some((ingress) => ingress.kind === "Socks5");
  if (!socksIngress) throw new Error("Run2 gateway has no SOCKS5 ingress");
  result.run2_shape = {
    node_id: live.node_id || null,
    peers: (live.peers || []).map((peer) => peer.id),
    mesh_peer_exits: meshPeerExits.map((exit) => exit.id),
    scheduler: live.scheduler,
  };
}

async function socks5Curl() {
  const out = await run("curl", [
    "--socks5-hostname",
    gatewaySocks5,
    "-sS",
    "-o",
    "/dev/null",
    "--max-time",
    String(curlMaxTimeSeconds),
    "-w",
    "http_code=%{http_code} time_total=%{time_total} remote_ip=%{remote_ip}\\n",
    target,
  ]);
  const parsed = parsePairs(out);
  if (parsed.http_code !== "200") throw new Error(`curl expected http_code=200 got ${out.trim()}`);
  return parsed;
}

function summarizeMetrics(metrics) {
  return {
    dispatch_success: metrics.dispatch_success,
    dispatch_failure: metrics.dispatch_failure,
    meshsec_drop_total: metrics.meshsec_drop_total,
    meshsec_auth_drop_total: metrics.meshsec_auth_drop_total,
    meshsec_replay_drop_total: metrics.meshsec_replay_drop_total,
    native_drop_total: metrics.native_drop_total,
    exits: Object.fromEntries((metrics.exits || []).map((exit) => [
      exit.exit_id,
      {
        send_count: exit.send_count,
        success_count: exit.success_count,
        failure_count: exit.failure_count,
        last_rtt_ms: exit.last_rtt_ms,
      },
    ])),
  };
}

function metricsDelta(before, after) {
  const beforeExits = new Map((before.exits || []).map((exit) => [exit.exit_id, exit]));
  const exits = {};
  for (const afterExit of after.exits || []) {
    const beforeExit = beforeExits.get(afterExit.exit_id) || {};
    exits[afterExit.exit_id] = {
      send_count: afterExit.send_count - (beforeExit.send_count || 0),
      success_count: afterExit.success_count - (beforeExit.success_count || 0),
      failure_count: afterExit.failure_count - (beforeExit.failure_count || 0),
      payload_bytes_total: afterExit.payload_bytes_total - (beforeExit.payload_bytes_total || 0),
    };
  }
  return {
    dispatch_success: after.dispatch_success - before.dispatch_success,
    dispatch_failure: after.dispatch_failure - before.dispatch_failure,
    bytes_sent: after.bytes_sent - before.bytes_sent,
    meshsec_drop_total: after.meshsec_drop_total - before.meshsec_drop_total,
    meshsec_auth_drop_total: after.meshsec_auth_drop_total - before.meshsec_auth_drop_total,
    meshsec_replay_drop_total: after.meshsec_replay_drop_total - before.meshsec_replay_drop_total,
    native_drop_total: after.native_drop_total - before.native_drop_total,
    native_queue_overflow_drop_total: after.native_queue_overflow_drop_total - before.native_queue_overflow_drop_total,
    exits,
  };
}

function assertNormalPoolMovement(data) {
  const delta = data.delta;
  if (delta.dispatch_success <= 0) {
    throw new Error(`dispatch_success did not increase: ${delta.dispatch_success}`);
  }
  if (!allowBackgroundTraffic) {
    if (delta.dispatch_failure !== 0) throw new Error(`dispatch_failure increased: ${delta.dispatch_failure}`);
    if (delta.meshsec_drop_total !== 0) throw new Error(`meshsec_drop_total increased: ${delta.meshsec_drop_total}`);
    if (delta.native_drop_total !== 0) throw new Error(`native_drop_total increased: ${delta.native_drop_total}`);
  }
  const movedExits = Object.entries(delta.exits)
    .filter(([, exit]) => exit.send_count > 0)
    .map(([exitId, exit]) => ({ exit_id: exitId, ...exit }));
  data.moved_exits = movedExits;
  if (movedExits.length === 0) throw new Error("no pool exit send_count increased");
}

async function runFailoverProbe() {
  if (!failoverPeerSsh || !failoverExit) {
    throw new Error("failover requires MESH_BUS_RUN2_FAILOVER_PEER_SSH and MESH_BUS_RUN2_FAILOVER_EXIT");
  }
  if (!allowServiceMutation) {
    throw new Error("failover would stop a pool service; set MESH_BUS_RUN2_ALLOW_SERVICE_MUTATION=1");
  }
  const out = {
    requested: true,
    peer_ssh: failoverPeerSsh,
    exit_id: failoverExit,
    service_mutation_allowed: true,
    probes: [],
  };
  await ssh(failoverPeerSsh, "systemctl stop mesh-bus.service");
  try {
    const before = await gatewayAdminJson("metrics-snapshot");
    for (let i = 1; i <= probes; i += 1) {
      try {
        out.probes.push({ iteration: i, ok: true, curl: await socks5Curl() });
      } catch (err) {
        out.probes.push({ iteration: i, ok: false, error: err.message });
      }
    }
    const after = await gatewayAdminJson("metrics-snapshot");
    out.delta = metricsDelta(before, after);
    const failedExitDelta = out.delta.exits[failoverExit] || { send_count: 0, failure_count: 0 };
    out.stopped_exit_delta = failedExitDelta;
    const successful = out.probes.filter((probe) => probe.ok).length;
    const failed = out.probes.length - successful;
    if (successful === 0) throw new Error("all failover probes failed");
    if (failed > failoverAllowedFailures) {
      throw new Error(`failover had too many failed probes: failed=${failed} limit=${failoverAllowedFailures}`);
    }
    if (!allowBackgroundTraffic && failedExitDelta.send_count > failoverStoppedExitSendLimit) {
      throw new Error(
        `stopped exit kept receiving new sends: ${failedExitDelta.send_count} limit=${failoverStoppedExitSendLimit}`,
      );
    }
  } finally {
    await ssh(failoverPeerSsh, "systemctl start mesh-bus.service");
    const active = (await ssh(failoverPeerSsh, "systemctl is-active mesh-bus.service || true")).trim();
    out.restarted_state = active;
    if (active !== "active") throw new Error(`failed to restart pool service: ${active}`);
  }
  return out;
}

function parsePairs(text) {
  const out = {};
  for (const part of text.trim().split(/\s+/)) {
    const idx = part.indexOf("=");
    if (idx > 0) out[part.slice(0, idx)] = part.slice(idx + 1);
  }
  return out;
}

function writeArtifact(data) {
  fs.mkdirSync(artifactDir, { recursive: true });
  const file = path.join(artifactDir, `run2-pool-${new Date().toISOString().replace(/[-:]/g, "").replace(/\..+/, "Z")}.json`);
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
  return file;
}

function ssh(host, command) {
  return run("ssh", [host, command]);
}

async function sshMaybe(host, command) {
  try {
    const stdout = await ssh(host, command);
    return { ok: true, stdout, stderr: "", error: "" };
  } catch (err) {
    return {
      ok: false,
      stdout: err.stdout || "",
      stderr: err.stderr || "",
      error: err.message,
    };
  }
}

function run(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"] });
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

function q(value) {
  return `'${String(value).replaceAll("'", "'\\''")}'`;
}
