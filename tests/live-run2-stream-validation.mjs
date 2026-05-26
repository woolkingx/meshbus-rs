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
const streamUnit = env.MESH_BUS_RUN2_STREAM_UNIT || "mesh-bus-run2-stream-origin.service";
const streamHost = env.MESH_BUS_RUN2_STREAM_HOST || hostPart(gatewaySocks5);
const streamPort = numberEnv("MESH_BUS_RUN2_STREAM_PORT", 18088);
const streamChunks = numberEnv("MESH_BUS_RUN2_STREAM_CHUNKS", 24);
const streamChunkBytes = numberEnv("MESH_BUS_RUN2_STREAM_CHUNK_BYTES", 32768);
const streamDelayMs = numberEnv("MESH_BUS_RUN2_STREAM_DELAY_MS", 1000);
const streamCurlMaxTimeSeconds = numberEnv("MESH_BUS_RUN2_STREAM_CURL_MAX_TIME_SECONDS", Math.ceil(streamChunks * streamDelayMs / 1000) + 30);
const sampleIntervalMs = numberEnv("MESH_BUS_RUN2_STREAM_SAMPLE_INTERVAL_MS", 5000);
const maxCpuPercent = numberEnv("MESH_BUS_RUN2_STREAM_MAX_CPU_PERCENT", 50);
const allowBackgroundTraffic = boolEnv("MESH_BUS_RUN2_ALLOW_BACKGROUND_TRAFFIC");
const artifactDir = env.MESH_BUS_ARTIFACT_DIR || "artifacts/live-acceptance";
const managedOrigin = !env.MESH_BUS_RUN2_STREAM_TARGET;
const target = env.MESH_BUS_RUN2_STREAM_TARGET ||
  `http://${streamHost}:${streamPort}/stream?chunks=${streamChunks}&chunk_bytes=${streamChunkBytes}&delay_ms=${streamDelayMs}`;
const defaultExpectedBytes = streamChunks * streamChunkBytes;
const defaultExpectedSeconds = streamChunks * streamDelayMs / 1000;
const minBytes = numberEnv("MESH_BUS_RUN2_STREAM_MIN_BYTES", managedOrigin ? defaultExpectedBytes : 1_000_000);
const minSeconds = numberEnv("MESH_BUS_RUN2_STREAM_MIN_SECONDS", managedOrigin ? Math.max(1, Math.floor(defaultExpectedSeconds * 0.75)) : 1);

const result = {
  kind: "mesh_bus.live_run2_stream_validation",
  gateway_ssh: gatewaySsh,
  gateway_socks5: gatewaySocks5,
  gateway_operator: gatewayOperator,
  gateway_service: gatewayService,
  gateway_bin: gatewayBin,
  gateway_admin_bin: gatewayAdminBin,
  gateway_config: gatewayConfig,
  stream_unit: streamUnit,
  stream_host: streamHost,
  stream_port: streamPort,
  stream_chunks: streamChunks,
  stream_chunk_bytes: streamChunkBytes,
  stream_delay_ms: streamDelayMs,
  stream_curl_max_time_seconds: streamCurlMaxTimeSeconds,
  sample_interval_ms: sampleIntervalMs,
  max_cpu_percent: maxCpuPercent,
  min_bytes: minBytes,
  min_seconds: minSeconds,
  allow_background_traffic: allowBackgroundTraffic,
  managed_origin: managedOrigin,
  target,
  samples: [],
};

try {
  result.diagnostics = {};
  result.diagnostics.before = await collectGatewayFull("before");
  assertGatewayShape(result.diagnostics.before);
  result.metrics_before = await gatewayAdminJson("metrics-snapshot");

  if (managedOrigin) {
    await startStreamOrigin();
    result.stream_origin = await streamOriginStatus("started");
  }

  const startedAt = Date.now();
  const curl = spawnCurl();
  let curlDone = false;
  let curlResult = null;
  const curlPromise = waitForChild(curl).then((out) => {
    curlDone = true;
    curlResult = out;
    return out;
  }, (err) => {
    curlDone = true;
    curlResult = err;
    throw err;
  });

  while (!curlDone) {
    await sleep(sampleIntervalMs);
    result.samples.push(await collectStreamSample(startedAt));
  }

  const curlOut = await curlPromise;
  result.curl = parseCurlOutput(curlOut.stdout);
  result.curl.stderr = curlOut.stderr.trim();
  result.metrics_after = await gatewayAdminJson("metrics-snapshot");
  result.diagnostics.after = await collectGatewayFull("after");
  result.delta = metricsDelta(result.metrics_before, result.metrics_after);
  assertStream(result);

  result.status = "ok";
  result.artifact = writeArtifact(result);
  console.log(JSON.stringify(result, null, 2));
} catch (err) {
  result.status = "failed";
  result.error = err.message;
  result.curl_error = curlErrorShape(err);
  result.diagnostics = result.diagnostics || {};
  result.diagnostics.failure = await safe(() => collectGatewayFull("failure"));
  if (managedOrigin) result.stream_origin = await safe(() => streamOriginStatus("failure"));
  result.artifact = writeArtifact(result);
  console.error(`LIVE_RUN2_STREAM_VALIDATION failed: ${err.message}`);
  console.error(`artifact=${result.artifact}`);
  if (err.stdout) console.error(err.stdout.trim());
  if (err.stderr) console.error(err.stderr.trim());
  process.exitCode = 1;
} finally {
  if (managedOrigin) await cleanupStreamOrigin();
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

function hostPart(hostPort) {
  const text = String(hostPort || "");
  if (text.startsWith("[")) {
    const end = text.indexOf("]");
    return end > 0 ? text.slice(1, end) : text;
  }
  const idx = text.lastIndexOf(":");
  return idx > 0 ? text.slice(0, idx) : text;
}

async function startStreamOrigin() {
  const script = Buffer.from(pythonStreamOrigin(), "utf8").toString("base64");
  const remotePath = `/tmp/${streamUnit.replace(/[^A-Za-z0-9_.-]/g, "_")}.py`;
  const systemdRun = [
    "systemd-run",
    `--unit=${q(streamUnit)}`,
    "--collect",
    "--property=Restart=no",
    "--property=DynamicUser=no",
    "/usr/bin/python3",
    q(remotePath),
    "--host",
    "0.0.0.0",
    "--port",
    q(String(streamPort)),
  ].join(" ");
  await ssh(gatewaySsh, [
    "set -e",
    `systemctl stop ${q(streamUnit)} >/dev/null 2>&1 || true`,
    `printf %s ${q(script)} | base64 -d > ${q(remotePath)}`,
    `chmod 0644 ${q(remotePath)}`,
    systemdRun,
  ].join("; "));
  for (let i = 0; i < 20; i += 1) {
    const health = await sshMaybe(gatewaySsh, `curl -fsS --max-time 2 http://127.0.0.1:${streamPort}/healthz >/dev/null`);
    if (health.ok) return;
    await sleep(500);
  }
  throw new Error(`stream origin did not become healthy on ${gatewaySsh}:${streamPort}`);
}

async function cleanupStreamOrigin() {
  await sshMaybe(gatewaySsh, `systemctl stop ${q(streamUnit)} >/dev/null 2>&1 || true`);
}

async function streamOriginStatus(label) {
  const state = await sshText(
    gatewaySsh,
    `systemctl show ${q(streamUnit)} --no-pager -p ActiveState -p SubState -p MainPID -p ExecMainStatus -p NRestarts -p ActiveEnterTimestamp`,
  );
  const listeners = await sshText(gatewaySsh, `ss -tanlp 2>/dev/null | grep -E ':${streamPort}\\b' || true`);
  const journal = await sshText(gatewaySsh, `journalctl -u ${q(streamUnit)} -n 80 --no-pager 2>/dev/null || true`);
  return { label, systemd: parseKeyValues(state), listeners, journal_tail: journal };
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

function spawnCurl() {
  return spawn("curl", [
    "--socks5-hostname",
    gatewaySocks5,
    "-sS",
    "-o",
    "/dev/null",
    "--max-time",
    String(streamCurlMaxTimeSeconds),
    "-w",
    "http_code=%{http_code} time_total=%{time_total} size_download=%{size_download} speed_download=%{speed_download} remote_ip=%{remote_ip}\\n",
    target,
  ], { stdio: ["ignore", "pipe", "pipe"] });
}

async function collectStreamSample(startedAt) {
  const snapshot = await collectGatewaySample(`stream-${result.samples.length + 1}`);
  const metrics = await gatewayAdminJson("metrics-snapshot");
  return {
    ...snapshot,
    elapsed_ms: Date.now() - startedAt,
    metrics: summarizeMetrics(metrics),
  };
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
  return {
    label,
    at: new Date().toISOString(),
    systemd,
    exec_start: execStart,
    exec_path: parseExecStartPath(execStart),
    exec_path_expected: gatewayBin,
    config_arg_expected: gatewayConfig,
    binary: await remoteFileEvidence(gatewayBin),
    config: await remoteFileEvidence(gatewayConfig),
    process: mainPid ? await sshText(gatewaySsh, `ps -p ${q(mainPid)} -o pid,ppid,pcpu,pmem,rss,vsz,etime,stat,comm,args --no-headers || true`) : "",
    threads: mainPid ? await sshText(gatewaySsh, `ps -L -p ${q(mainPid)} -o pid,tid,psr,pcpu,stat,comm,wchan:32 --no-headers || true`) : "",
    proc_status: mainPid ? await sshText(gatewaySsh, `cat /proc/${q(mainPid)}/status 2>/dev/null || true`) : "",
    sockets: await sshText(gatewaySsh, "ss -tanup 2>/dev/null | grep -E '(:2080|:19081|:9092|mesh-bus)' || true"),
    journal_tail: await sshText(gatewaySsh, `journalctl -u ${q(gatewayService)} -n 120 --no-pager 2>/dev/null || true`),
  };
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

function assertGatewayShape(snapshot) {
  if (snapshot.systemd?.ActiveState !== "active") {
    throw new Error(`${gatewayService} not active before stream: ${snapshot.systemd?.ActiveState || "unknown"}`);
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
}

function assertStream(data) {
  const curl = data.curl;
  if (curl.http_code !== "200") throw new Error(`stream curl expected HTTP 200 got ${curl.http_code || "missing"}`);
  const sizeDownload = Number(curl.size_download || 0);
  if (sizeDownload < minBytes) {
    throw new Error(`stream truncated: size_download=${sizeDownload} expected_at_least=${minBytes}`);
  }
  const timeTotal = Number(curl.time_total || 0);
  if (timeTotal < minSeconds) {
    throw new Error(`stream completed too quickly: time_total=${timeTotal} expected_min_seconds=${minSeconds}`);
  }
  if (data.delta.dispatch_success <= 0) {
    throw new Error(`dispatch_success did not increase: ${data.delta.dispatch_success}`);
  }
  if (!allowBackgroundTraffic) {
    if (data.delta.dispatch_failure !== 0) throw new Error(`dispatch_failure increased: ${data.delta.dispatch_failure}`);
    if (data.delta.meshsec_drop_total !== 0) throw new Error(`meshsec_drop_total increased: ${data.delta.meshsec_drop_total}`);
    if (data.delta.native_drop_total !== 0) throw new Error(`native_drop_total increased: ${data.delta.native_drop_total}`);
  }
  const movedExits = Object.entries(data.delta.exits)
    .filter(([, exit]) => exit.send_count > 0 || exit.success_count > 0)
    .map(([exitId, exit]) => ({ exit_id: exitId, ...exit }));
  data.moved_exits = movedExits;
  if (movedExits.length === 0) throw new Error("no pool exit moved stream traffic");
  const cpuValues = data.samples.flatMap((sample) => processCpuValues(sample.process));
  data.assertions = {
    min_bytes: minBytes,
    size_download: sizeDownload,
    min_seconds: minSeconds,
    time_total: timeTotal,
    max_cpu_percent_observed: cpuValues.length ? Math.max(...cpuValues) : null,
    dispatch_success_delta: data.delta.dispatch_success,
    dispatch_failure_delta: data.delta.dispatch_failure,
    meshsec_drop_delta: data.delta.meshsec_drop_total,
    native_drop_delta: data.delta.native_drop_total,
  };
  if (data.assertions.max_cpu_percent_observed !== null && data.assertions.max_cpu_percent_observed > maxCpuPercent) {
    throw new Error(`gateway CPU exceeded stream threshold: max=${data.assertions.max_cpu_percent_observed} threshold=${maxCpuPercent}`);
  }
}

function summarizeMetrics(metrics) {
  return {
    dispatch_success: metrics.dispatch_success,
    dispatch_failure: metrics.dispatch_failure,
    flows: metrics.flows,
    bytes_sent: metrics.bytes_sent,
    meshsec_drop_total: metrics.meshsec_drop_total,
    native_drop_total: metrics.native_drop_total,
    exits: (metrics.exits || []).map((exit) => ({
      exit_id: exit.exit_id,
      protocol: exit.protocol,
      supports_stream: exit.supports_stream,
      supports_datagram: exit.supports_datagram,
      send_count: exit.send_count,
      success_count: exit.success_count,
      failure_count: exit.failure_count,
      last_rtt_ms: exit.last_rtt_ms,
      payload_bytes_total: exit.payload_bytes_total,
    })),
  };
}

function metricsDelta(before, after) {
  const beforeExits = groupExits(before.exits || []);
  const afterExits = groupExits(after.exits || []);
  const exits = {};
  for (const [exitId, afterExit] of afterExits) {
    const beforeExit = beforeExits.get(exitId) || {};
    exits[exitId] = {
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

function groupExits(exits) {
  const grouped = new Map();
  for (const exit of exits) {
    const prev = grouped.get(exit.exit_id) || {
      send_count: 0,
      success_count: 0,
      failure_count: 0,
      payload_bytes_total: 0,
    };
    prev.send_count += exit.send_count || 0;
    prev.success_count += exit.success_count || 0;
    prev.failure_count += exit.failure_count || 0;
    prev.payload_bytes_total += exit.payload_bytes_total || 0;
    grouped.set(exit.exit_id, prev);
  }
  return grouped;
}

function parseCurlOutput(stdout) {
  const out = {};
  for (const part of stdout.trim().split(/\s+/)) {
    const idx = part.indexOf("=");
    if (idx > 0) out[part.slice(0, idx)] = part.slice(idx + 1);
  }
  return out;
}

function processCpuValues(text) {
  return String(text || "")
    .split(/\r?\n/)
    .map((line) => line.trim().split(/\s+/)[1])
    .map((value) => Number(value))
    .filter((value) => Number.isFinite(value));
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

function writeArtifact(data) {
  fs.mkdirSync(artifactDir, { recursive: true });
  const file = path.join(artifactDir, `run2-stream-${new Date().toISOString().replace(/[-:]/g, "").replace(/\..+/, "Z")}.json`);
  data.artifact = file;
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
  return file;
}

async function sshText(host, command) {
  const out = await sshMaybe(host, command);
  if (out.ok) return out.stdout;
  return [`error=${out.error}`, out.stdout.trim(), out.stderr.trim()].filter(Boolean).join("\n");
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

function waitForChild(child) {
  return new Promise((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk.toString("utf8"); });
    child.stderr.on("data", (chunk) => { stderr += chunk.toString("utf8"); });
    child.on("error", reject);
    child.on("close", (code, signal) => {
      if (code === 0) {
        resolve({ stdout, stderr });
        return;
      }
      const err = new Error(`curl exited code=${code} signal=${signal}`);
      err.stdout = stdout;
      err.stderr = stderr;
      reject(err);
    });
  });
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

async function safe(fn) {
  try {
    return await fn();
  } catch (err) {
    return { status: "error", error: err.message };
  }
}

function curlErrorShape(err) {
  if (!err || !err.message) return null;
  return {
    message: err.message,
    stdout: err.stdout || "",
    stderr: err.stderr || "",
  };
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function q(value) {
  return `'${String(value).replaceAll("'", "'\\''")}'`;
}

function pythonStreamOrigin() {
  return String.raw`#!/usr/bin/env python3
import argparse
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/healthz":
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if parsed.path != "/stream":
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        query = parse_qs(parsed.query)
        chunks = max(1, int(query.get("chunks", ["24"])[0]))
        chunk_bytes = max(1, int(query.get("chunk_bytes", ["32768"])[0]))
        delay_ms = max(0, int(query.get("delay_ms", ["1000"])[0]))
        self.send_response(200)
        self.send_header("Content-Type", "video/mp2t")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        for index in range(chunks):
            prefix = ("mesh-bus-stream chunk=%06d\n" % index).encode("ascii")
            payload = prefix + (b"x" * max(0, chunk_bytes - len(prefix)))
            self.wfile.write(("%x\r\n" % len(payload)).encode("ascii"))
            self.wfile.write(payload)
            self.wfile.write(b"\r\n")
            self.wfile.flush()
            if delay_ms:
                time.sleep(delay_ms / 1000.0)
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.serve_forever()

if __name__ == "__main__":
    main()
`;
}
