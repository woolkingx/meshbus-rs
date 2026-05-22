#!/usr/bin/env node
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const env = process.env;
const remoteSsh = required("MESH_BUS_REMOTE_SSH");
const remoteSocks5 = required("MESH_BUS_REMOTE_SOCKS5");
const remoteOperator = required("MESH_BUS_REMOTE_OPERATOR");
const soakSeconds = numberEnv("MESH_BUS_SOAK_SECONDS", 120);
const intervalSeconds = numberEnv("MESH_BUS_SOAK_INTERVAL_SECONDS", 10);
const curlMaxTimeSeconds = numberEnv("MESH_BUS_SOAK_CURL_MAX_TIME_SECONDS", 30);
const target = env.MESH_BUS_SOAK_TARGET || "https://example.com";
const artifactDir = env.MESH_BUS_ARTIFACT_DIR || "artifacts/live-acceptance";

const result = {
  kind: "mesh_bus.live_service_soak",
  remote_ssh: remoteSsh,
  remote_socks5: remoteSocks5,
  remote_operator: remoteOperator,
  target,
  soak_seconds: soakSeconds,
  interval_seconds: intervalSeconds,
  curl_max_time_seconds: curlMaxTimeSeconds,
  samples: [],
};

try {
  await assertActive("before");
  result.before = {
    metrics: await remoteAdminJson("metrics-snapshot"),
    process: await remoteProcessSnapshot(),
  };

  const startedAt = Date.now();
  const deadline = startedAt + soakSeconds * 1_000;
  let iteration = 0;
  while (Date.now() < deadline) {
    iteration += 1;
    await assertActive(`iteration-${iteration}`);
    const curl = await socks5Curl();
    const metrics = await remoteAdminJson("metrics-snapshot");
    const process = await remoteProcessSnapshot();
    result.samples.push({
      iteration,
      elapsed_ms: Date.now() - startedAt,
      curl,
      dispatch_success: metrics.dispatch_success,
      dispatch_failure: metrics.dispatch_failure,
      flows: metrics.flows,
      rss_kb: process.rss_kb,
      fd_count: process.fd_count,
      threads: process.threads,
    });
    if (Date.now() < deadline) await sleep(intervalSeconds * 1_000);
  }

  result.after = {
    metrics: await remoteAdminJson("metrics-snapshot"),
    process: await remoteProcessSnapshot(),
  };
  assertStable(result);
  result.status = "ok";
  result.artifact = writeArtifact(result);
  console.log(JSON.stringify(result, null, 2));
} catch (err) {
  result.status = "failed";
  result.error = err.message;
  result.artifact = writeArtifact(result);
  console.error(`LIVE_SERVICE_SOAK failed: ${err.message}`);
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
  return value;
}

async function assertActive(label) {
  const active = (await ssh("systemctl is-active mesh-bus.service")).trim();
  if (active !== "active") throw new Error(`mesh-bus.service not active ${label}: ${active}`);
}

async function remoteAdminJson(command) {
  const out = await ssh(`/opt/mesh-bus/bin/mesh-bus admin ${command} --api ${q(remoteOperator)}`);
  try {
    return JSON.parse(out);
  } catch (err) {
    err.message = `remote admin ${command} returned non-json: ${err.message}`;
    err.stdout = out;
    throw err;
  }
}

async function remoteProcessSnapshot() {
  const script = [
    "set -e",
    "pid=$(pidof mesh-bus)",
    "rss=$(awk '/^VmRSS:/ {print $2}' /proc/$pid/status)",
    "threads=$(awk '/^Threads:/ {print $2}' /proc/$pid/status)",
    "fds=$(ls /proc/$pid/fd | wc -l)",
    'printf \'{"pid":%s,"rss_kb":%s,"threads":%s,"fd_count":%s}\\n\' "$pid" "$rss" "$threads" "$fds"',
  ].join("; ");
  return JSON.parse(await ssh(script));
}

async function socks5Curl() {
  const out = await run("curl", [
    "--socks5-hostname",
    remoteSocks5,
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

function assertStable(data) {
  const beforeMetrics = data.before.metrics;
  const afterMetrics = data.after.metrics;
  const beforeProc = data.before.process;
  const afterProc = data.after.process;
  const successDelta = afterMetrics.dispatch_success - beforeMetrics.dispatch_success;
  const failureDelta = afterMetrics.dispatch_failure - beforeMetrics.dispatch_failure;
  const rssDelta = afterProc.rss_kb - beforeProc.rss_kb;
  const fdDelta = afterProc.fd_count - beforeProc.fd_count;

  data.assertions = {
    dispatch_success_delta: successDelta,
    dispatch_failure_delta: failureDelta,
    rss_delta_kb: rssDelta,
    fd_delta: fdDelta,
  };

  if (successDelta <= 0) throw new Error(`dispatch_success did not increase: delta=${successDelta}`);
  if (failureDelta !== 0) throw new Error(`dispatch_failure increased: delta=${failureDelta}`);
  if (rssDelta > 64 * 1024) throw new Error(`RSS grew too much: delta_kb=${rssDelta}`);
  if (fdDelta > 16) throw new Error(`fd count grew too much: delta=${fdDelta}`);
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
  const file = path.join(artifactDir, `soak-${new Date().toISOString().replace(/[-:]/g, "").replace(/\..+/, "Z")}.json`);
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
  return file;
}

function ssh(command) {
  return run("ssh", [remoteSsh, command]);
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

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function q(value) {
  return `'${String(value).replaceAll("'", "'\\''")}'`;
}
