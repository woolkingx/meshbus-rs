#!/usr/bin/env node
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const env = process.env;
const remoteSsh = required("MESH_BUS_REMOTE_SSH");
const remoteOperator = required("MESH_BUS_REMOTE_OPERATOR");
const artifactDir = env.MESH_BUS_ARTIFACT_DIR || "artifacts/live-acceptance";
const forbidden = [
  "static_key_hex",
  "MESH_BUS_MESHSEC_KEY_HEX",
  "password=",
  "Authorization:",
  "Bearer ",
];

const result = {
  kind: "mesh_bus.live_diagnose_bundle",
  remote_ssh: remoteSsh,
  remote_operator: remoteOperator,
};

try {
  const stdout = await ssh(`/opt/mesh-bus/bin/mesh-bus admin diagnose --api ${q(remoteOperator)}`);
  const bundle = JSON.parse(stdout);
  bundle.remote = await remoteHostEvidence();
  assertBundle(bundle);
  result.bundle = bundle;
  result.status = "ok";
  result.artifact = writeArtifact(result);
  console.log(JSON.stringify(result, null, 2));
} catch (err) {
  result.status = "failed";
  result.error = err.message;
  result.artifact = writeArtifact(result);
  console.error(`LIVE_DIAGNOSE_BUNDLE failed: ${err.message}`);
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

function assertBundle(bundle) {
  if (bundle.kind !== "operator.diagnose_bundle") {
    throw new Error(`unexpected diagnose kind ${bundle.kind}`);
  }
  if (bundle.status?.kind !== "operator.live_status") {
    throw new Error("diagnose bundle missing live status");
  }
  if (bundle.metrics?.kind !== "operator.metrics_snapshot") {
    throw new Error("diagnose bundle missing metrics snapshot");
  }
  assertNumber(bundle.metrics.meshsec_drop_total, "metrics.meshsec_drop_total");
  assertNumber(bundle.metrics.meshsec_auth_drop_total, "metrics.meshsec_auth_drop_total");
  assertNumber(bundle.metrics.meshsec_replay_drop_total, "metrics.meshsec_replay_drop_total");
  assertNumber(bundle.metrics.native_drop_total, "metrics.native_drop_total");
  assertNumber(
    bundle.metrics.native_queue_overflow_drop_total,
    "metrics.native_queue_overflow_drop_total",
  );
  if (!bundle.effective_config?.config?.fingerprint) {
    throw new Error("diagnose bundle missing config fingerprint");
  }
  if (!bundle.remote?.systemd?.includes("active")) {
    throw new Error("diagnose bundle missing active systemd state");
  }
  const text = JSON.stringify(bundle);
  for (const marker of forbidden) {
    if (text.includes(marker)) throw new Error(`diagnose bundle leaked ${marker}`);
  }
}

function assertNumber(value, path) {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new Error(`diagnose bundle ${path} must be a number`);
  }
}

function writeArtifact(data) {
  fs.mkdirSync(artifactDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\..+/, "Z");
  const file = path.join(artifactDir, `diagnose-${stamp}.json`);
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
  return file;
}

async function remoteHostEvidence() {
  const systemd = await ssh("systemctl is-active mesh-bus.service || true");
  const process = await ssh(
    "pid=$(pidof mesh-bus 2>/dev/null || true); if [ -n \"$pid\" ]; then printf 'pid=%s\\n' \"$pid\"; grep -E '^(VmRSS|Threads|FDSize):' /proc/$pid/status; printf 'fd_count='; ls /proc/$pid/fd | wc -l; fi",
  );
  const sockets = await ssh("ss -lntup 2>/dev/null | grep mesh-bus || true");
  const journal = await ssh("journalctl -u mesh-bus.service -n 80 --no-pager 2>/dev/null || true");
  return {
    ssh: remoteSsh,
    systemd: redactText(systemd),
    process: redactText(process),
    sockets: redactText(sockets),
    journal_tail: redactText(journal),
  };
}

function redactText(text) {
  return text
    .split("\n")
    .filter((line) => !forbidden.some((marker) => line.includes(marker)))
    .join("\n");
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

function q(value) {
  return `'${String(value).replaceAll("'", "'\\''")}'`;
}
