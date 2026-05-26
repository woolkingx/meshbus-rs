#!/usr/bin/env node
import { spawn } from "node:child_process";

const env = process.env;
const remoteSsh = required("MESH_BUS_REMOTE_SSH");
const remoteConfig = env.MESH_BUS_REMOTE_CONFIG || "/etc/mesh-bus/config.yaml";
const remoteBin = env.MESH_BUS_REMOTE_BIN || "/opt/mesh-bus/bin/mesh-bus";
const remoteService = env.MESH_BUS_REMOTE_SERVICE || "mesh-bus.service";

const result = {
  kind: "mesh_bus.live_production_faults",
  remote_config: remoteConfig,
  remote_bin: remoteBin,
  remote_service: remoteService,
  probes: [],
};

try {
  await assertActive("before");
  await badConfigProbe();
  await portCollisionProbe();
  await restartRollbackProbe();
  await remoteUnavailableProbe();
  await assertActive("after");
  console.log(JSON.stringify(result, null, 2));
} catch (err) {
  console.error(`LIVE_PRODUCTION_FAULTS failed: ${err.message}`);
  if (err.stdout) console.error(err.stdout.trim());
  if (err.stderr) console.error(err.stderr.trim());
  process.exitCode = 1;
}

function required(name) {
  const value = env[name];
  if (!value) die(`${name} is required`);
  return value;
}

async function assertActive(label) {
  const active = (await ssh(`systemctl is-active ${shellQuote(remoteService)}`)).trim();
  if (active !== "active") die(`${remoteService} not active ${label}: ${active}`);
}

async function badConfigProbe() {
  const tmp = `/tmp/mesh-bus-bad-${Date.now()}.yaml`;
  const command = [
    `cp ${shellQuote(remoteConfig)} ${shellQuote(tmp)}`,
    `printf '\\ninvalid_yaml: [' >> ${shellQuote(tmp)}`,
    `${shellQuote(remoteBin)} check --config ${shellQuote(tmp)} >/tmp/mesh-bus-bad-check.out 2>/tmp/mesh-bus-bad-check.err`,
    "code=$?",
    `rm -f ${shellQuote(tmp)}`,
    "cat /tmp/mesh-bus-bad-check.out",
    "cat /tmp/mesh-bus-bad-check.err >&2",
    'test "$code" = "0"',
  ].join("; ");
  const res = await sshStatus(command);
  if (res.code === 0) die("bad config unexpectedly passed check");
  await assertActive("after bad config");
  result.probes.push({ name: "bad_config_check", status: "ok", exit_code: res.code });
}

async function portCollisionProbe() {
  const res = await sshStatus(`timeout 5s ${shellQuote(remoteBin)} run --config ${shellQuote(remoteConfig)}`);
  if (res.code === 0 || res.code === 124) {
    die(`port collision probe did not fail fast: exit_code=${res.code}`);
  }
  await assertActive("after port collision");
  result.probes.push({ name: "port_collision", status: "ok", exit_code: res.code });
}

async function restartRollbackProbe() {
  await ssh(`systemctl restart ${shellQuote(remoteService)} && systemctl is-active ${shellQuote(remoteService)}`);
  const binBackup = (await ssh(`ls -1 ${backupGlob(remoteBin)} 2>/dev/null | tail -1 || true`)).trim();
  const configBackup = (await ssh(`ls -1 ${backupGlob(remoteConfig)} 2>/dev/null | tail -1 || true`)).trim();
  if (!binBackup) die("missing binary backup");
  if (!configBackup) die("missing config backup");
  result.probes.push({ name: "restart_rollback", status: "ok", bin_backup: binBackup, config_backup: configBackup });
}

async function remoteUnavailableProbe() {
  const ports = await remoteFreePorts();
  const tmp = `/tmp/mesh-bus-unavailable-${Date.now()}.yaml`;
  const makeConfig = String.raw`
import pathlib, sys
src, dst = sys.argv[1], sys.argv[2]
socks, mesh, metrics, operator = sys.argv[3:7]
text = pathlib.Path(src).read_text()
text = text.replace("listen: 127.0.0.1:19080", f"listen: 127.0.0.1:{operator}")
text = text.replace("listen: 127.0.0.1:9091", f"listen: 127.0.0.1:{metrics}")
text = text.replace("listen: 0.0.0.0:1081", f"listen: 127.0.0.1:{socks}")
text = text.replace("listen: 0.0.0.0:19000", f"listen: 127.0.0.1:{mesh}")
for host in ["198.51.100.20", "198.51.100.21", "198.51.100.22", "198.51.100.23", "198.51.100.24"]:
    text = text.replace(f"upstream: {host}:1080", "upstream: 127.0.0.1:9")
pathlib.Path(dst).write_text(text)
`;
  await ssh(`python3 -c ${shellQuote(makeConfig)} ${shellQuote(remoteConfig)} ${shellQuote(tmp)} ${ports.socks} ${ports.mesh} ${ports.metrics} ${ports.operator}`);
  const command = [
    `set -e`,
    `${shellQuote(remoteBin)} check --config ${shellQuote(tmp)} >/tmp/mesh-bus-unavailable-check.out`,
    `${shellQuote(remoteBin)} run --config ${shellQuote(tmp)} >/tmp/mesh-bus-unavailable.out 2>/tmp/mesh-bus-unavailable.err & pid=$!`,
    `python3 -c ${shellQuote(waitForTcpScript())} ${ports.socks}`,
    `set +e`,
    `curl --socks5-hostname 127.0.0.1:${ports.socks} -sS -o /dev/null --max-time 5 https://example.com >/tmp/mesh-bus-unavailable-curl.out 2>/tmp/mesh-bus-unavailable-curl.err`,
    "curl_code=$?",
    "kill -0 $pid",
    "alive=$?",
    "kill $pid >/dev/null 2>&1 || true",
    "wait $pid >/dev/null 2>&1 || true",
    `rm -f ${shellQuote(tmp)}`,
    "cat /tmp/mesh-bus-unavailable-curl.out",
    "cat /tmp/mesh-bus-unavailable-curl.err >&2",
    'test "$curl_code" != "0"',
    'test "$alive" = "0"',
  ].join("; ");
  const res = await sshStatus(command);
  if (res.code !== 0) die(`remote unavailable probe failed: exit_code=${res.code}`);
  await assertActive("after remote unavailable");
  result.probes.push({ name: "remote_unavailable", status: "ok", socks_port: ports.socks });
}

function waitForTcpScript() {
  return `
import socket, sys, time
port = int(sys.argv[1])
deadline = time.time() + 5
while time.time() < deadline:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
            raise SystemExit(0)
    except OSError:
        time.sleep(0.1)
raise SystemExit(1)
`;
}

async function remoteFreePorts() {
  const script = String.raw`
import json, socket
ports = []
sockets = []
for _ in range(4):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    ports.append(s.getsockname()[1])
    sockets.append(s)
print(json.dumps({"socks": ports[0], "mesh": ports[1], "metrics": ports[2], "operator": ports[3]}))
`;
  return JSON.parse(await ssh(`python3 -c ${shellQuote(script)}`));
}

async function ssh(command) {
  return run("ssh", [remoteSsh, command]);
}

async function sshStatus(command) {
  const wrapped = `${command}; code=$?; printf '\\n__EXIT:%s\\n' "$code"; exit 0`;
  const out = await run("ssh", [remoteSsh, wrapped]);
  const match = out.match(/\n__EXIT:(\d+)\n?$/);
  if (!match) die(`missing ssh status marker for command: ${command}`);
  return { code: Number(match[1]), stdout: out.replace(/\n__EXIT:\d+\n?$/, "") };
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

function shellQuote(value) {
  return `'${String(value).replaceAll("'", "'\\''")}'`;
}

function posixDir(file) {
  const idx = file.lastIndexOf("/");
  return idx > 0 ? file.slice(0, idx) : ".";
}

function posixBase(file) {
  const idx = file.lastIndexOf("/");
  return idx >= 0 ? file.slice(idx + 1) : file;
}

function backupGlob(file) {
  const dir = `${posixDir(file)}/.backup`;
  const base = posixBase(file);
  if (!/^[A-Za-z0-9_.-]+$/.test(base)) die(`unsafe backup basename: ${base}`);
  return `${shellQuote(dir)}/${base}.*`;
}

function die(message) {
  throw new Error(message);
}
