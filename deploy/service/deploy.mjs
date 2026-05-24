#!/usr/bin/env node
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const defaults = {
  remoteSsh: "root@198.51.100.36",
  localBin: "target/release/mesh-bus",
  remoteBin: "/opt/mesh-bus/bin/mesh-bus",
  localConfig: "config/example.yaml",
  remoteConfig: "/etc/mesh-bus/config.yaml",
  service: "mesh-bus.service",
  rollback: false,
  preserveRemoteConfig: false,
  rollbackBin: "",
  rollbackConfig: "",
};

try {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    printHelp();
    process.exit(0);
  }
  const result = args.rollback ? await rollback(args) : await deploy(args);
  console.log(JSON.stringify(result, null, 2));
} catch (err) {
  console.error(`deploy/service failed: ${err.message}`);
  if (err.stdout) console.error(err.stdout.trim());
  if (err.stderr) console.error(err.stderr.trim());
  process.exitCode = 1;
}

async function deploy(args) {
  assertLocalFile(args.localBin, "local binary");
  if (!args.preserveRemoteConfig) assertLocalFile(args.localConfig, "local config");
  const serviceExecPath = await requireServiceExecPath(args);

  const timestamp = timestampId();
  const binHash = sha256File(args.localBin);
  const configHash = args.preserveRemoteConfig ? null : sha256File(args.localConfig);
  const remoteBinDir = posixDir(args.remoteBin);
  const remoteConfigDir = posixDir(args.remoteConfig);
  const binBackup = `${remoteBinDir}/.backup/${path.posix.basename(args.remoteBin)}.${timestamp}`;
  const configBackup = `${remoteConfigDir}/.backup/${path.posix.basename(args.remoteConfig)}.${timestamp}`;
  const tmpBin = `/tmp/mesh-bus-deploy-${timestamp}.bin`;
  const tmpConfig = args.preserveRemoteConfig ? "" : `/tmp/mesh-bus-deploy-${timestamp}.yaml`;

  await ssh(args, [
    "set -e",
    `mkdir -p ${q(remoteBinDir)} ${q(remoteConfigDir)} ${q(`${remoteBinDir}/.backup`)} ${q(`${remoteConfigDir}/.backup`)}`,
    `[ ! -e ${q(args.remoteBin)} ] || cp -a ${q(args.remoteBin)} ${q(binBackup)}`,
    `[ ! -e ${q(args.remoteConfig)} ] || cp -a ${q(args.remoteConfig)} ${q(configBackup)}`,
  ].join("; "));
  await scp(args, args.localBin, `${args.remoteSsh}:${tmpBin}`);
  if (!args.preserveRemoteConfig) await scp(args, args.localConfig, `${args.remoteSsh}:${tmpConfig}`);
  const installConfig = args.preserveRemoteConfig
    ? []
    : [
        `install -m 0644 ${q(tmpConfig)} ${q(args.remoteConfig)}`,
        `rm -f ${q(tmpConfig)}`,
      ];
  await ssh(args, [
    "set -e",
    `install -m 0755 ${q(tmpBin)} ${q(args.remoteBin)}`,
    ...installConfig,
    `rm -f ${q(tmpBin)}`,
    `${q(args.remoteBin)} check --config ${q(args.remoteConfig)}`,
    `systemctl restart ${q(args.service)}`,
    `systemctl is-active ${q(args.service)}`,
  ].join("; "));

  const serviceState = (await ssh(args, `systemctl is-active ${q(args.service)}`)).trim();
  const remoteBinHash = (await ssh(args, `sha256sum ${q(args.remoteBin)} | awk '{print $1}'`)).trim();
  const remoteConfigHash = (await ssh(args, `sha256sum ${q(args.remoteConfig)} | awk '{print $1}'`)).trim();

  return {
    kind: "mesh_bus.service_deploy",
    action: "deploy",
    remote_ssh: args.remoteSsh,
    remote_bin: args.remoteBin,
    service_exec_path: serviceExecPath,
    remote_config: args.remoteConfig,
    service: args.service,
    service_active: serviceState === "active",
    service_state: serviceState,
    preserve_remote_config: args.preserveRemoteConfig,
    local_bin_sha256: binHash,
    remote_bin_sha256: remoteBinHash,
    local_config_sha256: configHash,
    remote_config_sha256: remoteConfigHash,
    bin_backup: binBackup,
    config_backup: configBackup,
  };
}

async function rollback(args) {
  const serviceExecPath = await requireServiceExecPath(args);
  const remoteBinDir = posixDir(args.remoteBin);
  const remoteConfigDir = posixDir(args.remoteConfig);
  const binBackup = args.rollbackBin || (await latestRemoteBackup(args, `${remoteBinDir}/.backup/${path.posix.basename(args.remoteBin)}.*`));
  const configBackup = args.rollbackConfig || (await latestRemoteBackup(args, `${remoteConfigDir}/.backup/${path.posix.basename(args.remoteConfig)}.*`));
  if (!binBackup) throw new Error("no remote binary backup found");
  if (!configBackup) throw new Error("no remote config backup found");

  await ssh(args, [
    "set -e",
    `test -f ${q(binBackup)}`,
    `test -f ${q(configBackup)}`,
    `install -m 0755 ${q(binBackup)} ${q(args.remoteBin)}`,
    `install -m 0644 ${q(configBackup)} ${q(args.remoteConfig)}`,
    `${q(args.remoteBin)} check --config ${q(args.remoteConfig)}`,
    `systemctl restart ${q(args.service)}`,
    `systemctl is-active ${q(args.service)}`,
  ].join("; "));

  const serviceState = (await ssh(args, `systemctl is-active ${q(args.service)}`)).trim();
  const remoteBinHash = (await ssh(args, `sha256sum ${q(args.remoteBin)} | awk '{print $1}'`)).trim();
  const remoteConfigHash = (await ssh(args, `sha256sum ${q(args.remoteConfig)} | awk '{print $1}'`)).trim();
  return {
    kind: "mesh_bus.service_deploy",
    action: "rollback",
    remote_ssh: args.remoteSsh,
    remote_bin: args.remoteBin,
    service_exec_path: serviceExecPath,
    remote_config: args.remoteConfig,
    service: args.service,
    service_active: serviceState === "active",
    service_state: serviceState,
    remote_bin_sha256: remoteBinHash,
    remote_config_sha256: remoteConfigHash,
    restored_bin_backup: binBackup,
    restored_config_backup: configBackup,
  };
}

async function requireServiceExecPath(args) {
  const script = `set -e; systemctl show ${q(args.service)} -p ExecStart --value | sed -n 's/.*path=\\([^ ;]*\\).*/\\1/p' | head -1`;
  const serviceExecPath = (await ssh(args, script)).trim();
  if (!serviceExecPath) {
    throw new Error(`cannot read ExecStart path for ${args.service}`);
  }
  if (serviceExecPath !== args.remoteBin) {
    throw new Error(
      `remote_bin does not match ${args.service} ExecStart: remote_bin=${args.remoteBin} exec=${serviceExecPath}`,
    );
  }
  return serviceExecPath;
}

async function latestRemoteBackup(args, pattern) {
  const out = await ssh(args, `ls -1 ${pattern} 2>/dev/null | tail -1 || true`);
  return out.trim();
}

function parseArgs(argv) {
  const args = { ...defaults };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") return { ...args, help: true };
    if (arg === "--rollback") {
      args.rollback = true;
      continue;
    }
    if (arg === "--preserve-remote-config") {
      args.preserveRemoteConfig = true;
      continue;
    }
    const value = argv[i + 1];
    if (!value || value.startsWith("--")) throw new Error(`${arg} requires a value`);
    i += 1;
    switch (arg) {
      case "--remote-ssh":
        args.remoteSsh = value;
        break;
      case "--local-bin":
        args.localBin = value;
        break;
      case "--remote-bin":
        args.remoteBin = value;
        break;
      case "--local-config":
        args.localConfig = value;
        break;
      case "--remote-config":
        args.remoteConfig = value;
        break;
      case "--service":
        args.service = value;
        break;
      case "--rollback-bin":
        args.rollbackBin = value;
        break;
      case "--rollback-config":
        args.rollbackConfig = value;
        break;
      default:
        throw new Error(`unknown argument: ${arg}`);
    }
  }
  validateArgs(args);
  return args;
}

function validateArgs(args) {
  const required = ["remoteSsh", "remoteBin", "remoteConfig", "service"];
  if (!args.rollback) required.push("localBin");
  if (!args.rollback && !args.preserveRemoteConfig) required.push("localConfig");
  for (const key of required) {
    if (!args[key]) throw new Error(`${key} is required`);
  }
  if (!/^[A-Za-z0-9_.@-]+\.service$/.test(args.service)) {
    throw new Error(`invalid systemd service name: ${args.service}`);
  }
}

function printHelp() {
  console.log(`mesh-bus service deploy

Usage:
  node deploy/service/deploy.mjs [options]
  node deploy/service/deploy.mjs --rollback [options]

Options:
  --remote-ssh <target>       SSH target (default: ${defaults.remoteSsh})
  --local-bin <path>          Local binary (default: ${defaults.localBin})
  --remote-bin <path>         Remote binary (default: ${defaults.remoteBin})
  --local-config <path>       Local config YAML (default: ${defaults.localConfig})
  --remote-config <path>      Remote config YAML (default: ${defaults.remoteConfig})
  --service <name>            systemd unit (default: ${defaults.service})
  --preserve-remote-config    Deploy binary only; keep and preflight remote config
  --rollback                  Restore latest remote backups instead of deploying
  --rollback-bin <path>       Explicit remote binary backup for rollback
  --rollback-config <path>    Explicit remote config backup for rollback
  --help                      Show this help

Deploy behavior:
  sha256 local inputs -> backup remote artifacts -> scp temp files ->
  install atomically -> mesh-bus check --config -> systemctl restart ->
  systemctl is-active -> JSON evidence

Use --preserve-remote-config when binary release and remote service config have
different lifecycles.`);
}

function assertLocalFile(file, label) {
  if (!fs.existsSync(file)) throw new Error(`${label} not found: ${file}`);
  if (!fs.statSync(file).isFile()) throw new Error(`${label} is not a file: ${file}`);
}

function sha256File(file) {
  const hash = crypto.createHash("sha256");
  hash.update(fs.readFileSync(file));
  return hash.digest("hex");
}

function posixDir(file) {
  const dir = path.posix.dirname(file);
  if (!dir || dir === ".") throw new Error(`remote path must include directory: ${file}`);
  return dir;
}

function timestampId() {
  return new Date().toISOString().replace(/[-:]/g, "").replace(/\..+/, "Z");
}

function ssh(args, command) {
  return run("ssh", [args.remoteSsh, command]);
}

function scp(args, localPath, remotePath) {
  return run("scp", [localPath, remotePath]);
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
