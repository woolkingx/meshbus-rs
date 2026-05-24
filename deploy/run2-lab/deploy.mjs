#!/usr/bin/env node
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const defaults = {
  targetTriple: "x86_64-unknown-linux-musl",
  localBin: "target/x86_64-unknown-linux-musl/release/mesh-bus",
  poolRemoteBin: "/opt/mesh-bus/bin/mesh-bus",
  gatewayRemoteBin: "/opt/mesh-bus/bin/mesh-bus-run2",
  gatewayConfig: "/etc/mesh-bus/run2.yaml",
  poolConfig: "/etc/mesh-bus/config.yaml",
  gatewayService: "mesh-bus-run2.service",
  poolService: "mesh-bus.service",
  gatewayOperator: "http://127.0.0.1:19081",
  probes: 5,
  target: "https://example.com",
};

try {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    printHelp();
    process.exit(0);
  }
  const result = await runRun2Deploy(args);
  console.log(JSON.stringify(result, null, 2));
} catch (err) {
  console.error(`deploy/run2-lab failed: ${err.message}`);
  if (err.stdout) console.error(err.stdout.trim());
  if (err.stderr) console.error(err.stderr.trim());
  process.exitCode = 1;
}

async function runRun2Deploy(args) {
  const nodes = resolveNodes(args);
  const result = {
    kind: "mesh_bus.run2_lab_deploy",
    dry_run: args.dryRun,
    only: args.only,
    build: !args.skipBuild,
    target_triple: args.targetTriple,
    validate: args.validate,
    gateway: nodes.gateway,
    pool: nodes.pool,
    deployed: [],
  };

  if (args.dryRun) {
    result.plan = deployPlan(args, nodes);
    return result;
  }

  assertLocalFile(args.localBin, "local binary");
  if (!args.skipBuild) {
    result.build_output = await run("cargo", [
      "build",
      "--release",
      "--target",
      args.targetTriple,
      "-p",
      "mesh-bus-bin",
    ]);
  }

  const plan = deployPlan(args, nodes);
  for (const target of plan) {
    result.deployed.push(await runDeployService(args, target));
  }

  if (args.validate && args.only !== "pool") {
    result.validation = await runValidation(args, nodes);
  }

  return result;
}

function deployPlan(args, nodes) {
  const plan = [];
  if (args.only !== "gateway") {
    for (const ssh of nodes.pool) {
      plan.push({
        role: "pool",
        remoteSsh: ssh,
        remoteBin: args.poolRemoteBin,
        remoteConfig: args.poolConfig,
        service: args.poolService,
      });
    }
  }
  if (args.only !== "pool") {
    plan.push({
      role: "gateway",
      remoteSsh: nodes.gateway,
      remoteBin: args.gatewayRemoteBin,
      remoteConfig: args.gatewayConfig,
      service: args.gatewayService,
    });
  }
  return plan;
}

async function runDeployService(args, target) {
  const stdout = await run("node", [
    "deploy/service/deploy.mjs",
    "--remote-ssh",
    target.remoteSsh,
    "--local-bin",
    args.localBin,
    "--remote-bin",
    target.remoteBin,
    "--remote-config",
    target.remoteConfig,
    "--service",
    target.service,
    "--preserve-remote-config",
  ]);
  try {
    return {
      role: target.role,
      ...JSON.parse(stdout),
    };
  } catch (err) {
    err.message = `deploy/service returned non-json for ${target.role} ${target.remoteSsh}: ${err.message}`;
    err.stdout = stdout;
    throw err;
  }
}

async function runValidation(args, nodes) {
  const gatewayHost = sshHost(nodes.gateway);
  const gatewaySocks5 = args.gatewaySocks5 || `${gatewayHost}:2080`;
  const env = {
    ...process.env,
    MESH_BUS_RUN2_GATEWAY_SSH: nodes.gateway,
    MESH_BUS_RUN2_GATEWAY_SOCKS5: gatewaySocks5,
    MESH_BUS_RUN2_GATEWAY_OPERATOR: args.gatewayOperator,
    MESH_BUS_RUN2_PROBES: String(args.probes),
    MESH_BUS_RUN2_TARGET: args.target,
  };
  if (args.allowBackgroundTraffic) env.MESH_BUS_RUN2_ALLOW_BACKGROUND_TRAFFIC = "1";
  if (args.failoverPeerSsh || args.failoverExit) {
    env.MESH_BUS_RUN2_ALLOW_SERVICE_MUTATION = "1";
    if (args.failoverPeerSsh) env.MESH_BUS_RUN2_FAILOVER_PEER_SSH = args.failoverPeerSsh;
    if (args.failoverExit) env.MESH_BUS_RUN2_FAILOVER_EXIT = args.failoverExit;
  }

  const stdout = await run("node", ["tests/live-run2-pool-validation.mjs"], { env });
  try {
    return JSON.parse(stdout);
  } catch (err) {
    err.message = `live-run2-pool-validation returned non-json: ${err.message}`;
    err.stdout = stdout;
    throw err;
  }
}

function parseArgs(argv) {
  const args = {
    ...defaults,
    targetTriple: process.env.MESH_BUS_RUN2_DEPLOY_TARGET || defaults.targetTriple,
    gatewaySsh: process.env.MESH_BUS_RUN2_DEPLOY_GATEWAY_SSH || "",
    poolSshs: splitCsv(process.env.MESH_BUS_RUN2_DEPLOY_POOL_SSHS || ""),
    subnet: process.env.MESH_BUS_RUN2_DEPLOY_SUBNET || "",
    sshUser: process.env.MESH_BUS_RUN2_DEPLOY_SSH_USER || "root",
    gatewaySuffix: process.env.MESH_BUS_RUN2_DEPLOY_GATEWAY_SUFFIX || "",
    poolSuffixes: process.env.MESH_BUS_RUN2_DEPLOY_POOL_SUFFIXES || "",
    gatewaySocks5: process.env.MESH_BUS_RUN2_GATEWAY_SOCKS5 || "",
    failoverPeerSsh: process.env.MESH_BUS_RUN2_FAILOVER_PEER_SSH || "",
    failoverExit: process.env.MESH_BUS_RUN2_FAILOVER_EXIT || "",
    only: "all",
    dryRun: false,
    skipBuild: false,
    validate: true,
    allowBackgroundTraffic: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") return { ...args, help: true };
    if (arg === "--dry-run") {
      args.dryRun = true;
      continue;
    }
    if (arg === "--skip-build") {
      args.skipBuild = true;
      continue;
    }
    if (arg === "--no-validate") {
      args.validate = false;
      continue;
    }
    if (arg === "--allow-background-traffic") {
      args.allowBackgroundTraffic = true;
      continue;
    }
    const value = argv[i + 1];
    if (!value || value.startsWith("--")) throw new Error(`${arg} requires a value`);
    i += 1;
    switch (arg) {
      case "--gateway-ssh":
        args.gatewaySsh = value;
        break;
      case "--pool-ssh":
        args.poolSshs = splitCsv(value);
        break;
      case "--subnet":
        args.subnet = value;
        break;
      case "--ssh-user":
        args.sshUser = value;
        break;
      case "--gateway-suffix":
        args.gatewaySuffix = value;
        break;
      case "--pool-suffixes":
        args.poolSuffixes = value;
        break;
      case "--local-bin":
        args.localBin = value;
        break;
      case "--target-triple":
        args.targetTriple = value;
        break;
      case "--remote-bin":
        args.gatewayRemoteBin = value;
        args.poolRemoteBin = value;
        break;
      case "--gateway-remote-bin":
        args.gatewayRemoteBin = value;
        break;
      case "--pool-remote-bin":
        args.poolRemoteBin = value;
        break;
      case "--gateway-config":
        args.gatewayConfig = value;
        break;
      case "--pool-config":
        args.poolConfig = value;
        break;
      case "--gateway-service":
        args.gatewayService = value;
        break;
      case "--pool-service":
        args.poolService = value;
        break;
      case "--gateway-socks5":
        args.gatewaySocks5 = value;
        break;
      case "--gateway-operator":
        args.gatewayOperator = value;
        break;
      case "--probes":
        args.probes = positiveInt(value, "--probes");
        break;
      case "--target":
        args.target = value;
        break;
      case "--only":
        args.only = value;
        break;
      case "--failover-peer-ssh":
        args.failoverPeerSsh = value;
        break;
      case "--failover-exit":
        args.failoverExit = value;
        break;
      default:
        throw new Error(`unknown argument: ${arg}`);
    }
  }

  if (!["all", "gateway", "pool"].includes(args.only)) {
    throw new Error("--only must be all, gateway, or pool");
  }
  if (args.probes <= 0) throw new Error("--probes must be positive");
  return args;
}

function resolveNodes(args) {
  const gateway = args.gatewaySsh || sshFromSuffix(args, args.gatewaySuffix, "gateway");
  const pool = args.poolSshs.length > 0
    ? args.poolSshs
    : expandSuffixes(args.poolSuffixes).map((suffix) => sshFromSuffix(args, suffix, "pool"));

  if (!gateway && args.only !== "pool") {
    throw new Error("gateway is required: use --gateway-ssh or --subnet + --gateway-suffix");
  }
  if (pool.length === 0 && args.only !== "gateway") {
    throw new Error("pool is required: use --pool-ssh or --subnet + --pool-suffixes");
  }
  return { gateway, pool };
}

function sshFromSuffix(args, suffix, label) {
  if (!args.subnet || !suffix) {
    throw new Error(`${label} needs --subnet and suffix when explicit SSH is not provided`);
  }
  return `${args.sshUser}@${args.subnet}.${suffix}`;
}

function expandSuffixes(value) {
  const out = [];
  for (const part of splitCsv(value)) {
    const match = part.match(/^(\d+)-(\d+)$/);
    if (!match) {
      out.push(part);
      continue;
    }
    const start = Number(match[1]);
    const end = Number(match[2]);
    if (!Number.isInteger(start) || !Number.isInteger(end) || start > end) {
      throw new Error(`invalid suffix range: ${part}`);
    }
    for (let n = start; n <= end; n += 1) out.push(String(n));
  }
  return out;
}

function splitCsv(value) {
  return String(value || "")
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
}

function sshHost(remoteSsh) {
  const at = remoteSsh.lastIndexOf("@");
  return at >= 0 ? remoteSsh.slice(at + 1) : remoteSsh;
}

function positiveInt(value, name) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) throw new Error(`${name} must be a positive integer`);
  return parsed;
}

function assertLocalFile(file, label) {
  if (!fs.existsSync(file)) throw new Error(`${label} not found: ${file}`);
  if (!fs.statSync(file).isFile()) throw new Error(`${label} is not a file: ${file}`);
}

function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"], ...options });
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

function printHelp() {
  const bin = path.relative(process.cwd(), process.argv[1]);
  console.log(`mesh-bus Run2 lab deploy

Usage:
  node ${bin} --subnet 192.0.2 --gateway-suffix 36 --pool-suffixes 20-24
  node ${bin} --gateway-ssh root@host-a --pool-ssh root@host-b,root@host-c

Options:
  --gateway-ssh <ssh>        Gateway SSH target.
  --pool-ssh <csv>           Pool SSH targets.
  --subnet <prefix>          Host prefix used with suffixes, for example 192.0.2.
  --ssh-user <user>          SSH user for suffix mode (default: root).
  --gateway-suffix <n>       Gateway host suffix for suffix mode.
  --pool-suffixes <list>     Pool suffixes, supports ranges like 20-24.
  --local-bin <path>         Local release binary (default: ${defaults.localBin}).
  --target-triple <triple>   Cargo target for build step (default: ${defaults.targetTriple}).
  --remote-bin <path>        Remote binary path for both roles.
  --gateway-remote-bin <path> Gateway binary path (default: ${defaults.gatewayRemoteBin}).
  --pool-remote-bin <path>   Pool binary path (default: ${defaults.poolRemoteBin}).
  --gateway-config <path>    Gateway remote config (default: ${defaults.gatewayConfig}).
  --pool-config <path>       Pool remote config (default: ${defaults.poolConfig}).
  --gateway-service <name>   Gateway systemd unit (default: ${defaults.gatewayService}).
  --pool-service <name>      Pool systemd unit (default: ${defaults.poolService}).
  --only <all|gateway|pool>  Deploy a subset (default: all).
  --skip-build               Do not run cargo build --release -p mesh-bus-bin.
  --no-validate              Skip tests/live-run2-pool-validation.mjs after deploy.
  --allow-background-traffic Allow validation counters to move from other users.
  --gateway-socks5 <host:port>    Validation SOCKS5 endpoint (default: gatewayHost:2080).
  --gateway-operator <url>        Validation Operator API from gateway SSH host (default: ${defaults.gatewayOperator}).
  --probes <n>                    Validation probe count (default: ${defaults.probes}).
  --target <url>                  Validation target (default: ${defaults.target}).
  --failover-peer-ssh <ssh>       Optional failover peer to stop during validation.
  --failover-exit <exit>          Optional failover exit id, for example mesh22.
  --dry-run                       Print resolved plan only.
  --help                          Show this help.

Behavior:
  build release binary for the requested target -> deploy pool nodes first -> deploy gateway last ->
  preserve each remote config -> restart services -> optionally run the Run2
  live validation gate. Pool-first/gateway-last keeps the single-gateway lab
  shape simple; incompatible wire changes still mean this is a short lab
  maintenance window, not a zero-downtime rolling upgrade.`);
}
