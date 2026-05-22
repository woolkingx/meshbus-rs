#!/usr/bin/env node
import dgram from "node:dgram";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import tls from "node:tls";
import { spawn } from "node:child_process";

const env = process.env;
const bin = env.MESH_BUS_BIN || path.resolve("target/debug/mesh-bus");
const remoteHost = required("MESH_BUS_REMOTE_HOST");
const remotePort = Number(env.MESH_BUS_REMOTE_PORT || "19000");
const keyHex = env.MESH_BUS_MESHSEC_KEY_HEX || "";
const targetHost = env.MESH_BUS_LIVE_TARGET_HOST || "www.google.com";
const targetPort = Number(env.MESH_BUS_LIVE_TARGET_PORT || "443");
const dnsServer = env.MESH_BUS_LIVE_DNS_SERVER || "1.1.1.1";
const dnsName = env.MESH_BUS_LIVE_DNS_NAME || "example.com";

if (!/^[0-9a-fA-F]{64}$/.test(keyHex)) {
  die("MESH_BUS_MESHSEC_KEY_HEX must be set to the 64-hex MeshSec PSK; it is never printed");
}
if (!fs.existsSync(bin)) {
  die(`mesh-bus binary not found: ${bin}`);
}

function required(name) {
  const value = env[name];
  if (!value) die(`${name} is required`);
  return value;
}

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-bus-live-mihomo-"));
let child;
let relay;
let stopping = false;

try {
  const socksPort = await freeTcpPort();
  const relayPort = await freeUdpPort();
  relay = await startUdpRelay(relayPort, remoteHost, remotePort);
  const configPath = path.join(tmp, "node-local.yaml");
  fs.writeFileSync(configPath, localConfig({ socksPort, relayPort, keyHex }));

  child = spawn(bin, ["run", "--config", configPath], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => {
    stdout += chunk.toString("utf8");
    child.stdoutText = stdout;
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString("utf8");
    child.stderrText = stderr;
  });
  child.on("exit", (code, signal) => {
    if (!stopping) {
      fail(`mesh-bus exited early code=${code} signal=${signal}\n${stdout}\n${stderr}`);
    }
  });

  await waitForTcp(`127.0.0.1`, socksPort, 5_000);
  await socks5ConnectProbe(socksPort, targetHost, targetPort);
  console.log(`LIVE_CONNECT ok target=${targetHost}:${targetPort}`);

  await socks5UdpDnsProbe(socksPort, dnsServer, dnsName);
  console.log(`LIVE_UDP_DNS ok server=${dnsServer} name=${dnsName}`);

  assertWireOpaque(relay.packets);
  const bytes = relay.packets.reduce((sum, packet) => sum + packet.length, 0);
  console.log(`LIVE_WIRE_CAPTURE packets=${relay.packets.length} bytes=${bytes}`);

  await clearFailClosed(remoteHost, remotePort);
  console.log("LIVE_FAIL_CLOSED ok");

  assertNoSecrets(stdout + stderr);
  console.log("LIVE_STARTUP_LOG ok");
} catch (err) {
  console.error(`LIVE_MIHOMO_REPLACEMENT failed: ${err.message}`);
  if (relay) {
    const outboundBytes = relay.packets.reduce((sum, packet) => sum + packet.length, 0);
    const inboundBytes = relay.inboundPackets.reduce((sum, packet) => sum + packet.length, 0);
    console.error(
      `--- relay packets outbound=${relay.packets.length}/${outboundBytes} inbound=${relay.inboundPackets.length}/${inboundBytes} ---`,
    );
  }
  if (child) {
    console.error("--- mesh-bus stdout ---");
    console.error((child.stdoutText || "").split("\n").slice(-20).join("\n"));
    console.error("--- mesh-bus stderr ---");
    console.error((child.stderrText || "").split("\n").slice(-20).join("\n"));
  }
  process.exitCode = 1;
} finally {
  stopping = true;
  if (child && child.exitCode === null) {
    child.kill("SIGTERM");
    await onceExit(child, 2_000).catch(() => child.kill("SIGKILL"));
  }
  if (relay) relay.close();
  fs.rmSync(tmp, { recursive: true, force: true });
}

function localConfig({ socksPort, relayPort, keyHex }) {
  return `logging:
  level: info
  format: compact

health:
  failure_threshold: 2
  recovery_window_ms: 30000
  probe_after_ms: 1000

scheduler:
  kind: Cake

node:
  id: local-secure

peers:
  - id: remote-main
    node_id: node-36
    route_groups: [mesh-upstream]
    meshsec:
      profile: MeshSec-0RTT-PSK-XChaCha
      static_key_hex: ${keyHex}

ingresses:
  - kind: Socks5
    listen: 127.0.0.1:${socksPort}
    handshake_timeout_ms: 5000
    accept_backoff_ms: 50
    max_connections: 128
    udp_forward_concurrency: 64

egresses:
  - kind: MeshPeerUdp
    id: remote-main
    peer_id: remote-main
    peer: 127.0.0.1:${relayPort}
    groups: [mesh-upstream]
    timeout_ms: 5000
`;
}

async function socks5ConnectProbe(port, host, targetPort) {
  const socket = await tcpConnect("127.0.0.1", port);
  try {
    socket.write(Buffer.from([0x05, 0x01, 0x00]));
    await readExact(socket, 2, 5_000, "CONNECT greeting");
    const hostBytes = Buffer.from(host, "utf8");
    socket.write(Buffer.concat([
      Buffer.from([0x05, 0x01, 0x00, 0x03, hostBytes.length]),
      hostBytes,
      u16(targetPort),
    ]));
    const reply = await readSocksReply(socket, "CONNECT reply");
    if (reply[1] !== 0x00) fail(`SOCKS CONNECT failed rep=0x${reply[1].toString(16)}`);
    const app = targetPort === 443 ? await tlsOverSocket(socket, host) : socket;
    app.write(Buffer.from(`GET / HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: mesh-bus-live-smoke/1\r\nConnection: close\r\n\r\n`));
    const body = await readUntil(app, Buffer.from("HTTP/"), 8_000, "CONNECT HTTP response");
    if (!body.includes("HTTP/")) fail("SOCKS CONNECT returned no HTTP status");
  } finally {
    socket.destroy();
  }
}

function tlsOverSocket(socket, servername, timeoutMs = 8_000) {
  return new Promise((resolve, reject) => {
    const secure = tls.connect({ socket, servername });
    const timer = setTimeout(() => {
      secure.destroy();
      reject(new Error(`TLS handshake timeout ${servername}`));
    }, timeoutMs);
    const cleanup = () => {
      clearTimeout(timer);
      secure.off("secureConnect", onSecure);
      secure.off("error", onError);
    };
    const onSecure = () => {
      cleanup();
      resolve(secure);
    };
    const onError = (err) => {
      cleanup();
      reject(err);
    };
    secure.once("secureConnect", onSecure);
    secure.once("error", onError);
  });
}

async function socks5UdpDnsProbe(port, server, name) {
  const control = await tcpConnect("127.0.0.1", port);
  const udp = dgram.createSocket("udp4");
  try {
    await new Promise((resolve, reject) => {
      udp.once("error", reject);
      udp.bind(0, "127.0.0.1", resolve);
    });
    const udpPort = udp.address().port;
    control.write(Buffer.from([0x05, 0x01, 0x00]));
    await readExact(control, 2, 5_000, "UDP greeting");
    control.write(Buffer.concat([
      Buffer.from([0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1]),
      u16(udpPort),
    ]));
    const reply = await readSocksReply(control, "UDP ASSOCIATE reply");
    if (reply[1] !== 0x00) fail(`SOCKS UDP ASSOCIATE failed rep=0x${reply[1].toString(16)}`);
    const relayPort = reply.readUInt16BE(reply.length - 2);
    const dns = dnsQuery(name);
    const packet = Buffer.concat([
      Buffer.from([0, 0, 0, 1]),
      Buffer.from(server.split(".").map(Number)),
      u16(53),
      dns,
    ]);
    udp.send(packet, relayPort, "127.0.0.1");
    const response = await udpMessage(udp, 8_000, "UDP DNS response");
    const payload = parseSocksUdpPayload(response);
    if (payload.readUInt16BE(0) !== 0x4d42) fail("DNS response transaction id mismatch");
  } finally {
    udp.close();
    control.destroy();
  }
}

function dnsQuery(name) {
  const labels = name.split(".");
  const qname = Buffer.concat(labels.flatMap((label) => [
    Buffer.from([Buffer.byteLength(label)]),
    Buffer.from(label, "ascii"),
  ]).concat([Buffer.from([0])]));
  return Buffer.concat([
    Buffer.from([0x4d, 0x42, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]),
    qname,
    Buffer.from([0, 1, 0, 1]),
  ]);
}

function parseSocksUdpPayload(packet) {
  if (packet[0] !== 0 || packet[1] !== 0 || packet[2] !== 0) fail("invalid SOCKS UDP response header");
  let offset = 4;
  if (packet[3] === 1) offset += 4;
  else if (packet[3] === 3) offset += 1 + packet[4];
  else if (packet[3] === 4) offset += 16;
  else fail(`unsupported SOCKS UDP ATYP ${packet[3]}`);
  offset += 2;
  return packet.subarray(offset);
}

async function startUdpRelay(localPort, remoteHost, remotePort) {
  const socket = dgram.createSocket("udp4");
  const packets = [];
  const inboundPackets = [];
  let client;
  socket.on("message", (msg, rinfo) => {
    if (rinfo.address === remoteHost && rinfo.port === remotePort) {
      inboundPackets.push(Buffer.from(msg));
      if (client) socket.send(msg, client.port, client.address);
      return;
    }
    client = { address: rinfo.address, port: rinfo.port };
    packets.push(Buffer.from(msg));
    socket.send(msg, remotePort, remoteHost);
  });
  await new Promise((resolve, reject) => {
    socket.once("error", reject);
    // Bind wildcard so the same relay socket can receive localhost client
    // packets and send WAN packets with a routable source address.
    socket.bind(localPort, "0.0.0.0", resolve);
  });
  return { packets, inboundPackets, close: () => socket.close() };
}

function assertWireOpaque(packets) {
  if (packets.length === 0) fail("capture relay saw no outbound MeshSec packets");
  const joined = Buffer.concat(packets).toString("latin1");
  for (const forbidden of ["GET /", targetHost, dnsName, "mesh-upstream", "127.0.0.1"]) {
    if (joined.includes(forbidden)) fail(`wire capture leaked ${forbidden}`);
  }
}

function assertNoSecrets(logs) {
  for (const forbidden of [keyHex, "static_key_hex"]) {
    if (logs.includes(forbidden)) fail(`startup log leaked ${forbidden === keyHex ? "MeshSec key" : forbidden}`);
  }
}

async function clearFailClosed(host, port) {
  const socket = dgram.createSocket("udp4");
  try {
    socket.send(Buffer.from("MBclear-mesh-frame-should-drop"), port, host);
    const received = await udpMessage(socket, 1_000, "clear fail-closed probe")
      .then(() => true)
      .catch(() => false);
    if (received) fail("clear MeshFrame probe received a reply");
  } finally {
    socket.close();
  }
}

async function freeTcpPort() {
  const server = net.createServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}

async function freeUdpPort() {
  const socket = dgram.createSocket("udp4");
  await new Promise((resolve) => socket.bind(0, "127.0.0.1", resolve));
  const port = socket.address().port;
  socket.close();
  return port;
}

async function waitForTcp(host, port, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const socket = await tcpConnect(host, port, 250);
      socket.destroy();
      return;
    } catch {
      await delay(50);
    }
  }
  fail(`timeout waiting for TCP ${host}:${port}`);
}

function tcpConnect(host, port, timeoutMs = 5_000) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host, port });
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error(`connect timeout ${host}:${port}`));
    }, timeoutMs);
    socket.once("connect", () => {
      clearTimeout(timer);
      resolve(socket);
    });
    socket.once("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

async function readSocksReply(socket, label) {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const timer = setTimeout(() => cleanup(new Error(`${label} timeout`)), 5_000);
    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      const total = socksReplyLength(buf, label);
      if (total && buf.length >= total) cleanup(null, buf.subarray(0, total));
    };
    const cleanup = (err, data) => {
      clearTimeout(timer);
      socket.off("data", onData);
      socket.off("close", onClose);
      socket.off("end", onEnd);
      err ? reject(err) : resolve(data);
    };
    const onClose = () => cleanup(new Error(`${label} socket closed before reply`));
    const onEnd = () => cleanup(new Error(`${label} socket ended before reply`));
    socket.on("data", onData);
    socket.once("close", onClose);
    socket.once("end", onEnd);
  });
}

function socksReplyLength(buf, label) {
  if (buf.length < 4) return 0;
  if (buf[3] === 1) return 4 + 4 + 2;
  if (buf[3] === 3) {
    if (buf.length < 5) return 0;
    return 4 + 1 + buf[4] + 2;
  }
  if (buf[3] === 4) return 4 + 16 + 2;
  fail(`${label} unsupported SOCKS ATYP ${buf[3]}`);
}

function readExact(socket, len, timeoutMs = 5_000, label = "read") {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const timer = setTimeout(() => cleanup(new Error(`${label} timeout`)), timeoutMs);
    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length >= len) cleanup(null, buf.subarray(0, len));
    };
    const cleanup = (err, data) => {
      clearTimeout(timer);
      socket.off("data", onData);
      err ? reject(err) : resolve(data);
    };
    socket.on("data", onData);
  });
}

function readUntil(socket, needle, timeoutMs, label = "read until") {
  return new Promise((resolve, reject) => {
    let text = "";
    const timer = setTimeout(() => cleanup(new Error(`${label} timeout`)), timeoutMs);
    const onData = (chunk) => {
      text += chunk.toString("latin1");
      if (text.includes(needle.toString("latin1"))) cleanup(null, text);
    };
    const cleanup = (err, data) => {
      clearTimeout(timer);
      socket.off("data", onData);
      err ? reject(err) : resolve(data);
    };
    socket.on("data", onData);
  });
}

function udpMessage(socket, timeoutMs, label = "udp") {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => cleanup(new Error(`${label} timeout`)), timeoutMs);
    const onMessage = (msg) => cleanup(null, msg);
    const cleanup = (err, msg) => {
      clearTimeout(timer);
      socket.off("message", onMessage);
      err ? reject(err) : resolve(msg);
    };
    socket.on("message", onMessage);
  });
}

function onceExit(proc, timeoutMs) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("exit timeout")), timeoutMs);
    proc.once("exit", () => {
      clearTimeout(timer);
      resolve();
    });
  });
}

function u16(n) {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n);
  return b;
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function fail(message) {
  throw new Error(message);
}

function die(message) {
  console.error(`LIVE_MIHOMO_REPLACEMENT failed: ${message}`);
  process.exit(1);
}
