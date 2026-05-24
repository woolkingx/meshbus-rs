#!/usr/bin/env node
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, "../..");
const outPath = path.join(scriptDir, "testing-index.html");

const moduleRoots = [
  ...childDirs("crates"),
  ...childDirs("lib"),
  "config",
  "schemas",
  "deploy/systemd",
  "deploy/service",
  "deploy/run2-lab",
  "tests",
].filter((rel) => existsSync(path.join(repoRoot, rel)));

function childDirs(rel) {
  const abs = path.join(repoRoot, rel);
  if (!existsSync(abs)) return [];
  return readdirSync(abs, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => path.posix.join(rel, entry.name))
    .sort();
}

function has(rel, file) {
  return existsSync(path.join(repoRoot, rel, file));
}

function hasCode(rel) {
  const abs = path.join(repoRoot, rel);
  return (
    existsSync(path.join(abs, "Cargo.toml")) ||
    existsSync(path.join(abs, "src")) ||
    readdirSync(abs, { withFileTypes: true }).some((entry) => entry.isFile() && /\.(rs|mjs|js|yaml|toml)$/.test(entry.name))
  );
}

function link(rel, label = rel) {
  const target = path.posix.relative("docs/handbook", rel);
  return `<a href="${escapeHtml(target)}">${escapeHtml(label)}</a>`;
}

function requiredSurfaces(rel) {
  if (rel === "tests") {
    return { claude: true, schema: false, test: true, code: false, kind: "service/e2e composition" };
  }
  if (rel === "schemas") {
    return { claude: true, schema: false, test: true, code: false, kind: "schema collection" };
  }
  if (rel === "deploy/systemd") {
    return { claude: true, schema: true, test: true, code: false, kind: "deployment contract" };
  }
  if (rel === "deploy/service") {
    return { claude: true, schema: true, test: true, code: true, kind: "deployment action owner" };
  }
  if (rel === "deploy/run2-lab") {
    return { claude: true, schema: true, test: true, code: true, kind: "deployment composition owner" };
  }
  return { claude: true, schema: true, test: true, code: true, kind: "module owner" };
}

function mark(ok, href, label, required = true) {
  if (!required) return `<span class="warn">n/a</span>`;
  if (!ok) return `<span class="missing">missing</span>`;
  return href ? link(href, label) : `<span class="ok">present</span>`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

const rows = moduleRoots.map((rel) => {
  const required = requiredSurfaces(rel);
  const claude = has(rel, "CLAUDE.md");
  const schema = has(rel, "schema.json");
  const test = has(rel, "test.html");
  const code = hasCode(rel);
  const complete = (!required.claude || claude) && (!required.schema || schema) && (!required.test || test) && (!required.code || code);
  const missing = [
    required.claude && !claude && "CLAUDE.md",
    required.schema && !schema && "schema.json",
    required.test && !test && "test.html",
    required.code && !code && "code",
  ].filter(Boolean);
  return { rel, required, claude, schema, test, code, complete, missing };
});

const completeCount = rows.filter((row) => row.complete).length;
const generatedAt = new Date().toISOString().slice(0, 10);

const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Test Proof Graph Index - mesh-bus Handbook</title>
  <style>
    :root { color-scheme: light dark; --fg:#182026; --bg:#f7f8fa; --panel:#fff; --line:#d8dee4; --accent:#1f6feb; --ok:#1a7f37; --warn:#9a6700; --bad:#cf222e; }
    @media (prefers-color-scheme: dark) { :root { --fg:#e6edf3; --bg:#0d1117; --panel:#161b22; --line:#30363d; --accent:#58a6ff; --ok:#3fb950; --warn:#d29922; --bad:#ff7b72; } }
    * { box-sizing:border-box; }
    body { margin:0; font:16px/1.5 system-ui,sans-serif; color:var(--fg); background:var(--bg); }
    header, main { max-width:1180px; margin:0 auto; }
    header { padding:28px 24px 18px; }
    main { padding:0 24px 48px; }
    section { margin:0 0 18px; border:1px solid var(--line); border-radius:8px; padding:18px; background:var(--panel); }
    h1,h2 { margin:0 0 10px; line-height:1.2; }
    p { margin:8px 0; }
    a { color:var(--accent); }
    code { padding:1px 4px; border-radius:4px; background:rgba(127,127,127,.15); }
    table { width:100%; border-collapse:collapse; margin-top:8px; }
    th,td { border:1px solid var(--line); padding:8px; text-align:left; vertical-align:top; }
    th { background:rgba(127,127,127,.10); }
    .ok { color:var(--ok); font-weight:600; }
    .missing { color:var(--bad); font-weight:600; }
    .warn { color:var(--warn); font-weight:600; }
  </style>
</head>
<body>
  <header>
    <p><a href="index.html">Back to handbook index</a></p>
    <h1>Test Proof Graph Index</h1>
    <p>Generated proof-contract graph. Source of truth stays in each owner-local <code>test.html</code>; this page is navigation and gap detection only.</p>
  </header>
  <main>
    <section id="contract">
      <h2>Graph Contract</h2>
      <table>
        <tr><th>Surface</th><th>Role</th></tr>
        <tr><td><code>CLAUDE.md</code></td><td>Agent entry, local rules, and navigation.</td></tr>
        <tr><td><code>schema.json</code></td><td>Owned data contract and legal shape.</td></tr>
        <tr><td><code>test.html</code></td><td>Proof contract: fixtures, runner, boundaries, e2e projections, and forbidden tests.</td></tr>
        <tr><td>code</td><td>Implementation: legal operators over schema data when the node owns implementation code.</td></tr>
      </table>
      <p>Regenerate with <code>node docs/handbook/generate-test-index.mjs</code>. Check freshness with <code>node docs/handbook/generate-test-index.mjs --check</code>.</p>
    </section>
    <section id="summary">
      <h2>Summary</h2>
      <p><strong>${completeCount}</strong> of <strong>${rows.length}</strong> proof graph nodes currently have their required surfaces. Generated: <code>${generatedAt}</code>.</p>
    </section>
    <section id="modules">
      <h2>Proof Graph Nodes</h2>
      <table>
        <tr><th>Node</th><th>Kind</th><th>CLAUDE.md</th><th>schema.json</th><th>test.html</th><th>code</th><th>Status</th></tr>
${rows.map((row) => `        <tr><td><code>${escapeHtml(row.rel)}</code></td><td>${escapeHtml(row.required.kind)}</td><td>${mark(row.claude, `${row.rel}/CLAUDE.md`, "CLAUDE.md", row.required.claude)}</td><td>${mark(row.schema, `${row.rel}/schema.json`, "schema.json", row.required.schema)}</td><td>${mark(row.test, `${row.rel}/test.html`, "test.html", row.required.test)}</td><td>${mark(row.code, null, null, row.required.code)}</td><td>${row.complete ? '<span class="ok">complete</span>' : `<span class="warn">missing ${escapeHtml(row.missing.join(", "))}</span>`}</td></tr>`).join("\n")}
      </table>
    </section>
  </main>
</body>
</html>
`;

if (process.argv.includes("--check")) {
  const current = existsSync(outPath) ? readFileSync(outPath, "utf8") : "";
  if (current !== html) {
    console.error("docs/handbook/testing-index.html is stale. Run node docs/handbook/generate-test-index.mjs");
    process.exit(1);
  }
  process.exit(0);
}

writeFileSync(outPath, html);
console.log(`wrote ${path.relative(repoRoot, outPath)} (${rows.length} modules, ${completeCount} complete)`);
