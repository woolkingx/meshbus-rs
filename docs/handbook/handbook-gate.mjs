#!/usr/bin/env node
// Handbook topology gate. Zero-dep ESM. Enforces the 6 discipline rules over
// the id/href/data-* graph. Run: node docs/handbook/handbook-gate.mjs
// Exit 0 = all hard rules pass. Exit 1 = a hard rule failed.
// Hard: R1 R3 R4 R5(link-scope) R6.  Advisory (semantic, needs data-*): R2 R5(prose).

import { readFileSync, readdirSync, existsSync } from "node:fs";
import { resolve, dirname, basename, relative } from "node:path";
import { fileURLToPath } from "node:url";

const HB = dirname(fileURLToPath(import.meta.url));         // docs/handbook
const ROOT = resolve(HB, "../..");                          // worktree root
const htmlFiles = readdirSync(HB).filter(f => f.endsWith(".html"));

const read = p => readFileSync(p, "utf8");
const slug = /^[a-z0-9][a-z0-9-]*$/;
const fail = [];   // hard violations
const warn = [];   // advisory
const activeTextDirs = ["docs/handbook", "docs/plan", "crates", "lib", "tests", "config", "deploy", "schemas"];
const stalePhrases = [
  /not yet runtime-built/,
  /planned wire-contract/,
  /only .*runtime-complete/,
  /reliable peer transport/,
  /QUIC reference binding carries reliable/,
  /QUIC provides reliable/,
  /QUIC reliable/,
  /shared Quinn/,
  /optional QUIC binding/,
];

function walkTextFiles(absDir, relDir = relative(ROOT, absDir)) {
  if (!existsSync(absDir)) return [];
  const out = [];
  for (const name of readdirSync(absDir, { withFileTypes: true })) {
    const abs = resolve(absDir, name.name);
    const rel = `${relDir}/${name.name}`.replace(/^\.\//, "");
    if (name.isDirectory()) {
      if (["target", ".backup", ".cleanup", ".git"].includes(name.name)) continue;
      out.push(...walkTextFiles(abs, rel));
      continue;
    }
    if (/\.(html|md|json)$/.test(name.name) || name.name === "CLAUDE.md") out.push({ abs, rel });
  }
  return out;
}

// ---- index every file: section attrs + all ids ----
const idsOf = new Map();      // file -> Set(id)
const sections = [];          // {file, id, attrs, body}
for (const f of htmlFiles) {
  const html = read(resolve(HB, f));
  const ids = new Set([...html.matchAll(/\bid="([^"]+)"/g)].map(m => m[1]));
  idsOf.set(f, ids);
  const re = /<section\b([^>]*)>([\s\S]*?)<\/section>/g;
  let m;
  while ((m = re.exec(html))) {
    const attrs = m[1], body = m[2];
    const id = (attrs.match(/\bid="([^"]+)"/) || [])[1] || null;
    sections.push({ file: f, id, attrs, body });
  }
}

// ---- R1: every section has a stable slug id ----
let r1 = 0;
for (const s of sections) {
  if (!s.id) { fail.push(`R1 ${s.file}: <section> with no id`); r1++; }
  else if (!slug.test(s.id)) { fail.push(`R1 ${s.file}#${s.id}: id not a stable slug`); r1++; }
}

// ---- R6: every intra-repo href resolves (file exists + #id exists) ----
let r6 = 0;
for (const f of htmlFiles) {
  const html = read(resolve(HB, f));
  for (const m of html.matchAll(/<a\b[^>]*\bhref="([^"]+)"/g)) {
    const href = m[1];
    if (/^(https?:|mailto:|#$)/.test(href)) continue;
    const [path, hash] = href.split("#");
    if (!path) {                                   // same-file anchor
      if (!idsOf.get(f).has(hash)) { fail.push(`R6 ${f}: dead anchor #${hash}`); r6++; }
      continue;
    }
    const tgt = resolve(HB, path);
    if (!existsSync(tgt)) { fail.push(`R6 ${f}: dangling href ${href}`); r6++; continue; }
    if (hash && path.endsWith(".html")) {
      const tf = basename(tgt);
      const tids = idsOf.get(tf) || new Set([...read(tgt).matchAll(/\bid="([^"]+)"/g)].map(x => x[1]));
      if (!tids.has(hash)) { fail.push(`R6 ${f}: ${path} has no #${hash}`); r6++; }
    }
  }
}

// ---- R3: every schema.json referenced by some handbook chapter ----
const actualSchemas = [
  ...readdirSync(resolve(ROOT, "crates")).map(d => `crates/${d}/schema.json`),
  ...readdirSync(resolve(ROOT, "lib")).map(d => `lib/${d}/schema.json`),
].filter(p => existsSync(resolve(ROOT, p)));
const specDir = resolve(HB, "spec");
if (existsSync(specDir))
  for (const s of readdirSync(specDir).filter(x => x.endsWith(".schema.json")))
    actualSchemas.push(`docs/handbook/spec/${s}`);

const referenced = new Set();
for (const f of htmlFiles) {
  const html = read(resolve(HB, f));
  for (const m of html.matchAll(/(?:href|data-schema)="([^"]+\.schema\.json|[^"]*schema\.json)"/g)) {
    const abs = resolve(HB, m[1].split("#")[0]);
    referenced.add(relative(ROOT, abs));
  }
}
let r3 = 0;
for (const s of actualSchemas)
  if (!referenced.has(s)) { fail.push(`R3 unreferenced schema: ${s}`); r3++; }

// ---- R4: every plan backlinks to a handbook node ----
const planDir = resolve(ROOT, "docs/plan");
let r4 = 0, plans = 0;
if (existsSync(planDir)) {
  for (const p of readdirSync(planDir).filter(x => x.endsWith(".md"))) {
    plans++;
    const txt = read(resolve(planDir, p));
    if (!/(docs\/)?handbook\/[\w-]+\.html|handbook\/index\.html|task-plans\.html/.test(txt)) {
      fail.push(`R4 plan has no handbook backlink: docs/plan/${p}`); r4++;
    }
  }
}

// ---- R5: module CLAUDE.md link-scope (hard) + arch-prose smell (advisory) ----
const modDirs = [
  ...readdirSync(resolve(ROOT, "crates")).map(d => `crates/${d}`),
  ...readdirSync(resolve(ROOT, "lib")).map(d => `lib/${d}`),
];
const claudeTargets = ["crates", "lib", "tests"]
  .flatMap(d => walkTextFiles(resolve(ROOT, d), d))
  .filter(f => basename(f.rel) === "CLAUDE.md");
let r5 = 0;
const proseSmell = /^\S[\w.\-]*\s+(governs|depends_on|extends|thesis|invariants|primitives|roadmap|extension-rule|testing-rule|perf-backlog):/m;
for (const d of modDirs) {
  const cm = resolve(ROOT, d, "CLAUDE.md");
  if (!existsSync(cm)) continue;
  const txt = read(cm), lines = txt.split("\n").length;
  if (!/handbook\//.test(txt)) { fail.push(`R5 ${d}/CLAUDE.md: no handbook pointer`); r5++; }
  if (lines > 60) warn.push(`R5* ${d}/CLAUDE.md: ${lines} lines (boot-card cap ~60)`);
  if (proseSmell.test(txt)) warn.push(`R5* ${d}/CLAUDE.md: graph-serialization arch-prose smell`);
}

// ---- R8: every local boot card carries the design boundary guard ----
let r8 = 0;
for (const f of claudeTargets) {
  const txt = read(f.abs);
  const count = [...txt.matchAll(/^design-rule:/gm)].length;
  if (count !== 1) {
    fail.push(`R8 ${f.rel}: expected exactly one design-rule block, found ${count}`);
    r8++;
  }
}

// ---- R2: core-concept => table/diagram. Unenforceable without data-concept ----
let r2cand = 0;
for (const s of sections) {
  if (/\bdata-concept=/.test(s.attrs)) {
    if (!/<table|class="flow"|<svg/.test(s.body))
      { fail.push(`R2 ${s.file}#${s.id}: data-concept without table/diagram`); }
    continue;
  }
  if (!/<table|class="flow"|<svg/.test(s.body)) r2cand++;
}
warn.push(`R2* ${r2cand} sections have no table/diagram (advisory: add data-concept to make enforceable)`);

// ---- R7: stale semantic wording must not return to active docs ----
let r7 = 0;
const allowedStaleFiles = new Set([
  "docs/plan/2026-05-19-handbook-topology-alignment-cleanup.md",
]);
for (const rootRel of activeTextDirs) {
  for (const f of walkTextFiles(resolve(ROOT, rootRel), rootRel)) {
    if (allowedStaleFiles.has(f.rel)) continue;
    const txt = read(f.abs);
    for (const rx of stalePhrases) {
      if (rx.test(txt)) {
        fail.push(`R7 stale semantic wording ${f.rel}: ${rx}`);
        r7++;
      }
    }
  }
}

// ---- report ----
const P = (n, ok) => `${ok ? "PASS" : "FAIL"} ${n}`;
console.log("== handbook topology gate ==");
console.log(P(`R1 section stable id      (${sections.length} sections)`, r1 === 0));
console.log(P(`R3 schema referenced      (${actualSchemas.length} schemas)`, r3 === 0));
console.log(P(`R4 plan backlink          (${plans} plans)`, r4 === 0));
console.log(P(`R5 module CLAUDE.md scope (${modDirs.length} modules)`, r5 === 0));
console.log(P(`R6 link/anchor resolve`, r6 === 0));
console.log(P(`R7 stale semantics`, r7 === 0));
console.log(P(`R8 CLAUDE design-rule   (${claudeTargets.length} files)`, r8 === 0));
console.log(`R2 advisory only (needs data-concept)`);
if (fail.length) { console.log("\n-- hard violations --"); fail.forEach(x => console.log("  " + x)); }
if (warn.length) { console.log("\n-- advisory --"); warn.forEach(x => console.log("  " + x)); }
console.log(`\nhard=${fail.length} advisory=${warn.length}`);
process.exit(fail.length ? 1 : 0);
