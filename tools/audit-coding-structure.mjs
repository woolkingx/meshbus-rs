#!/usr/bin/env node
import {
  existsSync,
  readdirSync,
  readFileSync,
  statSync,
} from "node:fs";
import { join } from "node:path";

const roots = ["crates", "lib"];
const fail = process.argv.includes("--fail");
const sourceLimit = 900;
const testLimit = 900;

function walk(dir, out = []) {
  for (const entry of readdirSync(dir)) {
    if ([".git", ".cleanup", ".backup", "target"].includes(entry)) continue;
    const path = join(dir, entry);
    const stat = statSync(path);
    if (stat.isDirectory()) walk(path, out);
    else out.push(path);
  }
  return out;
}

function rustFiles() {
  return roots
    .filter((root) => existsSync(root))
    .flatMap((root) => walk(root))
    .filter((path) => path.endsWith(".rs"));
}

function isTestFile(path) {
  return path.includes("/tests/") || path.endsWith("_tests.rs") || path.endsWith("/tests.rs");
}

function countLines(path) {
  return readFileSync(path, "utf8").split("\n").length;
}

function inlineTestBodies(path, text) {
  return [...text.matchAll(/^\s*#\[cfg\(test\)\]\s*\r?\n\s*mod\s+\w+\s*\{/gm)].map(
    (match) => match.index,
  );
}

function bridgeMatches(text) {
  return [
    ...text.matchAll(
      /^#\[cfg\(test\)\]\n(?:#\[path = "[^"]+"\]\n)?mod [A-Za-z_][A-Za-z0-9_]*;\n/gm,
    ),
  ];
}

function bridgePlacementIssue(path, text) {
  const matches = bridgeMatches(text);
  if (!matches.length) return null;
  const last = matches.at(-1);
  const after = text.slice(last.index + last[0].length).trim();
  if (after.length === 0) return null;
  return path;
}

function contractRows() {
  const rows = [];
  for (const root of roots) {
    if (!existsSync(root)) continue;
    for (const entry of readdirSync(root)) {
      const dir = join(root, entry);
      if (!statSync(dir).isDirectory()) continue;
      const hasClaude = existsSync(join(dir, "CLAUDE.md"));
      const hasTest = existsSync(join(dir, "test.html"));
      const hasSchema =
        existsSync(join(dir, "schema.json")) || existsSync(join(dir, "schema"));
      const testHtml = hasTest ? readFileSync(join(dir, "test.html"), "utf8") : "";
      const schemaWaived = /No local schema\.json|No schema\.json/i.test(testHtml);
      if (!hasClaude || !hasTest || (!hasSchema && !schemaWaived)) {
        rows.push({
          dir,
          hasClaude,
          hasTest,
          hasSchema,
          schemaWaived,
        });
      }
    }
  }
  return rows;
}

const files = rustFiles();
const lineRows = files
  .map((path) => ({ path, lines: countLines(path), test: isTestFile(path) }))
  .sort((a, b) => b.lines - a.lines);

const inlineBodies = [];
const bridgeIssues = [];
for (const file of files) {
  const text = readFileSync(file, "utf8");
  if (inlineTestBodies(file, text).length) inlineBodies.push(file);
  const bridgeIssue = bridgePlacementIssue(file, text);
  if (bridgeIssue) bridgeIssues.push(bridgeIssue);
}

const oversizedSources = lineRows.filter((row) => !row.test && row.lines > sourceLimit);
const oversizedTests = lineRows.filter((row) => row.test && row.lines > testLimit);
const contractIssues = contractRows();

console.log("coding structure audit");
console.log(`rust files: ${files.length}`);
console.log(`inline cfg(test) bodies: ${inlineBodies.length}`);
console.log(`test bridges with production after bridge: ${bridgeIssues.length}`);
console.log(`oversized source files > ${sourceLimit}: ${oversizedSources.length}`);
console.log(`oversized test files > ${testLimit}: ${oversizedTests.length}`);
console.log(`contract coverage issues: ${contractIssues.length}`);

function printRows(title, rows, render) {
  if (!rows.length) return;
  console.log(`\n${title}`);
  for (const row of rows.slice(0, 20)) console.log(render(row));
}

printRows("top files", lineRows.slice(0, 20), (row) => {
  const kind = row.test ? "test" : "src";
  return `${String(row.lines).padStart(5)} ${kind} ${row.path}`;
});
printRows("inline test bodies", inlineBodies, (path) => `- ${path}`);
printRows("bridge placement issues", bridgeIssues, (path) => `- ${path}`);
printRows(
  "contract coverage issues",
  contractIssues,
  (row) =>
    `- ${row.dir} claude=${row.hasClaude} test=${row.hasTest} schema=${row.hasSchema} schema_waived=${row.schemaWaived}`,
);

if (fail && (inlineBodies.length || bridgeIssues.length || contractIssues.length)) {
  process.exit(1);
}
