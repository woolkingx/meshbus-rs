#!/usr/bin/env node
import { readdirSync, readFileSync, statSync, writeFileSync, existsSync } from "node:fs";
import { basename, dirname, join, relative } from "node:path";

const roots = ["crates", "lib"];
const dryRun = process.argv.includes("--dry-run");

function walk(dir, out = []) {
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    const stat = statSync(path);
    if (stat.isDirectory()) {
      if (entry === "target" || entry === ".git" || entry === ".cleanup" || entry === ".backup") {
        continue;
      }
      walk(path, out);
    } else if (entry.endsWith(".rs")) {
      out.push(path);
    }
  }
  return out;
}

function findLineStart(text, index) {
  const prev = text.lastIndexOf("\n", index - 1);
  return prev < 0 ? 0 : prev + 1;
}

function findLineEnd(text, index) {
  const next = text.indexOf("\n", index);
  return next < 0 ? text.length : next + 1;
}

function includePrecedingDocComments(text, cfgStart) {
  let start = cfgStart;
  while (start > 0) {
    const prevEnd = start - 1;
    const prevStart = findLineStart(text, prevEnd);
    const line = text.slice(prevStart, start);
    const trimmed = line.trim();
    if (trimmed === "" || trimmed.startsWith("///")) {
      start = prevStart;
      continue;
    }
    break;
  }
  return start;
}

function stripRustTrivia(text, index, state) {
  const ch = text[index];
  const next = text[index + 1];

  if (state.lineComment) {
    if (ch === "\n") state.lineComment = false;
    return true;
  }
  if (state.blockComment > 0) {
    if (ch === "/" && next === "*") {
      state.blockComment += 1;
      return true;
    }
    if (ch === "*" && next === "/") {
      state.blockComment -= 1;
      state.skipNext = true;
      return true;
    }
    return true;
  }
  if (state.string) {
    if (state.escape) {
      state.escape = false;
      return true;
    }
    if (ch === "\\") {
      state.escape = true;
      return true;
    }
    if (ch === state.string) {
      state.string = null;
    }
    return true;
  }
  if (ch === "/" && next === "/") {
    state.lineComment = true;
    return true;
  }
  if (ch === "/" && next === "*") {
    state.blockComment = 1;
    state.skipNext = true;
    return true;
  }
  if (ch === '"' || ch === "'") {
    state.string = ch;
    return true;
  }
  return false;
}

function findMatchingBrace(text, openIndex) {
  const state = {
    lineComment: false,
    blockComment: 0,
    string: null,
    escape: false,
    skipNext: false,
  };
  let depth = 0;
  for (let i = openIndex; i < text.length; i += 1) {
    if (state.skipNext) {
      state.skipNext = false;
      continue;
    }
    if (stripRustTrivia(text, i, state)) continue;
    if (text[i] === "{") depth += 1;
    if (text[i] === "}") {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  throw new Error(`unclosed brace at ${openIndex}`);
}

function dedentModuleBody(body) {
  let lines = body.replace(/^\n/, "").replace(/\s*$/, "\n").split("\n");
  if (lines.at(-1) === "") lines = lines.slice(0, -1);
  const nonEmpty = lines.filter((line) => line.trim().length > 0);
  const indent = nonEmpty.length
    ? Math.min(...nonEmpty.map((line) => line.match(/^\s*/)[0].length))
    : 0;
  return lines.map((line) => line.slice(Math.min(indent, line.length))).join("\n") + "\n";
}

function docCommentsAsInner(docs) {
  const lines = docs
    .split("\n")
    .map((line) => {
      const trimmed = line.trim();
      if (trimmed.startsWith("///")) return `//!${trimmed.slice(3)}`;
      return "";
    })
    .filter((line) => line.length > 0);
  return lines.length ? `${lines.join("\n")}\n\n` : "";
}

function moduleNameFor(sourcePath, inlineName, usedNames) {
  if (inlineName !== "tests") return inlineName;
  const stem = basename(sourcePath, ".rs")
    .replace(/[^A-Za-z0-9_]/g, "_")
    .replace(/^mod$/, "module");
  let name = `${stem}_tests`;
  let suffix = 2;
  while (usedNames.has(name)) {
    name = `${stem}_tests_${suffix}`;
    suffix += 1;
  }
  return name;
}

function declarationFor(sourcePath, targetName) {
  const stem = basename(sourcePath, ".rs");
  const pathAttr = stem === "lib" || stem === "mod" ? "" : `#[path = "${targetName}.rs"]\n`;
  return `#[cfg(test)]\n${pathAttr}mod ${targetName};\n`;
}

function extractFile(path) {
  const text = readFileSync(path, "utf8");
  const pattern = /^[ \t]*#\[cfg\(test\)\][ \t]*\r?\n[ \t]*mod[ \t]+([A-Za-z_][A-Za-z0-9_]*)[ \t]*\{/gm;
  const blocks = [];
  const usedNames = new Set();
  let match;

  while ((match = pattern.exec(text)) !== null) {
    const cfgStart = includePrecedingDocComments(text, match.index);
    const openIndex = pattern.lastIndex - 1;
    const closeIndex = findMatchingBrace(text, openIndex);
    const blockEnd = findLineEnd(text, closeIndex);
    const inlineName = match[1];
    const targetName = moduleNameFor(path, inlineName, usedNames);
    usedNames.add(targetName);
    blocks.push({
      cfgStart,
      attrStart: match.index,
      blockEnd,
      openIndex,
      closeIndex,
      inlineName,
      targetName,
    });
    pattern.lastIndex = blockEnd;
  }

  if (!blocks.length) return [];

  const edits = [];
  let nextText = text;
  for (const block of [...blocks].reverse()) {
    nextText = nextText.slice(0, block.cfgStart) + nextText.slice(block.blockEnd);
  }

  const declarations = blocks
    .map((block) => declarationFor(path, block.targetName))
    .join("");

  nextText = appendTestDeclarations(nextText, declarations);

  for (const block of blocks) {
    const target = join(dirname(path), `${block.targetName}.rs`);
    if (existsSync(target)) {
      throw new Error(`${relative(process.cwd(), target)} already exists; refusing to overwrite`);
    }
    const body = text.slice(block.openIndex + 1, block.closeIndex);
    const docs = text.slice(block.cfgStart, block.attrStart);
    edits.push({
      source: path,
      target,
      inlineName: block.inlineName,
      targetName: block.targetName,
      content: docCommentsAsInner(docs) + dedentModuleBody(body),
    });
  }

  if (!dryRun) {
    writeFileSync(path, nextText);
    for (const edit of edits) writeFileSync(edit.target, edit.content);
  }

  return edits;
}

function appendTestDeclarations(text, declarations) {
  const body = text.trimEnd();
  return `${body}\n\n${declarations}`;
}

const files = roots.flatMap((root) => existsSync(root) ? walk(root) : []);
const allEdits = [];
for (const file of files) {
  allEdits.push(...extractFile(file));
}

for (const edit of allEdits) {
  console.log(
    `${dryRun ? "would extract" : "extracted"} ${relative(process.cwd(), edit.source)}::${edit.inlineName} -> ${relative(process.cwd(), edit.target)}::${edit.targetName}`
  );
}
console.log(`${dryRun ? "would extract" : "extracted"} ${allEdits.length} inline test modules`);
