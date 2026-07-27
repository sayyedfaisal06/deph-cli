#!/usr/bin/env node
"use strict";

// Copies src/deph into npm/vendor/deph so the published tarball is
// self-contained. Runs from `prepack`, so `npm pack` and `npm publish` can
// never ship a stale copy.
//
// It also checks that the two version numbers agree: an npm package claiming
// 0.2.0 while vendoring 0.1.0 would be a lie users can't see.

const fs = require("fs");
const path = require("path");

const NPM_DIR = path.join(__dirname, "..");
const SRC = path.join(NPM_DIR, "..", "src", "deph");
const DEST = path.join(NPM_DIR, "vendor", "deph");

const SKIP_DIRS = new Set(["__pycache__", ".mypy_cache", ".pytest_cache"]);
const SKIP_FILES = /\.(pyc|pyo)$/;

function copyDir(from, to) {
  fs.mkdirSync(to, { recursive: true });
  for (const entry of fs.readdirSync(from, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      copyDir(path.join(from, entry.name), path.join(to, entry.name));
    } else if (!SKIP_FILES.test(entry.name)) {
      fs.copyFileSync(path.join(from, entry.name), path.join(to, entry.name));
    }
  }
}

function pythonVersion() {
  const init = fs.readFileSync(path.join(SRC, "__init__.py"), "utf8");
  const m = init.match(/__version__\s*=\s*["']([^"']+)["']/);
  return m ? m[1] : null;
}

if (!fs.existsSync(SRC)) {
  console.error(`sync-python: ${SRC} not found. Run this from the repo, not `
    + `from an installed package.`);
  process.exit(1);
}

const pkg = JSON.parse(fs.readFileSync(path.join(NPM_DIR, "package.json"), "utf8"));
const pyVersion = pythonVersion();
if (pyVersion && pyVersion !== pkg.version) {
  console.error(
    `sync-python: version mismatch. package.json is ${pkg.version} but `
    + `src/deph/__init__.py is ${pyVersion}. Bump both.`);
  process.exit(1);
}

fs.rmSync(DEST, { recursive: true, force: true });
copyDir(SRC, DEST);

// The dashboard template is package data, not code; a missing one would only
// show up when someone ran `deph studio`.
const template = path.join(DEST, "studio", "template.html");
if (!fs.existsSync(template)) {
  console.error("sync-python: studio/template.html did not get copied.");
  process.exit(1);
}

const files = [];
(function walk(dir) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p);
    else files.push(p);
  }
})(DEST);

console.log(`sync-python: vendored deph ${pyVersion} (${files.length} files)`);
