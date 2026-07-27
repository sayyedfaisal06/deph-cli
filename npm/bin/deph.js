#!/usr/bin/env node
"use strict";

// Runs the vendored Python package with whatever interpreter is on the box.
//
// deph has no Python dependencies, so there is nothing to install: point
// PYTHONPATH at the vendored source and run it. That is the whole reason this
// wrapper can be a few lines instead of a binary download.

const { spawnSync } = require("child_process");
const path = require("path");
const fs = require("fs");

const VENDOR = path.join(__dirname, "..", "vendor");
const MIN = [3, 9];

// Exit 2 means "couldn't get far enough to judge", which is exactly what a
// missing interpreter is. Matches the CLI's own exit-code contract.
const EXIT_CANNOT_RUN = 2;

function candidates() {
  // DEPH_PYTHON is exclusive, not a hint. Someone who names an interpreter
  // wants that one; falling back to another silently would mean the override
  // appears to work while doing nothing.
  const fromEnv = process.env.DEPH_PYTHON;
  if (fromEnv) return [fromEnv];
  return process.platform === "win32"
    ? ["python", "python3", "py"]
    : ["python3", "python"];
}

function versionOf(exe) {
  const args =
    exe === "py"
      ? ["-3", "-c", "import sys;print('%d.%d' % sys.version_info[:2])"]
      : ["-c", "import sys;print('%d.%d' % sys.version_info[:2])"];
  const probe = spawnSync(exe, args, { encoding: "utf8" });
  if (probe.error || probe.status !== 0) return null;
  const parts = String(probe.stdout).trim().split(".");
  const major = Number(parts[0]);
  const minor = Number(parts[1]);
  if (!Number.isInteger(major) || !Number.isInteger(minor)) return null;
  return [major, minor];
}

function atLeast(found, min) {
  return found[0] > min[0] || (found[0] === min[0] && found[1] >= min[1]);
}

function findPython() {
  const tooOld = [];
  for (const exe of candidates()) {
    const version = versionOf(exe);
    if (!version) continue;
    if (atLeast(version, MIN)) {
      return { exe, version };
    }
    tooOld.push(`${exe} (${version.join(".")})`);
  }
  return { exe: null, tooOld };
}

function fail(lines) {
  for (const line of lines) process.stderr.write(`${line}\n`);
  process.exit(EXIT_CANNOT_RUN);
}

if (!fs.existsSync(path.join(VENDOR, "deph", "cli.py"))) {
  fail([
    "deph: the vendored Python source is missing from this package.",
    "This is a packaging bug; please report it at",
    "https://github.com/sayyedfaisal06/deph/issues",
  ]);
}

const found = findPython();
if (!found.exe) {
  if (process.env.DEPH_PYTHON) {
    fail([
      `deph: DEPH_PYTHON is set to ${JSON.stringify(process.env.DEPH_PYTHON)}, `
        + `which is not a usable Python ${MIN.join(".")}+ interpreter.`,
      "Unset it to search PATH instead.",
    ]);
  }
  const lines = [
    `deph needs Python ${MIN.join(".")} or newer on PATH.`,
    "",
    "It ships no Python dependencies, so an interpreter is all it wants:",
    "  macOS     already has one, or: brew install python",
    "  Debian    sudo apt install python3",
    "  Windows   https://www.python.org/downloads/ (tick 'Add to PATH')",
    "",
    "Set DEPH_PYTHON to point at a specific interpreter if it isn't on PATH.",
  ];
  if (found.tooOld && found.tooOld.length) {
    lines.splice(1, 0, `Found, but too old: ${found.tooOld.join(", ")}.`);
  }
  fail(lines);
}

const args =
  found.exe === "py"
    ? ["-3", "-m", "deph.cli", ...process.argv.slice(2)]
    : ["-m", "deph.cli", ...process.argv.slice(2)];

const env = Object.assign({}, process.env, {
  PYTHONPATH: process.env.PYTHONPATH
    ? `${VENDOR}${path.delimiter}${process.env.PYTHONPATH}`
    : VENDOR,
  // Unbuffered, so piping `deph check` into another process streams rather
  // than arriving all at once when the interpreter exits.
  PYTHONUNBUFFERED: "1",
});

const run = spawnSync(found.exe, args, { stdio: "inherit", env });

if (run.error) {
  fail([`deph: could not start ${found.exe}: ${run.error.message}`]);
}

// The exit code is a documented contract (0 clean, 1 policy failure, 2 could
// not judge, 130 interrupted), so pass it through untouched.
if (run.signal) {
  process.exit(run.signal === "SIGINT" ? 130 : 1);
}
process.exit(run.status === null ? EXIT_CANNOT_RUN : run.status);
