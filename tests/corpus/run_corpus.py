#!/usr/bin/env python3
"""Scan real repositories and report what deph could and could not read.

Hand-written fixtures only ever contain shapes I thought of. This clones a
handful of real projects and checks that discovery finds their manifests, that
the scanners return something, and that nothing raises. Run by CI on a
schedule, or locally with:

    python tests/corpus/run_corpus.py --workdir /tmp/deph-corpus

Exit codes: 0 all expectations met, 1 an expectation failed, 2 setup failed.
"""

import argparse
import json
import os
import subprocess
import sys
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "src"))

from deph import scanners  # noqa: E402


def clone(repo: dict, workdir: str) -> str:
    dest = os.path.join(workdir, repo["name"].replace("/", "__"))
    if os.path.isdir(os.path.join(dest, ".git")):
        return dest
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    # Shallow clone of one tag: the whole history is megabytes we don't need.
    cmd = ["git", "clone", "--depth", "1", "--branch", repo["ref"],
           "--quiet", repo["url"], dest]
    subprocess.run(cmd, check=True, timeout=600)
    return dest


def scan_repo(path: str):
    """-> (rows, failures). Never raises: a crash is a result, not an abort."""
    rows = []
    failures = []
    for dp in scanners.discover(path):
        try:
            result = scanners.scanner_for(dp.ecosystem).scan(dp.manifest_abspath)
        except Exception:                                   # noqa: BLE001
            failures.append("%s (%s): %s" % (dp.manifest, dp.ecosystem,
                                             traceback.format_exc(limit=2)))
            continue
        reasons: dict = {}
        for item in result.unresolved:
            reasons[item.reason] = reasons.get(item.reason, 0) + 1
        rows.append({
            "manifest": dp.manifest,
            "ecosystem": dp.ecosystem,
            "deps": len(result.deps),
            "unresolved": len(result.unresolved),
            "reasons": reasons,
            "direct": sum(1 for d in result.deps if not d.transitive),
            "dev": sum(1 for d in result.deps if d.dev),
        })
    return rows, failures


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workdir", default="/tmp/deph-corpus")
    ap.add_argument("--repos", default=os.path.join(HERE, "repos.json"))
    ap.add_argument("--only", default=None, help="substring filter on name")
    ap.add_argument("--json", dest="as_json", action="store_true")
    args = ap.parse_args()

    with open(args.repos, "r", encoding="utf-8") as f:
        config = json.load(f)
    repos = [r for r in config["repos"]
             if not args.only or args.only in r["name"]]
    os.makedirs(args.workdir, exist_ok=True)

    report = []
    problems = []
    for repo in repos:
        try:
            path = clone(repo, args.workdir)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            print("SETUP FAIL %s: %s" % (repo["name"], e), file=sys.stderr)
            return 2

        rows, failures = scan_repo(path)
        total_deps = sum(r["deps"] for r in rows)
        found = {os.path.basename(r["manifest"]) for r in rows}

        for crash in failures:
            problems.append("%s: scanner raised on %s" % (repo["name"], crash))
        for expected in repo.get("expect_manifests", []):
            # A repo may legitimately not commit a lockfile; only complain if
            # the file is present in the tree but discovery missed it.
            present = any(expected in files
                          for _, _, files in os.walk(path))
            if present and expected not in found:
                problems.append(
                    "%s: %s exists but discovery did not pick it up"
                    % (repo["name"], expected))
        if total_deps < repo.get("expect_min_deps", 0):
            problems.append("%s: %d deps, expected at least %d"
                            % (repo["name"], total_deps,
                               repo["expect_min_deps"]))

        report.append({"repo": repo["name"], "ref": repo["ref"],
                       "projects": rows, "total_deps": total_deps,
                       "crashes": len(failures)})

    if args.as_json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        _print_table(report)

    if problems:
        print("\nProblems:", file=sys.stderr)
        for p in problems:
            print("  - %s" % p, file=sys.stderr)
        return 1
    print("\nAll corpus expectations met.")
    return 0


def _print_table(report) -> None:
    print("%-26s %-22s %-9s %6s %6s  %s"
          % ("repo", "manifest", "ecosystem", "deps", "unres", "reasons"))
    print("-" * 100)
    for entry in report:
        if not entry["projects"]:
            print("%-26s %s" % (entry["repo"], "(no manifests found)"))
        for row in entry["projects"]:
            reasons = ", ".join("%s=%d" % (k, v)
                                for k, v in sorted(row["reasons"].items()))
            print("%-26s %-22s %-9s %6d %6d  %s"
                  % (entry["repo"], os.path.basename(row["manifest"])[:22],
                     row["ecosystem"], row["deps"], row["unresolved"],
                     reasons))


if __name__ == "__main__":
    sys.exit(main())
