"""Command line interface."""

import argparse
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import List, Optional

from . import __version__, enrich, parser, policy, scanners, versions

ENRICH_WORKERS = 8

INIT_TEMPLATE = '''// deph v1 policy for this repository.
// Grammar: https://github.com/sayyedfaisal06/deph-cli/blob/main/docs/SPEC.md
//
// `deph scan` rewrites everything below the generated marker. Everything
// above it is yours and is preserved byte-for-byte: policy, waivers, and
// any comments you leave here.

policy {
  // Fail on high and critical vulnerabilities, warn on the rest.
  fail vuln     >= high
  warn vuln     >= low

  // Licenses allowed here. "MIT OR Apache-2.0" passes if either is listed.
  // These are the permissive ones that turn up throughout any real dependency
  // tree; a list that rejects tslib or minimatch just trains you to ignore
  // the output. Copyleft is deliberately absent: LGPL and GPL are decisions
  // to make per dependency, with a waiver and a reason.
  fail license  not [MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, MPL-2.0,
                     0BSD, BlueOak-1.0.0, CC0-1.0, CC-BY-4.0, Unlicense,
                     Python-2.0, Zlib, PSF-2.0, WTFPL]

  // A full major version behind is worth knowing about, but not worth
  // failing a build over. Only for code you ship.
  warn lag      >= major for prod

  // Warn if anything in a manifest couldn't be pinned to a version, because
  // deph cannot audit what it cannot resolve and a quietly partial scan is
  // worse than a loud failure.
  warn unresolved >= 1
}

// Rules can be narrowed with `for direct`, `for transitive`, `for dev` or
// `for prod` when the tail behind your own dependencies deserves less noise:
//
//   fail vuln >= high for direct
//   warn vuln >= high for transitive

// Accept a specific finding, with a reason, until you deal with it:
// waive GHSA-xxxx-yyyy-zzzz "vendored code not exposed; upgrade planned Q3"
'''


def _err(msg: str) -> None:
    print("deph: %s" % msg, file=sys.stderr)


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _iso_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _write_atomic(path: str, content: str) -> None:
    # Temp file in the same directory, then rename: a crash or a Ctrl-C
    # halfway through must not leave a half-written .deph behind.
    tmp = "%s.tmp.%d" % (path, os.getpid())
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(content)
    try:
        os.replace(tmp, path)
    except OSError:
        os.unlink(tmp)
        raise


def find_deph_file(explicit: Optional[str], cwd: str = ".") -> str:
    """The one .deph file under cwd, or exit 2.

    Several .deph files is an error rather than a heuristic: picking the wrong
    one would silently audit the wrong policy.
    """
    if explicit:
        if not os.path.exists(explicit):
            _err("file not found: %s" % explicit)
            raise SystemExit(2)
        return explicit
    candidates: List[str] = []
    for dirpath, dirnames, filenames in os.walk(cwd):
        dirnames[:] = sorted(d for d in dirnames if d not in scanners.SKIP_DIRS)
        for f in sorted(filenames):
            if f.endswith(".deph"):
                candidates.append(os.path.join(dirpath, f))
    if not candidates:
        _err("no .deph file found; run `deph init` to create one")
        raise SystemExit(2)
    if len(candidates) > 1:
        _err("multiple .deph files found, use --file to pick one:\n  %s"
             % "\n  ".join(candidates))
        raise SystemExit(2)
    return candidates[0]


def _parse_or_die(path: str) -> parser.Document:
    try:
        return parser.parse_file(path)
    except parser.DephSyntaxError as e:
        _err(str(e))
        raise SystemExit(2) from None


def cmd_init(args) -> int:
    path = args.file or "repo.deph"
    if os.path.exists(path):
        _err("%s already exists, refusing to overwrite it" % path)
        return 1
    with open(path, "w", encoding="utf-8") as f:
        f.write(INIT_TEMPLATE)
    print("Created %s" % path)
    print("Now run `deph scan`.")
    return 0


def cmd_scan(args) -> int:
    path = find_deph_file(args.file)
    # Parse before writing anything: the whole header has to survive, and the
    # write at the end replaces the file wholesale.
    doc = _parse_or_die(path)

    # The .deph file normally lives at the root of the tree it describes. --root
    # separates them, for auditing a checkout you don't want to write into.
    root = os.path.abspath(args.root) if args.root \
        else os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(root):
        _err("not a directory: %s" % root)
        return 2
    discovered = scanners.discover(root)
    if not discovered:
        print("No manifests found under %s" % root)

    enricher = enrich.Enricher(offline=args.offline, source=args.advisories)
    doc.projects = []
    for dp in discovered:
        scanner = scanners.scanner_for(dp.ecosystem)
        try:
            scanned = scanner.scan(dp.manifest_abspath)
        except Exception as e:  # noqa: BLE001 - skip the manifest, keep going
            enricher.warnings.append(
                "skipped %s (%s: %s)" % (dp.manifest, type(e).__name__, e))
            continue
        project = parser.Project(name=dp.name, ecosystem=dp.language,
                                 manifest=dp.manifest)
        raw_deps = scanned.sorted_deps()
        advisories = enricher.advisories(
            dp.language, [(d.name, d.version) for d in raw_deps])
        # One HTTP round trip per name, so do them concurrently; a thousand
        # deps serially is minutes of waiting. Enricher and Cache take locks.
        wanted = sorted({(d.name, d.version) for d in raw_deps})
        with ThreadPoolExecutor(max_workers=ENRICH_WORKERS) as pool:
            metas = dict(zip(wanted, pool.map(
                lambda nv, eco=dp.language: enricher.package_meta(
                    eco, nv[0], nv[1]),
                wanted)))
        for raw in raw_deps:
            project.deps.append(_build_dep(
                raw, metas[(raw.name, raw.version)],
                advisories.get((raw.name, raw.version), []), dp.language))
        for item in scanned.sorted_unresolved():
            project.unresolved.append(parser.UnresolvedEntry(
                spec=item.spec, reason=item.reason, name=item.name))
        if not project.deps and not project.unresolved:
            # Nothing to say about it. Real repos are full of package.json and
            # pyproject.toml files with no dependencies (test fixtures, docs
            # builds, examples), and a block per each is noise in the diff.
            continue
        doc.projects.append(project)
        note = "%d deps" % len(project.deps)
        if project.unresolved:
            note += ", %d unresolved" % len(project.unresolved)
        print("  scanned %-28s %-9s (%s)" % (dp.name, dp.language, note))

    doc.has_generated_section = True
    _write_atomic(path, parser.render(doc, timestamp=_timestamp()))

    for w in enricher.warnings:
        _err("warning: %s" % w)
    total = sum(len(p.deps) for p in doc.projects)
    unresolved = sum(len(p.unresolved) for p in doc.projects)
    summary = "Wrote %s (%d projects, %d dependencies" % (
        path, len(doc.projects), total)
    if unresolved:
        summary += ", %d unresolved" % unresolved
    print(summary + ")")
    if unresolved:
        _err("warning: %d dependenc%s could not be pinned to a version and "
             "were not audited; run `deph check` for the breakdown"
             % (unresolved, "y" if unresolved == 1 else "ies"))
    return 0


def _build_dep(raw, meta, advisories, ecosystem: str) -> parser.Dep:
    dep = parser.Dep(name=raw.name, version=raw.version,
                     transitive=raw.transitive, dev=raw.dev)
    if meta.license:
        dep.license = meta.license
    tags: List[parser.Tag] = []
    fixes: List[str] = []
    for adv in advisories:
        tags.append(parser.Tag(
            kind="vuln",
            parts=[policy.normalize_severity(adv.severity), adv.id]))
        if adv.fixed:
            fixes.append(adv.fixed)
        if adv.cwe and "cwe" not in dep.attrs:
            dep.attrs["cwe"] = adv.cwe
        # The CVSS vector deliberately doesn't go in the file. It's 40-odd
        # characters that make every dep line unreadable in a diff, the
        # severity is already derived from it, and the advisory link has it.
    if fixes:
        # The upgrade that clears every advisory on this dep is the highest of
        # the individual fixed versions, not the lowest.
        best = fixes[0]
        for candidate in fixes[1:]:
            if versions.compare(candidate, best, ecosystem) > 0:
                best = candidate
        dep.attrs["fix"] = best
    if meta.yanked:
        tags.append(parser.Tag(kind="yanked", parts=[]))
        dep.attrs["yanked"] = meta.yanked[:80]
    if meta.deprecated:
        tags.append(parser.Tag(kind="deprecated", parts=[]))
        dep.attrs["deprecated"] = meta.deprecated[:80]
    if meta.latest:
        lag = versions.classify_lag(raw.version, meta.latest, ecosystem)
        if lag:
            dep.latest = meta.latest
            tags.append(parser.Tag(kind="lag", parts=[lag]))
    dep.tags = tags
    return dep


_GHA_LEVEL = {policy.FAIL: "error", policy.WARN: "warning"}


def cmd_check(args) -> int:
    path = find_deph_file(args.file)
    doc = _parse_or_die(path)
    findings = policy.evaluate(doc)
    summary = policy.Summary.of(findings)
    code = policy.exit_code(findings)

    if args.format == "json":
        print(json.dumps(check_json(path, doc, findings, summary, code),
                         indent=2, sort_keys=True))
        return code
    if args.format == "sarif":
        from . import report
        print(report.dumps(report.sarif(doc, findings, deph_file=path)))
        return code

    order = {policy.FAIL: 0, policy.WARN: 1, policy.WAIVED: 2}
    findings.sort(key=lambda f: (order.get(f.level, 3), f.project, f.dep))
    gha = os.environ.get("GITHUB_ACTIONS") == "true"
    for f in findings:
        line = "  %-6s %-11s %-20s %s" % (f.level.upper(), f.kind, f.project,
                                          f.message)
        if f.level == policy.WAIVED and f.waived_reason:
            line += "  (waived: %s)" % f.waived_reason
        elif f.waiver_expired:
            line += "  (waiver expired)"
        print(line)
        if gha and f.level in _GHA_LEVEL:
            print("::%s file=%s::%s" % (_GHA_LEVEL[f.level], path, f.message))

    unresolved = sum(len(p.unresolved) for p in doc.projects)
    audited = sum(len(p.deps) for p in doc.projects)
    print("deph check: %s (%d fail, %d warn, %d waived)"
          % ("FAIL" if code else "OK",
             summary.fail, summary.warn, summary.waived))
    print("  audited %d dependencies across %d projects%s"
          % (audited, len(doc.projects),
             "; %d could not be pinned and were skipped" % unresolved
             if unresolved else ""))
    return code


def check_json(path: str, doc, findings, summary, code: int) -> dict:
    # Schema 2, documented in the README. Add fields, don't repurpose them.
    # Schema 1 lacked coverage/unresolved, which made an incomplete scan
    # indistinguishable from a clean one to anything consuming this.
    audited = sum(len(p.deps) for p in doc.projects)
    unresolved = sum(len(p.unresolved) for p in doc.projects)
    by_reason: dict = {}
    for project in doc.projects:
        for entry in project.unresolved:
            by_reason[entry.reason] = by_reason.get(entry.reason, 0) + 1
    return {
        "schema": 2,
        "file": path,
        "ok": code == 0,
        "summary": {"fail": summary.fail, "warn": summary.warn,
                    "waived": summary.waived},
        "coverage": {
            "audited": audited,
            "unresolved": unresolved,
            "unresolved_by_reason": by_reason,
            "projects": len(doc.projects),
        },
        "findings": [f.to_dict() for f in findings],
    }


def cmd_validate(args) -> int:
    path = find_deph_file(args.file)
    try:
        doc = parser.parse_file(path)
    except parser.DephSyntaxError as e:
        print("%s:%d:%d: error: %s" % (e.file, e.line, e.col, e.message))
        return 1
    issues = parser.lint(doc, today=policy.today_utc())
    for issue in issues:
        print(issue.format(path))
    errors = sum(1 for i in issues if i.severity == "error")
    if errors:
        print("deph validate: %d error(s), %d warning(s)"
              % (errors, len(issues) - errors))
        return 1
    print("deph validate: OK (%d project(s), %d policy rule(s)%s)"
          % (len(doc.projects), len(doc.policy),
             ", %d warning(s)" % len(issues) if issues else ""))
    return 0


def cmd_studio(args) -> int:
    from .studio import server
    path = find_deph_file(args.file)
    _parse_or_die(path)          # complain now, not on the first request
    return server.serve(path, port=args.port, open_browser=not args.no_open)


def cmd_render(args) -> int:
    from .studio import build_html
    path = find_deph_file(args.file)
    doc = _parse_or_die(path)
    _write_atomic(args.output, build_html(doc))
    print("Wrote %s" % args.output)
    return 0


def cmd_sbom(args) -> int:
    from . import report
    path = find_deph_file(args.file)
    doc = _parse_or_die(path)
    payload = report.cyclonedx(doc, timestamp=_iso_timestamp())
    text = report.dumps(payload)
    if args.output and args.output != "-":
        _write_atomic(args.output, text + "\n")
        print("Wrote %s (%d components, %d vulnerabilities)"
              % (args.output, len(payload["components"]),
                 len(payload["vulnerabilities"])))
    else:
        print(text)
    unresolved = sum(len(p.unresolved) for p in doc.projects)
    if unresolved:
        _err("warning: %d unpinned dependenc%s absent from this SBOM"
             % (unresolved, "y is" if unresolved == 1 else "ies are"))
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="deph",
        description="Audit npm, pip and cargo dependencies for known "
                    "vulnerabilities, outdated versions and disallowed "
                    "licenses, against the policy in your .deph file.")
    p.add_argument("--version", action="version", version="deph %s" % __version__)
    sub = p.add_subparsers(dest="command", metavar="command")

    def add(name, func, help_):
        sp = sub.add_parser(name, help=help_)
        sp.set_defaults(func=func)
        sp.add_argument("--file", metavar="PATH.deph", default=None,
                        help="path to the .deph file (default: auto-discover)")
        return sp

    add("init", cmd_init, "write a repo.deph with a starting policy")

    sp = add("scan", cmd_scan,
             "find manifests, look up versions and advisories, rewrite the "
             "generated half of the .deph file")
    sp.add_argument("--offline", action="store_true",
                    help="read the cache only, make no network requests")
    sp.add_argument("--advisories", choices=["osv", "github"], default="osv",
                    help="vulnerability source (default: osv, which "
                         "aggregates GHSA, PyPA, RustSec and more)")
    sp.add_argument("--root", metavar="DIR", default=None,
                    help="directory to scan (default: the .deph file's own "
                         "directory). Use it to audit a repo without writing "
                         "anything into it.")

    sp = add("check", cmd_check,
             "apply the policy to what's in the file and exit 1 if anything "
             "fails; makes no network requests")
    sp.add_argument("--format", choices=["text", "json", "sarif"],
                    default="text",
                    help="output format (default: text). sarif feeds GitHub "
                         "code scanning")

    add("validate", cmd_validate, "check the .deph file parses and lints clean")

    sp = add("sbom", cmd_sbom, "write a CycloneDX SBOM of the scanned deps")
    sp.add_argument("-o", "--output", default="-",
                    help="output path, or - for stdout (default: -)")

    sp = add("studio", cmd_studio, "serve the dashboard on localhost")
    sp.add_argument("--port", type=int, default=5397,
                    help="port to listen on (default: 5397)")
    sp.add_argument("--no-open", action="store_true",
                    help="don't open a browser")

    sp = add("render", cmd_render, "write the dashboard to a single HTML file")
    sp.add_argument("-o", "--output", default="deph-report.html",
                    help="output path (default: deph-report.html)")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    if not getattr(args, "func", None):
        build_arg_parser().print_help()
        return 2
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
