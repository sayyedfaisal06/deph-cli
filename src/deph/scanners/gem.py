"""Gemfile.lock, read by indentation.

Bundler writes a small, strict shape: top-level section headers in caps at
column zero, two-space keys under them, and under `specs:` one line per gem
with its version in parentheses, then that gem's own requirements indented
further. That last level is the trap -- `activesupport (= 7.0.4)` under
`actionpack` is a constraint, not a locked version, and every gem named there
has its own line at the shallower level anyway. So only the shallowest level
inside a `specs:` block is read as dependencies.

What the file does and doesn't say:

DEPENDENCIES at the bottom is the Gemfile's own list, so it is the direct set;
everything in GEM specs that isn't in it got pulled in by something else.

GIT and PATH sections describe gems built from a checkout or a directory. Their
"version" is whatever the gemspec claimed at the time, which is not a released
version anyone can look up, so they go to the unresolved channel.

Bundler does not record Gemfile groups, so a lockfile cannot tell you that
rspec is test-only. dev stays False everywhere rather than being guessed at
from gem names.
"""

import os
import re
from typing import List, Optional, Set, Tuple

from . import RawDep, ScanResult, Scanner, Unresolved, register

# Sections with a specs: block, and why the gems in each can't be pinned.
_SOURCE_SECTIONS = {
    "GEM": "",
    "PATH": "local",
    "GIT": "vcs",
    "PLUGIN SOURCE": "local",
}
_SECTIONS = set(_SOURCE_SECTIONS) | {
    "DEPENDENCIES", "PLATFORMS", "RUBY VERSION", "BUNDLED WITH", "CHECKSUMS",
}

#   actionpack (7.0.4)
_SPEC_RE = re.compile(r"^(?P<name>[^\s()]+)\s+\((?P<version>[^()]*)\)$")
#   actionpack (~> 7.0)   |   mygem!   |   mygem (>= 0)!
_DEP_RE = re.compile(
    r"^(?P<name>[^\s()!]+)\s*(?:\((?P<req>[^()]*)\))?\s*!?$")


@register
class GemScanner(Scanner):
    ecosystem = "gem"
    manifest_names = ("Gemfile.lock",)
    # There is no second Ruby manifest format to lose to, but a Gemfile.lock
    # pins versions and a Gemfile does not, so leave room below 50.
    priority = 10

    def scan(self, manifest_path: str) -> ScanResult:
        result = ScanResult()
        try:
            with open(manifest_path, "r", encoding="utf-8",
                      errors="replace") as f:
                lines = f.readlines()
        except OSError:
            result.unresolved.append(Unresolved(
                spec=os.path.basename(manifest_path), reason="unparsed"))
            return result

        try:
            specs, blocked, declared, bad = _read(lines)
        except Exception:       # a lockfile must never take down a scan
            result.unresolved.append(Unresolved(
                spec=os.path.basename(manifest_path), reason="unparsed"))
            return result

        for name, version, reason, remote in blocked:
            result.unresolved.append(Unresolved(
                spec=("%s @ %s" % (name, remote) if remote
                      else "%s (%s)" % (name, version)),
                reason=reason, name=name))
        for spec in bad:
            result.unresolved.append(Unresolved(spec=spec, reason="unparsed"))

        unpinnable = {name for name, _, _, _ in blocked}
        seen: Set[Tuple[str, str]] = set()
        for name, version in specs:
            if name in unpinnable or (name, version) in seen:
                continue
            seen.add((name, version))
            result.deps.append(RawDep(
                name=name, version=version,
                # With no DEPENDENCIES section there is nothing to compare
                # against, so nothing is claimed to be transitive.
                transitive=bool(declared) and name not in declared))
        result.deps.sort(key=lambda d: (d.name, d.version))
        return result


_Read = Tuple[List[Tuple[str, str]], List[Tuple[str, str, str, str]],
              Set[str], List[str]]


def _read(lines: List[str]) -> _Read:
    """(specs, blocked, declared, bad) from a Gemfile.lock's lines.

    specs is [(name, version)] from GEM, blocked is
    [(name, version, reason, remote)] from GIT/PATH, declared is the
    DEPENDENCIES names, bad is lines inside a block that didn't parse.
    """
    specs: List[Tuple[str, str]] = []
    blocked: List[Tuple[str, str, str, str]] = []
    declared: Set[str] = set()
    bad: List[str] = []

    section = ""
    remote = ""
    # Indent of the "specs:" key, then of the gem lines under it. The gem
    # indent is learned from the first gem line rather than assumed to be four
    # spaces, because GIT sections nest one level deeper in some bundler
    # versions.
    specs_indent: Optional[int] = None
    gem_indent: Optional[int] = None

    for raw in lines:
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        indent = len(line) - len(line.lstrip(" \t"))
        if indent == 0:
            # Anything unrecognised at column zero -- a section from a newer
            # bundler, or binary noise -- silently skips its whole body.
            section = stripped if stripped in _SECTIONS else ""
            remote = ""
            specs_indent = None
            gem_indent = None
            continue

        if section == "DEPENDENCIES":
            match = _DEP_RE.match(stripped)
            if match:
                declared.add(match.group("name"))
            else:
                bad.append(stripped)
            continue

        if section not in _SOURCE_SECTIONS:
            continue

        if specs_indent is not None and indent <= specs_indent:
            # Back out to the key level: a source section can carry keys after
            # its specs: block in principle, so stop reading gems.
            specs_indent = None
            gem_indent = None

        if specs_indent is None:
            if stripped == "specs:":
                specs_indent = indent
            elif stripped.startswith("remote:"):
                remote = stripped[len("remote:"):].strip()
            # revision:, branch:, glob:, ref: -- metadata about the source.
            continue

        if gem_indent is None:
            gem_indent = indent
        if indent > gem_indent:
            continue        # this gem's own requirements, not locked versions

        match = _SPEC_RE.match(stripped)
        if match is None:
            bad.append(stripped)
            continue
        name = match.group("name")
        version = _clean_version(match.group("version"))
        if not version:
            bad.append(stripped)
            continue
        reason = _SOURCE_SECTIONS[section]
        if reason:
            blocked.append((name, version, reason, remote))
        else:
            specs.append((name, version))
    return specs, blocked, declared, bad


def _clean_version(version: str) -> str:
    """1.13.9-x86_64-linux -> 1.13.9.

    A dash in a locked gem version separates the platform from the version;
    rubygems spells prereleases with dots (1.0.0.pre.1), so nothing is lost.
    """
    version = version.strip()
    head = version.split("-", 1)[0].strip()
    return head or version
