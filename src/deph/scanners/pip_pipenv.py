"""Pipfile.lock, plus the Pipfile beside it for which packages are direct.

The lockfile is JSON, so this scanner gets to use the stdlib instead of
guessing at TOML. The Pipfile it reads for the direct set is TOML, and gets
the same by-hand treatment as cargo.py.

pipenv splits the graph into "default" and "develop" and pins both, including
transitive packages, with the same "==x.y.z" string. Entries that were never
resolved to a registry version -- git checkouts, local paths, direct wheel
URLs -- carry a "git"/"path"/"file" key instead of "version" and go to the
unresolved channel rather than being dropped.
"""

import json
import os
import re
from typing import Any, Dict, Set

from . import RawDep, ScanResult, Scanner, Unresolved, register
from .pip import normalize_name

_SECTION_RE = re.compile(r"^\s*\[+\s*([^\]]+?)\s*\]+\s*$")
_DEP_LINE_RE = re.compile(r'^\s*(?:"([^"]+)"|([A-Za-z0-9][A-Za-z0-9._-]*))\s*=')

# Keys pipenv writes in place of "version", and why each one can't be pinned.
# Order matters: a git entry also carries a "ref", so check the origin keys in
# the order that names the origin most specifically.
_ORIGIN_REASONS = (
    ("git", "vcs"),
    ("hg", "vcs"),
    ("svn", "vcs"),
    ("bzr", "vcs"),
    ("path", "local"),
    ("file", "url"),
)


@register
class PipenvScanner(Scanner):
    ecosystem = "pip-pipenv"
    manifest_names = ("Pipfile.lock",)
    # Pins the full graph, so it wins over pyproject.toml and requirements.txt
    # in the same directory, but yields to a poetry.lock if somehow both exist.
    priority = 15

    def scan(self, manifest_path: str) -> ScanResult:
        result = ScanResult()
        try:
            with open(manifest_path, "r", encoding="utf-8",
                      errors="replace") as f:
                data = json.load(f)
        except (OSError, ValueError):
            result.unresolved.append(Unresolved(
                spec=os.path.basename(manifest_path), reason="unparsed"))
            return result
        if not isinstance(data, dict):
            result.unresolved.append(Unresolved(
                spec=os.path.basename(manifest_path), reason="unparsed"))
            return result

        declared = self._declared(
            os.path.join(os.path.dirname(manifest_path), "Pipfile"))

        seen: Set[str] = set()
        # "default" first: a package in both groups is something the app needs
        # at runtime, and the runtime answer is the one that should stick.
        for group, dev in (("default", False), ("develop", True)):
            section = data.get(group)
            if not isinstance(section, dict):
                continue
            for raw_name in sorted(section):
                info = section[raw_name]
                norm = normalize_name(str(raw_name))
                if norm in seen:
                    continue
                if not isinstance(info, dict):
                    result.unresolved.append(Unresolved(
                        spec=str(raw_name), reason="unparsed", name=norm))
                    seen.add(norm)
                    continue

                version = info.get("version")
                if not isinstance(version, str) or not version.strip():
                    reason, spec = _origin(raw_name, info)
                    result.unresolved.append(Unresolved(
                        spec=spec, reason=reason, name=norm))
                    seen.add(norm)
                    continue

                version = version.strip()
                if not version.startswith("=="):
                    # pipenv normally writes exact pins; a specifier here means
                    # the lock was hand-edited or came from another tool.
                    result.unresolved.append(Unresolved(
                        spec="%s%s" % (raw_name, version),
                        reason="range", name=norm))
                    seen.add(norm)
                    continue

                pinned = version[2:].strip()
                if not pinned:
                    result.unresolved.append(Unresolved(
                        spec="%s%s" % (raw_name, version),
                        reason="unparsed", name=norm))
                    seen.add(norm)
                    continue

                seen.add(norm)
                result.deps.append(RawDep(
                    name=norm, version=pinned, dev=dev,
                    # Only the Pipfile knows which of these the author asked
                    # for; with no Pipfile nothing is marked transitive.
                    transitive=bool(declared) and norm not in declared))
        result.deps.sort(key=lambda d: (d.name, d.version))
        return result

    @staticmethod
    def _declared(pipfile: str) -> Set[str]:
        """Names under [packages] and [dev-packages] in the Pipfile."""
        declared: Set[str] = set()
        if not os.path.exists(pipfile):
            return declared
        in_table = False
        try:
            with open(pipfile, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.split("#", 1)[0]
                    m = _SECTION_RE.match(line)
                    if m:
                        section = m.group(1).strip()
                        parts = [p.strip() for p in section.split(".")]
                        if len(parts) == 2 and parts[0] in _DEP_TABLES:
                            # [packages.foo] names foo; its own keys are not
                            # package names, so stop scanning lines.
                            declared.add(normalize_name(parts[1].strip("'\"")))
                            in_table = False
                        else:
                            in_table = section in _DEP_TABLES
                        continue
                    if not in_table:
                        continue
                    dm = _DEP_LINE_RE.match(line)
                    if dm:
                        declared.add(normalize_name(dm.group(1) or dm.group(2)))
        except OSError:
            return set()
        declared.discard("")
        return declared


_DEP_TABLES = ("packages", "dev-packages")


def _origin(raw_name: Any, info: Dict[str, Any]) -> tuple:
    """(reason, spec) for a lock entry that has no resolved version."""
    for key, reason in _ORIGIN_REASONS:
        value = info.get(key)
        if isinstance(value, str) and value:
            return reason, "%s @ %s" % (raw_name, value)
    return "unparsed", str(raw_name)
