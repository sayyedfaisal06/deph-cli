"""uv.lock: the whole resolved graph, and not much else.

Read by hand for the same reason as cargo.py -- no tomllib on 3.9 -- and it
holds up here because uv writes the file itself: one [[package]] block per
package, with name, version and a single-line inline source table.

What uv.lock does *not* record is which packages the author asked for and
which the resolver pulled in, or which are only needed for development. That
information lives in pyproject.toml under specifiers that uv has already
resolved, and reconstructing it would mean re-implementing uv's group
handling. Guessing wrong here is worse than admitting we don't know, so every
dep comes back with transitive=False and dev=False.

The one thing uv.lock does mark clearly is the local project: workspace
members and editable installs get source = { virtual = "." } or
source = { editable = "..." }. Those are the repo's own code, not
dependencies, so they are dropped entirely rather than reported.
"""

import os
import re
from typing import Dict, List, Optional

from . import RawDep, ScanResult, Scanner, Unresolved, register
from .pip import normalize_name

_SECTION_RE = re.compile(r"^\s*\[+\s*([^\]]+?)\s*\]+\s*$")
_STR_KEY_RE = re.compile(r'^\s*([A-Za-z0-9_.-]+)\s*=\s*"([^"]*)"\s*$')
# source = { registry = "https://pypi.org/simple" }
_INLINE_SOURCE_RE = re.compile(r"^\s*source\s*=\s*\{(?P<body>.*)\}\s*$")
_FIRST_KEY_RE = re.compile(r"\s*([A-Za-z0-9_-]+)\s*=")

# The repo's own code, not a dependency.
_OWN_SOURCES = ("virtual", "editable")
_SOURCE_REASONS = {
    "git": "vcs",
    "url": "url",
    "path": "local",
    "directory": "local",
}


@register
class UvScanner(Scanner):
    ecosystem = "pip-uv"
    manifest_names = ("uv.lock",)
    # Pins everything, so it outranks pyproject.toml; behind poetry.lock only
    # because a repo with both almost certainly migrated away from poetry.
    priority = 12

    def scan(self, manifest_path: str) -> ScanResult:
        result = ScanResult()
        try:
            packages = self._parse_lock(manifest_path)
        except OSError:
            result.unresolved.append(Unresolved(
                spec=os.path.basename(manifest_path), reason="unparsed"))
            return result

        seen = set()
        for pkg in packages:
            name = pkg.get("name", "")
            if not name:
                result.unresolved.append(Unresolved(
                    spec=pkg.get("version", "") or "[[package]]",
                    reason="unparsed"))
                continue
            norm = normalize_name(name)
            kind = pkg.get("source", "")
            if kind in _OWN_SOURCES:
                continue

            reason = _SOURCE_REASONS.get(kind)
            if reason is not None:
                result.unresolved.append(Unresolved(
                    spec=pkg.get("source.url", "") or norm,
                    reason=reason, name=norm))
                continue

            version = pkg.get("version", "")
            if not version:
                result.unresolved.append(Unresolved(
                    spec=norm, reason="unparsed", name=norm))
                continue

            key = (norm, version)
            if key in seen:
                continue
            seen.add(key)
            # transitive/dev deliberately left False: see the module docstring.
            result.deps.append(RawDep(name=norm, version=version))
        result.deps.sort(key=lambda d: (d.name, d.version))
        return result

    @staticmethod
    def _parse_lock(path: str) -> List[Dict[str, str]]:
        """[[package]] blocks as flat dicts.

        "source" holds the *kind* of source (registry, git, virtual, ...) and
        "source.url" its value, whether it was written as an inline table on
        the source line or as a [package.source] sub-table.
        """
        packages: List[Dict[str, str]] = []
        # The table lines are currently landing in, and the [[package]] block
        # that any sub-table belongs to.
        current: Optional[Dict[str, str]] = None
        owner: Optional[Dict[str, str]] = None
        in_source = False
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                stripped = line.strip()
                if stripped == "[[package]]":
                    current = {}
                    owner = current
                    in_source = False
                    packages.append(current)
                    continue
                m = _SECTION_RE.match(stripped)
                if m:
                    # uv normally inlines the source table, but accept the
                    # expanded [package.source] form too.
                    if m.group(1) == "package.source" and owner is not None:
                        current, in_source = owner, True
                    else:
                        current, in_source = None, False
                    continue
                if current is None:
                    continue
                sm = _INLINE_SOURCE_RE.match(line)
                if sm and not in_source:
                    _store_source(current, sm.group("body"))
                    continue
                km = _STR_KEY_RE.match(line)
                if not km:
                    continue
                if in_source:
                    current["source"] = km.group(1)
                    current["source.url"] = km.group(2)
                else:
                    current[km.group(1)] = km.group(2)
        return packages


def _store_source(pkg: Dict[str, str], body: str) -> None:
    """Record the first key of an inline source table and its value.

    A source table has exactly one meaningful key -- registry, git, url,
    editable, virtual, path, directory -- so the first one names the kind. Any
    trailing keys (git's subdirectory, for instance) are only detail.
    """
    m = _FIRST_KEY_RE.match(body)
    if not m:
        return
    pkg["source"] = m.group(1)
    vm = re.search(r'=\s*"([^"]*)"', body)
    if vm:
        pkg["source.url"] = vm.group(1)
