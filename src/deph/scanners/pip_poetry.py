"""poetry.lock for pinned versions, pyproject.toml for which ones are direct.

Same constraint as cargo.py: tomllib is 3.11+ and deph supports 3.9, so this
reads the handful of keys it needs by hand. poetry.lock is machine-written and
very regular -- [[package]] blocks with name and version keys -- which is what
makes that safe. It is not a TOML parser and must not be used as one.

Two things about the format are worth knowing:

Poetry 1.1 tagged every locked package with category = "main" or "dev".
Poetry 1.2 dropped the field in favour of dependency groups, so for newer
locks dev-ness has to be recovered from pyproject.toml instead. Both paths are
supported, and the lock's own category wins when it is there.

Unlike Cargo.lock, poetry.lock does not list the root project among the
packages, so there is no own-package name to filter out.
"""

import os
import re
from typing import Dict, List, Optional, Set, Tuple

from . import RawDep, ScanResult, Scanner, Unresolved, register
from .pip import normalize_name

_SECTION_RE = re.compile(r"^\s*\[+\s*([^\]]+?)\s*\]+\s*$")
_STR_KEY_RE = re.compile(r'^\s*([A-Za-z0-9_.-]+)\s*=\s*"([^"]*)"\s*$')
_DEP_LINE_RE = re.compile(r'^\s*(?:"([^"]+)"|([A-Za-z0-9][A-Za-z0-9._-]*))\s*=')

# A [package.source] table means the version in the block came from somewhere
# other than a registry, so it can't be looked up or compared.
_SOURCE_REASONS = {
    "git": "vcs",
    "directory": "local",
    "file": "local",
    "url": "url",
    # "legacy" is a private index: a different registry, still a registry.
}


@register
class PoetryScanner(Scanner):
    ecosystem = "pip-poetry"
    manifest_names = ("poetry.lock",)
    # A poetry.lock pins the whole graph, so it beats the pyproject.toml next
    # to it and beats a requirements.txt export of the same environment.
    priority = 10

    def scan(self, manifest_path: str) -> ScanResult:
        result = ScanResult()
        try:
            packages = self._parse_lock(manifest_path)
        except OSError:
            result.unresolved.append(Unresolved(
                spec=os.path.basename(manifest_path), reason="unparsed"))
            return result

        pyproject = os.path.join(os.path.dirname(manifest_path),
                                 "pyproject.toml")
        prod, dev = self._declared(pyproject)
        declared = prod | dev

        seen = set()
        for pkg in packages:
            name = pkg.get("name", "")
            if not name:
                # A [[package]] block with no name at all: nothing to report it
                # under, but don't pretend the lock was fully understood.
                result.unresolved.append(Unresolved(
                    spec=pkg.get("version", "") or "[[package]]",
                    reason="unparsed"))
                continue
            norm = normalize_name(name)

            reason = _SOURCE_REASONS.get(pkg.get("source.type", ""))
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
            result.deps.append(RawDep(
                name=norm, version=version,
                # Only claim transitive when pyproject.toml told us what the
                # author actually asked for; otherwise everything looks direct.
                transitive=bool(declared) and norm not in declared,
                dev=pkg.get("category", "") == "dev"
                    or (norm in dev and norm not in prod),
            ))
        result.deps.sort(key=lambda d: (d.name, d.version))
        return result

    @staticmethod
    def _parse_lock(path: str) -> List[Dict[str, str]]:
        """[[package]] blocks as flat dicts, with source.* folded in.

        Poetry writes a package's origin in a [package.source] table directly
        after the block it belongs to, so those keys are stored on the block
        under a "source." prefix rather than losing them at the section break.
        """
        packages: List[Dict[str, str]] = []
        # The table lines are currently landing in, and the [[package]] block
        # that any sub-table belongs to.
        current: Optional[Dict[str, str]] = None
        owner: Optional[Dict[str, str]] = None
        prefix = ""
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                stripped = line.strip()
                if stripped == "[[package]]":
                    current = {}
                    owner = current
                    prefix = ""
                    packages.append(current)
                    continue
                m = _SECTION_RE.match(stripped)
                if m:
                    if m.group(1) == "package.source" and owner is not None:
                        current, prefix = owner, "source."
                    else:
                        current, prefix = None, ""
                    continue
                if current is not None:
                    km = _STR_KEY_RE.match(line)
                    if km:
                        current[prefix + km.group(1)] = km.group(2)
        return packages

    @staticmethod
    def _declared(pyproject: str) -> Tuple[Set[str], Set[str]]:
        """(main, dev) package names the author wrote down by hand.

        Recognises [tool.poetry.dependencies], the legacy
        [tool.poetry.dev-dependencies], and [tool.poetry.group.NAME.
        dependencies] -- any group other than "main" counts as dev, which is
        what `poetry install --without dev` effectively means for groups like
        "test" and "lint" too.
        """
        prod: Set[str] = set()
        dev: Set[str] = set()
        if not os.path.exists(pyproject):
            return prod, dev
        kind = ""
        try:
            with open(pyproject, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.split("#", 1)[0]
                    m = _SECTION_RE.match(line)
                    if m:
                        kind, header_name = _classify_table(m.group(1))
                        if header_name:
                            # [tool.poetry.dependencies.foo] names foo, and the
                            # lines under it are foo's settings, not packages.
                            _add(prod, dev, kind, header_name)
                            kind = ""
                        continue
                    if not kind:
                        continue
                    dm = _DEP_LINE_RE.match(line)
                    if dm:
                        _add(prod, dev, kind, dm.group(1) or dm.group(2))
        except OSError:
            return set(), set()
        return prod, dev


def _add(prod: Set[str], dev: Set[str], kind: str, name: str) -> None:
    # "python" is a constraint on the interpreter, not a PyPI package.
    if not name or name.lower() == "python":
        return
    (dev if kind == "dev" else prod).add(normalize_name(name))


def _classify_table(section: str) -> Tuple[str, str]:
    """Classify a pyproject table header.

    Returns (kind, name): kind is "main", "dev" or "" for anything that isn't
    a poetry dependency table, and name is non-empty only when the header
    itself names a package, as in [tool.poetry.dependencies.foo].
    """
    parts = [p.strip() for p in section.split(".")]
    if parts[:2] != ["tool", "poetry"]:
        return "", ""
    rest = parts[2:]
    name = ""
    if len(rest) >= 2 and rest[-2] in ("dependencies", "dev-dependencies"):
        name = rest[-1].strip("'\"")
        rest = rest[:-1]
    if rest == ["dependencies"]:
        return "main", name
    if rest == ["dev-dependencies"]:
        return "dev", name
    if len(rest) == 3 and rest[0] == "group" and rest[2] == "dependencies":
        group = rest[1].strip("'\"")
        return ("main" if group == "main" else "dev"), name
    return "", ""
