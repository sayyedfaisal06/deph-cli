"""Cargo.lock for the full dependency set, Cargo.toml for which are direct.

tomllib is 3.11+ and we support 3.9, so this reads the bits it needs by hand.
Cargo.lock is regular enough that this is fine: [[package]] blocks with name
and version keys. It is not a TOML parser and shouldn't be used as one.
"""

import os
import re
from typing import List, Optional, Set, Tuple

from . import RawDep, ScanResult, Scanner, Unresolved, register

_KEY_RE = re.compile(r'^\s*([A-Za-z0-9_-]+)\s*=\s*"([^"]*)"\s*$')
_SECTION_RE = re.compile(r"^\s*\[+\s*([^\]]+?)\s*\]+\s*$")
_DEP_LINE_RE = re.compile(r'^\s*([A-Za-z0-9_-]+)\s*=')
_DEV_SECTIONS = ("dev-dependencies", "build-dependencies")


@register
class CargoScanner(Scanner):
    ecosystem = "cargo"
    manifest_names = ("Cargo.lock",)
    priority = 10

    def scan(self, manifest_path: str) -> ScanResult:
        cargo_toml = os.path.join(os.path.dirname(manifest_path), "Cargo.toml")
        packages = self._parse_lock(manifest_path)
        direct, dev = self._dependency_tables(cargo_toml)
        # Cargo.lock lists the crate being built alongside its dependencies.
        own = self._own_crate_names(cargo_toml)
        patched = self._patched_crates(cargo_toml)

        result = ScanResult()
        seen = set()
        for name, version, source in packages:
            if name in own:
                continue
            key = (name, version)
            if key in seen:
                continue
            seen.add(key)
            # A [patch] override or a git source means the built code is not
            # the registry release of that version, so advisory and license
            # answers for it would be about the wrong code.
            if name in patched:
                result.unresolved.append(Unresolved(
                    spec="%s %s (patched)" % (name, version),
                    reason="local", name=name))
                continue
            if source and not source.startswith("registry+"):
                reason = "vcs" if source.startswith("git+") else "url"
                result.unresolved.append(Unresolved(
                    spec="%s %s (%s)" % (name, version, source.split("#", 1)[0]),
                    reason=reason, name=name))
                continue
            result.deps.append(RawDep(
                name=name, version=version,
                transitive=bool(direct) and name not in direct,
                dev=name in dev and name not in (direct - dev)))
        result.deps = result.sorted_deps()
        result.unresolved = result.sorted_unresolved()
        return result

    @staticmethod
    def _parse_lock(path: str) -> List[Tuple[str, str, str]]:
        packages = []
        current: Optional[dict] = None
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                stripped = line.strip()
                if stripped == "[[package]]":
                    current = {}
                    packages.append(current)
                    continue
                if stripped.startswith("["):
                    current = None
                    continue
                if current is not None:
                    m = _KEY_RE.match(line)
                    if m:
                        current[m.group(1)] = m.group(2)
        return [(p["name"], p["version"], p.get("source", ""))
                for p in packages if "name" in p and "version" in p]

    @classmethod
    def _dependency_tables(cls, cargo_toml: str) -> Tuple[Set[str], Set[str]]:
        """-> (all direct crate names, those declared only for dev/build).

        Covers plain [dependencies] entries, [dependencies.foo] headers, and
        the target-specific [target.'cfg(unix)'.dependencies] form.
        """
        direct: Set[str] = set()
        dev: Set[str] = set()
        if not os.path.exists(cargo_toml):
            return direct, dev
        section = ""
        try:
            with open(cargo_toml, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.split("#", 1)[0]
                    m = _SECTION_RE.match(line)
                    if m:
                        section = m.group(1)
                        parts = section.split(".")
                        for i, part in enumerate(parts):
                            if part.endswith("dependencies") and i + 1 < len(parts):
                                name = parts[i + 1].strip("'\"")
                                direct.add(name)
                                if part in _DEV_SECTIONS:
                                    dev.add(name)
                        continue
                    if _is_dep_section(section):
                        m = _DEP_LINE_RE.match(line)
                        if m:
                            direct.add(m.group(1))
                            if section.split(".")[-1] in _DEV_SECTIONS:
                                dev.add(m.group(1))
        except OSError:
            return set(), set()
        return direct, dev

    @staticmethod
    def _patched_crates(cargo_toml: str) -> Set[str]:
        """Crate names under any [patch.*] or [replace] table."""
        names: Set[str] = set()
        if not os.path.exists(cargo_toml):
            return names
        section = ""
        try:
            with open(cargo_toml, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.split("#", 1)[0]
                    m = _SECTION_RE.match(line)
                    if m:
                        section = m.group(1)
                        parts = section.split(".")
                        # [patch.crates-io.serde] names serde directly.
                        if parts[0] == "patch" and len(parts) >= 3:
                            names.add(parts[2].strip("'\""))
                        continue
                    if section.startswith("patch.") or section == "replace":
                        dm = _DEP_LINE_RE.match(line)
                        if dm:
                            names.add(dm.group(1))
        except OSError:
            pass
        return names

    @staticmethod
    def _own_crate_names(cargo_toml: str) -> Set[str]:
        names: Set[str] = set()
        if not os.path.exists(cargo_toml):
            return names
        section = ""
        try:
            with open(cargo_toml, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    m = _SECTION_RE.match(line)
                    if m:
                        section = m.group(1)
                        continue
                    if section == "package":
                        km = _KEY_RE.match(line)
                        if km and km.group(1) == "name":
                            names.add(km.group(2))
        except OSError:
            pass
        return names


def _is_dep_section(section: str) -> bool:
    # A dependencies table, but not a [dependencies.foo] item table: inside
    # one of those, keys are that crate's settings, not crate names.
    last = section.split(".")[-1]
    return last in ("dependencies", "dev-dependencies", "build-dependencies")
