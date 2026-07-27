"""pnpm-lock.yaml, read with a mapping-only YAML reader.

pnpm emits a narrow slice of YAML: nested block mappings, scalars, and inline
flow mappings that only ever appear as values (`resolution: {integrity: ...}`).
_read_mappings below covers exactly that slice and treats a flow mapping as an
opaque string, which is enough because every field this scanner needs -- the
`packages:` keys, `importers:`, the root dependency sections -- is a plain
mapping.

Two lockfile generations are in the wild and both are handled: keys of the
form `/axios@0.21.1` (lockfileVersion 6, and 9 without the leading slash) and
`/axios/0.21.1` (5.x), each optionally carrying a peer-dependency suffix.
"""

import re
from typing import Any, Dict, List, Optional, Set, Tuple

from . import RawDep, ScanResult, Scanner, Unresolved, register

_DEP_SECTIONS = ("dependencies", "optionalDependencies", "devDependencies")

# /@babel/core/7.26.0  -- 5.x, version after the last slash
_OLD_KEY = re.compile(r"^(?P<name>(?:@[^/@]+/)?[^/@]+)/(?P<version>\d.*)$")
# /@babel/core@7.26.0  -- 6.x and 9.x
_NEW_KEY = re.compile(r"^(?P<name>(?:@[^/@]+/)?[^/@]+)@(?P<version>.+)$")

_LOCAL_MARKERS = (("workspace:", "workspace"), ("link:", "local"),
                  ("file:", "local"))


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _split_key(line: str) -> Optional[Tuple[str, str]]:
    """Split "key: value" or "key:" into (key, value). None if neither.

    Quoted keys are taken whole; unquoted ones end at the first colon that is
    followed by a space or the end of the line, so colons inside a key
    (`link:../x:`) or a value (`{integrity: sha512-...}`) stay put.
    """
    if line[:1] in ("\"", "'"):
        quote = line[0]
        end = line.find(quote, 1)
        if end == -1:
            return None
        rest = line[end + 1:].lstrip()
        if not rest.startswith(":"):
            return None
        return line[1:end], rest[1:].strip()
    for i, ch in enumerate(line):
        if ch != ":":
            continue
        after = line[i + 1:]
        if after == "" or after[:1] in (" ", "\t"):
            return line[:i].strip(), after.strip()
    return None


def _read_mappings(text: str) -> Dict[str, Any]:
    """Nested dicts for the block-mapping subset of YAML pnpm writes."""
    root: Dict[str, Any] = {}
    stack: List[Tuple[int, Dict[str, Any]]] = [(-1, root)]
    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            continue
        indent = len(line) - len(line.lstrip(" \t"))
        split = _split_key(stripped)
        if split is None:
            continue
        key, value = split
        while len(stack) > 1 and stack[-1][0] >= indent:
            stack.pop()
        parent = stack[-1][1]
        if value:
            parent[key] = _unquote(value)
        else:
            child: Dict[str, Any] = {}
            parent[key] = child
            stack.append((indent, child))
    return root


def _clean_version(version: str) -> str:
    """Drop peer-dependency suffixes: 1.2.3(react@18.0.0), 1.2.3_react@18.0.0."""
    version = _unquote(version)
    paren = version.find("(")
    if paren != -1:
        version = version[:paren]
    return version.split("_", 1)[0].strip()


def _local_reason(*values: str) -> str:
    """Markers outer, values inner: a workspace dep resolved to link:../x is
    a workspace dep, whichever field is looked at first."""
    lows = [value.strip().lower() for value in values]
    for marker, reason in _LOCAL_MARKERS:
        for low in lows:
            if low.startswith(marker) or ("@" + marker) in low:
                return reason
    return ""


def _split_package_key(key: str) -> Tuple[str, str]:
    """('@babel/core', '7.26.0') for a packages: key, ('', '') if unreadable."""
    text = key.strip()
    if text.startswith("/"):
        text = text[1:]
    if not text:
        return "", ""
    paren = text.find("(")
    if paren != -1:
        text = text[:paren]
    # 5.x first: its name/version separator is a slash, which the newer
    # pattern would mistake for part of a scope.
    match = _OLD_KEY.match(text) or _NEW_KEY.match(text)
    if match is None:
        return "", ""
    version = _clean_version(match.group("version"))
    if not version or not version[0].isdigit():
        return "", ""
    return match.group("name"), version


@register
class PnpmScanner(Scanner):
    ecosystem = "npm-pnpm"
    manifest_names = ("pnpm-lock.yaml",)
    # Ahead of yarn.lock and package-lock.json: a repo with pnpm-lock.yaml is
    # a pnpm repo whatever else is lying around.
    priority = 15

    def scan(self, manifest_path: str) -> ScanResult:
        result = ScanResult()
        try:
            with open(manifest_path, "r", encoding="utf-8",
                      errors="replace") as f:
                text = f.read()
        except OSError:
            return result
        try:
            doc = _read_mappings(text)
        except Exception:        # a lockfile must never take down a scan
            doc = {}

        seen_unresolved: Set[Tuple[str, str, str]] = set()

        def unresolved(spec: str, reason: str, name: str = "") -> None:
            key = (name, reason, spec)
            if key not in seen_unresolved:
                seen_unresolved.add(key)
                result.unresolved.append(
                    Unresolved(spec=spec, reason=reason, name=name))

        direct, dev_only = self._direct(doc, unresolved)

        seen: Dict[str, RawDep] = {}

        def record(name: str, version: str, dev_flag: Optional[bool]) -> None:
            versions = direct.get(name)
            is_direct = versions is not None and (not versions
                                                  or version in versions)
            if dev_flag is None:
                dev = is_direct and name in dev_only
            else:
                dev = dev_flag
            key = "%s@%s" % (name, version)
            existing = seen.get(key)
            if existing is None:
                seen[key] = RawDep(name=name, version=version,
                                   transitive=not is_direct, dev=dev)
            else:
                existing.transitive = existing.transitive and not is_direct
                existing.dev = existing.dev and dev

        packages = doc.get("packages")
        if isinstance(packages, dict):
            for key, info in packages.items():
                reason = _local_reason(key)
                if reason:
                    unresolved(key, reason)
                    continue
                name, version = _split_package_key(key)
                if not name:
                    unresolved(key, "unparsed")
                    continue
                dev_flag = None
                if isinstance(info, dict) and isinstance(info.get("dev"), str):
                    # 5.x/6.x record dev per package; 9.x dropped the field.
                    dev_flag = info["dev"].strip().lower() == "true"
                record(name, version, dev_flag)

        # A declared direct dependency with no packages: entry (5.x lockfiles
        # for a single importer sometimes elide it) still has to be reported.
        for name, versions in direct.items():
            for version in versions:
                if "%s@%s" % (name, version) not in seen:
                    record(name, version, None)

        result.deps = sorted(seen.values(), key=lambda d: (d.name, d.version))
        return result

    @staticmethod
    def _direct(doc: Dict[str, Any], unresolved) -> Tuple[Dict[str, Set[str]],
                                                          Set[str]]:
        """({name: pinned versions}, dev-only names) for declared deps.

        Reads importers: when present -- the monorepo shape, and what 9.x
        writes even for one package -- and the root sections otherwise.
        """
        groups: List[Dict[str, Any]] = []
        importers = doc.get("importers")
        if isinstance(importers, dict):
            groups = [v for v in importers.values() if isinstance(v, dict)]
        if not groups:
            groups = [doc]

        direct: Dict[str, Set[str]] = {}
        runtime: Set[str] = set()
        dev: Set[str] = set()
        for group in groups:
            for section in _DEP_SECTIONS:
                entries = group.get(section)
                if not isinstance(entries, dict):
                    continue
                for name, value in entries.items():
                    if isinstance(value, dict):
                        version = str(value.get("version", ""))
                        specifier = str(value.get("specifier", ""))
                    elif isinstance(value, str):
                        version, specifier = value, ""
                    else:
                        continue
                    reason = _local_reason(version, specifier)
                    if reason:
                        unresolved("%s@%s" % (name, specifier or version),
                                   reason, name)
                        continue
                    if section == "devDependencies":
                        dev.add(name)
                    else:
                        runtime.add(name)
                    pinned = direct.setdefault(name, set())
                    version = _clean_version(version)
                    if version and version[0].isdigit():
                        pinned.add(version)
        return direct, dev - runtime
