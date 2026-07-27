"""package-lock.json: v2/v3 properly, v1 as well as it can be done."""

import json
import os
from typing import Dict, Set

from . import RawDep, ScanResult, Scanner, Unresolved, register

# Dependency specs that don't resolve to a registry version.
_LOCAL_PREFIXES = ("file:", "link:", "portal:")
_VCS_PREFIXES = ("git+", "git:", "github:", "gitlab:", "bitbucket:", "ssh://")


def classify_spec(spec: str) -> str:
    """-> an UNRESOLVED_REASONS value, or "" if it's a normal registry range."""
    s = spec.strip().lower()
    if s.startswith("workspace:"):
        return "workspace"
    if s.startswith(_LOCAL_PREFIXES):
        return "local"
    if s.startswith(_VCS_PREFIXES) or s.endswith(".git"):
        return "vcs"
    if s.startswith(("http://", "https://")):
        return "url"
    return ""


@register
class NpmScanner(Scanner):
    ecosystem = "npm"
    manifest_names = ("package-lock.json",)
    priority = 10

    def scan(self, manifest_path: str) -> ScanResult:
        with open(manifest_path, "r", encoding="utf-8") as f:
            try:
                lock = json.load(f)
            except RecursionError:
                # Absurdly nested JSON. Report it as a parse failure so the
                # caller skips this manifest rather than dying on it.
                raise ValueError("package-lock.json is too deeply nested") from None
        if not isinstance(lock, dict):
            raise ValueError("package-lock.json is not a JSON object")
        if isinstance(lock.get("packages"), dict):
            result = self._scan_v2v3(lock)
        else:
            result = self._scan_v1(lock, manifest_path)
        result.deps = result.sorted_deps()
        result.unresolved = result.sorted_unresolved()
        return result

    def _scan_v2v3(self, lock: dict) -> ScanResult:
        packages = lock["packages"]
        root = packages.get("", {})
        result = ScanResult()

        direct: Set[str] = set()
        dev_only: Set[str] = set()
        runtime: Set[str] = set()
        for key in ("dependencies", "optionalDependencies", "peerDependencies"):
            deps = root.get(key)
            if isinstance(deps, dict):
                direct.update(deps.keys())
                runtime.update(deps.keys())
        if isinstance(root.get("devDependencies"), dict):
            direct.update(root["devDependencies"].keys())
            dev_only.update(set(root["devDependencies"]) - runtime)

        # A workspace:* or file: sibling isn't a registry package, so it has no
        # advisories or license to look up. Record it rather than dropping it.
        for group in ("dependencies", "devDependencies", "optionalDependencies"):
            declared = root.get(group)
            if not isinstance(declared, dict):
                continue
            for name, spec in declared.items():
                if not isinstance(spec, str):
                    continue
                reason = classify_spec(spec)
                if reason:
                    result.unresolved.append(Unresolved(
                        spec="%s@%s" % (name, spec), reason=reason, name=name))

        seen: Dict[str, RawDep] = {}
        for path, info in packages.items():
            if not path or not isinstance(info, dict):
                continue
            if info.get("link"):
                continue
            version = info.get("version")
            if not version or not isinstance(version, str):
                continue
            path_name = self._path_name(path)
            if not path_name:
                continue        # workspace source dir, not an installed dep
            # An aliased install ("mychalk": "npm:chalk@^5") keeps its real
            # name here. Audit the alias instead and chalk's advisories are
            # silently missed, which is the worst kind of bug for this tool.
            real = info.get("name")
            name = real if isinstance(real, str) and real else path_name
            is_direct = (path_name in direct
                         and path == "node_modules/%s" % path_name)
            is_dev = bool(info.get("dev")) or path_name in dev_only
            key = "%s@%s" % (name, version)
            existing = seen.get(key)
            if existing is None:
                seen[key] = RawDep(name=name, version=version,
                                   transitive=not is_direct, dev=is_dev)
            else:
                if is_direct:
                    existing.transitive = False
                if not is_dev:
                    existing.dev = False
        result.deps = list(seen.values())
        return result

    @staticmethod
    def _path_name(path: str) -> str:
        marker = "node_modules/"
        idx = path.rfind(marker)
        if idx == -1:
            return ""
        return path[idx + len(marker):]

    def _scan_v1(self, lock: dict, manifest_path: str) -> ScanResult:
        # v1 has no root dependency list, so the direct set has to come from a
        # sibling package.json; without one we fall back to tree depth.
        result = ScanResult()
        direct: Set[str] = set()
        dev_only: Set[str] = set()
        pkg_json = os.path.join(os.path.dirname(manifest_path), "package.json")
        if os.path.exists(pkg_json):
            try:
                with open(pkg_json, "r", encoding="utf-8") as f:
                    pkg = json.load(f)
                runtime: Set[str] = set()
                for key in ("dependencies", "optionalDependencies"):
                    deps = pkg.get(key)
                    if isinstance(deps, dict):
                        direct.update(deps.keys())
                        runtime.update(deps.keys())
                if isinstance(pkg.get("devDependencies"), dict):
                    direct.update(pkg["devDependencies"].keys())
                    dev_only.update(set(pkg["devDependencies"]) - runtime)
                for group in ("dependencies", "devDependencies"):
                    declared = pkg.get(group)
                    if not isinstance(declared, dict):
                        continue
                    for name, spec in declared.items():
                        reason = classify_spec(spec) if isinstance(spec, str) else ""
                        if reason:
                            result.unresolved.append(Unresolved(
                                spec="%s@%s" % (name, spec), reason=reason,
                                name=name))
            except (OSError, ValueError):
                pass

        seen: Dict[str, RawDep] = {}

        # Explicit stack rather than recursion: nesting here is attacker-
        # controlled and a RecursionError would take down the whole scan.
        stack = []
        deps = lock.get("dependencies")
        if isinstance(deps, dict):
            stack.append((deps, 0))
        while stack:
            level, depth = stack.pop()
            for name, info in level.items():
                if not isinstance(info, dict):
                    continue
                version = info.get("version")
                if isinstance(version, str) and version:
                    is_direct = name in direct if direct else depth == 0
                    is_dev = bool(info.get("dev")) or name in dev_only
                    key = "%s@%s" % (name, version)
                    existing = seen.get(key)
                    if existing is None:
                        seen[key] = RawDep(name=name, version=version,
                                           transitive=not is_direct, dev=is_dev)
                    else:
                        if is_direct:
                            existing.transitive = False
                        if not is_dev:
                            existing.dev = False
                nested = info.get("dependencies")
                if isinstance(nested, dict):
                    stack.append((nested, depth + 1))
        result.deps = list(seen.values())
        return result
