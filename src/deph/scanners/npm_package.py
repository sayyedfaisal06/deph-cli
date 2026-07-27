"""package.json, for a repo with no lockfile committed.

Last resort. A package.json declares ranges (`"axios": "^1.6.0"`), and a range
is not a version, so almost everything here lands in unresolved. That is the
honest answer: without a lockfile deph cannot know what would be installed.

This scanner exists because the alternative was worse. An npm library with no
committed lockfile used to produce no project at all, so `deph check` passed
with nothing to say — silence that reads as approval.
"""

import json
import os
from . import RawDep, ScanResult, Scanner, Unresolved, register
from .npm import classify_spec

_GROUPS = ("dependencies", "optionalDependencies", "peerDependencies")
_DEV_GROUPS = ("devDependencies",)

# An exact version, as opposed to a range. npm allows a bare "1.2.3".
_EXACT_PREFIXES = tuple("0123456789")


@register
class NpmPackageScanner(Scanner):
    ecosystem = "npm-package"
    manifest_names = ("package.json",)
    priority = 90        # every lockfile format beats this
    last_resort = True

    def scan(self, manifest_path: str) -> ScanResult:
        result = ScanResult()
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                pkg = json.load(f)
        except (OSError, ValueError, RecursionError):
            result.unresolved.append(Unresolved(
                spec=os.path.basename(manifest_path), reason="unparsed"))
            return result
        if not isinstance(pkg, dict):
            return result

        for group in _GROUPS + _DEV_GROUPS:
            declared = pkg.get(group)
            if not isinstance(declared, dict):
                continue
            dev = group in _DEV_GROUPS
            for name, spec in declared.items():
                if not isinstance(name, str) or not isinstance(spec, str):
                    continue
                self._add(result, name, spec.strip(), dev)

        result.deps = result.sorted_deps()
        result.unresolved = result.sorted_unresolved()
        return result

    @staticmethod
    def _add(result: ScanResult, name: str, spec: str, dev: bool) -> None:
        reason = classify_spec(spec)
        if reason:
            result.unresolved.append(Unresolved(
                spec="%s@%s" % (name, spec), reason=reason, name=name))
            return
        if spec.startswith(_EXACT_PREFIXES) and _is_exact(spec):
            result.deps.append(RawDep(name=name, version=spec,
                                      transitive=False, dev=dev))
            return
        result.unresolved.append(Unresolved(
            spec="%s@%s" % (name, spec),
            reason="unpinned" if spec in ("", "*", "latest") else "range",
            name=name))


def _is_exact(spec: str) -> bool:
    """"1.2.3" is a pin; "1.2.x", "1 - 2" and "1.2.3 || 2" are not."""
    if any(ch in spec for ch in " |,<>=~^*"):
        return False
    return not any(part in ("x", "X") for part in spec.split("."))
