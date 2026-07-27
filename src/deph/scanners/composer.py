"""composer.lock for the pinned graph, composer.json for which deps are direct.

Both files are JSON, so this is the one scanner in the set that gets to use the
stdlib parser instead of reading a format by hand.

The lockfile is two arrays -- "packages" and "packages-dev" -- of objects with a
name and a version, which is nearly all this needs. Two wrinkles:

Composer keeps the tag it installed from, so versions arrive as "v1.2.3" about
as often as "1.2.3". The leading v is a git tag convention, not part of the
version, and it comes off so that the same release compares equal however the
maintainer tagged it. Nothing else about the string is touched.

A version like "dev-main" or "1.x-dev" is a branch, not a release: the code at
that name changes under you and no registry can tell you what was installed.
Those go to the unresolved channel as "vcs", and packages installed from a path
repository go there as "local".

composer.lock flattens the graph -- a transitive package sits in "packages"
looking exactly like one the author asked for -- so direct-ness comes from the
"require" and "require-dev" keys of composer.json when it is there, and is not
guessed at when it isn't.
"""

import json
import os
from typing import Any, Dict, List, Set, Tuple

from . import RawDep, ScanResult, Scanner, Unresolved, register

# Source/dist types that mean the version string isn't a released version.
_PATH_TYPES = ("path",)
_VCS_TYPES = ("git", "hg", "svn", "fossil")


@register
class ComposerScanner(Scanner):
    ecosystem = "composer"
    manifest_names = ("composer.lock",)
    # Pins the whole graph, so it beats the composer.json beside it.
    priority = 10

    def scan(self, manifest_path: str) -> ScanResult:
        result = ScanResult()
        data = _read_json(manifest_path)
        if not isinstance(data, dict):
            result.unresolved.append(Unresolved(
                spec=os.path.basename(manifest_path), reason="unparsed"))
            return result

        declared = _declared(os.path.join(os.path.dirname(manifest_path),
                                          "composer.json"))
        seen: Set[str] = set()
        # Runtime packages first: if a package somehow appears in both arrays,
        # the answer that matters is that production ships it.
        for key, dev in (("packages", False), ("packages-dev", True)):
            entries = data.get(key)
            if not isinstance(entries, list):
                if entries is not None:
                    result.unresolved.append(Unresolved(spec=key,
                                                        reason="unparsed"))
                continue
            for entry in entries:
                self._read_entry(entry, dev, declared, seen, result)
        result.deps.sort(key=lambda d: (d.name, d.version))
        return result

    @staticmethod
    def _read_entry(entry: Any, dev: bool, declared: Set[str],
                    seen: Set[str], result: ScanResult) -> None:
        if not isinstance(entry, dict):
            result.unresolved.append(Unresolved(spec=str(entry)[:120],
                                                reason="unparsed"))
            return
        name = entry.get("name")
        if not isinstance(name, str) or not name.strip():
            result.unresolved.append(Unresolved(spec="(unnamed package)",
                                                reason="unparsed"))
            return
        name = name.strip()
        if name in seen:
            return
        seen.add(name)

        raw_version = entry.get("version")
        if not isinstance(raw_version, str) or not raw_version.strip():
            result.unresolved.append(Unresolved(spec=name, reason="unparsed",
                                                name=name))
            return
        raw_version = raw_version.strip()

        reason, origin = _unpinnable(entry, raw_version)
        if reason:
            result.unresolved.append(Unresolved(
                spec=("%s @ %s" % (name, origin) if origin
                      else "%s %s" % (name, raw_version)),
                reason=reason, name=name))
            return

        result.deps.append(RawDep(
            name=name, version=_clean_version(raw_version), dev=dev,
            transitive=bool(declared) and name not in declared))


def _read_json(path: str) -> Any:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _origins(entry: Dict[str, Any]) -> List[Tuple[str, str]]:
    """[(type, url)] from the entry's source and dist tables."""
    found: List[Tuple[str, str]] = []
    for key in ("source", "dist"):
        table = entry.get(key)
        if not isinstance(table, dict):
            continue
        kind = table.get("type")
        url = table.get("url")
        found.append((kind.lower() if isinstance(kind, str) else "",
                      url if isinstance(url, str) else ""))
    return found


def _unpinnable(entry: Dict[str, Any], version: str) -> Tuple[str, str]:
    """(reason, origin) if the version isn't a release, ("", "") if it is.

    A git source is not on its own a problem -- that is how every package on
    Packagist is fetched, and the version next to it is a tag. It is the
    branch-shaped version that means there is no release to look up.
    """
    origins = _origins(entry)
    for kind, url in origins:
        if kind in _PATH_TYPES:
            return "local", url
    if not _is_branch(version):
        return "", ""
    for kind, url in origins:
        if kind in _VCS_TYPES:
            return "vcs", url
    # A branch version with no usable source table is still a branch.
    return "vcs", ""


def _is_branch(version: str) -> bool:
    low = version.strip().lower()
    return low.startswith("dev-") or low.endswith("-dev")


def _clean_version(version: str) -> str:
    """v1.2.3 -> 1.2.3, and anything else exactly as written."""
    if len(version) > 1 and version[0] == "v" and version[1].isdigit():
        return version[1:]
    return version


def _declared(composer_json: str) -> Set[str]:
    """Package names under require and require-dev in composer.json.

    Platform requirements (php, ext-mbstring, composer-plugin-api) are dropped:
    they never appear in the lock's package arrays and they aren't packages.
    """
    data = _read_json(composer_json)
    if not isinstance(data, dict):
        return set()
    declared: Set[str] = set()
    for key in ("require", "require-dev"):
        table = data.get(key)
        if not isinstance(table, dict):
            continue
        for name in table:
            # Every real Composer package is vendor/name; nothing else is.
            if isinstance(name, str) and "/" in name:
                declared.add(name.strip())
    return declared
