"""go.sum for the modules that get built, go.mod for which ones are direct.

Neither file needs a real parser. go.sum is three whitespace-separated columns
and go.mod is line-oriented directives, so both are read by hand here, same as
cargo.py reads the slice of TOML it needs.

Three things about the format drive the code below:

go.sum lists every module twice -- once for the module zip and once for the
go.mod inside it, the second with a "/go.mod" suffix on the version. Only the
first is a module that ends up in the build, so the suffixed lines are skipped
rather than deduplicated afterwards.

Pseudo-versions (v0.0.0-20210101120000-abcdef123456) and +incompatible
versions are ordinary pins: a pseudo-version names one commit and nothing else,
so it is kept exactly as written. The +incompatible marker is Go's way of
saying "this v2+ module has no /v2 import path", which is about import paths
and not about which code is built, so it comes off the version string.

A replace directive means the version in the requirement is not the version
being compiled. Reporting the requirement anyway would audit code that isn't
there, so the replaced module goes to the unresolved channel instead: "local"
when it points at a directory, "unparsed" when it points at another module,
because deph has no way to tell what that other module resolves to.
"""

import os
import re
from typing import Dict, List, Optional, Set, Tuple

from . import RawDep, ScanResult, Scanner, Unresolved, register

# Every go.mod and go.sum version starts with "v" and then a digit.
_VERSION_RE = re.compile(r"^v\d")

_INCOMPATIBLE = "+incompatible"

# Directives that take either one inline argument list or a parenthesised
# block. "module", "go" and "toolchain" are single-line only; anything a later
# Go release adds is ignored rather than reported, so a new directive doesn't
# turn into a pile of unresolved lines.
_BLOCK_DIRECTIVES = ("require", "replace", "exclude", "retract", "godebug")


class _Replacement:
    """A replace directive, keyed by the module path it replaces.

    versions is the set of versions it applies to; empty means "every version",
    which is what a replace with no version on the left-hand side means.
    """

    def __init__(self, versions: Set[str], reason: str, spec: str) -> None:
        self.versions = versions
        self.reason = reason
        self.spec = spec


class _GoMod:
    def __init__(self) -> None:
        self.module = ""
        # (path, version, indirect) in file order.
        self.requires: List[Tuple[str, str, bool]] = []
        self.replaced: Dict[str, _Replacement] = {}
        # Lines inside a require/replace block that didn't parse. Unknown
        # top-level directives are not in here; see _BLOCK_DIRECTIVES.
        self.bad: List[str] = []


@register
class GoScanner(Scanner):
    ecosystem = "go"
    # go.sum first: it is the file that pins the whole graph, and go.mod is
    # only a fallback for a module that has no dependencies to hash yet.
    manifest_names = ("go.sum", "go.mod")
    priority = 10

    def scan(self, manifest_path: str) -> ScanResult:
        result = ScanResult()
        handed_gomod = os.path.basename(manifest_path) == "go.mod"
        gomod_path = manifest_path if handed_gomod else os.path.join(
            os.path.dirname(manifest_path), "go.mod")
        mod = _read_gomod_safely(gomod_path)

        if handed_gomod:
            if mod is None:
                result.unresolved.append(Unresolved(
                    spec=os.path.basename(manifest_path), reason="unparsed"))
                return result
            self._from_gomod(mod, result)
        else:
            self._from_gosum(manifest_path, mod, result)
        result.deps.sort(key=lambda d: (d.name, d.version))
        return result

    @staticmethod
    def _from_gomod(mod: _GoMod, result: ScanResult) -> None:
        _report_replacements(mod, result)
        for raw in mod.bad:
            result.unresolved.append(Unresolved(spec=raw, reason="unparsed"))
        seen: Set[Tuple[str, str]] = set()
        for path, version, indirect in mod.requires:
            if path == mod.module or _is_replaced(mod, path, version):
                continue
            key = (path, version)
            if key in seen:
                continue
            seen.add(key)
            # Go has no dev/test dependency distinction: a test-only import is
            # a requirement of the module like any other.
            result.deps.append(RawDep(name=path, version=version,
                                      transitive=indirect))

    @staticmethod
    def _from_gosum(sum_path: str, mod: Optional[_GoMod],
                    result: ScanResult) -> None:
        try:
            with open(sum_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except OSError:
            result.unresolved.append(Unresolved(
                spec=os.path.basename(sum_path), reason="unparsed"))
            return

        if mod is not None:
            # A replace in the sibling go.mod changes what the hashes in this
            # go.sum are for, so it has to be reported from here too.
            _report_replacements(mod, result)
        direct: Set[str] = set()
        known = False
        if mod is not None and mod.requires:
            known = True
            direct = {path for path, _, indirect in mod.requires if not indirect}

        seen: Set[Tuple[str, str]] = set()
        for raw in lines:
            line = raw.strip()
            if not line or line.startswith("//"):
                continue
            tokens = line.split()
            if len(tokens) < 2 or not _VERSION_RE.match(tokens[1]):
                result.unresolved.append(Unresolved(spec=line,
                                                    reason="unparsed"))
                continue
            path, version = tokens[0], tokens[1]
            if version.endswith("/go.mod"):
                # The hash of the module's go.mod file. The module itself gets
                # its own line, so this one carries no new information.
                continue
            version = _clean_version(version)
            if mod is not None and (path == mod.module
                                    or _is_replaced(mod, path, version)):
                continue
            key = (path, version)
            if key in seen:
                continue
            seen.add(key)
            result.deps.append(RawDep(
                name=path, version=version,
                # Without a go.mod there is no record of what the author asked
                # for, and guessing would mark half the graph wrong.
                transitive=known and path not in direct))


def _read_gomod_safely(path: str) -> Optional[_GoMod]:
    try:
        return _read_gomod(path)
    except OSError:
        return None
    except Exception:       # a manifest must never take down a scan
        return None


def _read_gomod(path: str) -> _GoMod:
    mod = _GoMod()
    block = ""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            code, comment = _split_comment(raw.rstrip("\n"))
            stripped = code.strip()
            if not stripped:
                continue
            if block:
                if stripped == ")":
                    block = ""
                    continue
                _read_entry(mod, block, stripped, comment, raw.strip())
                continue
            parts = stripped.split(None, 1)
            keyword = parts[0]
            rest = parts[1].strip() if len(parts) > 1 else ""
            if keyword == "module":
                mod.module = _unquote(rest)
                continue
            if keyword in _BLOCK_DIRECTIVES:
                if rest == "(":
                    block = keyword
                elif rest:
                    _read_entry(mod, keyword, rest, comment, raw.strip())
    return mod


def _read_entry(mod: _GoMod, kind: str, code: str, comment: str,
                raw: str) -> None:
    if kind == "require":
        tokens = [_unquote(t) for t in code.split()]
        if len(tokens) >= 2 and _VERSION_RE.match(tokens[1]):
            mod.requires.append((tokens[0], _clean_version(tokens[1]),
                                 _is_indirect(comment)))
        else:
            mod.bad.append(raw)
    elif kind == "replace":
        _read_replace(mod, code, raw)
    # exclude, retract and godebug say nothing about what is built: an exclude
    # only removes a version from consideration, and the version that wins
    # instead is the one go.sum and the require lines already name.


def _read_replace(mod: _GoMod, code: str, raw: str) -> None:
    if "=>" not in code:
        mod.bad.append(raw)
        return
    left, right = code.split("=>", 1)
    old = [_unquote(t) for t in left.split()]
    new = [_unquote(t) for t in right.split()]
    if not old or not new:
        mod.bad.append(raw)
        return
    versions: Set[str] = set()
    if len(old) > 1 and _VERSION_RE.match(old[1]):
        versions.add(_clean_version(old[1]))
    reason = "local" if _is_local_path(new[0]) else "unparsed"
    existing = mod.replaced.get(old[0])
    if existing is None:
        mod.replaced[old[0]] = _Replacement(versions, reason, raw)
        return
    # Several replaces for one path: union the versions they cover, and an
    # unversioned one swallows the rest.
    if existing.versions and versions:
        existing.versions |= versions
    else:
        existing.versions = set()


def _report_replacements(mod: _GoMod, result: ScanResult) -> None:
    for path in sorted(mod.replaced):
        rep = mod.replaced[path]
        result.unresolved.append(Unresolved(spec=rep.spec, reason=rep.reason,
                                            name=path))


def _is_replaced(mod: _GoMod, path: str, version: str) -> bool:
    rep = mod.replaced.get(path)
    if rep is None:
        return False
    return not rep.versions or version in rep.versions


def _clean_version(version: str) -> str:
    """v2.0.0+incompatible -> v2.0.0; everything else as written.

    Pseudo-versions are left alone on purpose: the timestamp and commit hash
    are the pin.
    """
    version = version.strip()
    if version.endswith(_INCOMPATIBLE):
        version = version[:-len(_INCOMPATIBLE)]
    return version


def _split_comment(line: str) -> Tuple[str, str]:
    index = line.find("//")
    if index == -1:
        return line, ""
    return line[:index], line[index + 2:]


def _is_indirect(comment: str) -> bool:
    return "indirect" in comment.replace(";", " ").split()


def _is_local_path(target: str) -> bool:
    """Whether a replace target is a directory rather than a module path."""
    if target in (".", ".."):
        return True
    if target.startswith(("./", "../", "/", ".\\", "..\\", "\\")):
        return True
    return len(target) > 1 and target[1] == ":"      # C:\deps\thing


def _unquote(token: str) -> str:
    token = token.strip()
    if len(token) >= 2 and token[0] == token[-1] and token[0] in "\"'`":
        return token[1:-1]
    return token
