"""requirements.txt.

Only `name==version` lines can be audited: a range has no single version to
look up. But an audit that quietly ignores `flask>=2.0` and reports a clean
result is a lie, so everything this scanner cannot pin is recorded as an
Unresolved with a reason and surfaced in `deph check`.

`-r` and `-c` includes are followed, because a repo that splits its
requirements across files is normal and reading only the entry point would
under-report most of it.
"""

import os
import re
from typing import List, Optional, Set, Tuple

from . import RawDep, ScanResult, Scanner, Unresolved, register

_NAME = r"[A-Za-z0-9][A-Za-z0-9._-]*"
_PIN_RE = re.compile(
    r"""^\s*
    (?P<name>%s)
    (?:\[[^\]]*\])?                           # extras
    \s*===?\s*
    (?P<version>[A-Za-z0-9][A-Za-z0-9._+!-]*)
    \s*$
    """ % _NAME,
    re.VERBOSE,
)
# A requirement we can identify by name but not pin to one version.
_SPEC_RE = re.compile(
    r"""^\s*
    (?P<name>%s)
    (?:\[[^\]]*\])?
    \s*(?P<rest>.*)$
    """ % _NAME,
    re.VERBOSE,
)
_INCLUDE_RE = re.compile(r"^\s*(?:-r|--requirement|-c|--constraint)[=\s]+(?P<path>.+?)\s*$")
_DEV_HINTS = ("dev", "test", "tests", "lint", "docs", "ci", "typing")


def normalize_name(name: str) -> str:
    # PEP 503: PyYAML, pyyaml and py_yaml are one package to PyPI.
    return re.sub(r"[-_.]+", "-", name).lower()


def looks_like_dev_file(path: str) -> bool:
    """requirements-dev.txt and friends.

    A guess based on the filename, because a requirements file carries no
    group information. Wrong occasionally, and only ever downgrades how
    loudly a finding is reported.
    """
    stem = os.path.basename(path).lower()
    for word in _DEV_HINTS:
        if word in stem:
            return True
    parent = os.path.basename(os.path.dirname(path)).lower()
    return parent in _DEV_HINTS


@register
class PipScanner(Scanner):
    ecosystem = "pip"
    manifest_names = ("requirements.txt",)
    # requirements-dev.txt, dev-requirements.txt, requirements/base.txt:
    # exact-name matching missed most real Python repos.
    manifest_globs = ("requirements*.txt", "*-requirements.txt",
                      "requirements-*.txt")
    priority = 40
    # Several requirements files in one directory are several real dependency
    # sets, not competing descriptions of one.
    exclusive = False

    @classmethod
    def filter_candidates(cls, paths: List[str]) -> List[str]:
        """Drop files another candidate already pulls in with -r or -c.

        requirements.txt commonly starts with `-r base.txt`. Scanning both
        would report base.txt's dependencies twice and inflate every count.
        """
        included = set()
        for path in paths:
            for target in cls._includes(path):
                included.add(os.path.realpath(
                    os.path.join(os.path.dirname(path), target)))
        kept = [p for p in paths if os.path.realpath(p) not in included]
        # If they all include each other, keep them all rather than nothing.
        return kept or paths

    @staticmethod
    def _includes(path: str) -> List[str]:
        out: List[str] = []
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    m = _INCLUDE_RE.match(line.rstrip("\n"))
                    if m:
                        out.append(m.group("path").split("#", 1)[0].strip())
        except OSError:
            pass
        return out

    def scan(self, manifest_path: str) -> ScanResult:
        result = ScanResult()
        seen: Set[Tuple[str, str]] = set()
        # Includes can form cycles (-r a.txt from b.txt and back); track what
        # we've read by real path so we read each file once.
        visited: Set[str] = set()
        self._read(manifest_path, result, seen, visited,
                   dev=looks_like_dev_file(manifest_path))
        result.deps = result.sorted_deps()
        result.unresolved = result.sorted_unresolved()
        return result

    def _read(self, path: str, result: ScanResult,
              seen: Set[Tuple[str, str]], visited: Set[str], dev: bool) -> None:
        try:
            real = os.path.realpath(path)
        except OSError:
            real = path
        if real in visited:
            return
        visited.add(real)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                raw = f.read()
        except OSError as e:
            result.unresolved.append(Unresolved(
                spec=os.path.basename(path), reason="missing",
                name=os.path.basename(path)))
            del e
            return

        raw = raw.replace("\\\n", " ")
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            include = _INCLUDE_RE.match(line)
            if include:
                target = include.group("path").split("#", 1)[0].strip()
                nested = os.path.join(os.path.dirname(path), target)
                self._read(nested, result, seen, visited,
                           dev=dev or looks_like_dev_file(nested))
                continue

            if line.startswith("-"):     # --hash, --index-url, -e, ...
                self._record_option(line, result)
                continue

            body = line.split(";", 1)[0]              # environment marker
            body = re.sub(r"\s+#.*$", "", body)
            # Trailing per-requirement options: `pkg==1.2.3 --hash=sha256:...`
            # is a normal pin in a hash-pinned requirements file.
            body = re.split(r"\s+--[A-Za-z]", body)[0].strip()
            if not body:
                continue

            pin = _PIN_RE.match(body)
            if pin:
                name = normalize_name(pin.group("name"))
                version = pin.group("version")
                if (name, version) in seen:
                    continue
                seen.add((name, version))
                result.deps.append(RawDep(name=name, version=version,
                                          transitive=False, dev=dev))
                continue

            result.unresolved.append(self._classify(body))

    @staticmethod
    def _record_option(line: str, result: ScanResult) -> None:
        if re.match(r"^\s*(?:-e|--editable)[=\s]+", line):
            result.unresolved.append(Unresolved(spec=line, reason="local"))
        # --hash, --index-url, --extra-index-url, --find-links and friends are
        # configuration, not dependencies; nothing to report.

    @staticmethod
    def _classify(body: str) -> Unresolved:
        lowered = body.lower()
        if lowered.startswith(("http://", "https://", "file://")):
            return Unresolved(spec=body, reason="url")
        if lowered.startswith(("git+", "hg+", "svn+", "bzr+")):
            return Unresolved(spec=body, reason="vcs")

        name = ""
        m = _SPEC_RE.match(body)
        rest = ""
        if m:
            name = normalize_name(m.group("name"))
            rest = m.group("rest").strip()

        if "@" in body:
            target = body.split("@", 1)[1].strip().lower()
            if target.startswith(("git+", "git:")):
                return Unresolved(spec=body, reason="vcs", name=name)
            if target.startswith(("http://", "https://")):
                return Unresolved(spec=body, reason="url", name=name)
            if target.startswith(("file:", ".", "/")):
                return Unresolved(spec=body, reason="local", name=name)
        if not name:
            return Unresolved(spec=body, reason="unparsed")
        if not rest:
            return Unresolved(spec=body, reason="unpinned", name=name)
        if re.match(r"^[<>=!~,\s0-9A-Za-z.*+!_-]+$", rest):
            return Unresolved(spec=body, reason="range", name=name)
        return Unresolved(spec=body, reason="unparsed", name=name)


def scan_requirements(path: str) -> ScanResult:
    """Used by other Python scanners that need to read a requirements file."""
    return PipScanner().scan(path)


def direct_names(specs: List[str]) -> Set[str]:
    """Normalized names out of a list of requirement strings."""
    out: Set[str] = set()
    for spec in specs:
        m = _SPEC_RE.match(spec.strip())
        if m:
            out.add(normalize_name(m.group("name")))
    return out


def pinned_version(spec: str) -> Optional[str]:
    m = _PIN_RE.match(spec.strip())
    return m.group("version") if m else None
