"""pyproject.toml, PEP 621 metadata, when there is no lockfile at all.

This is the last-resort Python scanner: priority 50 means any lock next to it
wins. A pyproject.toml declares what the author is willing to accept, not what
got installed, so most of what it says cannot be pinned to a version -- and
that is the expected outcome here, not a failure. "flask>=2.0" becomes an
unresolved entry with reason "range" and gets counted and reported; only an
exact "requests==2.31.0" is something deph can audit.

A report that is mostly unresolved is the honest answer to a repo with no
lockfile. The alternative -- resolving ">=2.0" ourselves, or quietly ignoring
it -- would either need the network or produce a green check for packages
nobody actually looked at.

Read by hand because tomllib is 3.11+ and deph supports 3.9. Only two shapes
matter: [project] dependencies = [...] and the tables under
[project.optional-dependencies].

Not supported on purpose: PEP 735 [dependency-groups], setuptools'
dynamic = ["dependencies"] indirection (reported unresolved rather than
followed), and poetry-style [tool.poetry.dependencies] tables, which are the
poetry scanner's business -- a poetry pyproject with no lock is flagged
unresolved so it can't pass as an empty clean scan.
"""

import os
import re
from typing import Dict, List, Optional, Tuple

from . import RawDep, ScanResult, Scanner, Unresolved, register
from .pip import normalize_name

_SECTION_RE = re.compile(r"^\s*\[+\s*([^\]]+?)\s*\]+\s*$")
_ARRAY_START_RE = re.compile(r"^\s*(?P<key>[A-Za-z0-9_.-]+)\s*=\s*\[")
_QUOTED_RE = re.compile(r"\"([^\"]*)\"|'([^']*)'")

_REQ_RE = re.compile(
    r"""^\s*
    (?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)      # package name
    (?:\[(?P<extras>[^\]]*)\])?               # optional extras
    \s*(?P<rest>.*)$""",
    re.VERBOSE,
)
# == and === (PEP 440 arbitrary equality) both name one version. A wildcard
# pin like ==1.4.* names a series, so it is excluded here on purpose.
_PIN_RE = re.compile(
    r"^={2,3}\s*(?P<version>[A-Za-z0-9][A-Za-z0-9._+!-]*)$")


@register
class PyprojectScanner(Scanner):
    ecosystem = "pip-pyproject"
    manifest_names = ("pyproject.toml",)
    priority = 50
    last_resort = True

    def scan(self, manifest_path: str) -> ScanResult:
        result = ScanResult()
        try:
            groups, flags = self._read(manifest_path)
        except OSError:
            result.unresolved.append(Unresolved(
                spec=os.path.basename(manifest_path), reason="unparsed"))
            return result

        if flags["dynamic_deps"]:
            result.unresolved.append(Unresolved(
                spec='dynamic = ["dependencies"]', reason="unparsed"))
        if not flags["has_project"] and flags["poetry_deps"]:
            # A poetry project without poetry.lock. Say so instead of handing
            # back an empty result that reads like "nothing to audit".
            result.unresolved.append(Unresolved(
                spec="[tool.poetry.dependencies]", reason="unparsed"))

        seen = set()
        for spec, dev in groups:
            name, version, reason = _parse_requirement(spec)
            if version is None:
                result.unresolved.append(Unresolved(
                    spec=spec.strip(), reason=reason, name=name))
                continue
            key = (name, version)
            if key in seen:
                continue
            seen.add(key)
            # Nothing in a pyproject.toml is transitive: every line is
            # something the author wrote down.
            result.deps.append(RawDep(name=name, version=version, dev=dev))
        result.deps.sort(key=lambda d: (d.name, d.version))
        return result

    @staticmethod
    def _read(path: str) -> Tuple[List[Tuple[str, bool]], Dict[str, bool]]:
        """Requirement strings paired with a dev flag, plus a few file facts.

        Anything in [project.optional-dependencies] is dev: extras are how a
        PEP 621 project spells "not needed to run this".
        """
        specs: List[Tuple[str, bool]] = []
        flags = {"has_project": False, "dynamic_deps": False,
                 "poetry_deps": False}
        section = ""
        pending_dev = False
        buffer = ""
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if buffer:
                    buffer += line
                    if _depth(buffer) <= 0:
                        specs.extend((s, pending_dev)
                                     for s in _strings(buffer))
                        buffer = ""
                    continue
                bare = line.split("#", 1)[0]
                m = _SECTION_RE.match(bare)
                if m:
                    section = m.group(1).strip()
                    if section == "project":
                        flags["has_project"] = True
                    elif section.startswith("tool.poetry"):
                        flags["poetry_deps"] = True
                    continue
                am = _ARRAY_START_RE.match(bare)
                if am is None:
                    continue
                key = am.group("key")
                if section == "project" and key == "dependencies":
                    pending_dev = False
                elif section == "project.optional-dependencies":
                    pending_dev = True
                elif section == "project" and key == "dynamic":
                    if "dependencies" in _strings(bare):
                        flags["dynamic_deps"] = True
                    continue
                else:
                    continue        # build-system requires, project.keywords...
                if _depth(bare) > 0:
                    buffer = bare   # array continues on the following lines
                else:
                    specs.extend((s, pending_dev) for s in _strings(bare))
        return specs, flags


def _strings(text: str) -> List[str]:
    return [a or b for a, b in _QUOTED_RE.findall(text)]


def _depth(text: str) -> int:
    # Bracket depth ignoring anything inside quotes: markers routinely contain
    # punctuation, and extras contain brackets of their own.
    stripped = _QUOTED_RE.sub("", text)
    return stripped.count("[") - stripped.count("]")


def _parse_requirement(spec: str) -> Tuple[str, Optional[str], str]:
    """(name, version, reason). version is None when it couldn't be pinned.

    A pin with an environment marker still counts: "foo==1.2; sys_platform ==
    'win32'" installs exactly 1.2 wherever it installs at all.
    """
    m = _REQ_RE.match(spec.strip())
    if m is None:
        return "", None, "unparsed"
    name = normalize_name(m.group("name"))
    rest = m.group("rest").strip()
    if rest.startswith("@"):
        target = rest[1:].strip().split(";", 1)[0].strip()
        if target.startswith("file:") or not re.match(r"^[a-z+]+://", target):
            return name, None, "local"
        return name, None, "url"
    constraint = rest.split(";", 1)[0].strip()
    if not constraint:
        # Bare name, or a name with only a marker attached.
        return name, None, "unpinned"
    if constraint.startswith("(") and constraint.endswith(")"):
        constraint = constraint[1:-1].strip()
    pm = _PIN_RE.match(constraint)
    if pm is not None:
        return name, pm.group("version"), ""
    if re.match(r"^[=<>!~^]", constraint):
        return name, None, "range"
    return name, None, "unparsed"
