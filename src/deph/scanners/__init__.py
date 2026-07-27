"""Manifest discovery and the per-ecosystem scanner registry.

A scanner is a class with an ecosystem name, the manifest filenames that
identify it, and a scan() returning a ScanResult. Register it and discovery
picks it up; see CONTRIBUTING.md for the whole procedure.

Two rules that matter more than they look:

Scanners never touch the network. Parsing lockfiles and asking registries
about them are separate jobs, and only the second one can be slow or fail.

Scanners never drop a dependency silently. Anything in a manifest that can't
be pinned to a single version goes into ScanResult.unresolved with a reason,
and it gets counted and reported. A tool that quietly audits 1 of 6 packages
and prints a green check is worse than one that crashes.
"""

import fnmatch
import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Type

SKIP_DIRS = {
    "node_modules", ".git", "target", "venv", ".venv", "dist", "build",
    "__pycache__", ".tox", ".hg", ".svn", "site-packages", ".mypy_cache",
    ".pytest_cache", ".idea", ".vscode", "vendor", ".gradle", ".next",
    ".cargo", "bower_components", ".terraform",
}

# Why a line couldn't be pinned. Keep these stable: they end up in the .deph
# file and in `deph check` output.
UNRESOLVED_REASONS = (
    "range",        # a version range, not a pin: flask>=2.0, "^1.2.3"
    "unpinned",     # named with no version constraint at all
    "vcs",          # git/hg/svn dependency
    "url",          # direct URL or local archive
    "local",        # path/editable install, file:, link:
    "workspace",    # workspace: or path sibling inside the repo
    "missing",      # an include (-r / -c) deph could not read
    "unparsed",     # a line whose syntax we don't understand
)


@dataclass
class RawDep:
    name: str
    version: str
    transitive: bool = False
    dev: bool = False       # dev/test/build-only dependency


@dataclass
class Unresolved:
    spec: str               # the manifest text, as written
    reason: str             # one of UNRESOLVED_REASONS
    name: str = ""          # package name, when we could work it out


@dataclass
class ScanResult:
    deps: List[RawDep] = field(default_factory=list)
    unresolved: List[Unresolved] = field(default_factory=list)

    def sorted_deps(self) -> List[RawDep]:
        return sorted(self.deps, key=lambda d: (d.name, d.version))

    def sorted_unresolved(self) -> List[Unresolved]:
        return sorted(self.unresolved, key=lambda u: (u.name, u.spec))


class Scanner:
    # Unique registry key, e.g. "npm-yarn". Hyphenated suffixes mark a second
    # manifest format for the same language.
    ecosystem = ""
    manifest_names: Tuple[str, ...] = ()  # exact filenames that mark a project
    # fnmatch patterns, for conventions rather than fixed names:
    # requirements-dev.txt, requirements/base.txt and so on all count.
    manifest_globs: Tuple[str, ...] = ()
    # When several manifests sit in one directory the lowest number wins: a
    # lockfile pins versions, the file next to it only declares ranges.
    priority = 50
    # False when several manifests of this kind in one directory are additive
    # rather than alternatives. requirements.txt and requirements-dev.txt are
    # two real dependency sets; package-lock.json and yarn.lock are two
    # spellings of one.
    exclusive = True
    # True for a manifest that only declares ranges, used when nothing better
    # exists. These are suppressed inside a workspace, where the root lockfile
    # already pins the member's dependencies.
    last_resort = False

    @classmethod
    def matches(cls, filename: str) -> bool:
        if filename in cls.manifest_names:
            return True
        return any(fnmatch.fnmatch(filename, pattern)
                   for pattern in cls.manifest_globs)

    @classmethod
    def filter_candidates(cls, paths: List[str]) -> List[str]:
        """Narrow a directory's matches before they become projects.

        Default is to keep everything. Overridden where one manifest can
        contain another and scanning both would double-count.
        """
        return paths

    @classmethod
    def language(cls) -> str:
        """What to call this in the .deph file and which registry to ask.

        yarn.lock and package-lock.json are both "npm": same registry, same
        advisory ecosystem, same thing as far as policy is concerned.
        """
        return cls.ecosystem.split("-", 1)[0]

    def scan(self, manifest_path: str) -> ScanResult:
        raise NotImplementedError


_REGISTRY: Dict[str, Type[Scanner]] = {}


def register(cls: Type[Scanner]) -> Type[Scanner]:
    _REGISTRY[cls.ecosystem] = cls
    return cls


def _ensure_builtin():
    # Imported here, not at module scope, to keep the @register decorators off
    # the import path of anything that only needs the registry types.
    from . import (npm, npm_yarn, npm_pnpm, npm_package, pip,  # noqa: F401
                   pip_poetry, pip_pipenv, pip_uv, pip_pyproject, cargo, go,
                   gem, composer)


@dataclass
class DiscoveredProject:
    name: str           # posix-style path relative to root
    ecosystem: str      # scanner key, e.g. "npm-yarn"
    language: str       # what goes in the file, e.g. "npm"
    manifest: str       # posix-style path relative to root
    manifest_abspath: str
    priority: int = 50
    rank: int = 0       # index in the scanner's manifest_names, as a tiebreak
    exclusive: bool = True
    last_resort: bool = False


def _scanner_for_file(filename: str) -> Optional[Type[Scanner]]:
    """Exact names win over globs, so requirements.txt isn't claimed by a
    pattern belonging to some other scanner."""
    for cls in _REGISTRY.values():
        if filename in cls.manifest_names:
            return cls
    for cls in _REGISTRY.values():
        if cls.matches(filename):
            return cls
    return None


def _rank_of(cls: Type[Scanner], filename: str) -> int:
    # manifest_names is in preference order: go.sum pins every module, go.mod
    # only requires them. Glob matches sort after every exact name.
    if filename in cls.manifest_names:
        return cls.manifest_names.index(filename)
    return len(cls.manifest_names)


def discover(root: str) -> List[DiscoveredProject]:
    _ensure_builtin()
    found: List[DiscoveredProject] = []
    root = os.path.abspath(root)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)

        by_scanner: Dict[str, List[str]] = {}
        for fname in sorted(filenames):
            cls = _scanner_for_file(fname)
            if cls is not None:
                by_scanner.setdefault(cls.ecosystem, []).append(fname)

        here: List[DiscoveredProject] = []
        for ecosystem, names in by_scanner.items():
            cls = _REGISTRY[ecosystem]
            keep = cls.filter_candidates(
                [os.path.join(dirpath, n) for n in names])
            for abspath in keep:
                fname = os.path.basename(abspath)
                rel_dir = os.path.relpath(dirpath, root)
                dir_name = "." if rel_dir == "." else rel_dir.replace(os.sep, "/")
                manifest_rel = (fname if rel_dir == "."
                                else "%s/%s" % (dir_name, fname))
                here.append(DiscoveredProject(
                    name=dir_name, ecosystem=cls.ecosystem,
                    language=cls.language(), manifest=manifest_rel,
                    manifest_abspath=abspath, priority=cls.priority,
                    rank=_rank_of(cls, fname), exclusive=cls.exclusive,
                    last_resort=cls.last_resort))
        found.extend(_resolve_directory(here))
    return _disambiguate(_drop_workspace_members(found))


def _is_workspace_root(directory: str) -> bool:
    """Does this directory declare a workspace whose members it locks for?"""
    if os.path.exists(os.path.join(directory, "pnpm-workspace.yaml")):
        return True
    pkg = os.path.join(directory, "package.json")
    if os.path.exists(pkg):
        try:
            with open(pkg, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict) and data.get("workspaces"):
                return True
        except (OSError, ValueError):
            pass
    return False


def _drop_workspace_members(projects: List[DiscoveredProject]
                            ) -> List[DiscoveredProject]:
    """Remove last-resort manifests that a workspace root already covers.

    In a pnpm or yarn workspace the root lockfile pins every member's
    dependencies. Scanning each member's package.json as well reports all of
    its ranges as unresolved, which is both noise and a lie: they are pinned,
    just one directory up. Observed on a real monorepo as 165 phantom
    unresolved entries.
    """
    roots = []
    for p in projects:
        if p.last_resort:
            continue
        directory = os.path.dirname(p.manifest_abspath)
        if _is_workspace_root(directory):
            roots.append((directory, p.language))
    if not roots:
        return projects

    kept = []
    for p in projects:
        if not p.last_resort:
            kept.append(p)
            continue
        directory = os.path.dirname(p.manifest_abspath)
        covered = any(
            language == p.language and directory != root
            and directory.startswith(root + os.sep)
            for root, language in roots)
        if not covered:
            kept.append(p)
    return kept


def _resolve_directory(candidates: List[DiscoveredProject]
                       ) -> List[DiscoveredProject]:
    """Decide which of one directory's manifests become projects.

    A repo with package-lock.json and yarn.lock has one set of node
    dependencies described two ways, so scanning both would double-report
    every finding. requirements.txt and requirements-dev.txt are two genuinely
    different sets, so both are kept.
    """
    best: Dict[str, DiscoveredProject] = {}
    additive: List[DiscoveredProject] = []
    for c in candidates:
        if not c.exclusive:
            additive.append(c)
            continue
        current = best.get(c.language)
        if current is None or (c.priority, c.rank) < (current.priority,
                                                     current.rank):
            best[c.language] = c

    out = [best[k] for k in sorted(best)]
    # An additive manifest is only superseded by a *stronger* exclusive one. A
    # poetry.lock beside a requirements.txt is the truth for that directory; a
    # pyproject.toml beside a requirements-dev.txt is not, and dropping the
    # requirements file there would lose every dependency it names.
    for a in additive:
        rival = best.get(a.language)
        if rival is None or a.priority < rival.priority:
            out.append(a)
    return out


def _disambiguate(projects: List[DiscoveredProject]
                  ) -> List[DiscoveredProject]:
    """Give every project a unique name.

    Two requirements files in one directory would otherwise both be called
    after that directory, and duplicate project names are a lint error.
    """
    counts: Dict[str, int] = {}
    for p in projects:
        counts[p.name] = counts.get(p.name, 0) + 1
    for p in projects:
        if counts[p.name] > 1:
            p.name = p.manifest
    return projects


def scanner_for(ecosystem: str) -> Scanner:
    _ensure_builtin()
    return _REGISTRY[ecosystem]()
