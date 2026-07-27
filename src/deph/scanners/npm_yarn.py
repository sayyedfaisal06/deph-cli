"""yarn.lock: classic (v1) and berry (v2+), hand-parsed.

Berry lockfiles are YAML and classic ones are a YAML-ish dialect that no YAML
parser accepts, so both are read with the same line reader: a header at column
zero listing one or more descriptors, then an indented body holding the
resolved version. That is the whole of what an audit needs from either format.

What yarn does *not* record is which packages are direct and which are
dev-only, in either version. That has to come from a sibling package.json; if
there isn't one, every dep is reported as direct and non-dev rather than
guessed at, because a wrong dev flag silently downgrades a real finding.
"""

import json
import os
from typing import Dict, Iterator, List, Optional, Set, Tuple

from . import RawDep, ScanResult, Scanner, Unresolved, register

# Descriptor protocols, longest-lived first. A range starting with one of
# these is not a registry version, so the entry cannot be pinned.
_PROTOCOLS: Tuple[Tuple[str, str], ...] = (
    ("workspace:", "workspace"),
    ("link:", "local"),
    ("portal:", "local"),
    ("file:", "local"),
    # patch: points at a patch file in the repo; the patched version is only
    # meaningful together with that file, so it is reported, not pinned.
    ("patch:", "local"),
    ("exec:", "local"),
    ("git:", "vcs"),
    ("git+", "vcs"),
    ("github:", "vcs"),
    ("gitlab:", "vcs"),
    ("bitbucket:", "vcs"),
    ("ssh://", "vcs"),
    ("http://", "url"),
    ("https://", "url"),
)

# Everything above plus npm:, used to find where a name ends and a range
# begins even when the range itself contains an "@" (git URLs with a userinfo
# part, aliased installs).
_PROTOCOL_PREFIXES: Tuple[str, ...] = ("npm:",) + tuple(
    p for p, _ in _PROTOCOLS)


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _blocks(text: str) -> Iterator[Tuple[str, List[str]]]:
    """Yield (header-without-colon, body-lines) for each column-zero block."""
    lines = text.splitlines()
    i, n = 0, len(lines)
    while i < n:
        line = lines[i]
        i += 1
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if line[:1].isspace():
            continue            # body line with no header: nothing to attach to
        if not stripped.endswith(":"):
            continue
        body: List[str] = []
        while i < n:
            nxt = lines[i]
            if nxt.strip() and not nxt[:1].isspace():
                break
            body.append(nxt)
            i += 1
        yield stripped[:-1], body


def _descriptors(header: str) -> List[str]:
    """Split a block header into descriptors.

    Classic quotes each descriptor separately ('"a@^1", "a@^2":'), berry wraps
    the whole comma-joined list in one pair of quotes ('"a@npm:^1, a@npm:^2":').
    Quotes never carry meaning inside a descriptor, so dropping them all and
    splitting on commas handles both.
    """
    flat = header.replace('"', "").replace("'", "")
    out = []
    for part in flat.split(","):
        part = part.strip()
        # Top-level YAML keys such as __metadata have no "@" and are not
        # entries; skipping them keeps them out of unresolved.
        if part and "@" in part[1:]:
            out.append(part)
    return out


def _tail_split(text: str) -> Optional[Tuple[str, str]]:
    at = text.rfind("@")
    if at <= 0:
        return None
    return text[:at], text[at + 1:]


def _split_descriptor(desc: str) -> Tuple[str, str]:
    """('@scope/name', 'range') for a descriptor, ('', '') if malformed.

    The "@" that separates name from range is the last one, not the first, so
    that @scope/name survives -- except when the range is protocol-prefixed,
    where the protocol marks the boundary instead. Without that exception
    "pkg@git+ssh://git@github.com/o/r.git" splits inside the URL.
    """
    at = -1
    for i in range(1, len(desc)):
        if desc[i] != "@":
            continue
        rest = desc[i + 1:].lower()
        if any(rest.startswith(p) for p in _PROTOCOL_PREFIXES):
            at = i
            break
    if at == -1:
        at = desc.rfind("@")
    if at <= 0:
        return "", ""
    name, rng = desc[:at], desc[at + 1:]
    if rng[:4].lower() == "npm:":
        rng = rng[4:]
        # An aliased install ("mychalk@npm:chalk@^5") must be audited under the
        # real package name, or chalk's advisories are missed entirely.
        inner = _tail_split(rng)
        if inner is not None and inner[0]:
            name, rng = inner
    return name, rng


def _reason_for_range(rng: str) -> str:
    """"" when the range is an ordinary registry range."""
    low = rng.strip().lower()
    for prefix, reason in _PROTOCOLS:
        if low.startswith(prefix):
            return reason
    if ".git#" in low or low.endswith(".git") or "#commit=" in low:
        return "vcs"
    return ""


def _body_version(body: List[str]) -> str:
    """The block's own `version`, ignoring anything nested deeper."""
    base = None
    for raw in body:
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        if base is None:
            base = indent
        if indent != base:
            continue            # inside dependencies:, peerDependencies:, ...
        if not stripped.startswith("version"):
            continue
        rest = stripped[len("version"):]
        if rest[:1] == ":":
            rest = rest[1:]
        elif rest[:1] not in (" ", "\t"):
            continue            # "versionCompat" and friends
        return _unquote(rest)
    return ""


@register
class YarnScanner(Scanner):
    ecosystem = "npm-yarn"
    manifest_names = ("yarn.lock",)
    # Below package-lock.json: when both exist, yarn.lock is the one the
    # install actually used.
    priority = 20

    def scan(self, manifest_path: str) -> ScanResult:
        result = ScanResult()
        try:
            with open(manifest_path, "r", encoding="utf-8",
                      errors="replace") as f:
                text = f.read()
        except OSError:
            return result

        direct, dev_only = self._sibling_package_json(manifest_path)
        known = direct is not None

        seen: Dict[str, RawDep] = {}
        seen_unresolved: Set[Tuple[str, str, str]] = set()

        def unresolved(spec: str, reason: str, name: str = "") -> None:
            key = (name, reason, spec)
            if key not in seen_unresolved:
                seen_unresolved.add(key)
                result.unresolved.append(
                    Unresolved(spec=spec, reason=reason, name=name))

        for header, body in _blocks(text):
            descriptors = _descriptors(header)
            if not descriptors:
                continue
            version = _body_version(body)
            for desc in descriptors:
                name, rng = _split_descriptor(desc)
                if not name:
                    unresolved(desc, "unparsed")
                    continue
                reason = _reason_for_range(rng)
                if reason:
                    unresolved(desc, reason, name)
                    continue
                if not version:
                    unresolved(desc, "unparsed", name)
                    continue
                transitive = known and name not in direct
                dev = known and name in dev_only
                key = "%s@%s" % (name, version)
                existing = seen.get(key)
                if existing is None:
                    seen[key] = RawDep(name=name, version=version,
                                       transitive=transitive, dev=dev)
                else:
                    # Reached both ways: the weaker claim wins.
                    existing.transitive = existing.transitive and transitive
                    existing.dev = existing.dev and dev

        result.deps = sorted(seen.values(), key=lambda d: (d.name, d.version))
        return result

    @staticmethod
    def _sibling_package_json(manifest_path: str
                              ) -> Tuple[Optional[Set[str]], Set[str]]:
        """(direct names, dev-only names); (None, set()) with no package.json."""
        path = os.path.join(os.path.dirname(os.path.abspath(manifest_path)),
                            "package.json")
        try:
            with open(path, "r", encoding="utf-8") as f:
                pkg = json.load(f)
        except (OSError, ValueError, RecursionError):
            return None, set()
        if not isinstance(pkg, dict):
            return None, set()

        def names(key: str) -> Set[str]:
            section = pkg.get(key)
            if not isinstance(section, dict):
                return set()
            return {k for k in section if isinstance(k, str)}

        runtime = names("dependencies") | names("optionalDependencies")
        peer = names("peerDependencies")
        dev = names("devDependencies")
        return runtime | peer | dev, dev - runtime - peer
