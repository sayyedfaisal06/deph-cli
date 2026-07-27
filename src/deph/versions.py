"""Per-ecosystem version comparison and range matching.

The generic lenient comparison that used to live in enrich.py is fine for
sorting but wrong for deciding whether a version is vulnerable. The three
ecosystems disagree in ways that produce both false negatives and false
positives:

- PEP 440 has epochs (`1!2.0`), a `~=` compatible-release operator, `.post`
  and `.dev` segments with specific ordering, and `==1.4.*` prefix matching.
- npm semver orders prereleases by dot-separated identifier with numeric
  identifiers ranking below alphanumeric ones, and has `^`/`~`/`x` ranges.
- Cargo uses semver ordering with Cargo's own `^`-by-default caret rules.

Getting this wrong in a security tool means either missing a real advisory or
crying wolf, so each ecosystem gets its own comparison and its own matcher.
"""

import re
from typing import Callable, List, Optional, Sequence, Tuple

Key = Tuple

# ---------------------------------------------------------------------------
# semver (npm, cargo, go, composer, gem)
# ---------------------------------------------------------------------------

_SEMVER_RE = re.compile(r"^[vV=\s]*(?P<rest>[0-9].*?)\s*$")


def parse_semver(version: str) -> Optional[Tuple[List[int], Tuple]]:
    """-> (numeric release segments, prerelease sort key), or None.

    The release part is any number of dotted integers, not just three. Ruby
    gems and Go modules routinely use four (`rails 7.0.4.3`), and reading the
    fourth as a prerelease made 7.0.4.3 sort *older* than 7.0.4 — which throws
    off both lag reporting and, worse, advisory range matching.

    A prerelease starts at a `-`, or at the first dotted segment that isn't
    numeric (rubygems writes `1.0.0.beta1`). Build metadata after `+` is
    ignored, per semver.
    """
    m = _SEMVER_RE.match(version or "")
    if not m:
        return None
    body = m.group("rest").split("+", 1)[0]

    pre: Optional[str] = None
    if "-" in body:
        body, pre = body.split("-", 1)

    release: List[int] = []
    tail: List[str] = []
    for i, piece in enumerate(body.split(".")):
        if tail or not piece.isdigit():
            tail.append(piece)
        else:
            release.append(int(piece))
        del i
    if not release:
        return None
    if tail:
        # `1.0.0.beta1` plus a `-rc.1` would be odd, but keep both.
        joined = ".".join(tail)
        pre = joined if pre is None else "%s.%s" % (joined, pre)

    # Trailing zeros aren't significant: 1.2 == 1.2.0 == 1.2.0.0.
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    return release, _prerelease_key(pre)


def _prerelease_key(pre: Optional[str]) -> Tuple:
    # A release outranks any of its prereleases, so no prerelease sorts high.
    if not pre:
        return (1,)
    parts: List[Tuple] = [(0,)]
    for piece in pre.split("."):
        if piece.isdigit():
            parts.append((0, int(piece), ""))
        else:
            parts.append((1, 0, piece))
    return tuple(parts)


def semver_key(version: str) -> Key:
    parsed = parse_semver(version)
    if parsed is None:
        return (0, _loose_key(version))
    release, pre = parsed
    return (1, tuple(release), pre)


# ---------------------------------------------------------------------------
# PEP 440 (pip)
# ---------------------------------------------------------------------------

_PEP440_RE = re.compile(
    r"^\s*v?"
    r"(?:(?P<epoch>\d+)!)?"
    r"(?P<release>\d+(?:\.\d+)*)"
    r"(?:[-_.]?(?P<pre_l>a|b|c|rc|alpha|beta|pre|preview)[-_.]?(?P<pre_n>\d*))?"
    r"(?:-(?P<post_n1>\d+)|[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>\d*))?"
    r"(?:[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>\d*))?"
    r"(?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?"
    r"\s*$",
    re.IGNORECASE,
)

_PRE_NORMAL = {"alpha": "a", "beta": "b", "c": "rc", "pre": "rc", "preview": "rc"}


def parse_pep440(version: str):
    m = _PEP440_RE.match(version or "")
    if not m:
        return None
    epoch = int(m.group("epoch") or 0)
    release = tuple(int(p) for p in m.group("release").split("."))

    pre = None
    if m.group("pre_l"):
        letter = m.group("pre_l").lower()
        pre = (_PRE_NORMAL.get(letter, letter), int(m.group("pre_n") or 0))

    post = None
    if m.group("post_n1"):
        post = int(m.group("post_n1"))
    elif m.group("post_l"):
        post = int(m.group("post_n2") or 0)

    dev = int(m.group("dev_n") or 0) if m.group("dev_l") else None
    return epoch, release, pre, post, dev, m.group("local")


def pep440_key(version: str) -> Key:
    parsed = parse_pep440(version)
    if parsed is None:
        return (0, _loose_key(version))
    epoch, release, pre, post, dev, local = parsed

    # Trailing zeros are not significant: 1.0 == 1.0.0.
    trimmed = list(release)
    while len(trimmed) > 1 and trimmed[-1] == 0:
        trimmed.pop()

    if pre is None and post is None and dev is not None:
        # X.Y.devN sorts before X.Y and before any of its prereleases.
        pre_key: Tuple = (-1,)
    elif pre is None:
        pre_key = (1,)          # a final release outranks its prereleases
    else:
        pre_key = (0, pre[0], pre[1])

    post_key = (-1,) if post is None else (1, post)
    dev_key = (1,) if dev is None else (0, dev)
    local_key = (0,) if local is None else (1, local)
    return (1, epoch, tuple(trimmed), pre_key, post_key, dev_key, local_key)


def _loose_key(version: str) -> Tuple:
    """Last resort for versions no grammar accepts: digits then text."""
    parts: List[Tuple] = []
    for piece in re.split(r"[._+-]", (version or "").strip()):
        if piece.isdigit():
            parts.append((0, int(piece), ""))
        elif piece:
            parts.append((1, 0, piece))
    return tuple(parts)


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

_KEYERS = {
    "pip": pep440_key,
    "npm": semver_key,
    "cargo": semver_key,
    "go": semver_key,
    "gem": semver_key,
    "composer": semver_key,
}


def key_for(ecosystem: str) -> Callable[[str], Key]:
    return _KEYERS.get(_language(ecosystem), semver_key)


def _language(ecosystem: str) -> str:
    return (ecosystem or "").split("-", 1)[0]


def compare(a: str, b: str, ecosystem: str = "npm") -> int:
    keyer = key_for(ecosystem)
    ka, kb = keyer(a), keyer(b)
    if ka == kb:
        return 0
    try:
        return -1 if ka < kb else 1
    except TypeError:
        # Mixed shapes (one parsed, one not). Fall back to text so this can
        # never raise mid-scan.
        return -1 if str(ka) < str(kb) else 1


def is_prerelease(version: str, ecosystem: str = "npm") -> bool:
    if _language(ecosystem) == "pip":
        parsed = parse_pep440(version)
        return bool(parsed and (parsed[2] is not None or parsed[4] is not None))
    parsed = parse_semver(version)
    return bool(parsed and parsed[1] != (1,))


def classify_lag(current: str, latest: str, ecosystem: str = "npm"
                 ) -> Optional[str]:
    """major / minor / patch / prerelease, or None if not behind.

    prerelease is its own level: 1.0.0-rc.1 behind 1.0.0 is not a patch
    behind, and calling it one is simply wrong.
    """
    if compare(current, latest, ecosystem) >= 0:
        return None
    cur = _release_triple(current, ecosystem)
    lat = _release_triple(latest, ecosystem)
    if cur is None or lat is None:
        return "patch"
    if lat[0] != cur[0]:
        return "major"
    if lat[1] != cur[1]:
        return "minor"
    if lat[2] != cur[2]:
        return "patch"
    # Same major.minor.patch. Either the current version is a prerelease of it,
    # or a fourth segment moved (rubygems does this), which is patch-like.
    return "prerelease" if is_prerelease(current, ecosystem) else "patch"


def _release_triple(version: str, ecosystem: str) -> Optional[Tuple[int, int, int]]:
    if _language(ecosystem) == "pip":
        parsed = parse_pep440(version)
        if parsed is None:
            return None
        release = list(parsed[1]) + [0, 0, 0]
        return release[0], release[1], release[2]
    parsed = parse_semver(version)
    if parsed is None:
        return None
    release = list(parsed[0]) + [0, 0, 0]
    return release[0], release[1], release[2]


# ---------------------------------------------------------------------------
# Range matching
# ---------------------------------------------------------------------------

_OP_RE = re.compile(r"^\s*(>=|<=|==|!=|~=|\^|~|>|<|=)?\s*(.+?)\s*$")
_X_RANGE_RE = re.compile(r"(?:^|\.)[xX](?:\.|$)")


def satisfies(version: str, spec: str, ecosystem: str = "npm") -> bool:
    """Does `version` satisfy the constraint expression `spec`?

    Handles the comma/space-separated conjunctions that advisory databases and
    manifests use, plus `||` alternation from npm. Anything unparseable
    returns False: better to miss an advisory than to invent one.
    """
    if not spec or not str(spec).strip():
        return False
    spec = str(spec).strip()
    if spec in ("*", "any", "latest"):
        return True

    for alternative in re.split(r"\s*\|\|\s*", spec):
        if not alternative.strip():
            continue
        if _satisfies_all(version, alternative, ecosystem):
            return True
    return False


def _split_clauses(expr: str) -> List[str]:
    parts = [p.strip() for p in expr.split(",")]
    out: List[str] = []
    for part in parts:
        if not part:
            continue
        # "> 1.0 < 2.0" with no comma, as GitHub sometimes emits.
        out.extend(m.group(0).strip()
                   for m in re.finditer(r"(?:>=|<=|==|!=|~=|\^|~|>|<|=)?\s*"
                                        r"[0-9vV][^\s,]*", part))
    return [o for o in out if o]


def _satisfies_all(version: str, expr: str, ecosystem: str) -> bool:
    clauses = _split_clauses(expr)
    if not clauses:
        return False
    for clause in clauses:
        if not _satisfies_one(version, clause, ecosystem):
            return False
    return True


def _satisfies_one(version: str, clause: str, ecosystem: str) -> bool:
    m = _OP_RE.match(clause)
    if not m:
        return False
    op = m.group(1) or "=="
    bound = m.group(2).strip()
    if not bound:
        return False

    if op in ("^", "~", "~="):
        lower, upper = _compatible_bounds(bound, op, ecosystem)
        if lower is None:
            return False
        if compare(version, lower, ecosystem) < 0:
            return False
        return upper is None or compare(version, upper, ecosystem) < 0

    # npm writes 1.4.x where PEP 440 writes 1.4.*; both mean a prefix match.
    if "*" in bound or _X_RANGE_RE.search(bound):
        return _prefix_match(version, bound, op, ecosystem)

    cmp = compare(version, bound, ecosystem)
    if op == ">=":
        return cmp >= 0
    if op == "<=":
        return cmp <= 0
    if op == ">":
        return cmp > 0
    if op == "<":
        return cmp < 0
    if op == "!=":
        return cmp != 0
    return cmp == 0


def _prefix_match(version: str, bound: str, op: str, ecosystem: str) -> bool:
    """`==1.4.*` and npm's `1.4.x`."""
    prefix = bound.replace("x", "*").replace("X", "*").split("*", 1)[0]
    prefix = prefix.rstrip(".")
    if not prefix:
        return op != "!="
    keyer = key_for(ecosystem)
    matched = (keyer(version)[:1] == keyer(prefix)[:1]
               and _release_prefix(version, prefix, ecosystem))
    return not matched if op == "!=" else matched


def _release_prefix(version: str, prefix: str, ecosystem: str) -> bool:
    want = _release_parts(prefix, ecosystem)
    have = _release_parts(version, ecosystem)
    if want is None or have is None:
        return False
    return have[:len(want)] == want


def _release_parts(version: str, ecosystem: str) -> Optional[Sequence[int]]:
    if _language(ecosystem) == "pip":
        parsed = parse_pep440(version)
        return list(parsed[1]) if parsed else None
    parsed = parse_semver(version)
    return list(parsed[0]) if parsed else None


def _compatible_bounds(bound: str, op: str, ecosystem: str
                       ) -> Tuple[Optional[str], Optional[str]]:
    """Lower (inclusive) and upper (exclusive) bounds for ^ ~ and ~=."""
    parts = _release_parts(bound, ecosystem)
    if not parts:
        return None, None
    p = list(parts) + [0, 0, 0]

    if op == "^":
        # npm/cargo caret: allow changes that don't alter the leftmost
        # non-zero component. ^0.2.3 means >=0.2.3 <0.3.0.
        if p[0] != 0:
            return bound, "%d.0.0" % (p[0] + 1)
        if p[1] != 0:
            return bound, "0.%d.0" % (p[1] + 1)
        return bound, "0.0.%d" % (p[2] + 1)

    if op == "~":
        # npm tilde: ~1.2.3 -> >=1.2.3 <1.3.0; ~1.2 -> >=1.2 <1.3.
        if len(parts) >= 2:
            return bound, "%d.%d.0" % (p[0], p[1] + 1)
        return bound, "%d.0.0" % (p[0] + 1)

    # PEP 440 ~=: ~=1.4.2 -> >=1.4.2 <1.5.0. Needs at least two components.
    if len(parts) < 2:
        return None, None
    head = list(parts[:-1])
    head[-1] += 1
    return bound, ".".join(str(x) for x in head)
