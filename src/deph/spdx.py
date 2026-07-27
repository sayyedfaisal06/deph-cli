"""SPDX license expressions.

A real recursive-descent evaluator over the expression grammar, because the
string-splitting version this replaced got `(MIT OR GPL-3.0) AND Apache-2.0`
wrong, and license compliance is one of the three things deph claims to do.

Supported: AND, OR, WITH, parentheses, `+` (or-later), `LicenseRef-*`, the
deprecated `GPL-2.0`-style ids mapped to their current spelling, and npm's
`MIT/Apache-2.0` slash spelling. Case-insensitive throughout, since registries
are inconsistent about it.

Precedence, per the SPDX spec: WITH binds tightest, then AND, then OR.
"""

import re
from typing import List, Optional, Sequence, Set

# Deprecated identifier -> current one. An allowlist written with either
# spelling should accept a package declaring the other.
DEPRECATED_IDS = {
    "gpl-1.0": "gpl-1.0-only",
    "gpl-2.0": "gpl-2.0-only",
    "gpl-3.0": "gpl-3.0-only",
    "gpl-1.0+": "gpl-1.0-or-later",
    "gpl-2.0+": "gpl-2.0-or-later",
    "gpl-3.0+": "gpl-3.0-or-later",
    "lgpl-2.0": "lgpl-2.0-only",
    "lgpl-2.1": "lgpl-2.1-only",
    "lgpl-3.0": "lgpl-3.0-only",
    "lgpl-2.0+": "lgpl-2.0-or-later",
    "lgpl-2.1+": "lgpl-2.1-or-later",
    "lgpl-3.0+": "lgpl-3.0-or-later",
    "agpl-1.0": "agpl-1.0-only",
    "agpl-3.0": "agpl-3.0-only",
    "agpl-3.0+": "agpl-3.0-or-later",
    "bsd-2-clause-freebsd": "bsd-2-clause",
    "bsd-2-clause-netbsd": "bsd-2-clause",
    "zlib-acknowledgement": "zlib-acknowledgement",
    "nunit": "nunit",
    "wxwindows": "wxwindows-exception-3.1",
    "gfdl-1.1": "gfdl-1.1-only",
    "gfdl-1.2": "gfdl-1.2-only",
    "gfdl-1.3": "gfdl-1.3-only",
}

_TOKEN_RE = re.compile(r"\(|\)|[^\s()]+")
_OPERATORS = {"and", "or", "with"}


class Node:
    def licenses(self) -> Set[str]:
        raise NotImplementedError

    def satisfied_by(self, allowed: Set[str]) -> bool:
        raise NotImplementedError


class Leaf(Node):
    def __init__(self, ident: str, exception: Optional[str] = None):
        self.ident = normalize_id(ident)
        self.exception = normalize_id(exception) if exception else None

    def licenses(self) -> Set[str]:
        return {self.ident}

    def satisfied_by(self, allowed: Set[str]) -> bool:
        if self.ident in allowed:
            return True
        # "GPL-3.0-or-later" is satisfied by an allowlist naming the exact
        # version, and "X+" is the same statement in older syntax.
        if self.ident.endswith("-or-later"):
            base = self.ident[: -len("-or-later")]
            return base in allowed or (base + "-only") in allowed
        if self.ident.endswith("-only"):
            return self.ident[: -len("-only")] in allowed
        return False

    def __repr__(self):  # pragma: no cover
        return "Leaf(%s)" % self.ident


class And(Node):
    def __init__(self, parts: Sequence[Node]):
        self.parts = list(parts)

    def licenses(self) -> Set[str]:
        out: Set[str] = set()
        for p in self.parts:
            out |= p.licenses()
        return out

    def satisfied_by(self, allowed: Set[str]) -> bool:
        return all(p.satisfied_by(allowed) for p in self.parts)


class Or(Node):
    def __init__(self, parts: Sequence[Node]):
        self.parts = list(parts)

    def licenses(self) -> Set[str]:
        out: Set[str] = set()
        for p in self.parts:
            out |= p.licenses()
        return out

    def satisfied_by(self, allowed: Set[str]) -> bool:
        return any(p.satisfied_by(allowed) for p in self.parts)


def normalize_id(ident: str) -> str:
    s = (ident or "").strip().lower().rstrip(",;")
    if s.endswith("+") and s not in DEPRECATED_IDS:
        base = s[:-1]
        mapped = DEPRECATED_IDS.get(s)
        if mapped:
            return mapped
        return base + "-or-later"
    return DEPRECATED_IDS.get(s, s)


def _tokenize(expr: str) -> List[str]:
    # npm writes MIT/Apache-2.0 for a dual license; treat / as OR. A bare
    # slash inside an identifier is not a thing in SPDX.
    expr = (expr or "").replace("/", " OR ")
    return _TOKEN_RE.findall(expr)


class _Parser:
    def __init__(self, tokens: List[str]):
        self.tokens = tokens
        self.pos = 0

    def peek(self) -> Optional[str]:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def next(self) -> Optional[str]:
        tok = self.peek()
        if tok is not None:
            self.pos += 1
        return tok

    def parse(self) -> Optional[Node]:
        node = self.parse_or()
        if self.peek() is not None:
            return None          # trailing junk: treat the whole thing as opaque
        return node

    def parse_or(self) -> Optional[Node]:
        parts = []
        first = self.parse_and()
        if first is None:
            return None
        parts.append(first)
        while self.peek() and self.peek().lower() == "or":
            self.next()
            nxt = self.parse_and()
            if nxt is None:
                return None
            parts.append(nxt)
        return parts[0] if len(parts) == 1 else Or(parts)

    def parse_and(self) -> Optional[Node]:
        parts = []
        first = self.parse_with()
        if first is None:
            return None
        parts.append(first)
        while self.peek() and self.peek().lower() == "and":
            self.next()
            nxt = self.parse_with()
            if nxt is None:
                return None
            parts.append(nxt)
        return parts[0] if len(parts) == 1 else And(parts)

    def parse_with(self) -> Optional[Node]:
        node = self.parse_atom()
        if node is None:
            return None
        while self.peek() and self.peek().lower() == "with":
            self.next()
            exception = self.next()
            if exception is None:
                return None
            # The exception narrows the licence but doesn't change which
            # identifier it is, which is what an allowlist matches on.
            if isinstance(node, Leaf):
                node = Leaf(node.ident, exception)
        return node

    def parse_atom(self) -> Optional[Node]:
        tok = self.next()
        if tok is None:
            return None
        if tok == "(":
            inner = self.parse_or()
            if inner is None or self.next() != ")":
                return None
            return inner
        if tok == ")" or tok.lower() in _OPERATORS:
            return None
        return Leaf(tok)


def parse(expr: str) -> Optional[Node]:
    """The expression tree, or None if `expr` isn't a valid SPDX expression.

    Callers MUST handle None. Registries publish plenty of licence fields that
    aren't expressions at all ("See LICENSE", a pasted licence text, an empty
    string), so None is a normal result rather than an edge case, and treating
    it as "no obligations" would silently pass a package that was never
    checked. `satisfies` and `any_of` already do the safe thing; prefer them.
    """
    tokens = _tokenize(expr)
    if not tokens:
        return None
    return _Parser(tokens).parse()


def satisfies(expr: str, allowlist: Sequence[str]) -> bool:
    """Is every obligation in `expr` covered by the allowlist?

    Unparseable expressions are not allowed: an expression we can't read is
    not one we can certify, and silently passing it would defeat the check.
    """
    allowed = {normalize_id(a) for a in allowlist}
    node = parse(expr)
    if node is None:
        return normalize_id(expr) in allowed
    return node.satisfied_by(allowed)


def _family(ident: str) -> str:
    """Drop an -only/-or-later suffix.

    A denylist entry names a licence family: someone writing `in [AGPL-3.0]`
    means every AGPL-3.0 variant, not one exact spelling.
    """
    for suffix in ("-or-later", "-only"):
        if ident.endswith(suffix):
            return ident[: -len(suffix)]
    return ident


def any_of(expr: str, names: Sequence[str]) -> bool:
    """Does any identifier in `expr` appear in `names`?  (Denylist test.)"""
    wanted = {_family(normalize_id(n)) for n in names}
    node = parse(expr)
    idents = node.licenses() if node is not None else {normalize_id(expr)}
    return any(_family(ident) in wanted for ident in idents)


def and_groups(expr: str) -> List[List[str]]:
    """Flattened AND-groups of OR-alternatives, for callers that want a list."""
    node = parse(expr)
    if node is None:
        return [[normalize_id(expr)]]
    if isinstance(node, And):
        return [sorted(p.licenses()) for p in node.parts]
    return [sorted(node.licenses())]


def identifiers(expr: str) -> List[str]:
    node = parse(expr)
    if node is None:
        return [normalize_id(expr)]
    return sorted(node.licenses())


def is_valid(expr: str) -> bool:
    return parse(expr) is not None
