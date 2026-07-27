"""SPDX expression evaluation.

The string-splitting version this replaced passed `(MIT OR GPL-3.0) AND
Apache-2.0` against an allowlist of just MIT, which is a false negative on a
licence check. These pin the real grammar.
"""

import pytest

from deph import spdx

ALLOW = ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC"]


@pytest.mark.parametrize("expr,ok", [
    ("MIT", True),
    ("mit", True),                                  # registries vary on case
    ("GPL-3.0-only", False),
    ("MIT OR Apache-2.0", True),
    ("GPL-3.0-only OR MIT", True),
    ("GPL-3.0-only OR AGPL-3.0-only", False),
    ("MIT/Apache-2.0", True),                       # npm's slash spelling
    ("MIT AND Apache-2.0", True),
    ("MIT AND GPL-3.0-only", False),
    ("(MIT OR GPL-3.0-only) AND Apache-2.0", True),
    ("(MIT OR GPL-3.0-only) AND GPL-2.0-only", False),
    ("(GPL-3.0-only OR AGPL-3.0-only) AND MIT", False),
    ("Apache-2.0 WITH LLVM-exception", True),
    ("GPL-3.0-only WITH Classpath-exception-2.0", False),
])
def test_satisfies(expr, ok):
    assert spdx.satisfies(expr, ALLOW) is ok


def test_precedence_and_binds_tighter_than_or():
    # MIT OR (GPL-3.0-only AND GPL-2.0-only): the MIT branch alone satisfies.
    assert spdx.satisfies("MIT OR GPL-3.0-only AND GPL-2.0-only", ALLOW)
    # Without correct precedence this would read as (X OR Y) AND Z and fail.
    assert not spdx.satisfies("GPL-3.0-only OR GPL-2.0-only AND MIT", ALLOW)


def test_deprecated_ids_match_current_spelling():
    assert spdx.satisfies("GPL-2.0", ["GPL-2.0-only"])
    assert spdx.satisfies("GPL-2.0-only", ["GPL-2.0"])
    assert spdx.satisfies("LGPL-2.1", ["LGPL-2.1-only"])


def test_or_later_suffix():
    assert spdx.normalize_id("GPL-3.0+") == "gpl-3.0-or-later"
    assert spdx.satisfies("GPL-3.0+", ["GPL-3.0-or-later"])
    # An allowlist naming the exact version also covers "or later".
    assert spdx.satisfies("GPL-3.0-or-later", ["GPL-3.0-only"])


def test_unparseable_expression_is_not_allowed():
    """An expression we can't read is one we can't certify."""
    for bad in ["MIT AND", "OR MIT", "(MIT", "MIT)", "MIT OR OR Apache-2.0"]:
        assert not spdx.is_valid(bad)
        assert not spdx.satisfies(bad, ALLOW)


def test_free_text_license_is_not_silently_allowed():
    assert not spdx.satisfies("See LICENSE file", ALLOW)
    assert not spdx.satisfies("Proprietary", ALLOW)


def test_exact_free_text_can_be_allowlisted_verbatim():
    # An escape hatch for registries that emit a non-SPDX name.
    assert spdx.satisfies("Proprietary", ["Proprietary"])


@pytest.mark.parametrize("expr,names,ok", [
    ("GPL-3.0-only", ["GPL-3.0-only"], True),
    ("MIT OR GPL-3.0-only", ["GPL-3.0-only"], True),
    ("MIT", ["GPL-3.0-only"], False),
    ("GPL-3.0", ["GPL-3.0-only"], True),
    ("AGPL-3.0-or-later", ["AGPL-3.0"], True),
])
def test_any_of_denylist(expr, names, ok):
    assert spdx.any_of(expr, names) is ok


def test_identifiers():
    assert spdx.identifiers("MIT OR Apache-2.0") == ["apache-2.0", "mit"]
    assert spdx.identifiers("(MIT OR ISC) AND Apache-2.0") == [
        "apache-2.0", "isc", "mit"]


def test_empty_and_none_are_not_allowed():
    assert not spdx.satisfies("", ALLOW)
    assert not spdx.satisfies(None, ALLOW)


def test_parse_returns_none_for_non_expressions():
    """Documented contract: callers must handle None.

    Registries publish licence fields that aren't expressions at all, so this
    is a normal result. Treating it as "no obligations" would pass a package
    that was never actually checked.
    """
    for junk in ["", None, "See LICENSE file", "MIT AND", "(MIT"]:
        assert spdx.parse(junk) is None
    assert spdx.parse("MIT") is not None


def test_satisfies_and_any_of_are_safe_against_none():
    # The guarded API never lets an unparseable expression pass an allowlist...
    assert not spdx.satisfies("MIT AND", ALLOW)
    # ...and never claims a denylist match it can't justify.
    assert not spdx.any_of("MIT AND", ["GPL-3.0-only"])
