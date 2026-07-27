"""Per-ecosystem version comparison and range matching.

These are the cases where a single generic comparator gets it wrong, which is
why versions.py exists. A mis-matched range means either a missed advisory or
a fabricated one.
"""

import pytest

from deph import versions


# -- semver ordering ----------------------------------------------------------

@pytest.mark.parametrize("lower,higher", [
    ("1.0.0", "1.0.1"),
    ("1.9.0", "1.10.0"),          # not string ordering
    ("0.21.1", "1.18.1"),
    ("1.0.0-alpha", "1.0.0"),     # a release beats its prerelease
    ("1.0.0-alpha.1", "1.0.0-alpha.2"),
    ("1.0.0-alpha.9", "1.0.0-alpha.10"),   # numeric identifiers, not text
    ("1.0.0-alpha", "1.0.0-beta"),
    ("1.0.0-rc.1", "1.0.0"),
    ("v1.2.3", "v1.2.4"),
])
def test_semver_order(lower, higher):
    assert versions.compare(lower, higher, "npm") < 0
    assert versions.compare(higher, lower, "npm") > 0


def test_semver_equality_ignores_build_and_prefix():
    assert versions.compare("1.2.3", "v1.2.3", "npm") == 0
    assert versions.compare("1.2.3+build.1", "1.2.3+build.2", "npm") == 0
    assert versions.compare("1.2", "1.2.0", "npm") == 0


# -- PEP 440 ------------------------------------------------------------------

@pytest.mark.parametrize("lower,higher", [
    ("1.0", "1.0.1"),
    ("1.0a1", "1.0b1"),
    ("1.0b1", "1.0rc1"),
    ("1.0rc1", "1.0"),
    ("1.0", "1.0.post1"),          # a post-release is newer
    ("1.0.dev1", "1.0a1"),         # dev is oldest of all
    ("1.0.dev1", "1.0"),
    ("1.0", "1!0.1"),              # an epoch outranks everything
    ("2.0", "1!1.0"),
    ("1.0a2", "1.0a10"),
])
def test_pep440_order(lower, higher):
    assert versions.compare(lower, higher, "pip") < 0
    assert versions.compare(higher, lower, "pip") > 0


def test_pep440_equivalences():
    assert versions.compare("1.0", "1.0.0", "pip") == 0
    assert versions.compare("1.0", "1.0.0.0", "pip") == 0
    assert versions.compare("1.0alpha1", "1.0a1", "pip") == 0
    assert versions.compare("1.0-rc1", "1.0rc1", "pip") == 0


def test_pep440_and_semver_disagree_about_prerelease_spelling():
    """The reason this module is per-ecosystem rather than shared.

    "1.0.post1" is a valid PEP 440 version newer than 1.0. Read as semver it
    is a prerelease of 1.0, i.e. older. Both readings are right for their own
    ecosystem, so a single comparator has to be wrong for one of them.
    """
    assert versions.compare("1.0.post1", "1.0", "pip") > 0
    assert versions.compare("1.0.post1", "1.0", "npm") < 0


# -- lag classification -------------------------------------------------------

@pytest.mark.parametrize("current,latest,expected", [
    ("0.21.1", "1.18.1", "major"),
    ("1.2.0", "1.3.0", "minor"),
    ("1.2.3", "1.2.9", "patch"),
    ("1.0.0-rc.1", "1.0.0", "prerelease"),
    ("1.2.3", "1.2.3", None),
    ("2.0.0", "1.0.0", None),
])
def test_classify_lag(current, latest, expected):
    assert versions.classify_lag(current, latest, "npm") == expected


def test_classify_lag_pep440():
    assert versions.classify_lag("1.0rc1", "1.0", "pip") == "prerelease"
    assert versions.classify_lag("5.4", "6.0.2", "pip") == "major"


# -- range matching -----------------------------------------------------------

@pytest.mark.parametrize("version,spec,ok", [
    ("0.21.1", "< 0.21.2", True),
    ("0.21.2", "< 0.21.2", False),
    ("3.0.5", ">= 3.0.0, < 3.0.9", True),
    ("3.0.9", ">= 3.0.0, < 3.0.9", False),
    ("2.0.0", "= 2.0.0", True),
    ("1.0.0", "", False),
    ("1.0.0", "total gibberish", False),
    ("1.0.0", "*", True),
    # npm-style, including the space-separated form GitHub sometimes emits
    ("1.5.0", ">= 1.0.0 < 2.0.0", True),
    ("2.5.0", ">= 1.0.0 < 2.0.0", False),
    ("1.2.9", "^1.2.3", True),
    ("2.0.0", "^1.2.3", False),
    ("0.2.5", "^0.2.3", True),     # caret on 0.x only allows patch
    ("0.3.0", "^0.2.3", False),
    ("1.2.9", "~1.2.3", True),
    ("1.3.0", "~1.2.3", False),
    ("1.4.0", "1.4.x", True),
    ("1.5.0", "1.4.x", False),
    # alternation
    ("2.1.0", "^1.0.0 || ^2.0.0", True),
    ("3.1.0", "^1.0.0 || ^2.0.0", False),
])
def test_satisfies_npm(version, spec, ok):
    assert versions.satisfies(version, spec, "npm") is ok


@pytest.mark.parametrize("version,spec,ok", [
    ("1.4.9", "~=1.4.2", True),
    ("1.5.0", "~=1.4.2", False),
    ("1.4.7", "==1.4.*", True),
    ("1.5.0", "==1.4.*", False),
    ("1.26.4", ">=1.21.1,<1.26.5", True),
    ("1.26.5", ">=1.21.1,<1.26.5", False),
    ("2.0.0", "!=2.0.0", False),
    ("2.0.1", "!=2.0.0", True),
])
def test_satisfies_pip(version, spec, ok):
    assert versions.satisfies(version, spec, "pip") is ok


def test_unparseable_versions_never_raise():
    for a, b in [("not-a-version", "1.0"), ("", "1.0"), ("1.0", ""),
                 ("latest", "stable"), ("$$$", "%%%")]:
        assert versions.compare(a, b, "npm") in (-1, 0, 1)
        assert versions.compare(a, b, "pip") in (-1, 0, 1)
        assert versions.classify_lag(a, b, "npm") in (
            None, "major", "minor", "patch", "prerelease")


def test_go_pseudo_version_is_comparable():
    old = "v0.0.0-20210101120000-abcdef123456"
    new = "v0.0.0-20220101120000-abcdef123456"
    assert versions.compare(old, new, "go") < 0


def test_is_prerelease():
    assert versions.is_prerelease("1.0.0-rc.1", "npm")
    assert not versions.is_prerelease("1.0.0", "npm")
    assert versions.is_prerelease("1.0rc1", "pip")
    assert versions.is_prerelease("1.0.dev1", "pip")
    assert not versions.is_prerelease("1.0", "pip")
