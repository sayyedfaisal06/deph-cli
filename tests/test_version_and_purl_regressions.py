"""Defects found auditing the post-0.1.0 surface, now fixed and kept fixed.

Both were reported as xfail reproductions and both were real:

  PURLs weren't percent-encoded, so a name containing `#` or `?` produced a
  malformed identifier — those characters delimit a PURL's subpath and
  qualifiers, so everything after one was silently discarded.

  Four-segment versions were read as a prerelease of their first three, so
  `rails 7.0.4.3` sorted *older* than `7.0.4`. Rubygems and Go modules use
  four segments routinely, and getting the order wrong corrupts both lag
  reporting and advisory range matching.
"""
import pytest

from deph import report, versions


def test_purl_percent_encodes_special_chars():
    p = report.purl("npm", "evil name#?x", "1.0.0")
    assert " " not in p and "#" not in p and "?" not in p, p
    # a benign name must still be untouched
    assert report.purl("npm", "lodash", "4.17.21") == "pkg:npm/lodash@4.17.21"


@pytest.mark.parametrize("eco,name,version,expected", [
    # Straight from the purl spec's own test suite
    # (tests/types/{npm,golang}-test.json): the scope's @ is encoded, the
    # module path's / is not. Both halves have to hold at once.
    ("npm", "@angular/animation", "12.3.1",
     "pkg:npm/%40angular/animation@12.3.1"),
    ("go", "github.com/gorilla/context", "234fd47e07d1004f0aed9c",
     "pkg:golang/github.com/gorilla/context@234fd47e07d1004f0aed9c"),
    ("go", "rsc.io/quote", "v1.5.2", "pkg:golang/rsc.io/quote@v1.5.2"),
    ("composer", "monolog/monolog", "3.5.0",
     "pkg:composer/monolog/monolog@3.5.0"),
    ("npm", "lodash", "4.17.21", "pkg:npm/lodash@4.17.21"),
    ("pip", "pyyaml", "5.4", "pkg:pypi/pyyaml@5.4"),
])
def test_purl_canonical_form(eco, name, version, expected):
    assert report.purl(eco, name, version) == expected


def test_purl_keeps_build_metadata_readable():
    """`+` is legal here and appears in semver build metadata constantly."""
    assert report.purl("npm", "pkg", "1.0.0+build.1") == \
        "pkg:npm/pkg@1.0.0+build.1"


@pytest.mark.parametrize("eco", ["gem", "go", "composer", "npm", "cargo"])
def test_four_component_version_ordering(eco):
    # 1.2.3.4 is newer than 1.2.3, not a prerelease of it.
    assert versions.compare("1.2.3.4", "1.2.3", eco) > 0
    # and a trailing zero is not significant
    assert versions.compare("1.2.3.0", "1.2.3", eco) == 0
    assert versions.compare("1.2.3.4", "1.2.3.5", eco) < 0
    assert versions.compare("1.2.3.10", "1.2.3.9", eco) > 0


def test_real_rubygems_versions():
    """The shape that made this matter: rails and nokogiri ship four."""
    assert versions.compare("7.0.4.3", "7.0.4", "gem") > 0
    assert versions.compare("7.0.4.3", "7.0.4.2", "gem") > 0
    assert versions.compare("1.13.9.1", "1.13.9", "gem") > 0
    # A four-segment version must still be caught by a range.
    assert versions.satisfies("7.0.4.3", "< 7.0.5", "gem")
    assert not versions.satisfies("7.0.4.3", "< 7.0.4", "gem")
    assert versions.satisfies("7.0.4.3", ">= 7.0.4", "gem")


def test_rubygems_dotted_prerelease_still_sorts_early():
    """Rubygems writes 1.0.0.beta1 rather than 1.0.0-beta1."""
    assert versions.compare("1.0.0.beta1", "1.0.0", "gem") < 0
    assert versions.compare("1.0.0.beta1", "1.0.0.beta2", "gem") < 0
    assert versions.is_prerelease("1.0.0.beta1", "gem")
    assert not versions.is_prerelease("7.0.4.3", "gem")


def test_four_segment_bump_is_patch_not_prerelease():
    assert versions.classify_lag("7.0.4.3", "7.0.4.5", "gem") == "patch"
    # a genuine prerelease still reports as one
    assert versions.classify_lag("1.0.0-rc.1", "1.0.0", "npm") == "prerelease"
