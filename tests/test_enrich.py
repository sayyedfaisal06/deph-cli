import io
import json
import urllib.error

import pytest

from deph import enrich
from deph.enrich import (Cache, Enricher, classify_lag, compare_versions,
                         pypi_license, version_in_range)


@pytest.fixture
def cache(tmp_path):
    return Cache(str(tmp_path / "cache.db"))


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def fake_urlopen(payloads):
    """payloads: dict url-substring -> python object (or Exception to raise)."""
    calls = []

    def opener(req, timeout=None):
        url = req.full_url
        calls.append(url)
        for frag, payload in payloads.items():
            if frag in url:
                if isinstance(payload, Exception):
                    raise payload
                return FakeResponse(json.dumps(payload).encode())
        raise urllib.error.HTTPError(url, 404, "not found", {}, None)

    opener.calls = calls
    return opener


# -- version math -------------------------------------------------------------

def test_compare_versions():
    assert compare_versions("1.0.0", "1.0.0") == 0
    assert compare_versions("0.21.1", "1.18.1") == -1
    assert compare_versions("2.0", "1.9.9") == 1
    assert compare_versions("1.0.0-beta", "1.0.0") == -1
    assert compare_versions("1.0", "1.0.0") == 0
    # weird versions never raise
    assert compare_versions("not-a-version", "1.0") in (-1, 0, 1)


def test_classify_lag():
    assert classify_lag("0.21.1", "1.18.1") == "major"
    assert classify_lag("1.2.0", "1.3.0") == "minor"
    assert classify_lag("1.2.3", "1.2.9") == "patch"
    assert classify_lag("1.2.3", "1.2.3") is None
    assert classify_lag("2.0.0", "1.0.0") is None    # ahead of latest


def test_version_in_range():
    assert version_in_range("0.21.1", "< 0.21.2")
    assert version_in_range("3.0.5", ">= 3.0.0, < 3.0.9")
    assert not version_in_range("3.0.9", ">= 3.0.0, < 3.0.9")
    assert version_in_range("2.0.0", "= 2.0.0")
    assert not version_in_range("1.0.0", "")
    assert not version_in_range("1.0.0", "total gibberish")


# -- PyPI license chain ---------------------------------------------------------

def test_pypi_license_prefers_expression():
    assert pypi_license({"license_expression": "MIT", "license": "junk"}) == "MIT"


def test_pypi_license_falls_back_to_license_field():
    assert pypi_license({"license": "Apache-2.0"}) == "Apache-2.0"


def test_pypi_license_rejects_full_text_and_uses_classifiers():
    info = {
        "license": "Permission is hereby granted, free of charge..." * 20,
        "classifiers": ["License :: OSI Approved :: MIT License"],
    }
    assert pypi_license(info) == "MIT"


def test_pypi_license_empty_field_uses_classifiers():
    info = {"license": "",
            "classifiers": ["License :: OSI Approved :: Apache Software License"]}
    assert pypi_license(info) == "Apache-2.0"


def test_pypi_license_none_when_nothing_usable():
    assert pypi_license({"license": "", "classifiers": ["Framework :: Flask"]}) is None


# -- cache ----------------------------------------------------------------------

def test_cache_roundtrip(cache):
    cache.put("k", "v")
    assert cache.get("k") == "v"
    assert cache.get("k", max_age=10000) == "v"
    assert cache.get("missing") is None


def test_cache_ttl_expiry(cache, monkeypatch):
    cache.put("k", "v")
    real_time = enrich.time.time()
    monkeypatch.setattr(enrich.time, "time", lambda: real_time + 999999)
    assert cache.get("k", max_age=10) is None
    assert cache.get("k") == "v"    # no TTL: still there (offline path)


# -- enricher HTTP behaviour -------------------------------------------------------

def test_npm_meta(cache, monkeypatch):
    monkeypatch.setattr(enrich, "_urlopen", fake_urlopen({
        "registry.npmjs.org/axios": {
            "dist-tags": {"latest": "1.18.1"},
            "versions": {"1.18.1": {"license": "MIT"}},
        },
    }))
    e = Enricher(cache=cache, retries=0)
    assert e.latest_and_license("npm", "axios") == ("1.18.1", "MIT")


def test_npm_meta_served_from_cache_second_time(cache, monkeypatch):
    opener = fake_urlopen({
        "registry.npmjs.org/axios": {"dist-tags": {"latest": "1.18.1"},
                                     "license": "MIT"},
    })
    monkeypatch.setattr(enrich, "_urlopen", opener)
    e = Enricher(cache=cache, retries=0)
    e.latest_and_license("npm", "axios")
    e.latest_and_license("npm", "axios")
    assert len(opener.calls) == 1


def test_offline_serves_stale_cache_and_never_touches_network(cache, monkeypatch):
    url = "https://registry.npmjs.org/axios"
    cache.put(url, json.dumps({"dist-tags": {"latest": "1.18.1"}, "license": "MIT"}))

    def explode(*a, **kw):
        raise AssertionError("network access in offline mode")

    monkeypatch.setattr(enrich, "_urlopen", explode)
    e = Enricher(cache=cache, offline=True)
    assert e.latest_and_license("npm", "axios") == ("1.18.1", "MIT")
    # not cached -> None, still no network
    assert e.latest_and_license("npm", "unknown-pkg") == (None, None)


def test_pypi_meta(cache, monkeypatch):
    monkeypatch.setattr(enrich, "_urlopen", fake_urlopen({
        "pypi.org/pypi/pyyaml/json": {
            "info": {"version": "6.0.2", "license": "MIT", "classifiers": []},
        },
    }))
    e = Enricher(cache=cache, retries=0)
    assert e.latest_and_license("pip", "pyyaml") == ("6.0.2", "MIT")


def test_crates_meta(cache, monkeypatch):
    monkeypatch.setattr(enrich, "_urlopen", fake_urlopen({
        "crates.io/api/v1/crates/tokio": {
            "crate": {"max_stable_version": "1.47.1"},
            "versions": [{"num": "1.47.1", "license": "MIT"}],
        },
    }))
    e = Enricher(cache=cache, retries=0)
    assert e.latest_and_license("cargo", "tokio") == ("1.47.1", "MIT")


def test_retry_then_success_on_rate_limit(cache, monkeypatch):
    state = {"n": 0}

    def opener(req, timeout=None):
        state["n"] += 1
        if state["n"] == 1:
            raise urllib.error.HTTPError(req.full_url, 429, "rate limited", {}, None)
        return FakeResponse(json.dumps(
            {"dist-tags": {"latest": "1.0.0"}, "license": "MIT"}).encode())

    monkeypatch.setattr(enrich, "_urlopen", opener)
    monkeypatch.setattr(enrich.time, "sleep", lambda s: None)
    e = Enricher(cache=cache, retries=2, backoff=0.01)
    assert e.latest_and_license("npm", "thing") == ("1.0.0", "MIT")
    assert state["n"] == 2


def test_advisories_graceful_degradation(cache, monkeypatch):
    def opener(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 403, "rate limited", {}, None)

    monkeypatch.setattr(enrich, "_urlopen", opener)
    monkeypatch.setattr(enrich.time, "sleep", lambda s: None)
    e = Enricher(cache=cache, retries=0)
    result = e.advisories("npm", [("axios", "0.21.1")])
    assert result == {("axios", "0.21.1"): []}
    assert any("advisories unavailable" in w for w in e.warnings)
    # once dead, later calls short-circuit without hammering the API
    e.advisories("npm", [("lodash", "4.17.20")])
    assert len(e.warnings) == 1


def test_advisories_matching_and_medium_severity(cache, monkeypatch):
    advisories = [
        {
            "ghsa_id": "GHSA-aaaa",
            "severity": "medium",   # GitHub REST says medium, never moderate
            "vulnerabilities": [
                {"package": {"ecosystem": "npm", "name": "follow-redirects"},
                 "vulnerable_version_range": "< 1.14.7"},
            ],
        },
        {
            "ghsa_id": "GHSA-bbbb",
            "severity": "high",
            "vulnerabilities": [
                {"package": {"ecosystem": "npm", "name": "axios"},
                 "vulnerable_version_range": ">= 0, < 0.21.2"},
                {"package": {"ecosystem": "npm", "name": "axios"},
                 "vulnerable_version_range": "< 0.21.2"},   # duplicate entry
            ],
        },
    ]
    advisories[1]["vulnerabilities"][0]["first_patched_version"] = {
        "identifier": "0.21.2"}
    monkeypatch.setattr(enrich, "_urlopen", fake_urlopen({
        "api.github.com/advisories": advisories,
    }))
    e = Enricher(cache=cache, retries=0, source="github")
    result = e.advisories("npm", [("axios", "0.21.1"),
                                  ("follow-redirects", "1.14.0"),
                                  ("lodash", "4.17.21")])
    axios = result[("axios", "0.21.1")]
    assert [(a.id, a.severity) for a in axios] == [("GHSA-bbbb", "high")]
    assert axios[0].fixed == "0.21.2"          # remediation, not just detection
    fr = result[("follow-redirects", "1.14.0")]
    assert [(a.id, a.severity) for a in fr] == [("GHSA-aaaa", "medium")]
    assert result[("lodash", "4.17.21")] == []


def test_advisories_honor_github_token(cache, monkeypatch):
    seen_headers = {}

    def opener(req, timeout=None):
        seen_headers.update(req.headers)
        return FakeResponse(b"[]")

    monkeypatch.setattr(enrich, "_urlopen", opener)
    e = Enricher(cache=cache, token="tok123", retries=0, source="github")
    e.advisories("pip", [("pyyaml", "5.4")])
    assert seen_headers.get("Authorization") == "Bearer tok123"


def test_unknown_ecosystem_advisories_empty(cache):
    e = Enricher(cache=cache, offline=True)
    assert e.advisories("brew", [("x", "1")]) == {("x", "1"): []}


# -- failure containment (audit P1) ---------------------------------------------

def failing_opener():
    calls = []

    def opener(req, timeout=None):
        calls.append(req.full_url)
        raise urllib.error.URLError("connection refused")

    opener.calls = calls
    return opener


def test_negative_cache_prevents_repaying_retries(cache, monkeypatch):
    """A failed fetch is negative-cached: the next call for the same URL
    returns immediately without touching the network again."""
    opener = failing_opener()
    monkeypatch.setattr(enrich, "_urlopen", opener)
    monkeypatch.setattr(enrich.time, "sleep", lambda s: None)
    e = Enricher(cache=cache, retries=2, backoff=0.01)
    assert e.latest_and_license("npm", "doomed") == (None, None)
    first_calls = len(opener.calls)
    assert first_calls == 3          # 1 try + 2 retries
    assert e.latest_and_license("npm", "doomed") == (None, None)
    assert len(opener.calls) == first_calls   # zero new network calls


def test_stale_cache_served_when_fetch_fails(cache, monkeypatch):
    """An expired-but-present success beats a fresh failure."""
    url = "https://registry.npmjs.org/oldie"
    cache.put(url, json.dumps({"dist-tags": {"latest": "2.0.0"},
                               "license": "MIT"}))
    real_time = enrich.time.time()
    monkeypatch.setattr(enrich.time, "time", lambda: real_time + 30 * 24 * 3600)
    monkeypatch.setattr(enrich, "_urlopen", failing_opener())
    monkeypatch.setattr(enrich.time, "sleep", lambda s: None)
    e = Enricher(cache=cache, retries=0)
    assert e.latest_and_license("npm", "oldie") == ("2.0.0", "MIT")


def test_host_circuit_breaker_stops_hammering_dead_registry(cache, monkeypatch):
    opener = failing_opener()
    monkeypatch.setattr(enrich, "_urlopen", opener)
    monkeypatch.setattr(enrich.time, "sleep", lambda s: None)
    e = Enricher(cache=cache, retries=0)
    for i in range(enrich.HOST_FAILURE_LIMIT):
        e.latest_and_license("npm", "pkg-%d" % i)
    tripped = len(opener.calls)
    assert any("unreachable" in w for w in e.warnings)
    # Further lookups on the dead host make no network calls at all.
    for i in range(10):
        assert e.latest_and_license("npm", "more-%d" % i) == (None, None)
    assert len(opener.calls) == tripped
    # ...but a different host is unaffected (breaker is per-host).
    e.latest_and_license("pip", "elsewhere")
    assert len(opener.calls) == tripped + 1


def test_success_resets_host_failure_count(cache, monkeypatch):
    e = Enricher(cache=cache, retries=0)
    e._record_host("h", ok=False)
    e._record_host("h", ok=False)
    e._record_host("h", ok=True)
    assert not e._host_dead("h")


# -- redirect hardening (audit S2) ------------------------------------------------

def test_redirect_strips_authorization_on_cross_host():
    handler = enrich._SafeRedirectHandler()
    req = enrich.urllib.request.Request(
        "https://api.github.com/advisories",
        headers={"Authorization": "Bearer secret", "Accept": "application/json"})
    new = handler.redirect_request(
        req, None, 302, "Found", {}, "https://evil.example.com/capture")
    assert new is not None
    assert not any(k.lower() == "authorization" for k in new.headers)
    # same-host redirects keep the header
    same = handler.redirect_request(
        req, None, 302, "Found", {}, "https://api.github.com/other")
    assert any(k.lower() == "authorization" for k in same.headers)


# -- cache permissions (audit S3) ---------------------------------------------------

def test_cache_file_is_private(tmp_path):
    import os
    import stat
    c = Cache(str(tmp_path / "sub" / "cache.db"))
    c.put("k", "v")
    if os.name != "nt":
        assert stat.S_IMODE(os.stat(c.path).st_mode) == 0o600
        assert stat.S_IMODE(os.stat(os.path.dirname(c.path)).st_mode) == 0o700


def test_classify_lag_prerelease():
    assert classify_lag("1.0.0-rc.1", "1.0.0") == "prerelease"
    assert classify_lag("1.0.0", "1.0.1-rc.1") == "patch"


# -- OSV (the default advisory source) -----------------------------------------

OSV_VULN = {
    "id": "PYSEC-2021-1",
    "summary": "arbitrary code execution in full_load",
    "aliases": ["CVE-2020-14343", "GHSA-8q59-q68h-6hv4"],
    "database_specific": {"severity": "CRITICAL", "cwe_ids": ["CWE-20"]},
    "severity": [{"type": "CVSS_V3",
                  "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "affected": [{
        "package": {"name": "pyyaml", "ecosystem": "PyPI"},
        "ranges": [{"type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "5.4.1"}]}],
    }],
}


def osv_opener(batch_payload, details):
    """Fake OSV: a POST for querybatch, GETs for each vuln id."""
    calls = []

    def opener(req, timeout=None):
        calls.append(req.full_url)
        if "querybatch" in req.full_url:
            assert req.get_method() == "POST"
            return FakeResponse(json.dumps(batch_payload).encode())
        for vid, detail in details.items():
            if req.full_url.endswith(vid):
                return FakeResponse(json.dumps(detail).encode())
        raise urllib.error.HTTPError(req.full_url, 404, "no", {}, None)

    opener.calls = calls
    return opener


def test_osv_is_the_default_source(cache):
    assert Enricher(cache=cache).source == "osv"


def test_osv_batch_maps_advisories_and_prefers_the_ghsa_alias(cache, monkeypatch):
    batch = {"results": [{"vulns": [{"id": "PYSEC-2021-1"}]}, {}]}
    monkeypatch.setattr(enrich, "_urlopen",
                        osv_opener(batch, {"PYSEC-2021-1": OSV_VULN}))
    e = Enricher(cache=cache, retries=0)
    result = e.advisories("pip", [("pyyaml", "5.4"), ("requests", "2.32.3")])

    advisories = result[("pyyaml", "5.4")]
    assert len(advisories) == 1
    adv = advisories[0]
    # GHSA is what people paste into a waiver, so it wins over the PYSEC id.
    assert adv.id == "GHSA-8q59-q68h-6hv4"
    assert adv.url == "https://github.com/advisories/GHSA-8q59-q68h-6hv4"
    assert adv.severity == "critical"
    assert adv.fixed == "5.4.1"          # the upgrade to recommend
    assert adv.cwe == "CWE-20"
    assert adv.cvss.startswith("CVSS:3.1")
    assert result[("requests", "2.32.3")] == []


def test_osv_without_a_ghsa_alias_keeps_its_own_id(cache, monkeypatch):
    vuln = dict(OSV_VULN, aliases=["CVE-2020-14343"], id="RUSTSEC-2021-0001")
    batch = {"results": [{"vulns": [{"id": "RUSTSEC-2021-0001"}]}]}
    monkeypatch.setattr(enrich, "_urlopen",
                        osv_opener(batch, {"RUSTSEC-2021-0001": vuln}))
    e = Enricher(cache=cache, retries=0)
    adv = e.advisories("cargo", [("tokio", "1.8.0")])[("tokio", "1.8.0")][0]
    # RustSec advisories are exactly what a GitHub-only query would miss.
    assert adv.id == "RUSTSEC-2021-0001"
    assert adv.url == "https://osv.dev/vulnerability/RUSTSEC-2021-0001"


def test_osv_lowest_fixed_version_wins(cache, monkeypatch):
    vuln = dict(OSV_VULN, affected=[{
        "package": {"name": "pyyaml", "ecosystem": "PyPI"},
        "ranges": [
            {"events": [{"introduced": "0"}, {"fixed": "6.0.1"}]},
            {"events": [{"introduced": "0"}, {"fixed": "5.4.1"}]},
        ],
    }])
    batch = {"results": [{"vulns": [{"id": "PYSEC-2021-1"}]}]}
    monkeypatch.setattr(enrich, "_urlopen",
                        osv_opener(batch, {"PYSEC-2021-1": vuln}))
    e = Enricher(cache=cache, retries=0)
    adv = e.advisories("pip", [("pyyaml", "5.4")])[("pyyaml", "5.4")][0]
    assert adv.fixed == "5.4.1"


def test_osv_post_is_cached_by_body(cache, monkeypatch):
    batch = {"results": [{}]}
    opener = osv_opener(batch, {})
    monkeypatch.setattr(enrich, "_urlopen", opener)
    e = Enricher(cache=cache, retries=0)
    e.advisories("pip", [("a", "1.0")])
    first = len(opener.calls)
    e.advisories("pip", [("a", "1.0")])          # same batch: cached
    assert len(opener.calls) == first
    e.advisories("pip", [("b", "2.0")])          # different batch: fetched
    assert len(opener.calls) > first


def test_osv_failure_degrades_with_a_warning(cache, monkeypatch):
    def boom(req, timeout=None):
        raise urllib.error.URLError("osv down")

    monkeypatch.setattr(enrich, "_urlopen", boom)
    monkeypatch.setattr(enrich.time, "sleep", lambda s: None)
    e = Enricher(cache=cache, retries=0)
    assert e.advisories("pip", [("pyyaml", "5.4")]) == {("pyyaml", "5.4"): []}
    assert any("advisories unavailable" in w for w in e.warnings)


def test_osv_offline_uses_only_the_cache(cache, monkeypatch):
    def explode(*a, **kw):
        raise AssertionError("network access in offline mode")

    monkeypatch.setattr(enrich, "_urlopen", explode)
    e = Enricher(cache=cache, offline=True)
    assert e.advisories("pip", [("pyyaml", "5.4")]) == {("pyyaml", "5.4"): []}


def test_severity_from_cvss_score():
    from deph.enrich import _severity_from_cvss
    assert _severity_from_cvss("CVSS:3.1/AV:N 9.8") == "critical"
    assert _severity_from_cvss("7.5") == "high"
    assert _severity_from_cvss("5.0") == "medium"
    assert _severity_from_cvss("1.0") == "low"
    assert _severity_from_cvss("nonsense") == ""


def test_unknown_ecosystem_has_no_osv_mapping(cache):
    e = Enricher(cache=cache, offline=True)
    assert e.advisories("brew", [("x", "1")]) == {("x", "1"): []}


# -- yanked and deprecated ------------------------------------------------------

def test_pypi_yanked_release_is_reported(cache, monkeypatch):
    monkeypatch.setattr(enrich, "_urlopen", fake_urlopen({
        "pypi.org/pypi/badpkg/json": {
            "info": {"version": "2.0.0", "license_expression": "MIT"},
            "releases": {"1.0.0": [{"yanked": True,
                                    "yanked_reason": "broken wheel"}]},
        },
    }))
    e = Enricher(cache=cache, retries=0)
    meta = e.package_meta("pip", "badpkg", "1.0.0")
    assert meta.yanked == "broken wheel"
    assert e.package_meta("pip", "badpkg", "2.0.0").yanked is None


def test_npm_deprecated_package_is_reported(cache, monkeypatch):
    monkeypatch.setattr(enrich, "_urlopen", fake_urlopen({
        "registry.npmjs.org/request": {
            "dist-tags": {"latest": "2.88.2"},
            "deprecated": "request has been deprecated",
            "versions": {"2.88.2": {"license": "Apache-2.0"}},
        },
    }))
    meta = Enricher(cache=cache, retries=0).package_meta("npm", "request")
    assert meta.deprecated == "request has been deprecated"
    assert meta.latest == "2.88.2"


def test_crates_yanked_version(cache, monkeypatch):
    monkeypatch.setattr(enrich, "_urlopen", fake_urlopen({
        "crates.io/api/v1/crates/pulled": {
            "crate": {"max_stable_version": "2.0.0"},
            "versions": [{"num": "2.0.0", "license": "MIT"},
                         {"num": "1.0.0", "license": "MIT", "yanked": True}],
        },
    }))
    e = Enricher(cache=cache, retries=0)
    assert e.package_meta("cargo", "pulled", "1.0.0").yanked == "yanked"


# -- the other registries -------------------------------------------------------

def test_go_proxy_latest(cache, monkeypatch):
    monkeypatch.setattr(enrich, "_urlopen", fake_urlopen({
        "proxy.golang.org/github.com/gin-gonic/gin/@latest":
            {"Version": "v1.10.0", "Time": "2024-05-07T00:00:00Z"},
    }))
    meta = Enricher(cache=cache, retries=0).package_meta(
        "go", "github.com/gin-gonic/gin")
    assert meta.latest == "v1.10.0"


def test_go_module_path_escaping():
    from deph.enrich import _go_escape
    # The proxy lowercases capitals as !x so paths stay case-safe.
    assert _go_escape("github.com/BurntSushi/toml") == \
        "github.com/!burnt!sushi/toml"


def test_rubygems_meta(cache, monkeypatch):
    monkeypatch.setattr(enrich, "_urlopen", fake_urlopen({
        "rubygems.org/api/v1/gems/rails.json":
            {"version": "7.1.3", "licenses": ["MIT"]},
    }))
    meta = Enricher(cache=cache, retries=0).package_meta("gem", "rails")
    assert (meta.latest, meta.license) == ("7.1.3", "MIT")


def test_packagist_meta_picks_the_highest_release(cache, monkeypatch):
    monkeypatch.setattr(enrich, "_urlopen", fake_urlopen({
        "repo.packagist.org/p2/monolog/monolog.json": {
            "packages": {"monolog/monolog": [
                {"version": "v2.9.1", "license": ["MIT"]},
                {"version": "v3.5.0", "license": ["MIT"]},
                {"version": "dev-main", "license": ["MIT"]},
            ]},
        },
    }))
    meta = Enricher(cache=cache, retries=0).package_meta(
        "composer", "monolog/monolog")
    assert meta.latest == "3.5.0"        # v stripped, dev-main ignored
    assert meta.license == "MIT"


def test_registry_meta_never_raises_on_a_weird_shape(cache, monkeypatch):
    monkeypatch.setattr(enrich, "_urlopen", fake_urlopen({
        "registry.npmjs.org/odd": ["not", "an", "object"],
        "pypi.org/pypi/odd/json": {"info": "a string"},
        "crates.io/api/v1/crates/odd": {"crate": []},
    }))
    e = Enricher(cache=cache, retries=0)
    for eco in ("npm", "pip", "cargo"):
        meta = e.package_meta(eco, "odd")
        assert meta.latest is None and meta.license is None


# -- private registries ---------------------------------------------------------

def test_registry_base_defaults():
    assert enrich.registry_base("npm") == "https://registry.npmjs.org"
    assert enrich.registry_base("pip") == "https://pypi.org/pypi"


def test_registry_base_from_env(monkeypatch):
    monkeypatch.setenv("NPM_CONFIG_REGISTRY", "https://nexus.corp/npm/")
    assert enrich.registry_base("npm") == "https://nexus.corp/npm"
    monkeypatch.setenv("DEPH_NPM_REGISTRY", "https://deph.corp/npm")
    # The deph-specific variable wins over the tool's own.
    assert enrich.registry_base("npm") == "https://deph.corp/npm"


def test_goproxy_list_takes_the_first_real_entry(monkeypatch):
    monkeypatch.setenv("GOPROXY", "https://proxy.corp,direct")
    assert enrich.registry_base("go") == "https://proxy.corp"
    monkeypatch.setenv("GOPROXY", "off")
    assert enrich.registry_base("go") == "https://proxy.golang.org"


def test_private_registry_is_actually_used(cache, monkeypatch):
    monkeypatch.setenv("DEPH_PIP_INDEX_URL", "https://pypi.corp/simple")
    monkeypatch.setenv("DEPH_PIP_TOKEN", "secret-token")
    seen = {}

    def opener(req, timeout=None):
        seen["url"] = req.full_url
        seen["auth"] = req.headers.get("Authorization")
        return FakeResponse(json.dumps(
            {"info": {"version": "1.0.0", "license_expression": "MIT"}}).encode())

    monkeypatch.setattr(enrich, "_urlopen", opener)
    meta = Enricher(cache=cache, retries=0).package_meta("pip", "internal-lib")
    assert seen["url"] == "https://pypi.corp/simple/internal-lib/json"
    assert seen["auth"] == "Bearer secret-token"
    assert meta.latest == "1.0.0"
