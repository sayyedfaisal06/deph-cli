"""End-to-end: the CLI as a subprocess, against a copy of the fixture repo.

Scans run on a pre-seeded cache via DEPH_CACHE_DIR, so these exercise the real
scan path without a network. Add a registry response to seed_cache() rather
than letting a test reach out.
"""

import json
import os
import shutil
import subprocess
import sys
import urllib.parse

import pytest

from deph import enrich

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "monorepo")


OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"

# (package, version) -> advisories the fake OSV serves for it.
# id, severity, fixed version.
SEEDED_ADVISORIES = {
    ("axios", "0.21.1"): [("GHSA-hfxv-24rg-xrqf", "high", "0.21.2")],
    ("follow-redirects", "1.14.0"): [("GHSA-r4q5-vmmm-2653", "medium", "1.14.7")],
    ("lodash", "4.17.20"): [("GHSA-35jh-r3h4-6jhm", "high", "4.17.21")],
    ("pyyaml", "5.4"): [("GHSA-8q59-q68h-6hv4", "critical", "5.4.1")],
    ("urllib3", "1.26.4"): [("GHSA-q2q7-5pp4-w6pg", "medium", "1.26.5")],
    ("tokio", "1.8.0"): [("GHSA-jxwc-jh89-vwj3", "medium", "1.8.4")],
}


def advisory_url(ecosystem, pairs):
    gh_eco = enrich.GITHUB_ECOSYSTEMS[ecosystem]   # e.g. cargo -> rust
    affects = ",".join("%s@%s" % (n, v) for n, v in pairs)
    return ("https://api.github.com/advisories?ecosystem=%s&affects=%s"
            "&per_page=100" % (gh_eco,
                               urllib.parse.quote(affects, safe=",@")))


def _seed_osv(cache, fixture_root):
    """Seed OSV responses for the exact batches a real scan will request.

    Derived from scanning the fixture rather than hardcoded, so adding a
    fixture project can't silently leave these tests hitting the network.
    """
    from deph import scanners

    for dp in scanners.discover(fixture_root):
        osv_eco = enrich.OSV_ECOSYSTEMS.get(dp.language)
        if not osv_eco:
            continue
        try:
            deps = scanners.scanner_for(dp.ecosystem).scan(
                dp.manifest_abspath).sorted_deps()
        except Exception:                               # noqa: BLE001
            continue
        if not deps:
            continue
        queries = [{"package": {"name": d.name, "ecosystem": osv_eco},
                    "version": d.version} for d in deps]
        results = []
        for d in deps:
            found = SEEDED_ADVISORIES.get((d.name, d.version), [])
            results.append({"vulns": [{"id": vid} for vid, _, _ in found]}
                           if found else {})
        key = enrich.post_cache_key(OSV_BATCH_URL, {"queries": queries})
        cache.put(key, json.dumps({"results": results}))

        for d in deps:
            for vid, severity, fixed in SEEDED_ADVISORIES.get(
                    (d.name, d.version), []):
                cache.put(
                    "https://api.osv.dev/v1/vulns/%s" % vid,
                    json.dumps({
                        "id": vid,
                        "summary": "seeded advisory for %s" % d.name,
                        "database_specific": {"severity": severity,
                                              "cwe_ids": ["CWE-79"]},
                        "severity": [{"type": "CVSS_V3", "score":
                                      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/"
                                      "C:H/I:H/A:H"}],
                        "affected": [{
                            "package": {"name": d.name, "ecosystem": osv_eco},
                            "ranges": [{"type": "ECOSYSTEM", "events": [
                                {"introduced": "0"}, {"fixed": fixed}]}],
                        }],
                    }))


def seed_cache(cache_dir):
    cache = enrich.Cache(os.path.join(cache_dir, "cache.db"))

    def put(url, obj):
        cache.put(url, json.dumps(obj))

    def npm(latest, lic):
        return {"dist-tags": {"latest": latest},
                "versions": {latest: {"license": lic}}}

    put("https://registry.npmjs.org/axios", npm("1.18.1", "MIT"))
    put("https://registry.npmjs.org/follow-redirects", npm("1.16.0", "MIT"))
    put("https://registry.npmjs.org/lodash", npm("4.17.21", "MIT"))

    def pypi(latest, lic):
        return {"info": {"version": latest, "license_expression": lic}}

    put("https://pypi.org/pypi/pyyaml/json", pypi("6.0.2", "MIT"))
    put("https://pypi.org/pypi/requests/json", pypi("2.32.4", "Apache-2.0"))
    put("https://pypi.org/pypi/urllib3/json", pypi("2.5.0", "MIT"))

    def crate(latest, lic):
        return {"crate": {"max_stable_version": latest},
                "versions": [{"num": latest, "license": lic}]}

    put("https://crates.io/api/v1/crates/tokio", crate("1.47.1", "MIT"))
    put("https://crates.io/api/v1/crates/serde", crate("1.0.219", "MIT OR Apache-2.0"))
    put("https://crates.io/api/v1/crates/regex", crate("1.11.1", "MIT OR Apache-2.0"))
    put("https://crates.io/api/v1/crates/mio", crate("1.0.4", "MIT"))

    # Scanners emit deps sorted by (name, version); batches follow that order.
    put(advisory_url("npm", [("axios", "0.21.1"),
                             ("follow-redirects", "1.14.0"),
                             ("lodash", "4.17.20")]),
        [
            {"ghsa_id": "GHSA-hfxv-24rg-xrqf", "severity": "high",
             "vulnerabilities": [{"package": {"name": "axios"},
                                  "vulnerable_version_range": "< 0.21.2"}]},
            {"ghsa_id": "GHSA-r4q5-vmmm-2653", "severity": "medium",
             "vulnerabilities": [{"package": {"name": "follow-redirects"},
                                  "vulnerable_version_range": "< 1.14.7"}]},
            {"ghsa_id": "GHSA-35jh-r3h4-6jhm", "severity": "high",
             "vulnerabilities": [{"package": {"name": "lodash"},
                                  "vulnerable_version_range": "< 4.17.21"}]},
        ])
    put(advisory_url("pip", [("pyyaml", "5.4"),
                             ("requests", "2.25.1"),
                             ("urllib3", "1.26.4")]),
        [
            {"ghsa_id": "GHSA-8q59-q68h-6hv4", "severity": "critical",
             "vulnerabilities": [{"package": {"name": "pyyaml"},
                                  "vulnerable_version_range": "< 5.4.1"}]},
            {"ghsa_id": "GHSA-q2q7-5pp4-w6pg", "severity": "medium",
             "vulnerabilities": [{"package": {"name": "urllib3"},
                                  "vulnerable_version_range": "< 1.26.5"}]},
        ])
    put(advisory_url("cargo", [("mio", "0.7.13"), ("regex", "1.5.4"),
                               ("serde", "1.0.126"), ("tokio", "1.8.0")]),
        [
            {"ghsa_id": "GHSA-jxwc-jh89-vwj3", "severity": "medium",
             "vulnerabilities": [{"package": {"name": "tokio"},
                                  "vulnerable_version_range": ">= 1.8.0, < 1.8.4"}]},
        ])

    # OSV is the default advisory source, so seed it too.
    _seed_osv(cache, FIXTURE)
    cache.close()


@pytest.fixture
def repo(tmp_path):
    """A throwaway copy of the fixture monorepo + a seeded offline cache."""
    repo_dir = tmp_path / "repo"
    shutil.copytree(FIXTURE, str(repo_dir))
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    seed_cache(str(cache_dir))
    return repo_dir


def run(args, cwd, env_extra=None):
    env = os.environ.copy()
    env.pop("GITHUB_ACTIONS", None)
    env.pop("GITHUB_TOKEN", None)
    cwd = str(cwd)
    env["DEPH_CACHE_DIR"] = os.path.join(os.path.dirname(cwd), "cache")
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, "-m", "deph.cli"] + args,
        cwd=cwd, env=env, capture_output=True, text=True, timeout=120)


def init_and_scan(repo_dir):
    assert run(["init"], repo_dir).returncode == 0
    r = run(["scan", "--offline"], repo_dir)
    assert r.returncode == 0, r.stderr
    return (repo_dir / "repo.deph").read_text()


# -- init ----------------------------------------------------------------------

def test_init_creates_valid_file_and_refuses_overwrite(repo):
    r = run(["init"], repo)
    assert r.returncode == 0
    content = (repo / "repo.deph").read_text()
    assert "policy {" in content
    assert run(["validate"], repo).returncode == 0
    r2 = run(["init"], repo)
    assert r2.returncode == 1
    assert "refusing to overwrite" in r2.stderr


# -- scan ----------------------------------------------------------------------

def test_scan_populates_projects_and_check_fails(repo):
    content = init_and_scan(repo)
    assert 'project "web/frontend" ecosystem=npm' in content
    assert 'project "services/api" ecosystem=pip' in content
    assert 'project "tools/agent" ecosystem=cargo' in content
    assert "dep axios 0.21.1 -> 1.18.1" in content
    assert "vuln:high:GHSA-hfxv-24rg-xrqf" in content
    assert "lag:major" in content
    assert "dep follow-redirects 1.14.0" in content
    assert "transitive" in content
    assert "vuln:critical:GHSA-8q59-q68h-6hv4" in content
    # cargo advisories resolve through OSV's "crates.io" ecosystem name, and
    # the finding carries the upgrade that clears it
    assert ("dep tokio 1.8.0 -> 1.47.1 license=MIT cwe=CWE-79 fix=1.8.4 "
            "[vuln:medium:GHSA-jxwc-jh89-vwj3") in content
    # unresolved lines are recorded, not dropped
    assert "unresolved" in content
    assert 'reason=range' in content
    # fixtures are vulnerable on purpose: the CI gate must trip
    r = run(["check"], repo)
    assert r.returncode == 1
    assert "FAIL" in r.stdout


def test_scan_preserves_hand_edited_header_byte_for_byte(repo):
    init_and_scan(repo)
    path = repo / "repo.deph"
    content = path.read_text()
    marker = content.index("// ---- generated by deph scan")
    custom_header = (
        "// my own banner, which had better survive\n\n"
        "policy {\n"
        "  fail vuln >= critical   // customized threshold\n"
        "  warn lag >= major\n"
        "}\n\n"
        'waive GHSA-hfxv-24rg-xrqf "axios SSRF not reachable; upgrade planned Q3"\n\n')
    path.write_text(custom_header + content[marker:])
    r = run(["scan", "--offline"], repo)
    assert r.returncode == 0, r.stderr
    rescanned = path.read_text()
    assert rescanned.startswith(custom_header)
    marker2 = rescanned.index("// ---- generated by deph scan")
    assert rescanned[:marker2] == custom_header


def test_two_scans_zero_diff_outside_timestamp(repo):
    first = init_and_scan(repo)
    r = run(["scan", "--offline"], repo)
    assert r.returncode == 0, r.stderr
    second = (repo / "repo.deph").read_text()
    changed = [a for a, b in zip(first.splitlines(), second.splitlines())
               if a != b]
    assert len(first.splitlines()) == len(second.splitlines())
    for line in changed:
        assert line.startswith("// ---- generated by deph scan")


def test_scan_offline_with_empty_cache_degrades_gracefully(tmp_path):
    repo_dir = tmp_path / "repo"
    shutil.copytree(FIXTURE, str(repo_dir))
    (tmp_path / "cache").mkdir()
    assert run(["init"], repo_dir).returncode == 0
    r = run(["scan", "--offline"], repo_dir)
    assert r.returncode == 0, r.stderr
    content = (repo_dir / "repo.deph").read_text()
    assert "dep axios 0.21.1" in content   # deps still recorded, unenriched


# -- check ----------------------------------------------------------------------

def test_check_waiver_flips_exit_code(repo):
    init_and_scan(repo)
    path = repo / "repo.deph"
    content = path.read_text()
    # Waive every failing finding: axios+lodash+pyyaml highs/criticals.
    waivers = ('waive GHSA-hfxv-24rg-xrqf "not exposed"\n'
               'waive GHSA-35jh-r3h4-6jhm "input sanitized upstream"\n'
               'waive GHSA-8q59-q68h-6hv4 "no untrusted yaml"\n')
    marker = content.index("// ---- generated")
    path.write_text(content[:marker] + waivers + "\n" + content[marker:])
    r = run(["check"], repo)
    assert r.returncode == 0, r.stdout
    assert "waived" in r.stdout


def test_check_json_format_stable_shape(repo):
    init_and_scan(repo)
    r = run(["check", "--format", "json"], repo)
    assert r.returncode == 1
    data = json.loads(r.stdout)
    assert data["schema"] == 2
    assert data["ok"] is False
    assert set(data["summary"]) == {"fail", "warn", "waived"}
    assert data["summary"]["fail"] >= 2
    f = data["findings"][0]
    assert set(f) == {"project", "dep", "version", "kind", "level", "id",
                      "detail", "message", "transitive", "dev", "fix", "url",
                      "cvss", "cwe", "waived_reason", "waiver_expired"}
    ids = {x["id"] for x in data["findings"]}
    assert "GHSA-hfxv-24rg-xrqf" in ids
    # Coverage is part of the contract: a consumer must be able to tell an
    # incomplete scan from a clean one.
    cov = data["coverage"]
    assert cov["audited"] > 0
    assert cov["unresolved"] > 0
    assert cov["unresolved_by_reason"]["range"] > 0
    vuln = next(x for x in data["findings"] if x["id"] == "GHSA-hfxv-24rg-xrqf")
    assert vuln["fix"] == "0.21.2"
    assert vuln["url"] == "https://github.com/advisories/GHSA-hfxv-24rg-xrqf"


def test_check_github_actions_annotations(repo):
    init_and_scan(repo)
    r = run(["check"], repo, env_extra={"GITHUB_ACTIONS": "true"})
    assert "::error file=" in r.stdout
    assert "::warning file=" in r.stdout


def test_check_is_fully_offline(repo):
    """check reads the file and nothing else: no cache, no network."""
    init_and_scan(repo)
    env = {"DEPH_CACHE_DIR": "/nonexistent-not-used",
           "http_proxy": "http://127.0.0.1:1", "https_proxy": "http://127.0.0.1:1"}
    r = run(["check"], repo, env_extra=env)
    assert r.returncode == 1


# -- validate ---------------------------------------------------------------------

def test_validate_reports_malformed_rule_with_position(repo, tmp_path):
    bad = repo / "repo.deph"
    bad.write_text("policy {\n  fail vuln fish high\n}\n")
    r = run(["validate"], repo)
    assert r.returncode == 1
    assert "repo.deph:2:3" in r.stdout
    assert "malformed" in r.stdout


def test_validate_catches_duplicate_project(repo):
    (repo / "repo.deph").write_text(
        "policy {\n  fail vuln >= high\n}\n"
        "// ---- generated by deph scan @ t — do not edit below ----\n"
        'project "a" ecosystem=npm { }\n'
        'project "a" ecosystem=pip { }\n')
    r = run(["validate"], repo)
    assert r.returncode == 1
    assert "duplicate project" in r.stdout


def test_validate_unknown_severity_rule(repo):
    (repo / "repo.deph").write_text("policy {\n  fail vuln >= enormous\n}\n")
    r = run(["validate"], repo)
    assert r.returncode == 1
    assert "unknown vulnerability severity" in r.stdout


# -- file discovery -----------------------------------------------------------------

def test_refuses_to_guess_between_multiple_deph_files(repo):
    (repo / "one.deph").write_text("policy {\n}\n")
    (repo / "two.deph").write_text("policy {\n}\n")
    r = run(["check"], repo)
    assert r.returncode == 2
    assert "multiple .deph files" in r.stderr
    # --file disambiguates
    r2 = run(["check", "--file", "one.deph"], repo)
    assert r2.returncode == 0


def test_missing_deph_file_suggests_init(repo):
    r = run(["check"], repo)
    assert r.returncode == 2
    assert "deph init" in r.stderr


# -- render -------------------------------------------------------------------------

def test_render_writes_self_contained_html(repo):
    init_and_scan(repo)
    r = run(["render", "-o", "report.html"], repo)
    assert r.returncode == 0
    html = (repo / "report.html").read_text()
    assert html.startswith("<!DOCTYPE html>")
    assert "GHSA-hfxv-24rg-xrqf" in html
    assert "web/frontend" in html
    # self-contained: no external resource loads
    assert "src=" not in html.split("<body>")[0]
    assert 'href="http' not in html.split("<body>")[0]


def test_scan_root_separates_the_file_from_the_tree(repo, tmp_path):
    """--root audits a checkout without writing anything into it."""
    out = tmp_path / "audit"
    out.mkdir()
    assert run(["init", "--file", "audit.deph"], out).returncode == 0
    r = run(["scan", "--offline", "--file", "audit.deph",
             "--root", str(repo)], out)
    assert r.returncode == 0, r.stderr
    content = (out / "audit.deph").read_text()
    assert 'project "web/frontend" ecosystem=npm' in content
    # Nothing was written into the scanned tree.
    assert not list(repo.glob("*.deph"))


def test_scan_root_must_be_a_directory(repo, tmp_path):
    out = tmp_path / "audit2"
    out.mkdir()
    run(["init", "--file", "a.deph"], out)
    r = run(["scan", "--offline", "--file", "a.deph",
             "--root", str(repo / "nope")], out)
    assert r.returncode == 2
    assert "not a directory" in r.stderr


def test_default_policy_allows_the_common_permissive_licences(repo, tmp_path):
    """A default that fails on tslib or minimatch trains people to ignore the
    output, which is the fatigue deph exists to fix. Found by scanning a real
    Next.js project: 10 of 24 licence failures were permissive licences every
    team allows."""
    out = tmp_path / "lic"
    out.mkdir()
    run(["init", "--file", "p.deph"], out)
    policy = (out / "p.deph").read_text()
    generated = "\n".join([
        "",
        "// ---- generated by deph scan @ t — do not edit below ----",
        "",
        'project "app" ecosystem=npm manifest="package-lock.json" {',
        "  dep tslib 2.8.1 license=0BSD transitive",
        "  dep minimatch 10.2.5 license=BlueOak-1.0.0 transitive",
        "  dep caniuse-lite 1.0.30001806 license=CC-BY-4.0 transitive",
        "  dep language-subtag-registry 0.3.23 license=CC0-1.0 transitive",
        "  dep argparse 2.0.1 license=Python-2.0 transitive",
        "}",
        "",
    ])
    (out / "p.deph").write_text(policy + generated)
    r = run(["check", "--file", "p.deph"], out)
    assert "FAIL   license" not in r.stdout, r.stdout
    assert r.returncode == 0, r.stdout


def test_default_policy_still_rejects_copyleft(repo, tmp_path):
    """Widening the allowlist must not have let LGPL/GPL through: those are
    per-dependency decisions that deserve a waiver with a reason."""
    out = tmp_path / "copyleft"
    out.mkdir()
    run(["init", "--file", "p.deph"], out)
    policy = (out / "p.deph").read_text()
    (out / "p.deph").write_text(policy + "\n".join([
        "",
        "// ---- generated by deph scan @ t — do not edit below ----",
        "",
        'project "app" ecosystem=npm manifest="package-lock.json" {',
        "  dep libvips 1.2.4 license=LGPL-3.0-or-later transitive",
        '  dep mixed 1.0.0 license="Apache-2.0 AND LGPL-3.0-or-later" transitive',
        "  dep gpl-thing 1.0.0 license=GPL-3.0-only transitive",
        "}",
        "",
    ]))
    r = run(["check", "--file", "p.deph"], out)
    assert r.returncode == 1
    assert r.stdout.count("FAIL   license") == 3, r.stdout
