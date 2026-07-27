"""Bugs found once, kept fixed.

Each of these had a real failure mode: script injection through the studio
error page, aliased npm packages audited under the wrong name (and so missing
their advisories), the writer emitting files it couldn't read back, hostile
lockfiles killing a scan with RecursionError, and a release counted as a patch
ahead of its own release candidate.

Findings and reproductions are written up in AUDIT.md.
"""
import json

import pytest

from deph import enrich, parser
from deph.parser import Dep, Document, Project
from deph.scanners import npm
from deph.studio import server


def test_studio_error_page_escapes_html(tmp_path):
    payload = "<img src=x onerror=alert(1)>"
    src = 'policy {\n  fail vuln >= high\n}\n"%s"\n' % payload
    p = tmp_path / "hostile.deph"
    p.write_text(src)
    with pytest.raises(parser.DephSyntaxError) as ei:
        parser.parse_file(str(p))
    body = server._error_page(ei.value)   # the page the handler actually serves
    assert payload not in body, "raw HTML reflected unescaped into error page"
    assert "&lt;img" in body               # escaped, still readable


def test_npm_alias_uses_real_name(tmp_path):
    lock = {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"mychalk": "npm:chalk@^5.0.0"}},
            "node_modules/mychalk": {"name": "chalk", "version": "5.3.0"},
        },
    }
    p = tmp_path / "package-lock.json"
    p.write_text(json.dumps(lock))
    deps = {d.name: d for d in npm.NpmScanner().scan(str(p)).deps}
    assert "chalk" in deps, "aliased package must be audited under its real name"
    assert deps["chalk"].version == "5.3.0"
    # the alias is a root dependency: still recognized as direct
    assert not deps["chalk"].transitive


def test_writer_roundtrips_names_with_spaces():
    doc = Document(header_text="", has_generated_section=True)
    doc.projects = [Project(name="p", ecosystem="npm",
                            deps=[Dep(name="foo bar", version="1.0.0")])]
    out = parser.render(doc, timestamp="t")
    reparsed = parser.parse(out)  # must not raise
    got = reparsed.projects[0].deps[0]
    assert (got.name, got.version) == ("foo bar", "1.0.0")


def test_hostile_version_cannot_inject_attributes():
    doc = Document(header_text="", has_generated_section=True)
    doc.projects = [Project(name="p", ecosystem="npm", deps=[
        Dep(name="pkg", version="1.0.0 evil license=GPL-3.0")])]
    reparsed = parser.parse(parser.render(doc, timestamp="t"))
    got = reparsed.projects[0].deps[0]
    assert got.version == "1.0.0 evil license=GPL-3.0"   # stays one value
    assert got.license is None                            # nothing injected


def test_comment_marker_in_name_roundtrips():
    doc = Document(header_text="", has_generated_section=True)
    doc.projects = [Project(name="p", ecosystem="npm",
                            deps=[Dep(name="weird//name", version="1.0.0")])]
    reparsed = parser.parse(parser.render(doc, timestamp="t"))
    assert reparsed.projects[0].deps[0].name == "weird//name"


def test_deeply_nested_lockfile_does_not_raise_recursionerror(tmp_path):
    n = 4000
    text = ('{"dependencies":' + '{"x":{"version":"1.0.0","dependencies":' * n
            + '{}' + '}' * n + '}')
    p = tmp_path / "package-lock.json"
    p.write_text(text)
    try:
        npm.NpmScanner().scan(str(p))
    except (OSError, ValueError):
        pass  # fine: cmd_scan skips these with a warning
    # A RecursionError escaping here is the bug; it would kill the scan.


def test_deep_v1_tree_within_json_limits_scans_iteratively(tmp_path):
    # Deep enough to have broken the old recursive walk, shallow enough that
    # json.load itself still copes.
    n = 300
    text = ('{"lockfileVersion": 1, "dependencies":'
            + '{"x":{"version":"1.0.0","dependencies":' * n
            + '{}' + '}}' * n + '}')
    p = tmp_path / "package-lock.json"
    p.write_text(text)
    deps = npm.NpmScanner().scan(str(p)).deps
    assert len(deps) == 1 and deps[0].name == "x"


def test_prerelease_to_release_lag():
    # A release is not a patch ahead of its own release candidate.
    assert enrich.classify_lag("1.0.0-rc.1", "1.0.0") == "prerelease"
