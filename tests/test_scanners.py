import json
import os

from deph import scanners
from deph.scanners import discover, scanner_for
from deph.scanners.pip import normalize_name

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "monorepo")


def dep_map(result):
    """Name -> dep, from either a ScanResult or a bare list of deps."""
    deps = getattr(result, "deps", result)
    return {d.name: d for d in deps}


def deps_of(result):
    return getattr(result, "deps", result)


def reasons(result):
    return sorted(u.reason for u in result.unresolved)


# -- discovery ---------------------------------------------------------------

def test_discover_finds_every_fixture_project():
    projects = discover(FIXTURE)
    by_name = {p.name: p for p in projects}
    assert set(by_name) >= {"web/frontend", "services/api", "tools/agent"}
    assert by_name["web/frontend"].ecosystem == "npm"
    assert by_name["web/frontend"].language == "npm"
    assert by_name["services/api"].ecosystem == "pip"
    assert by_name["tools/agent"].ecosystem == "cargo"
    assert by_name["web/frontend"].manifest == "web/frontend/package-lock.json"
    # Every language in the fixture repo is represented.
    assert {p.language for p in projects} >= {
        "npm", "pip", "cargo", "go", "gem", "composer"}


def test_discover_prefers_lockfile_over_declaration():
    """go.sum pins every module; go.mod only requires them."""
    projects = {p.name: p for p in discover(FIXTURE)}
    assert projects["svc/gosvc"].manifest.endswith("go.sum")


def test_discover_one_project_per_language_per_directory(tmp_path):
    (tmp_path / "package-lock.json").write_text(
        '{"lockfileVersion": 3, "packages": {"": {}}}')
    (tmp_path / "yarn.lock").write_text("# yarn lockfile v1\n")
    found = discover(str(tmp_path))
    assert len(found) == 1
    assert found[0].ecosystem == "npm"     # package-lock wins on priority


def test_discover_skips_node_modules(tmp_path):
    nm = tmp_path / "node_modules" / "some-dep"
    nm.mkdir(parents=True)
    (nm / "package-lock.json").write_text('{"lockfileVersion": 3, "packages": {}}')
    assert discover(str(tmp_path)) == []


# -- npm ---------------------------------------------------------------------

def test_npm_v3_direct_and_transitive():
    deps = scanner_for("npm").scan(
        os.path.join(FIXTURE, "web/frontend/package-lock.json"))
    m = dep_map(deps)
    assert m["axios"].version == "0.21.1"
    assert not m["axios"].transitive
    assert not m["lodash"].transitive
    assert m["follow-redirects"].transitive


def test_npm_v2_lockfile(tmp_path):
    lock = {
        "lockfileVersion": 2,
        "packages": {
            "": {"dependencies": {"left-pad": "^1.3.0"}},
            "node_modules/left-pad": {"version": "1.3.0"},
            "node_modules/@scope/pkg": {"version": "2.0.0"},
        },
        "dependencies": {},  # v2 carries the legacy tree too; must be ignored
    }
    p = tmp_path / "package-lock.json"
    p.write_text(json.dumps(lock))
    deps = dep_map(scanner_for("npm").scan(str(p)))
    assert not deps["left-pad"].transitive
    assert deps["@scope/pkg"].transitive
    assert deps["@scope/pkg"].version == "2.0.0"


def test_npm_v1_lockfile_with_package_json(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps(
        {"dependencies": {"a": "^1.0.0"}}))
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 1,
        "dependencies": {
            "a": {"version": "1.0.0",
                  "dependencies": {"b": {"version": "2.0.0"}}},
        },
    }))
    deps = dep_map(scanner_for("npm").scan(str(tmp_path / "package-lock.json")))
    assert not deps["a"].transitive
    assert deps["b"].transitive


def test_npm_skips_link_and_versionless_entries(tmp_path):
    lock = {
        "lockfileVersion": 3,
        "packages": {
            "": {},
            "node_modules/linked": {"link": True, "resolved": "../linked"},
            "node_modules/broken": {},
            "node_modules/ok": {"version": "1.0.0"},
        },
    }
    p = tmp_path / "package-lock.json"
    p.write_text(json.dumps(lock))
    deps = dep_map(scanner_for("npm").scan(str(p)))
    assert set(deps) == {"ok"}


def test_npm_nested_node_modules_name(tmp_path):
    lock = {
        "lockfileVersion": 3,
        "packages": {
            "": {},
            "node_modules/a/node_modules/b": {"version": "3.0.0"},
        },
    }
    p = tmp_path / "package-lock.json"
    p.write_text(json.dumps(lock))
    deps = dep_map(scanner_for("npm").scan(str(p)))
    assert deps["b"].version == "3.0.0"
    assert deps["b"].transitive


# -- pip ---------------------------------------------------------------------

def test_pip_pinned_with_comments_extras_markers():
    result = scanner_for("pip").scan(
        os.path.join(FIXTURE, "services/api/requirements.txt"))
    m = dep_map(result)
    assert set(m) == {"pyyaml", "requests", "urllib3"}
    assert m["pyyaml"].version == "5.4"
    assert m["requests"].version == "2.25.1"      # inline comment stripped
    assert m["urllib3"].version == "1.26.4"       # extras + marker handled
    assert all(not d.transitive for d in deps_of(result))


def test_pip_reports_everything_it_could_not_pin():
    """The whole point of the unresolved channel: a scan must not shrink
    silently. The fixture has a missing include, a VCS line, an editable
    install and an unpinned range, and all four have to be accounted for."""
    result = scanner_for("pip").scan(
        os.path.join(FIXTURE, "services/api/requirements.txt"))
    assert reasons(result) == ["local", "missing", "range", "vcs"]
    by_reason = {u.reason: u for u in result.unresolved}
    assert by_reason["range"].name == "flask"
    assert by_reason["missing"].name == "common.txt"


def test_pip_follows_includes(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "-r base.txt\n--constraint pins.txt\nrequests==2.31.0\n")
    (tmp_path / "base.txt").write_text("pyyaml==6.0.1\n")
    (tmp_path / "pins.txt").write_text("urllib3==2.2.1\n")
    m = dep_map(scanner_for("pip").scan(str(tmp_path / "requirements.txt")))
    assert set(m) == {"requests", "pyyaml", "urllib3"}


def test_pip_include_cycle_terminates(tmp_path):
    (tmp_path / "a.txt").write_text("-r b.txt\nfoo==1.0\n")
    (tmp_path / "b.txt").write_text("-r a.txt\nbar==2.0\n")
    m = dep_map(scanner_for("pip").scan(str(tmp_path / "a.txt")))
    assert set(m) == {"foo", "bar"}


def test_pip_hash_pinned_requirement_is_a_pin(tmp_path):
    p = tmp_path / "requirements.txt"
    p.write_text("django==4.2.1 --hash=sha256:abc123 \\\n"
                 "    --hash=sha256:def456\n")
    result = scanner_for("pip").scan(str(p))
    assert dep_map(result)["django"].version == "4.2.1"
    assert result.unresolved == []


def test_pip_dev_requirements_file_marks_dev(tmp_path):
    p = tmp_path / "requirements-dev.txt"
    p.write_text("pytest==8.0.0\n")
    assert dep_map(scanner_for("pip").scan(str(p)))["pytest"].dev


def test_pip_never_crashes_on_weird_lines(tmp_path):
    p = tmp_path / "requirements.txt"
    p.write_text(
        "==bogus\n"
        "https://example.com/pkg.whl\n"
        "pkg @ file:///tmp/x\n"
        "Django == 4.2.1\n"
        "some_Package.Name==1.0\n"
        "trailing==1.2.3 \\\n    --hash=sha256:abc\n"
    )
    deps = dep_map(scanner_for("pip").scan(str(p)))
    assert deps["django"].version == "4.2.1"
    assert "some-package-name" in deps
    assert deps["trailing"].version == "1.2.3"


def test_pip_name_normalization():
    assert normalize_name("PyYAML") == "pyyaml"
    assert normalize_name("some_pkg.name") == "some-pkg-name"


# -- cargo ---------------------------------------------------------------------

def test_cargo_direct_vs_transitive_and_own_crate_excluded():
    deps = scanner_for("cargo").scan(
        os.path.join(FIXTURE, "tools/agent/Cargo.lock"))
    m = dep_map(deps)
    assert "agent" not in m                       # own crate excluded
    assert not m["tokio"].transitive              # [dependencies]
    assert not m["serde"].transitive
    assert not m["regex"].transitive              # [dev-dependencies]
    assert m["mio"].transitive
    assert m["tokio"].version == "1.8.0"


def test_cargo_dotted_dependency_table(tmp_path):
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname = "x"\nversion = "0.1.0"\n'
        '[dependencies.fancy]\nversion = "2.0"\n')
    (tmp_path / "Cargo.lock").write_text(
        '[[package]]\nname = "fancy"\nversion = "2.0.0"\n'
        '[[package]]\nname = "x"\nversion = "0.1.0"\n')
    deps = dep_map(scanner_for("cargo").scan(str(tmp_path / "Cargo.lock")))
    assert set(deps) == {"fancy"}
    assert not deps["fancy"].transitive


def test_cargo_lock_without_cargo_toml(tmp_path):
    (tmp_path / "Cargo.lock").write_text(
        '[[package]]\nname = "solo"\nversion = "1.0.0"\n')
    deps = dep_map(scanner_for("cargo").scan(str(tmp_path / "Cargo.lock")))
    # No Cargo.toml: no direct set known; nothing marked transitive.
    assert not deps["solo"].transitive


# -- registry extensibility ---------------------------------------------------

def test_registry_contains_builtins():
    for eco in ("npm", "pip", "cargo"):
        assert scanner_for(eco).ecosystem == eco


def test_register_new_scanner(tmp_path):
    class FakeScanner(scanners.Scanner):
        ecosystem = "fake"
        manifest_names = ("fake.lock",)

        def scan(self, manifest_path):
            return [scanners.RawDep("thing", "1.0.0")]

    scanners.register(FakeScanner)
    try:
        (tmp_path / "fake.lock").write_text("")
        found = discover(str(tmp_path))
        assert len(found) == 1
        assert found[0].ecosystem == "fake"
    finally:
        scanners._REGISTRY.pop("fake", None)


# -- yarn ---------------------------------------------------------------------

YARNAPP = os.path.join(FIXTURE, "web/yarnapp/yarn.lock")


def test_yarn_v1_names_versions_and_scope():
    result = scanner_for("npm-yarn").scan(YARNAPP)
    m = dep_map(result.deps)
    assert m["@babel/core"].version == "7.26.0"      # last @ splits the scope
    assert m["axios"].version == "0.21.1"
    assert m["follow-redirects"].version == "1.14.9"
    assert "mylib" not in m


def test_yarn_direct_transitive_and_dev_from_package_json():
    result = scanner_for("npm-yarn").scan(YARNAPP)
    m = dep_map(result.deps)
    assert not m["@babel/core"].transitive
    assert not m["axios"].transitive
    assert m["@babel/parser"].transitive             # only a dependency-of
    assert m["semver"].transitive
    assert m["jest"].dev and not m["jest"].transitive
    assert not m["axios"].dev


def test_yarn_file_protocol_is_unresolved():
    result = scanner_for("npm-yarn").scan(YARNAPP)
    by_name = {u.name: u for u in result.unresolved}
    assert by_name["mylib"].reason == "local"
    assert by_name["mylib"].spec == "mylib@file:../mylib"


def test_yarn_without_package_json_makes_no_guesses(tmp_path):
    (tmp_path / "yarn.lock").write_text(
        "# yarn lockfile v1\n\n"
        'left-pad@^1.3.0:\n  version "1.3.0"\n')
    result = scanner_for("npm-yarn").scan(str(tmp_path / "yarn.lock"))
    dep = dep_map(result.deps)["left-pad"]
    assert not dep.transitive and not dep.dev


def test_yarn_berry_npm_protocol_and_workspace(tmp_path):
    (tmp_path / "yarn.lock").write_text(
        "__metadata:\n  version: 6\n  cacheKey: 8\n\n"
        '"axios@npm:^0.21.1, axios@npm:^0.21.4":\n'
        "  version: 0.21.1\n"
        '  resolution: "axios@npm:0.21.1"\n'
        "  dependencies:\n"
        "    follow-redirects: ^1.14.0\n"
        "  languageName: node\n"
        "  linkType: hard\n"
        "\n"
        '"@babel/core@npm:^7.0.0":\n'
        "  version: 7.26.0\n"
        '  resolution: "@babel/core@npm:7.26.0"\n'
        "\n"
        '"myapp@workspace:.":\n'
        "  version: 0.0.0-use.local\n"
        '  resolution: "myapp@workspace:."\n'
        "\n"
        '"shared@workspace:packages/shared":\n'
        "  version: 0.0.0-use.local\n")
    result = scanner_for("npm-yarn").scan(str(tmp_path / "yarn.lock"))
    m = dep_map(result.deps)
    assert set(m) == {"axios", "@babel/core"}
    assert m["axios"].version == "0.21.1"
    assert m["@babel/core"].version == "7.26.0"
    reasons = {u.name: u.reason for u in result.unresolved}
    assert reasons == {"myapp": "workspace", "shared": "workspace"}


def test_yarn_vcs_and_url_reasons(tmp_path):
    (tmp_path / "yarn.lock").write_text(
        "# yarn lockfile v1\n\n"
        '"gitdep@git+ssh://git@github.com/owner/repo.git#abc123":\n'
        '  version "1.0.0"\n'
        '  resolved "git+ssh://git@github.com/owner/repo.git#abc123"\n'
        "\n"
        '"tarball@https://example.com/pkg-1.0.0.tgz":\n'
        '  version "1.0.0"\n'
        "\n"
        '"linked@link:../linked":\n'
        '  version "0.0.0"\n'
        "\n"
        '"patched@patch:patched@npm%3A1.0.0#./p.patch":\n'
        '  version "1.0.0"\n')
    result = scanner_for("npm-yarn").scan(str(tmp_path / "yarn.lock"))
    assert result.deps == []
    reasons = {u.name: u.reason for u in result.unresolved}
    assert reasons["gitdep"] == "vcs"
    assert reasons["tarball"] == "url"
    assert reasons["linked"] == "local"
    assert reasons["patched"] == "local"


def test_yarn_aliased_install_reports_real_package(tmp_path):
    (tmp_path / "yarn.lock").write_text(
        "# yarn lockfile v1\n\n"
        '"mychalk@npm:chalk@^5.0.0":\n'
        '  version "5.3.0"\n')
    result = scanner_for("npm-yarn").scan(str(tmp_path / "yarn.lock"))
    assert dep_map(result.deps)["chalk"].version == "5.3.0"


def test_yarn_garbage_does_not_raise(tmp_path):
    p = tmp_path / "yarn.lock"
    p.write_text(
        "{{{ not a lockfile\n"
        "\x00\x01 binary-ish\n"
        "just-a-name:\n"
        "  nope\n"
        "@:\n"
        '  version ""\n'
        "noversion@^1.0.0:\n"
        "  resolved \"https://example.com/x.tgz\"\n"
        "   \n"
        "  orphan body line\n")
    result = scanner_for("npm-yarn").scan(str(p))
    assert result.deps == []
    assert {u.reason for u in result.unresolved} == {"unparsed"}


def test_yarn_missing_file_does_not_raise(tmp_path):
    result = scanner_for("npm-yarn").scan(str(tmp_path / "nope.lock"))
    assert result.deps == [] and result.unresolved == []


# -- pnpm ---------------------------------------------------------------------

PNPMAPP = os.path.join(FIXTURE, "web/pnpmapp/pnpm-lock.yaml")


def test_pnpm_v6_names_versions_and_scope():
    result = scanner_for("npm-pnpm").scan(PNPMAPP)
    m = dep_map(result.deps)
    assert m["@babel/core"].version == "7.26.0"
    assert m["axios"].version == "0.21.1"
    assert set(m) == {"@babel/core", "@babel/parser", "axios",
                      "follow-redirects", "typescript"}


def test_pnpm_direct_transitive_and_dev():
    result = scanner_for("npm-pnpm").scan(PNPMAPP)
    m = dep_map(result.deps)
    assert not m["axios"].transitive
    assert not m["@babel/core"].transitive
    assert m["follow-redirects"].transitive
    assert m["@babel/parser"].transitive
    assert m["typescript"].dev and not m["typescript"].transitive
    assert not m["axios"].dev


def test_pnpm_link_entry_is_unresolved():
    result = scanner_for("npm-pnpm").scan(PNPMAPP)
    by_name = {u.name: u for u in result.unresolved}
    assert by_name["mylib"].reason == "local"
    assert "mylib" not in dep_map(result.deps)


def test_pnpm_v9_importers_and_unslashed_keys(tmp_path):
    p = tmp_path / "pnpm-lock.yaml"
    p.write_text(
        "lockfileVersion: '9.0'\n"
        "\n"
        "importers:\n"
        "\n"
        "  .:\n"
        "    dependencies:\n"
        "      axios:\n"
        "        specifier: ^1.6.0\n"
        "        version: 1.6.8\n"
        "    devDependencies:\n"
        "      typescript:\n"
        "        specifier: ^5.3.0\n"
        "        version: 5.3.3\n"
        "\n"
        "  packages/shared:\n"
        "    dependencies:\n"
        "      mylib:\n"
        "        specifier: workspace:*\n"
        "        version: link:../other\n"
        "\n"
        "packages:\n"
        "\n"
        "  '@babel/core@7.26.0':\n"
        "    resolution: {integrity: sha512-AAA==}\n"
        "\n"
        "  axios@1.6.8:\n"
        "    resolution: {integrity: sha512-BBB==}\n"
        "\n"
        "  typescript@5.3.3:\n"
        "    resolution: {integrity: sha512-CCC==}\n"
        "    hasBin: true\n"
        "\n"
        "snapshots:\n"
        "\n"
        "  axios@1.6.8:\n"
        "    dependencies:\n"
        "      follow-redirects: 1.15.6\n")
    result = scanner_for("npm-pnpm").scan(str(p))
    m = dep_map(result.deps)
    assert m["axios"].version == "1.6.8" and not m["axios"].transitive
    assert m["typescript"].dev and not m["typescript"].transitive
    assert m["@babel/core"].transitive          # in packages:, not declared
    assert {u.name: u.reason for u in result.unresolved} == {
        "mylib": "workspace"}


def test_pnpm_v5_slash_keys_and_peer_suffix(tmp_path):
    p = tmp_path / "pnpm-lock.yaml"
    p.write_text(
        "lockfileVersion: 5.4\n"
        "\n"
        "specifiers:\n"
        "  axios: ^0.21.1\n"
        "  mocha: ^9.0.0\n"
        "\n"
        "dependencies:\n"
        "  axios: 0.21.1\n"
        "\n"
        "devDependencies:\n"
        "  mocha: 9.2.2\n"
        "\n"
        "packages:\n"
        "\n"
        "  /axios/0.21.1:\n"
        "    resolution: {integrity: sha512-AAA==}\n"
        "    dev: false\n"
        "\n"
        "  /@babel/plugin-x/7.0.0_@babel+core@7.26.0:\n"
        "    resolution: {integrity: sha512-BBB==}\n"
        "    dev: true\n"
        "\n"
        "  /mocha/9.2.2:\n"
        "    resolution: {integrity: sha512-CCC==}\n"
        "    dev: true\n")
    result = scanner_for("npm-pnpm").scan(str(p))
    m = dep_map(result.deps)
    assert m["axios"].version == "0.21.1" and not m["axios"].transitive
    assert m["mocha"].dev and not m["mocha"].transitive
    plugin = m["@babel/plugin-x"]
    assert plugin.version == "7.0.0"            # peer suffix stripped
    assert plugin.transitive and plugin.dev     # dev: true is authoritative


def test_pnpm_garbage_does_not_raise(tmp_path):
    p = tmp_path / "pnpm-lock.yaml"
    p.write_text(
        "\x00 not yaml at all\n"
        "packages:\n"
        "  '/broken\n"
        "  /:\n"
        "  /noversion:\n"
        "  file:../thing:\n"
        "    dev: false\n"
        "      - stray list item\n"
        "\t\ttabs: yes\n")
    result = scanner_for("npm-pnpm").scan(str(p))
    assert result.deps == []
    reasons = sorted(u.reason for u in result.unresolved)
    assert "local" in reasons
    assert all(r in scanners.UNRESOLVED_REASONS for r in reasons)


def test_pnpm_missing_file_does_not_raise(tmp_path):
    result = scanner_for("npm-pnpm").scan(str(tmp_path / "nope.yaml"))
    assert result.deps == [] and result.unresolved == []


def test_yarn_and_pnpm_language_and_priority():
    yarn = scanner_for("npm-yarn")
    pnpm = scanner_for("npm-pnpm")
    assert yarn.language() == "npm" and pnpm.language() == "npm"
    # package-lock.json is the most authoritative, then pnpm, then yarn.
    assert scanner_for("npm").priority < pnpm.priority < yarn.priority


# -- pip-poetry ---------------------------------------------------------------
#
# The four Python lock scanners are imported directly rather than through
# scanner_for(): they only need their own class, and going via the registry
# would drag in every other built-in scanner.

from deph.scanners.pip_pipenv import PipenvScanner        # noqa: E402
from deph.scanners.pip_poetry import PoetryScanner        # noqa: E402
from deph.scanners.pip_pyproject import PyprojectScanner  # noqa: E402
from deph.scanners.pip_uv import UvScanner                # noqa: E402

POETRY_LOCK = os.path.join(FIXTURE, "services/poetrysvc/poetry.lock")
PIPENV_LOCK = os.path.join(FIXTURE, "services/pipenvsvc/Pipfile.lock")
UV_LOCK = os.path.join(FIXTURE, "services/uvsvc/uv.lock")
BARELIB_PYPROJECT = os.path.join(FIXTURE, "libs/barelib/pyproject.toml")


def unresolved_map(result):
    return {u.name: u for u in result.unresolved}


def test_poetry_name_and_version_extraction():
    m = dep_map(PoetryScanner().scan(POETRY_LOCK).deps)
    assert m["flask"].version == "2.3.3"
    assert m["requests"].version == "2.31.0"
    assert m["werkzeug"].version == "2.3.7"     # name = "Werkzeug", normalized


def test_poetry_direct_vs_transitive_from_pyproject():
    m = dep_map(PoetryScanner().scan(POETRY_LOCK).deps)
    assert not m["flask"].transitive            # [tool.poetry.dependencies]
    assert not m["pytest"].transitive           # dev group counts as declared
    assert m["werkzeug"].transitive
    assert m["certifi"].transitive
    assert m["urllib3"].transitive


def test_poetry_dev_flags_from_dependency_groups():
    m = dep_map(PoetryScanner().scan(POETRY_LOCK).deps)
    assert m["pytest"].dev
    assert m["ruff"].dev                        # any group but "main" is dev
    assert not m["flask"].dev
    # A transitive dev-only package is indistinguishable from a runtime one in
    # a 1.2+ lock, so it is not guessed at.
    assert not m["pluggy"].dev


def test_poetry_source_tables_go_unresolved():
    u = unresolved_map(PoetryScanner().scan(POETRY_LOCK))
    assert u["internal-helpers"].reason == "vcs"
    assert "internal-helpers.git" in u["internal-helpers"].spec
    assert u["sibling-lib"].reason == "local"
    names = {d.name for d in PoetryScanner().scan(POETRY_LOCK).deps}
    assert "internal-helpers" not in names
    assert "sibling-lib" not in names


def test_poetry_legacy_category_field(tmp_path):
    (tmp_path / "poetry.lock").write_text(
        '[[package]]\nname = "pytest"\nversion = "7.4.2"\n'
        'category = "dev"\noptional = false\n\n'
        '[[package]]\nname = "flask"\nversion = "2.3.3"\n'
        'category = "main"\noptional = false\n')
    m = dep_map(PoetryScanner().scan(str(tmp_path / "poetry.lock")).deps)
    assert m["pytest"].dev
    assert not m["flask"].dev
    # No pyproject.toml, so nothing is known to be transitive.
    assert not m["pytest"].transitive
    assert not m["flask"].transitive


def test_poetry_legacy_dev_dependencies_table(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.poetry]\nname = "old"\n'
        '[tool.poetry.dependencies]\npython = "^3.9"\nflask = "^2.3"\n'
        '[tool.poetry.dev-dependencies]\npytest = "^7.4"\n')
    (tmp_path / "poetry.lock").write_text(
        '[[package]]\nname = "flask"\nversion = "2.3.3"\n\n'
        '[[package]]\nname = "pytest"\nversion = "7.4.2"\n\n'
        '[[package]]\nname = "pluggy"\nversion = "1.3.0"\n')
    m = dep_map(PoetryScanner().scan(str(tmp_path / "poetry.lock")).deps)
    assert m["pytest"].dev and not m["pytest"].transitive
    assert not m["flask"].dev and not m["flask"].transitive
    assert m["pluggy"].transitive
    # "python" is an interpreter constraint, never a package.
    assert "python" not in m


def test_poetry_never_raises_on_garbage(tmp_path):
    p = tmp_path / "poetry.lock"
    p.write_text(
        "\x00not toml at all\n"
        "[[package]]\nversion = \"1.0.0\"\n"          # no name
        "[[package]]\nname = \"nameonly\"\n"          # no version
        "[[[oops]]]\nname = \"ignored\"\n"
        "[[package]]\nname = \"good\"\nversion = \"1.2.3\"\n")
    result = PoetryScanner().scan(str(p))
    assert dep_map(result.deps)["good"].version == "1.2.3"
    assert {u.reason for u in result.unresolved} == {"unparsed"}


def test_poetry_missing_file_is_unresolved_not_an_exception(tmp_path):
    result = PoetryScanner().scan(str(tmp_path / "nope.lock"))
    assert result.deps == []
    assert result.unresolved[0].reason == "unparsed"


# -- pip-pipenv ---------------------------------------------------------------

def test_pipenv_strips_equals_and_splits_dev():
    result = PipenvScanner().scan(PIPENV_LOCK)
    m = dep_map(result.deps)
    assert m["django"].version == "4.2.4"       # "==4.2.4" -> "4.2.4"
    assert m["certifi"].version == "2023.7.22"
    assert not m["django"].dev
    assert m["black"].dev
    assert m["pytest"].dev
    assert m["pluggy"].dev


def test_pipenv_default_wins_over_develop():
    # requests is in both groups; the runtime answer is the one that matters.
    m = dep_map(PipenvScanner().scan(PIPENV_LOCK).deps)
    assert m["requests"].version == "2.31.0"
    assert not m["requests"].dev


def test_pipenv_unresolved_reasons():
    u = unresolved_map(PipenvScanner().scan(PIPENV_LOCK))
    assert u["internal-lib"].reason == "vcs"
    assert u["vendored-helpers"].reason == "local"   # name normalized too
    assert u["legacy-wheel"].reason == "url"
    assert u["urllib3"].reason == "range"            # not an exact pin
    assert "internal-lib" not in dep_map(
        PipenvScanner().scan(PIPENV_LOCK).deps)


def test_pipenv_without_pipfile_marks_nothing_transitive():
    assert all(not d.transitive
               for d in PipenvScanner().scan(PIPENV_LOCK).deps)


def test_pipenv_transitive_from_sibling_pipfile(tmp_path):
    (tmp_path / "Pipfile").write_text(
        "[[source]]\nurl = \"https://pypi.org/simple\"\n\n"
        "[packages]\ndjango = \"*\"\n\"my-pkg\" = {version = \"*\"}\n\n"
        "[dev-packages]\npytest = \"*\"\n\n"
        "[requires]\npython_version = \"3.9\"\n")
    (tmp_path / "Pipfile.lock").write_text(json.dumps({
        "default": {
            "Django": {"version": "==4.2.4"},
            "my_pkg": {"version": "==1.0.0"},
            "sqlparse": {"version": "==0.4.4"},
        },
        "develop": {"pytest": {"version": "==7.4.2"},
                    "pluggy": {"version": "==1.3.0"}},
    }))
    m = dep_map(PipenvScanner().scan(str(tmp_path / "Pipfile.lock")).deps)
    assert not m["django"].transitive
    assert not m["my-pkg"].transitive       # quoted key, normalized name
    assert not m["pytest"].transitive       # [dev-packages] is declared too
    assert m["sqlparse"].transitive
    assert m["pluggy"].transitive


def test_pipenv_never_raises_on_garbage(tmp_path):
    p = tmp_path / "Pipfile.lock"
    p.write_text("{not json")
    result = PipenvScanner().scan(str(p))
    assert result.deps == []
    assert result.unresolved[0].reason == "unparsed"

    p.write_text(json.dumps({
        "default": {"weird": "just-a-string", "empty": {},
                    "blank": {"version": "  "}, "half": {"version": "=="},
                    "ok": {"version": "==1.0.0"}},
        "develop": [],      # wrong type entirely
    }))
    result = PipenvScanner().scan(str(p))
    assert dep_map(result.deps)["ok"].version == "1.0.0"
    assert {u.name for u in result.unresolved} == {
        "weird", "empty", "blank", "half"}


def test_pipenv_missing_file_is_unresolved_not_an_exception(tmp_path):
    result = PipenvScanner().scan(str(tmp_path / "nope.lock"))
    assert result.deps == []
    assert result.unresolved[0].reason == "unparsed"


# -- pip-uv -------------------------------------------------------------------

def test_uv_name_and_version_extraction():
    m = dep_map(UvScanner().scan(UV_LOCK).deps)
    assert m["httpx"].version == "0.27.0"
    assert m["anyio"].version == "4.4.0"
    assert m["idna"].version == "3.7"
    assert m["sniffio"].version == "1.3.1"


def test_uv_excludes_virtual_and_editable_local_projects():
    result = UvScanner().scan(UV_LOCK)
    names = {d.name for d in result.deps} | {u.name for u in result.unresolved}
    assert "uvsvc" not in names          # source = { virtual = "." }
    assert "localtool" not in names      # source = { editable = "..." }


def test_uv_git_source_unresolved():
    u = unresolved_map(UvScanner().scan(UV_LOCK))
    assert u["vendored-lib"].reason == "vcs"     # name = "Vendored-Lib"
    assert "vendored-lib.git" in u["vendored-lib"].spec


def test_uv_leaves_dev_and_transitive_unset():
    # uv.lock does not record either, and a guess would be worse than a False.
    for d in UvScanner().scan(UV_LOCK).deps:
        assert not d.dev
        assert not d.transitive


def test_uv_expanded_source_table_and_url_source(tmp_path):
    p = tmp_path / "uv.lock"
    p.write_text(
        'version = 1\n\n'
        '[[package]]\nname = "wheelpkg"\nversion = "1.0.0"\n\n'
        '[package.source]\nurl = "https://example.com/wheelpkg-1.0.whl"\n\n'
        '[[package]]\nname = "pathpkg"\nversion = "0.1.0"\n'
        'source = { directory = "vendor/pathpkg" }\n\n'
        '[[package]]\nname = "plain"\nversion = "2.0.0"\n'
        'source = { registry = "https://pypi.org/simple" }\n')
    result = UvScanner().scan(str(p))
    assert {d.name for d in result.deps} == {"plain"}
    u = unresolved_map(result)
    assert u["wheelpkg"].reason == "url"
    assert u["pathpkg"].reason == "local"


def test_uv_never_raises_on_garbage(tmp_path):
    p = tmp_path / "uv.lock"
    p.write_text(
        "\x00\x01 junk\n"
        '[[package]]\nversion = "9.9.9"\n'                  # no name
        '[[package]]\nname = "noversion"\n'
        '[[package]]\nname = "fine"\nversion = "1.0.0"\n'
        'source = { registry = "https://pypi.org/simple" }\n'
        'wheels = [\n  { url = "https://x/y.whl", hash = "sha256:aa" },\n]\n')
    result = UvScanner().scan(str(p))
    assert {d.name for d in result.deps} == {"fine"}
    assert {u.reason for u in result.unresolved} == {"unparsed"}


def test_uv_missing_file_is_unresolved_not_an_exception(tmp_path):
    result = UvScanner().scan(str(tmp_path / "nope.lock"))
    assert result.deps == []
    assert result.unresolved[0].reason == "unparsed"


# -- pip-pyproject (last resort, mostly unresolved by design) ------------------

def test_pyproject_only_exact_pins_become_deps():
    result = PyprojectScanner().scan(BARELIB_PYPROJECT)
    m = dep_map(result.deps)
    assert m["requests"].version == "2.31.0"
    assert m["pyyaml"].version == "6.0.1"        # PyYAML normalized
    assert m["uvicorn"].version == "0.23.2"      # extras stripped
    assert "flask" not in m
    assert "click" not in m


def test_pyproject_unresolved_reasons():
    u = unresolved_map(PyprojectScanner().scan(BARELIB_PYPROJECT))
    assert u["flask"].reason == "range"
    assert u["attrs"].reason == "range"
    assert u["ruff"].reason == "range"           # ranges in an extra too
    assert u["click"].reason == "unpinned"
    assert u["tomli"].reason == "unpinned"       # marker only, no specifier
    assert u["vendored-thing"].reason == "url"
    assert u["flask"].spec == "flask>=2.0"       # spec kept as written


def test_pyproject_optional_dependency_groups_are_dev():
    m = dep_map(PyprojectScanner().scan(BARELIB_PYPROJECT).deps)
    assert m["pytest"].dev
    assert m["sphinx"].dev                       # every extra counts as dev
    assert not m["requests"].dev
    assert all(not d.transitive for d in m.values())


def test_pyproject_ignores_build_system_and_other_arrays():
    m = dep_map(PyprojectScanner().scan(BARELIB_PYPROJECT).deps)
    u = unresolved_map(PyprojectScanner().scan(BARELIB_PYPROJECT))
    for stray in ("setuptools", "wheel"):
        assert stray not in m and stray not in u


def test_pyproject_single_line_arrays_and_pin_forms(tmp_path):
    p = tmp_path / "pyproject.toml"
    p.write_text(
        '[project]\nname = "x"\n'
        'dependencies = ["a==1.0", "b === 2.0", "c==1.4.*", "d>1,<2"]\n'
        '[project.optional-dependencies]\n'
        'test = ["e==3.0"]\n')
    result = PyprojectScanner().scan(str(p))
    m = dep_map(result.deps)
    assert m["a"].version == "1.0"
    assert m["b"].version == "2.0"               # arbitrary equality is a pin
    assert m["e"].version == "3.0" and m["e"].dev
    u = unresolved_map(result)
    assert u["c"].reason == "range"              # ==1.4.* is a series
    assert u["d"].reason == "range"


def test_pyproject_local_and_dynamic_and_poetry_are_flagged(tmp_path):
    p = tmp_path / "pyproject.toml"
    p.write_text(
        '[project]\nname = "x"\n'
        'dynamic = ["dependencies"]\n'
        'dependencies = ["sib @ file:///srv/sib", "rel @ ../sib"]\n')
    result = PyprojectScanner().scan(str(p))
    assert result.deps == []
    u = unresolved_map(result)
    assert u["sib"].reason == "local"
    assert u["rel"].reason == "local"
    assert any(uu.reason == "unparsed" and "dynamic" in uu.spec
               for uu in result.unresolved)

    p.write_text('[tool.poetry]\nname = "x"\n'
                 '[tool.poetry.dependencies]\nflask = "^2.3"\n')
    result = PyprojectScanner().scan(str(p))
    # A poetry pyproject with no poetry.lock must not read as a clean scan.
    assert result.deps == []
    assert result.unresolved[0].reason == "unparsed"


def test_pyproject_never_raises_on_garbage(tmp_path):
    p = tmp_path / "pyproject.toml"
    p.write_text(
        "\x00 nonsense [[[\n"
        '[project]\ndependencies = ["==bogus", "!!!", "", "ok==1.0"]\n'
        'classifiers = ["Topic :: Utilities"]\n')
    result = PyprojectScanner().scan(str(p))
    assert dep_map(result.deps)["ok"].version == "1.0"
    assert "unparsed" in {u.reason for u in result.unresolved}
    assert "Topic :: Utilities" not in {u.spec for u in result.unresolved}


def test_pyproject_missing_file_is_unresolved_not_an_exception(tmp_path):
    result = PyprojectScanner().scan(str(tmp_path / "nope.toml"))
    assert result.deps == []
    assert result.unresolved[0].reason == "unparsed"


def test_python_lock_scanner_metadata():
    for cls, eco, manifest, prio in (
        (PoetryScanner, "pip-poetry", "poetry.lock", 10),
        (UvScanner, "pip-uv", "uv.lock", 12),
        (PipenvScanner, "pip-pipenv", "Pipfile.lock", 15),
        (PyprojectScanner, "pip-pyproject", "pyproject.toml", 50),
    ):
        assert cls.ecosystem == eco
        assert cls.manifest_names == (manifest,)
        assert cls.priority == prio
        # All four report as plain "pip" in the .deph file and to the registry.
        assert cls.language() == "pip"


# -- go -----------------------------------------------------------------------

GOSUM = os.path.join(FIXTURE, "svc/gosvc/go.sum")
GOMOD = os.path.join(FIXTURE, "svc/gosvc/go.mod")


def test_go_sum_names_versions_and_pseudo_versions():
    result = scanner_for("go").scan(GOSUM)
    m = dep_map(result.deps)
    assert m["github.com/stretchr/testify"].version == "v1.8.4"
    assert m["github.com/spf13/cobra"].version == "v1.7.0"
    # A pseudo-version names one commit, so it is a pin and stays as written.
    assert (m["golang.org/x/sync"].version
            == "v0.0.0-20210101120000-abcdef123456")
    # +incompatible is about import paths, not about which code is built.
    assert m["github.com/docker/docker"].version == "v20.10.7"


def test_go_sum_skips_the_go_mod_hash_lines():
    result = scanner_for("go").scan(GOSUM)
    assert not any("/go.mod" in d.name or "/go.mod" in d.version
                   for d in result.deps)
    # Every module appears once even though go.sum lists each one twice.
    assert len(result.deps) == len({d.name for d in result.deps})


def test_go_sum_direct_vs_indirect_from_sibling_gomod():
    m = dep_map(scanner_for("go").scan(GOSUM).deps)
    assert not m["github.com/stretchr/testify"].transitive
    assert not m["golang.org/x/sync"].transitive
    assert m["github.com/davecgh/go-spew"].transitive     # // indirect
    assert m["gopkg.in/yaml.v3"].transitive               # // indirect
    assert m["github.com/spf13/pflag"].transitive         # not in go.mod at all


def test_go_sum_without_gomod_makes_no_guesses(tmp_path):
    (tmp_path / "go.sum").write_text(
        "github.com/lone/mod v1.4.2 h1:AAAA=\n"
        "github.com/lone/mod v1.4.2/go.mod h1:BBBB=\n")
    result = scanner_for("go").scan(str(tmp_path / "go.sum"))
    dep = dep_map(result.deps)["github.com/lone/mod"]
    assert not dep.transitive and not dep.dev


def test_go_mod_require_blocks_and_indirect_comments():
    result = scanner_for("go").scan(GOMOD)
    m = dep_map(result.deps)
    assert m["github.com/stretchr/testify"].version == "v1.8.4"
    assert m["github.com/docker/docker"].version == "v20.10.7"
    assert not m["github.com/spf13/cobra"].transitive     # single-line require
    assert m["github.com/davecgh/go-spew"].transitive
    assert m["gopkg.in/yaml.v3"].transitive
    assert "example.com/svc/gosvc" not in m               # the module itself


def test_go_replace_directives_are_unresolved_not_deps():
    for manifest in (GOMOD, GOSUM):
        result = scanner_for("go").scan(manifest)
        u = unresolved_map(result)
        assert u["example.com/internal/helpers"].reason == "local"
        assert "../helpers" in u["example.com/internal/helpers"].spec
        # Replaced by another module: what that resolves to is not knowable
        # from the manifest, so the requirement is not reported as a pin.
        assert u["github.com/olddep/pkg"].reason == "unparsed"
        names = {d.name for d in result.deps}
        assert "example.com/internal/helpers" not in names
        assert "github.com/olddep/pkg" not in names


def test_go_mod_exclude_is_ignored_and_dev_is_never_set(tmp_path):
    (tmp_path / "go.mod").write_text(
        "module example.com/x\n\ngo 1.22\n\n"
        "require github.com/kept/mod v1.1.0\n\n"
        "exclude github.com/kept/mod v1.2.0\n"
        "exclude (\n\tgithub.com/never/seen v0.1.0\n)\n"
        "retract v0.9.0\n")
    result = scanner_for("go").scan(str(tmp_path / "go.mod"))
    assert {d.name for d in result.deps} == {"github.com/kept/mod"}
    assert dep_map(result.deps)["github.com/kept/mod"].version == "v1.1.0"
    assert result.unresolved == []
    # Go has no dev/test dependency distinction to report.
    assert all(not d.dev for d in result.deps)


def test_go_versioned_replace_only_hides_that_version(tmp_path):
    (tmp_path / "go.mod").write_text(
        "module example.com/x\n"
        "require github.com/a/b v1.0.0\n"
        "require github.com/c/d v2.0.0\n"
        "replace github.com/c/d v1.5.0 => ../d\n")
    m = dep_map(scanner_for("go").scan(str(tmp_path / "go.mod")).deps)
    assert set(m) == {"github.com/a/b", "github.com/c/d"}
    assert m["github.com/c/d"].version == "v2.0.0"


def test_go_garbage_does_not_raise(tmp_path):
    (tmp_path / "go.sum").write_text(
        "\x00\x01 binary-ish junk\n"
        "onlyonefield\n"
        "github.com/nover/mod notaversion h1:CCC=\n"
        "github.com/ok/mod v1.2.3 h1:AAA=\n"
        "github.com/ok/mod v1.2.3/go.mod h1:BBB=\n")
    result = scanner_for("go").scan(str(tmp_path / "go.sum"))
    assert {d.name for d in result.deps} == {"github.com/ok/mod"}
    assert {u.reason for u in result.unresolved} == {"unparsed"}

    (tmp_path / "go.mod").write_text(
        "\x00 nonsense (((\n"
        "module example.com/x\n"
        "require (\n\tbroken-line-with-no-version\n)\n"
        "require github.com/fine/mod v1.0.0\n"
        "replace oops-no-arrow\n"
        "godebug default=go1.21\n")
    result = scanner_for("go").scan(str(tmp_path / "go.mod"))
    assert {d.name for d in result.deps} == {"github.com/fine/mod"}
    reasons = {u.reason for u in result.unresolved}
    assert reasons == {"unparsed"}
    assert all(r in scanners.UNRESOLVED_REASONS for r in reasons)


def test_go_missing_file_is_unresolved_not_an_exception(tmp_path):
    for name in ("go.sum", "go.mod"):
        result = scanner_for("go").scan(str(tmp_path / name))
        assert result.deps == []
        assert result.unresolved[0].reason == "unparsed"


def test_go_scanner_metadata():
    scanner = scanner_for("go")
    assert scanner.ecosystem == "go" and scanner.language() == "go"
    assert scanner.manifest_names == ("go.sum", "go.mod")
    assert scanner.priority == 10


# -- gem ----------------------------------------------------------------------

GEMFILE_LOCK = os.path.join(FIXTURE, "svc/rubysvc/Gemfile.lock")


def test_gem_specs_names_and_versions():
    result = scanner_for("gem").scan(GEMFILE_LOCK)
    m = dep_map(result.deps)
    assert m["actionpack"].version == "7.0.4"
    assert m["rack"].version == "2.2.4"
    # A platform suffix is not part of the version.
    assert m["nokogiri"].version == "1.13.9"
    # Indented lines under a gem are its constraints, not locked versions, and
    # every gem named there has its own spec line.
    assert set(m) == {"actionpack", "activesupport", "concurrent-ruby",
                      "nokogiri", "racc", "rack", "rspec", "rspec-core",
                      "rspec-expectations", "rspec-support"}


def test_gem_direct_vs_transitive_from_dependencies_section():
    m = dep_map(scanner_for("gem").scan(GEMFILE_LOCK).deps)
    assert not m["actionpack"].transitive        # DEPENDENCIES, with a range
    assert not m["nokogiri"].transitive          # DEPENDENCIES, bare name
    assert not m["rspec"].transitive
    assert m["activesupport"].transitive
    assert m["rack"].transitive
    assert m["rspec-core"].transitive


def test_gem_git_and_path_sections_are_unresolved():
    result = scanner_for("gem").scan(GEMFILE_LOCK)
    u = unresolved_map(result)
    assert u["strong_migrations"].reason == "vcs"
    assert "strong_migrations.git" in u["strong_migrations"].spec
    assert u["vendored_gem"].reason == "local"
    assert "../vendored_gem" in u["vendored_gem"].spec
    names = {d.name for d in result.deps}
    assert "strong_migrations" not in names and "vendored_gem" not in names


def test_gem_dev_is_never_set():
    # Gemfile groups (:development, :test) are not written to the lockfile, so
    # rspec being test-only is not knowable here.
    for dep in scanner_for("gem").scan(GEMFILE_LOCK).deps:
        assert not dep.dev


def test_gem_without_dependencies_section_makes_no_guesses(tmp_path):
    (tmp_path / "Gemfile.lock").write_text(
        "GEM\n"
        "  remote: https://rubygems.org/\n"
        "  specs:\n"
        "    rake (13.0.6)\n"
        "\n"
        "BUNDLED WITH\n"
        "   2.3.7\n")
    result = scanner_for("gem").scan(str(tmp_path / "Gemfile.lock"))
    dep = dep_map(result.deps)["rake"]
    assert dep.version == "13.0.6"
    assert not dep.transitive and not dep.dev


def test_gem_garbage_does_not_raise(tmp_path):
    p = tmp_path / "Gemfile.lock"
    p.write_text(
        "\x00\x01 not a lockfile\n"
        "MYSTERY SECTION\n"
        "  whatever: yes\n"
        "GEM\n"
        "  remote: https://rubygems.org/\n"
        "  specs:\n"
        "    notagemline\n"
        "    blank ()\n"
        "    ok (1.0.0)\n"
        "DEPENDENCIES\n"
        "  ok!!\n")
    result = scanner_for("gem").scan(str(p))
    assert dep_map(result.deps)["ok"].version == "1.0.0"
    reasons = {u.reason for u in result.unresolved}
    assert reasons == {"unparsed"}
    assert all(r in scanners.UNRESOLVED_REASONS for r in reasons)


def test_gem_missing_file_is_unresolved_not_an_exception(tmp_path):
    result = scanner_for("gem").scan(str(tmp_path / "Gemfile.lock"))
    assert result.deps == []
    assert result.unresolved[0].reason == "unparsed"


def test_gem_scanner_metadata():
    scanner = scanner_for("gem")
    assert scanner.ecosystem == "gem" and scanner.language() == "gem"
    assert scanner.manifest_names == ("Gemfile.lock",)
    assert scanner.priority == 10


# -- composer -----------------------------------------------------------------

COMPOSER_LOCK = os.path.join(FIXTURE, "svc/phpsvc/composer.lock")


def test_composer_names_versions_and_leading_v():
    m = dep_map(scanner_for("composer").scan(COMPOSER_LOCK).deps)
    assert m["monolog/monolog"].version == "2.9.1"
    assert m["psr/log"].version == "3.0.0"          # "v3.0.0" as written
    assert m["sebastian/diff"].version == "5.1.1"   # "v5.1.1" as written


def test_composer_dev_flags_from_packages_dev():
    m = dep_map(scanner_for("composer").scan(COMPOSER_LOCK).deps)
    assert m["phpunit/phpunit"].dev
    assert m["sebastian/diff"].dev
    assert not m["monolog/monolog"].dev
    assert not m["psr/log"].dev


def test_composer_direct_vs_transitive_from_composer_json():
    m = dep_map(scanner_for("composer").scan(COMPOSER_LOCK).deps)
    assert not m["monolog/monolog"].transitive      # "require"
    assert not m["phpunit/phpunit"].transitive      # "require-dev"
    assert m["psr/log"].transitive
    assert m["sebastian/diff"].transitive


def test_composer_branch_version_is_unresolved():
    result = scanner_for("composer").scan(COMPOSER_LOCK)
    u = unresolved_map(result)
    assert u["example/internal-tools"].reason == "vcs"
    assert "internal-tools.git" in u["example/internal-tools"].spec
    assert "example/internal-tools" not in {d.name for d in result.deps}


def test_composer_path_repository_is_local(tmp_path):
    (tmp_path / "composer.lock").write_text(json.dumps({
        "packages": [
            {"name": "vendor/sibling", "version": "dev-main",
             "dist": {"type": "path", "url": "../sibling"}},
            {"name": "vendor/branch", "version": "1.x-dev",
             "source": {"type": "git", "url": "https://x.test/branch.git"}},
            {"name": "vendor/real", "version": "v2.1.0",
             "source": {"type": "git", "url": "https://x.test/real.git"}},
        ],
    }))
    result = scanner_for("composer").scan(str(tmp_path / "composer.lock"))
    assert {d.name for d in result.deps} == {"vendor/real"}
    u = unresolved_map(result)
    assert u["vendor/sibling"].reason == "local"
    assert u["vendor/branch"].reason == "vcs"       # "1.x-dev" is a branch


def test_composer_without_composer_json_makes_no_guesses(tmp_path):
    (tmp_path / "composer.lock").write_text(json.dumps({
        "packages": [{"name": "a/b", "version": "1.0.0"}],
        "packages-dev": [{"name": "c/d", "version": "2.0.0"}],
    }))
    result = scanner_for("composer").scan(str(tmp_path / "composer.lock"))
    m = dep_map(result.deps)
    assert not m["a/b"].transitive and not m["c/d"].transitive
    assert m["c/d"].dev          # dev still comes from the lock itself


def test_composer_garbage_does_not_raise(tmp_path):
    p = tmp_path / "composer.lock"
    p.write_text("{not json at all")
    result = scanner_for("composer").scan(str(p))
    assert result.deps == []
    assert result.unresolved[0].reason == "unparsed"

    p.write_text(json.dumps({
        "packages": ["just-a-string", {"version": "1.0"}, {"name": "a/b"},
                     {"name": "ok/pkg", "version": "v1.0.0"}],
        "packages-dev": {},                     # wrong type entirely
    }))
    result = scanner_for("composer").scan(str(p))
    assert dep_map(result.deps)["ok/pkg"].version == "1.0.0"
    reasons = {u.reason for u in result.unresolved}
    assert reasons == {"unparsed"}
    assert all(r in scanners.UNRESOLVED_REASONS for r in reasons)


def test_composer_missing_file_is_unresolved_not_an_exception(tmp_path):
    result = scanner_for("composer").scan(str(tmp_path / "composer.lock"))
    assert result.deps == []
    assert result.unresolved[0].reason == "unparsed"


def test_composer_scanner_metadata():
    scanner = scanner_for("composer")
    assert scanner.ecosystem == "composer" and scanner.language() == "composer"
    assert scanner.manifest_names == ("composer.lock",)
    assert scanner.priority == 10


# -- discovery of real-world layouts ------------------------------------------
#
# Every case here came from running tests/corpus/run_corpus.py against real
# repositories, where hand-written fixtures had missed them entirely.

def test_requirements_variants_are_discovered(tmp_path):
    for name in ("requirements.txt", "requirements-dev.txt",
                 "dev-requirements.txt", "requirements-test.txt"):
        (tmp_path / name).write_text("foo==1.0\n")
    found = {os.path.basename(p.manifest) for p in discover(str(tmp_path))}
    assert found == {"requirements.txt", "requirements-dev.txt",
                     "dev-requirements.txt", "requirements-test.txt"}


def test_requirements_files_get_distinct_project_names(tmp_path):
    (tmp_path / "requirements.txt").write_text("foo==1.0\n")
    (tmp_path / "requirements-dev.txt").write_text("bar==2.0\n")
    names = [p.name for p in discover(str(tmp_path))]
    assert len(names) == len(set(names)), "duplicate names would fail lint"


def test_included_requirements_file_is_not_scanned_twice(tmp_path):
    """requirements.txt starting with -r base.txt must not double-count."""
    (tmp_path / "requirements.txt").write_text("-r base.txt\nfoo==1.0\n")
    (tmp_path / "base.txt").write_text("bar==2.0\n")
    found = discover(str(tmp_path))
    assert [os.path.basename(p.manifest) for p in found] == ["requirements.txt"]
    m = dep_map(scanner_for("pip").scan(found[0].manifest_abspath))
    assert set(m) == {"foo", "bar"}       # both, counted once


def test_pyproject_does_not_suppress_a_requirements_file(tmp_path):
    """A pyproject.toml is the weakest Python source; a requirements file
    beside it still holds real pins."""
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = ["flask>=2.0"]\n')
    (tmp_path / "requirements-dev.txt").write_text("pytest==8.0.0\n")
    found = {os.path.basename(p.manifest) for p in discover(str(tmp_path))}
    assert found == {"pyproject.toml", "requirements-dev.txt"}


def test_lockfile_does_suppress_a_requirements_file(tmp_path):
    (tmp_path / "poetry.lock").write_text(
        '[[package]]\nname = "foo"\nversion = "1.0"\n')
    (tmp_path / "requirements.txt").write_text("foo==1.0\n")
    found = [os.path.basename(p.manifest) for p in discover(str(tmp_path))]
    assert found == ["poetry.lock"]


def test_bare_package_json_reports_ranges_as_unresolved(tmp_path):
    """An npm repo with no lockfile used to be invisible, so `deph check`
    passed with nothing to say."""
    (tmp_path / "package.json").write_text(json.dumps({
        "dependencies": {"axios": "^1.6.0", "exact": "1.2.3",
                         "sibling": "workspace:*"},
        "devDependencies": {"jest": "~29.0.0"},
    }))
    result = scanner_for("npm-package").scan(str(tmp_path / "package.json"))
    m = dep_map(result)
    assert set(m) == {"exact"}                    # only the pin is auditable
    assert m["exact"].version == "1.2.3"
    by_name = {u.name: u.reason for u in result.unresolved}
    assert by_name == {"axios": "range", "jest": "range",
                       "sibling": "workspace"}


def test_package_lock_beats_bare_package_json(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"axios": "^1.6.0"}}))
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {"": {"dependencies": {"axios": "^1.6.0"}},
                     "node_modules/axios": {"version": "1.6.2"}},
    }))
    found = discover(str(tmp_path))
    assert [p.ecosystem for p in found] == ["npm"]


def test_npm_workspace_protocol_is_unresolved_not_a_dep(tmp_path):
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"sibling": "workspace:*", "axios": "^1.0.0"}},
            "node_modules/axios": {"version": "1.6.2"},
        },
    }))
    result = scanner_for("npm").scan(str(tmp_path / "package-lock.json"))
    assert set(dep_map(result)) == {"axios"}
    assert [(u.name, u.reason) for u in result.unresolved] == \
        [("sibling", "workspace")]


def test_cargo_patched_crate_is_unresolved(tmp_path):
    """A [patch] override means the built code isn't the registry release, so
    advisories about that version would be about different code."""
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname = "x"\nversion = "0.1.0"\n'
        '[dependencies]\nserde = "1.0"\ntokio = "1.0"\n'
        '[patch.crates-io]\nserde = { git = "https://github.com/x/serde" }\n')
    (tmp_path / "Cargo.lock").write_text(
        '[[package]]\nname = "serde"\nversion = "1.0.100"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        '[[package]]\nname = "tokio"\nversion = "1.30.0"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        '[[package]]\nname = "x"\nversion = "0.1.0"\n')
    result = scanner_for("cargo").scan(str(tmp_path / "Cargo.lock"))
    assert set(dep_map(result)) == {"tokio"}
    assert [(u.name, u.reason) for u in result.unresolved] == \
        [("serde", "local")]


def test_cargo_git_source_is_unresolved(tmp_path):
    (tmp_path / "Cargo.lock").write_text(
        '[[package]]\nname = "forked"\nversion = "0.1.0"\n'
        'source = "git+https://github.com/x/forked#abc123"\n')
    result = scanner_for("cargo").scan(str(tmp_path / "Cargo.lock"))
    assert result.deps == []
    assert result.unresolved[0].reason == "vcs"


def test_cargo_dev_dependencies_are_marked_dev(tmp_path):
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname = "x"\nversion = "0.1.0"\n'
        '[dependencies]\nserde = "1.0"\n'
        '[dev-dependencies]\ncriterion = "0.5"\n')
    (tmp_path / "Cargo.lock").write_text(
        '[[package]]\nname = "serde"\nversion = "1.0.100"\n'
        '[[package]]\nname = "criterion"\nversion = "0.5.1"\n'
        '[[package]]\nname = "x"\nversion = "0.1.0"\n')
    m = dep_map(scanner_for("cargo").scan(str(tmp_path / "Cargo.lock")))
    assert m["criterion"].dev is True
    assert m["serde"].dev is False


def test_npm_dev_dependencies_are_marked_dev(tmp_path):
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"axios": "^1.0.0"},
                 "devDependencies": {"jest": "^29.0.0"}},
            "node_modules/axios": {"version": "1.6.2"},
            "node_modules/jest": {"version": "29.7.0", "dev": True},
        },
    }))
    m = dep_map(scanner_for("npm").scan(str(tmp_path / "package-lock.json")))
    assert m["jest"].dev is True
    assert m["axios"].dev is False


def test_no_scanner_raises_on_garbage(tmp_path):
    """Lockfiles come from other people's tools, and sometimes from repos that
    would rather deph fell over."""
    from deph.scanners import _REGISTRY, _ensure_builtin
    _ensure_builtin()
    garbage = b"\x00\xff\xfe not a manifest at all {[(<"
    for ecosystem, cls in sorted(_REGISTRY.items()):
        for name in (cls.manifest_names or ("x.txt",)):
            p = tmp_path / ("%s_%s" % (ecosystem.replace("-", "_"), name))
            p.write_bytes(garbage)
            try:
                cls().scan(str(p))
            except (OSError, ValueError):
                pass          # cmd_scan skips these with a warning


# -- workspace monorepos -------------------------------------------------------
#
# Found by scanning real pnpm monorepos: the root lockfile pins every member's
# dependencies, so also scanning each member's package.json reported all of
# their ranges as unresolved. On one repo that was 165 phantom entries.

def _workspace(tmp_path, root_lock="pnpm-lock.yaml", marker="pnpm-workspace.yaml"):
    (tmp_path / root_lock).write_text(
        "lockfileVersion: '6.0'\npackages:\n  /axios@1.6.2:\n    dev: false\n")
    if marker == "pnpm-workspace.yaml":
        (tmp_path / marker).write_text("packages:\n  - 'apps/*'\n")
    else:
        (tmp_path / "package.json").write_text(json.dumps(
            {"workspaces": ["apps/*"]}))
    for app in ("web", "admin"):
        d = tmp_path / "apps" / app
        d.mkdir(parents=True)
        (d / "package.json").write_text(json.dumps(
            {"dependencies": {"axios": "^1.6.0", "react": "^18.0.0"}}))
    return tmp_path


def test_pnpm_workspace_members_are_not_scanned_separately(tmp_path):
    _workspace(tmp_path)
    found = discover(str(tmp_path))
    assert [p.name for p in found] == ["."]
    assert found[0].ecosystem == "npm-pnpm"


def test_yarn_workspaces_key_also_suppresses_members(tmp_path):
    _workspace(tmp_path, root_lock="yarn.lock", marker="package.json")
    assert [p.name for p in discover(str(tmp_path))] == ["."]


def test_workspace_member_with_its_own_lockfile_is_still_scanned(tmp_path):
    """A member that pins its own dependencies is a real, separate project."""
    _workspace(tmp_path)
    desktop = tmp_path / "apps" / "desktop"
    desktop.mkdir(parents=True)
    (desktop / "package.json").write_text(json.dumps(
        {"dependencies": {"electron": "^28.0.0"}}))
    (desktop / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {"": {"dependencies": {"electron": "^28.0.0"}},
                     "node_modules/electron": {"version": "28.1.0"}},
    }))
    names = sorted(p.name for p in discover(str(tmp_path)))
    assert names == [".", "apps/desktop"]


def test_package_json_without_a_workspace_root_is_still_scanned(tmp_path):
    """No workspace declaration means no reason to assume coverage."""
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "package.json").write_text(json.dumps(
        {"dependencies": {"axios": "^1.6.0"}}))
    assert [p.name for p in discover(str(tmp_path))] == ["sub"]
