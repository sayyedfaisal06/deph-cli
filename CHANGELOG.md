# Changelog

Notable changes, newest first. Versions follow SemVer.

## [Unreleased]

### Fixed
- **Scanners no longer drop dependencies silently.** Anything a manifest names
  that can't be pinned to one version (a range, an unpinned requirement, a
  git/URL/path dependency, an unreadable include) is now recorded with a reason,
  counted, and reported. A realistic `requirements.txt` previously audited as
  one dependency out of six and reported a clean result.
- `-r` and `-c` includes in requirements files are followed. Files reachable as
  an include from another discovered file are scanned once, not twice.
- `requirements*.txt` and `*-requirements.txt` are discovered, not just the
  exact name `requirements.txt`.
- Hash-pinned requirements (`pkg==1.2.3 --hash=sha256:…`) parse as pins.
- Version comparison is per-ecosystem. PEP 440 epochs, `~=`, `.post`/`.dev`
  ordering and `==1.4.*` prefixes, and npm/cargo semver prerelease precedence
  and `^`/`~`/`x` ranges are each handled by their own logic. `1.0.post1` is
  newer than `1.0` in Python and older in npm, and both are now right.
- License checking uses a real SPDX expression evaluator. Parenthesised
  expressions like `(MIT OR GPL-3.0-only) AND Apache-2.0` were previously
  mis-read by a string splitter. `WITH`, `+`/`-or-later`, deprecated ids and
  npm's `MIT/Apache-2.0` are supported; an unparseable expression is not
  allowed rather than silently passing.
- A `[patch]`ed or git-sourced cargo crate is reported as unresolved instead of
  being audited as its registry release, which is different code.
- `go.sum` is preferred over `go.mod` when both are present.
- CycloneDX PURLs are canonical. Each path segment is percent-encoded on its
  own, so an npm scope becomes `pkg:npm/%40angular/animation@12.3.1` while a Go
  module path keeps its slashes — both forms verified against the purl spec's
  own test suite. Previously a name containing `#` or `?` produced a truncated
  identifier, since those delimit a purl's subpath and qualifiers.
- Four-segment versions are compared as releases, not prereleases. `rails
  7.0.4.3` sorted *older* than `7.0.4`, which is wrong for the rubygems and Go
  versions that use four segments routinely, and affected both lag reporting
  and advisory range matching. A bump in the fourth segment now reports as
  `patch` rather than `prerelease`.

### Added
- An npm package (`npx @sayyedfaisal06/deph-cli`) that vendors the Python
  source and runs it with the system interpreter, so a Node pipeline needs no
  Python setup step. Same tool, same version, exit codes passed through
  untouched. Requires Python 3.9+ on PATH; `DEPH_PYTHON` pins a specific
  interpreter and is honoured exclusively rather than as a hint.
- `scan --root DIR`, to audit a checkout without writing a `.deph` into it.
- Manifests: `pnpm-lock.yaml`, `yarn.lock` (classic and berry), `package.json`,
  `poetry.lock`, `uv.lock`, `Pipfile.lock`, `pyproject.toml`, `go.sum`/`go.mod`,
  `Gemfile.lock`, `composer.lock`. One project per language per directory.
- OSV.dev as the default advisory source, aggregating GHSA, PyPA, RustSec, Go
  and others. `--advisories github` keeps the previous behaviour.
- Findings carry the version that fixes them, plus CWE and an advisory link.
- `unresolved` policy subject, so a partial scan can warn or fail:
  `warn unresolved >= 1` is now in the default policy.
- Rule scopes: `fail vuln >= high for direct`, `for transitive`, `for dev`,
  `for prod`. Dependencies are marked `dev` where the manifest says so.
- Waiver expiry: `waive GHSA-x until 2026-09-01 "reason"`. Past the date the
  finding returns at full severity, flagged as an expired waiver.
- `deph check --format sarif` for GitHub code scanning, and `deph sbom` for a
  CycloneDX 1.5 SBOM with waivers expressed as VEX `not_affected`.
- `yanked` and `deprecated` tags from PyPI, crates.io and npm.
- Private registry support via `NPM_CONFIG_REGISTRY`, `PIP_INDEX_URL`,
  `GOPROXY` and `DEPH_*_REGISTRY`/`DEPH_*_TOKEN` overrides.
- `coverage` in `deph check --format json` (schema 2) and "% audited" in the
  dashboard, so an incomplete scan can't pass for a clean one.
- pre-commit hooks, a real-repository corpus (`tests/corpus/`), and a branch
  coverage gate in CI.

### Changed
- `Scanner.scan()` returns a `ScanResult` rather than a list of deps. Anyone
  who wrote a scanner against the old signature needs `.deps` and
  `.unresolved`.
- `deph check --format json` is schema 2. Findings gained `dev`, `fix`, `url`,
  `cvss`, `cwe` and `waiver_expired`; the top level gained `coverage`.

## [0.1.0] - 2026-07-27

First release. `deph-cli` on PyPI, `@sayyedfaisal06/deph-cli` on npm — `deph`
was taken on both registries, and npm additionally rejects the unscoped
`deph-cli` as too similar to an existing `del-cli`. The command, the import
name and the `.deph` file extension are all still `deph`.

- The `.deph` format: hand-written `policy` and `waive` blocks preserved byte
  for byte, generated `project`/`dep` blocks below a marker line. Tokenizer and
  recursive-descent parser with `file:line:col` errors; grammar in
  `docs/SPEC.md`. Repeat scans of unchanged dependencies produce no diff beyond
  the timestamp.
- Commands: `init`, `scan` (`--offline`), `check` (`--format json`, GitHub
  Actions annotations, exit 0/1), `validate`, `studio`, `render`.
- Scanners for npm (`package-lock.json` v1/v2/v3, including aliased installs),
  pip (pinned `requirements.txt`), and cargo (`Cargo.lock` plus `Cargo.toml`
  for the direct set), behind a registry that takes one class per ecosystem.
- Enrichment from registry.npmjs.org, pypi.org, and crates.io for versions and
  licenses; the GitHub Advisory Database for vulnerabilities, honouring
  `GITHUB_TOKEN`. Responses cached in sqlite. Failures are negative-cached,
  unreachable hosts are dropped for the rest of the run, and expired cache
  entries are served rather than nothing.
- Policy evaluation: severity thresholds judged once per vulnerability at the
  strongest match, SPDX `OR`/`AND` expressions, waivers with required reasons,
  A–F scores for the dashboard.
- Dashboard over `http.server` with a self-contained template, and static
  reports via `deph render`.
- VS Code extension: `.deph` syntax highlighting and an Open Studio command.
- CI across Python 3.9 to 3.13, plus a job that scans the deliberately
  vulnerable fixture repo and asserts `deph check` exits 1.
