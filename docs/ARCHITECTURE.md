# Architecture

Stdlib only, no runtime dependencies. That constraint shapes most of what
follows: the cache path logic, the TOML reading, and the HTTP layer are all
hand-rolled because pulling in `platformdirs`, `tomli`, or `requests` would
make a dependency-auditing tool ship dependencies.

```
.deph file ──parse──▶ Document ──evaluate──▶ Findings ──▶ check / studio / render
     ▲
     └──render(write)── Document ◀──scan── scanners + enrich
```

## Modules

| Module | Responsibility |
|---|---|
| `deph.parser` | Tokenizer, parser, writer, and linter for `.deph`. Round-trip safe: the hand-written header is stored verbatim and re-emitted byte for byte. |
| `deph.policy` | `Document` to `Finding`s. Severity ranking, the `moderate`/`medium` alias, per-vulnerability dedupe, rule scopes, waiver expiry, coverage, scores. |
| `deph.versions` | Per-ecosystem version comparison and range matching. |
| `deph.spdx` | A recursive-descent evaluator for SPDX license expressions. |
| `deph.scanners` | Manifest discovery and lockfile parsing, one class per format. |
| `deph.enrich` | Registry metadata, advisories (OSV or GitHub), the sqlite cache. |
| `deph.report` | SARIF and CycloneDX serialization. |
| `deph.cli` | argparse commands. Owns scan orchestration: discover, scan, enrich, rewrite. |
| `deph.studio` | Payload builder, one HTML template, one `http.server`. |

## Why versions and SPDX are their own modules

Both started as a few helper functions and both were wrong in ways that matter
for a security tool.

Version comparison was one lenient routine shared by every ecosystem. That is
fine for sorting and wrong for deciding whether a version is vulnerable: PEP
440 has epochs, `~=`, and `.post`/`.dev` ordering; npm semver orders
prereleases by dot-separated identifier with numeric parts ranking below
alphanumeric; `1.0.post1` is *newer* than `1.0` in Python and *older* read as
semver. A single comparator has to be wrong for one of them, and being wrong
here means either missing an advisory or inventing one. `versions.py` keys
each ecosystem separately and returns False for ranges it can't parse, on the
principle that missing an advisory is bad but fabricating one destroys trust.

License checking split strings on `AND`/`OR`. That got
`(MIT OR GPL-3.0-only) AND Apache-2.0` wrong against an allowlist of MIT and
Apache-2.0 — a false negative on a compliance check. `spdx.py` parses the real
grammar with WITH binding tighter than AND, which binds tighter than OR.

## The scanner registry

`_REGISTRY` maps a scanner key to its class:

```python
class Scanner:
    ecosystem = "npm-yarn"                 # unique key
    manifest_names = ("yarn.lock",)        # exact names, in preference order
    manifest_globs = ("requirements*.txt",)  # or fnmatch patterns
    priority = 20                          # lower wins within a language
    exclusive = True                       # one per language per directory?
    def scan(self, manifest_path) -> ScanResult: ...
```

`language()` is the ecosystem minus any hyphenated suffix, so `npm-yarn`,
`npm-pnpm` and `npm` are all `npm`: same registry, same advisory ecosystem,
same thing as far as policy is concerned. Only the language reaches the file.

`discover(root)` walks the tree once, skipping `node_modules`, `.git`,
`target`, `vendor`, `venv`, `dist` and friends, then resolves each directory:

- **Exclusive** manifests compete, lowest `priority` winning. `package-lock.json`,
  `pnpm-lock.yaml` and `yarn.lock` describe one dependency set three ways, and
  scanning all three would triple-report every finding.
- **Additive** manifests (only pip's requirements files) all survive, because
  `requirements.txt` and `requirements-dev.txt` are two real sets. They're
  dropped only by a *stronger* exclusive manifest: a `poetry.lock` is the truth
  for its directory, a `pyproject.toml` is not.
- `filter_candidates` lets a scanner narrow its own matches first. Pip uses it
  to drop files another candidate pulls in with `-r`, which would otherwise be
  counted twice.
- Names are made unique afterwards, since duplicate project names are a lint
  error. Two requirements files in one directory get named after their
  manifests rather than their shared directory.

### ScanResult, and why unresolved is not optional

```python
@dataclass
class ScanResult:
    deps: List[RawDep]              # name, version, transitive, dev
    unresolved: List[Unresolved]    # spec, reason, name
```

`RawDep` carries nothing a registry would have to tell us; everything richer
belongs to enrichment. That line is what makes scanners fast, offline, and
trivial to test against fixtures.

`unresolved` is the more important half. The original pip scanner skipped
anything it couldn't pin, so a realistic `requirements.txt` with an `-r`
include and four ranges audited as *one* dependency and reported a clean
result. A security tool that quietly audits a sixth of your dependencies and
prints a green check is worse than one that crashes, because the crash tells
you something is wrong. So every requirement a scanner declines to resolve is
recorded with a reason, counted in `deph check`, shown as "% audited" in the
dashboard, and exposed as `coverage` in the JSON.

Scanners must never raise for input reasons. Lockfiles come from other
people's tools and sometimes from repos that would rather deph fell over;
`cmd_scan` catches everything and skips the manifest with a warning, but a
scanner that returns an `Unresolved(reason="unparsed")` gives a better answer.

### Working out which deps are direct

- **npm v2/v3**: the names in `packages[""]`, and only where the entry lives at
  `node_modules/<name>`. A nested copy of the same package is transitive.
  Aliased installs (`"mychalk": "npm:chalk@^5"`) are recorded under the real
  name from the entry's `name` field, or their advisories would be missed.
- **npm v1**: no root dependency list exists, so the direct set comes from a
  sibling `package.json`. Without one, tree depth is the fallback.
- **pip**: everything in a requirements file was asked for by hand, so nothing
  is transitive.
- **cargo**: `Cargo.lock` has the full set; the direct names come from
  `Cargo.toml`'s dependency tables, including `[dependencies.foo]` headers and
  target-specific sections. The crate being built is excluded. With no
  `Cargo.toml` present, nothing is marked transitive rather than guessed at.

## Enrichment and the cache

Every HTTP request goes through `enrich._urlopen` into `Enricher._get`, which
serves fresh cache hits (24h for registry metadata, 6h for advisories),
otherwise fetches with exponential backoff on 403/429/5xx, and writes the
response back. A 404 is cached as an answer, because "no such package" is one.
Under `--offline` it reads the cache at any age and opens no sockets.

The retry logic needs bounding or it becomes a liability: a scan can be
thousands of URLs, and a registry that's timing out would otherwise cost the
full backoff for every single one. Three things prevent that.

- A failure is negative-cached for ten minutes, so the next dependency needing
  the same URL doesn't re-pay for it.
- A host that fails three times in a row is skipped for the rest of the run,
  after one warning.
- An expired cache entry is served in preference to nothing.

That last one has a consequence worth knowing: a degraded run can report data
older than the TTL. Stale beats blank for a health report, but it means offline
results are a floor rather than a current answer.

Registry lookups run on a `ThreadPoolExecutor` with 8 workers over unique
names. `Cache` and `Enricher` both take locks; the sqlite connection is opened
with `check_same_thread=False` and guarded.

The opener strips `Authorization` on any redirect that changes host, so
`GITHUB_TOKEN` can't follow a redirect off `api.github.com`.

The cache is one sqlite file under the platform cache directory
(`~/Library/Caches/deph`, `$XDG_CACHE_HOME/deph`,
`%LOCALAPPDATA%\deph\Cache`), overridable with `DEPH_CACHE_DIR`, created
`0700`/`0600`. The contents are public data, but a cache in a shared directory
shouldn't be someone else's to poison.

### Advisory sources

OSV.dev is the default. It aggregates GHSA, PyPA, RustSec, Go and others, and
does version-range matching server-side — logic we'd otherwise reimplement per
ecosystem and get subtly wrong. `POST /v1/querybatch` takes 500 pairs at a time
and returns ids; each id is then fetched from `/v1/vulns/{id}` for severity, CWE
and the fixed version. Those detail GETs cache like anything else, so a second
scan is free.

Neither source strictly contains the other, which is worth knowing before
assuming one is enough. Scanning the fixture repo both ways: OSV returned 199
distinct advisories, GitHub 163, with 36 unique to OSV and 5 unique to GitHub.
GitHub does mirror RustSec into GHSA, so cargo is covered either way. OSV is the
default because it was broader here and because its range matching and
fixed-version data are uniform across ecosystems, not because GitHub is missing
a database.

Where an OSV entry has a GHSA alias, that becomes the primary id: it's what
people paste into a waiver and what the advisory pages are keyed on.

`--advisories github` uses the GitHub Advisory Database instead: 30
`name@version` pairs per request against `GET /advisories`, matched back by
package name *and* `vulnerable_version_range` using `deph.versions`. Ecosystem
names are translated on the way out — cargo is `rust` to GitHub and
`crates.io` to OSV.

POST responses are cached under a key that includes a hash of the request body,
since two different dependency batches post to the same URL.

If a source stops answering, the scan finishes with an "advisories
unavailable" warning and whatever was matched before that.

### Registries

Each ecosystem has a base URL, overridable by environment variable so deph
works against a private mirror: `NPM_CONFIG_REGISTRY`, `PIP_INDEX_URL` and
`GOPROXY` are read directly, and every ecosystem also has `DEPH_*_REGISTRY`
and `DEPH_*_TOKEN` overrides that take precedence. `GOPROXY` is parsed as the
comma/pipe list it is, skipping `direct` and `off`.

Beyond latest version and license, registries also answer whether a release was
yanked (PyPI, crates.io) or the package deprecated (npm). Those become bare
`yanked` / `deprecated` tags on the dep line.

## Rewriting the file

`deph scan` parses the whole file before writing anything, then replaces it
atomically via a temp file in the same directory and `os.replace`. The output
is: the header verbatim, the marker line with a fresh timestamp, then projects
sorted by name with deps in scanner order. That ordering is what makes two
scans of unchanged dependencies produce no diff beyond the timestamp.

Names and versions that wouldn't survive a round trip as bare words — spaces,
`=`, brackets, `//` — are written as quoted strings, and the parser accepts
strings in those positions. deph should never write a file it can't read.

## Studio

`build_payload` returns one JSON-serialisable dict; `build_html` inlines it
into `template.html`. Vanilla JS, no build step, no external requests, which
is what lets the same output work as a served page and as a CI artifact. The
server re-reads the file per request, so there's no state and no reload logic.

Scores live in `deph.policy`: 100 minus a penalty per finding, waived findings
excluded. They exist to sort projects worst-first, nothing more. Coverage is
shown next to the grade precisely so a project can't look clean by being
unreadable — and unresolved rows are exempt from the severity and scope filters,
because a filter must never make an unaudited dependency disappear.

## Machine-readable output

`deph.report` builds SARIF 2.1.0 and CycloneDX 1.5 as plain dicts. Both
schemas are small and stable enough that a dependency would buy nothing.

SARIF groups rules by finding *kind* rather than per advisory, so code scanning
shows four rules instead of thousands of one-off ones, and `partialFingerprints`
are stable across runs so a finding is tracked rather than re-reported as new.
Waived findings become `note` level: visible, not failing.

CycloneDX identifies components by Package URL, marks dev dependencies as
`optional` scope, and expresses waivers as
`analysis.state = not_affected` with the waiver reason as the justification —
which is what a waiver actually means in VEX terms. Unpinned dependencies are
absent from the SBOM by definition, so `deph sbom` warns when it omits any.

## Testing

Unit tests and fixtures cover the shapes I thought of.
`tests/corpus/run_corpus.py` covers the ones I didn't: it shallow-clones a
handful of real repositories pinned to tags, scans them, and asserts that
discovery finds their manifests and nothing raises. Every entry in the README's
limitations list that isn't a design decision was found by running it.

CLI tests run `deph` as a subprocess against a copy of the fixture repo with a
pre-seeded cache, so they exercise the real scan path — argument parsing, exit
codes, atomic writes — without a network. The OSV seed is derived from an
actual scan of the fixtures rather than hardcoded, so adding a fixture project
can't silently leave those tests reaching for the internet.

## Rules I've been holding to

- **No runtime dependencies.** Ever.
- **`check` is pure.** File in, exit code out. No network, no cache, so a CI
  gate is reproducible and a reviewer can predict it from the diff.
- **The file is the only state.** Scan writes it, check reads it, studio
  renders it. Nothing is stashed anywhere else.
- **Degrade instead of dying.** An unparseable manifest is skipped with a
  warning. An unreachable registry costs enrichment, not the run.
