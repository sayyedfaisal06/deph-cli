# Contributing

```console
git clone https://github.com/sayyedfaisal06/deph && cd deph
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest
```

The tests never touch the network. Scans in `tests/test_cli.py` run against a
sqlite cache seeded by `seed_cache()`, which exercises the real scan path
against known fixtures. If you add a test that needs a registry response, seed
it there rather than reaching for the internet.

## Ground rules

- **No runtime dependencies.** If a change needs a package, it needs a
  different design. This is why the cache path, the TOML and YAML reading, the
  version comparison, the SPDX evaluator and the HTTP layer are all hand-rolled.
- **Never drop a dependency silently.** Anything a scanner can't pin goes into
  `ScanResult.unresolved` with a reason. This is the single most important rule
  in the codebase: a tool that audits a sixth of your dependencies and prints a
  green check is worse than one that crashes.
- **The hand-written half of a `.deph` file is untouchable.** Any change to the
  writer has to keep `test_scan_preserves_hand_edited_header_byte_for_byte` and
  `test_two_scans_zero_diff_outside_timestamp` passing.
- **Parse errors carry `file:line:col`.** Always.
- **A bad manifest is skipped with a warning, never fatal.** Lockfiles come
  from other people's tools and sometimes from hostile repos.
- **When unsure about a range, return False.** Missing an advisory is bad;
  inventing one destroys trust in every other finding.
- Python 3.9 syntax: no `X | Y` unions, no `match`.

## Adding an ecosystem

Two steps, and the registry is designed around them.

Write the scanner in `src/deph/scanners/<eco>.py`:

```python
from . import RawDep, ScanResult, Scanner, Unresolved, register

@register
class GradleScanner(Scanner):
    ecosystem = "gradle"                    # unique; "npm-yarn" style for a
                                            # second format of one language
    manifest_names = ("gradle.lockfile",)   # exact names, preference order
    priority = 10                           # lower wins within a language

    def scan(self, manifest_path: str) -> ScanResult:
        result = ScanResult()
        # Pinned versions go in result.deps, with transitive= and dev= set
        # where the format tells you.
        # Everything else goes in result.unresolved with a reason from
        # UNRESOLVED_REASONS. Do not skip it.
        result.deps = result.sorted_deps()
        result.unresolved = result.sorted_unresolved()
        return result
```

Add it to the import in `scanners/__init__.py::_ensure_builtin`.

Then teach `enrich.py` where the registry is, if the ecosystem has one: a
handler in `package_meta`, a default in `DEFAULT_REGISTRIES`, env-var overrides
in `_REGISTRY_ENV`/`_TOKEN_ENV`, and an entry in `OSV_ECOSYSTEMS` (and
`GITHUB_ECOSYSTEMS` if that database covers it). Check their docs for the exact
spelling — cargo is `rust` to GitHub and `crates.io` to OSV, which cost me an
afternoon.

If the ecosystem's versions aren't semver, add a keyer to `versions.py`. Don't
reuse the semver one and hope.

Scanners must not do network I/O. Enrichment owns the network so that scanning
stays fast, offline, and testable.

For tests, add a project under `tests/fixtures/monorepo/` exercising at least
one direct dep, one transitive dep, one dev dep and one unresolved entry, plus
unit tests for whatever your format does that's strange. Then add a real
repository to `tests/corpus/repos.json` — fixtures only contain the shapes you
thought of, and the corpus is what finds the rest.

## The corpus

```console
python tests/corpus/run_corpus.py --workdir /tmp/deph-corpus
python tests/corpus/run_corpus.py --only ripgrep     # one repo
```

It shallow-clones real repositories pinned to tags and reports what each
scanner found. Run it after touching any scanner. Most of the limitations
listed in the README were found this way, including two whole categories of
manifest that discovery used to ignore.

## Changing the file format

`docs/SPEC.md` is normative. A grammar change needs the EBNF updated, parser
and writer tests, and a story for forward compatibility: a v1 parser must not
break on your addition. New `key=value` attributes and new tag kinds are both
ignored by v1 parsers, so prefer those.

## The npm wrapper

`npm/` publishes the same tool to npm so a Node pipeline doesn't need a Python
setup step. It vendors `src/deph` at pack time and runs it with the system
`python3`; because deph has no Python dependencies, that's all it takes.

```console
cd npm
node scripts/sync-python.js     # copy src/deph -> npm/vendor/deph
npm test                        # 15 end-to-end checks through the wrapper
npm pack                        # prepack re-syncs, so the tarball can't be stale
```

`npm/vendor/` is generated and gitignored — `src/deph` is the only source of
truth. `sync-python.js` refuses to run if `npm/package.json` and
`src/deph/__init__.py` disagree about the version, so bump both together.

Both registries publish this as **`deph-cli`**, because `deph` was already
taken on npm and PyPI by unrelated projects. The command, the import name and
the `.deph` extension are all still `deph`; only the distribution name differs.
npm runs a package's sole `bin` regardless of its name, so `npx deph-cli` works
and lands on `deph`.

The wrapper's job is to pass the exit code through untouched, since that's the
contract CI depends on. `npm test` asserts 0/1/2 for a clean file, a failing
policy and a missing file, and that an unusable `DEPH_PYTHON` fails loudly
rather than silently using a different interpreter.

## Releases

Tag `vX.Y.Z` on `main`. `publish.yml` builds and publishes to PyPI via trusted
publishing, and to npm when the `PUBLISH_NPM` repository variable is `true` and
`NPM_TOKEN` is set. Bump `__version__` in `src/deph/__init__.py` (the packaging
version is read from it) and `version` in `npm/package.json`, and update
`CHANGELOG.md` in the same PR.
