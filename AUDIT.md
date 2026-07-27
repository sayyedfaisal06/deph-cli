# deph — security & correctness audit (re-audit)

**Auditor:** principal-engineer / appsec review
**Date:** 2026-07-27 (re-audit; original pass earlier same day)
**Under review:** the working tree at version 0.1.0
**Environment:** Python 3.9.6 (project `.venv`), macOS. `python -m pytest -q` → **111 passed** (was 96).

---

## Verdict: **SHIP**

All ten findings from the original audit (1 High, 4 Medium, 5 Low) have been remediated in
source and **independently re-verified** this pass. Every security/DoS PoC that previously
printed `PASS` (vulnerability present) now prints `FAIL` (vulnerability gone); the audit
regression suite was rewritten from `xfail` reproductions into **8 permanent passing
regressions**; the fixes introduced **no new findings** (fuzz still clean, bandit clean, the
new parallelism is correctly thread-safe, the new atomic write and negative-cache behave).
deph is ready to ship 0.1.0.

### Re-audit scoreboard

| ID | Sev | Finding | Fix (verified) | Evidence now |
|----|-----|---------|----------------|--------------|
| P1 | High | serial + unbounded-retry network path | `ThreadPoolExecutor(8)` + negative-cache (`NEGATIVE_TTL`) + per-host circuit breaker (`HOST_FAILURE_LIMIT=3`) | `poc_p1`: 6000→**9** sleeps, ~3.9h→**~21s** |
| S1 | Med | studio parse-error XSS | `server._error_page` → `html.escape` + `CSP: default-src 'none'` | `poc_s1`: **FAIL** (payload escaped) |
| C1 | Med | npm alias audited under alias | prefer `info["name"]` (real identity) | `poc_c1`: **FAIL** (real name `chalk` preserved) |
| C2 | Med | writer emits unquoted names/versions | name/version/latest routed through `_render_value` (+ `//` guard) | `poc_c2`: **FAIL** (round-trips) |
| C3 | Med | `RecursionError` DoS | `json.load` RecursionError→`ValueError`; iterative v1 walk; `cmd_scan` catches `Exception` | `poc_c3`: **FAIL** (skipped, not crashed) |
| S2 | Low | `GITHUB_TOKEN` on cross-host redirect | `_SafeRedirectHandler` strips `Authorization` on host change | `enrich.py:249-264` |
| S3 | Low | world-readable cache | dir `0700`, db `0600`; `check_same_thread=False`+lock | `enrich.py:67-89` |
| C4 | Low | prerelease→release lag mislabeled | new `"prerelease"` classification | `enrich.py:158-161`; test passes |
| K1 | Low | `python -m deph` failed | `src/deph/__main__.py` added | `python -m deph --version` → `deph 0.1.0` |
| K2 | Low | version dual-sourced | `[project] dynamic=["version"]` from `deph.__version__` | `pyproject.toml:7,43-44` |

### Findings count (this pass)

| Severity | Open | Fixed |
|----------|------|-------|
| Critical | 0 | 0 |
| High     | 0 | 1 (P1) |
| Medium   | 0 | 4 (S1, C1, C2, C3) |
| Low      | 0 | 5 (S2, S3, C4, K1, K2) |
| Info     | 0 | — |

**No open findings.**

---

## Verification performed this pass

Commands run (real output captured in the session):

- **Suite:** `pytest -q` → `111 passed`; `pytest tests/test_audit_regressions.py` → `8 passed`
  (the S1/C1/C2/C3/C4 reproductions now assert the *fixed* behaviour and pass, plus added
  cases for hostile-version attribute injection, `//`-in-name round-trip, and deep-but-legal
  v1 trees).
- **PoCs re-run against fixed code** — all now print `FAIL` (vuln absent):
  - `poc_s1_studio_xss.py` → payload HTML-escaped in `server._error_page`.
  - `poc_c1_npm_alias.py` → aliased dep audited as `chalk`, not `mychalk`.
  - `poc_c2_roundtrip.py` → `dep "foo bar" 1.0.0` re-parses cleanly.
  - `poc_c3_recursion.py` → deep lockfile/JSON raise `ValueError` (caught & skipped), not `RecursionError`.
  - `poc_p1_serial_retry.py` → **9** stubbed sleeps / ~21 s projected (host breaker trips after 3 failures) vs 6000 / ~3.9 h before.
- **Regression sweep on the fixed tree:**
  - Parser fuzz, 10 000 mutations → **0** non-`DephSyntaxError` exceptions.
  - `bandit -r src/` → clean (the prior B310 is gone; HTTP now flows through the hardened `_OPENER`).
  - `pyflakes` → only the 3 known side-effect-import false positives in `scanners/__init__.py:61` (carry `# noqa: F401`).
  - Thread-safety of the new parallel enrichment: `Cache` uses `sqlite3.connect(check_same_thread=False)` guarded by a `threading.Lock` on every `get`/`put`, and `Enricher._host_failures`/`warnings` mutate under `self._lock` — no cross-thread sqlite misuse.
  - Atomic write: `cmd_scan` and `cmd_render` write via `_write_atomic` (same-dir temp + `os.replace`, temp cleaned on failure). `cmd_init` still uses a plain `open("w")`, which is correct (it refuses to overwrite and creates a fresh file).
- **End-to-end on the fixture monorepo (offline):** `init` → `scan --offline` (3 projects, 10 deps) → `validate: OK` → `check` (rc 0 offline, as expected with an empty cache) → `render` → **zero-diff rescan confirmed identical except the timestamp line.**

---

## Still-correct properties (carried over, re-confirmed)

Dashboard client rendering escapes via `esc()` (+ JSON `</`→`<\/`); studio binds `127.0.0.1`
only and serves a single route; `os.walk` does not follow symlinks; URL sinks guarded by
`urllib.parse.quote`; SQL uses parameterised placeholders; no `subprocess`/`eval`/`exec`/
`pickle`; policy engine single-judgement, `moderate`→`medium`, SPDX `OR`, waivers never fail,
unknown severity never crashes; a new ecosystem (`go.sum`) is addable in ~15 lines with zero
core edits; PyPI publish uses trusted publishing (OIDC), no stored token; CI gates on real
test failure and the dogfood job asserts `deph check` exits 1 with `schema==1 && !ok`.

---

## Residual / nice-to-have (not blocking, not findings)

- **Q2 (info)** — `mypy --strict` still reports untyped-`args`/helper noise; consider adding a
  relaxed type-check job to CI for regression safety. Not a defect.
- **C5 (info, by design)** — pip `requirements.txt` entries are all classified `direct` (a
  `pip freeze` file therefore under-reports transitives); documented behaviour.
- **Cache grace-serve (info)** — on failure `_get` serves a *stale* cached success in
  preference to nothing; acceptable and clearly documented, but worth a one-line note in user
  docs that `--offline`/degraded runs may show data older than the TTL.

---

## Fix plan status

**Before any release** — P1, C3, C2, S1: **all done & verified.**
**Before 1.0** — C1, atomic write, cache `0600`, redirect token-strip: **all done & verified.**
**Nice to have** — `__main__.py`, single-sourced version, prerelease-lag: **all done.** Remaining
optional: CI type-check job (Q2).
