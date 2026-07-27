"""Latest versions, licenses, and vulnerability advisories.

Advisories come from OSV.dev by default. OSV aggregates GHSA, PyPA, RustSec,
Go and others, so a GitHub-only query misses things — RustSec advisories in
particular. It also does version-range matching server-side, which is exactly
the logic we'd otherwise be reimplementing per ecosystem. GitHub's Advisory
Database is still available (`--advisories github`) and honours GITHUB_TOKEN.

Registry metadata comes from registry.npmjs.org, the pypi.org JSON API,
crates.io, proxy.golang.org, rubygems.org and packagist.org, or from whatever
private mirror the environment points at.

Responses land in a sqlite cache; --offline reads that cache at any age and
opens no sockets. Nothing in here is allowed to fail a scan: a registry that's
down costs enrichment for those deps and a warning on stderr, not an exit code.
"""

import hashlib
import json
import os
import re
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from . import __version__, versions

USER_AGENT = "deph/%s (+https://github.com/sayyedfaisal06/deph-cli)" % __version__
DEFAULT_TTL = 24 * 3600          # registry metadata
ADVISORY_TTL = 6 * 3600          # advisories move faster
NEGATIVE_TTL = 10 * 60           # how long a failed fetch stays failed
HOST_FAILURE_LIMIT = 3           # consecutive failures before we skip a host

_FAILURE = "__deph_unavailable__"

# Ours -> GitHub's. Note cargo is "rust" there.
GITHUB_ECOSYSTEMS = {"npm": "npm", "pip": "pip", "cargo": "rust",
                     "go": "go", "gem": "rubygems", "composer": "composer"}

# Ours -> OSV's. Different spellings again, of course.
OSV_ECOSYSTEMS = {"npm": "npm", "pip": "PyPI", "cargo": "crates.io",
                  "go": "Go", "gem": "RubyGems", "composer": "Packagist"}

# Public default for each registry, overridable per ecosystem by env var so
# deph works against a private mirror or an artifact proxy.
DEFAULT_REGISTRIES = {
    "npm": "https://registry.npmjs.org",
    "pip": "https://pypi.org/pypi",
    "cargo": "https://crates.io/api/v1/crates",
    "go": "https://proxy.golang.org",
    "gem": "https://rubygems.org/api/v1",
    "composer": "https://repo.packagist.org",
}

# Checked in order; first non-empty wins. These are the variables the native
# tools already use, so a configured CI box usually needs nothing new.
_REGISTRY_ENV = {
    "npm": ("DEPH_NPM_REGISTRY", "NPM_CONFIG_REGISTRY", "npm_config_registry"),
    "pip": ("DEPH_PIP_INDEX_URL", "PIP_INDEX_URL"),
    "cargo": ("DEPH_CARGO_REGISTRY",),
    "go": ("DEPH_GO_PROXY", "GOPROXY"),
    "gem": ("DEPH_GEM_SOURCE",),
    "composer": ("DEPH_COMPOSER_REPO",),
}

# Bearer/basic token per ecosystem, for registries that need auth.
_TOKEN_ENV = {
    "npm": ("DEPH_NPM_TOKEN", "NPM_TOKEN"),
    "pip": ("DEPH_PIP_TOKEN",),
    "cargo": ("DEPH_CARGO_TOKEN",),
    "go": ("DEPH_GO_TOKEN",),
    "gem": ("DEPH_GEM_TOKEN",),
    "composer": ("DEPH_COMPOSER_TOKEN",),
}


def _env_first(names: Tuple[str, ...]) -> Optional[str]:
    for name in names:
        value = os.environ.get(name)
        if value:
            return value.strip()
    return None


def registry_base(ecosystem: str) -> str:
    configured = _env_first(_REGISTRY_ENV.get(ecosystem, ()))
    if configured:
        # GOPROXY is a comma/pipe list with "direct" and "off" sentinels.
        first = re.split(r"[,|]", configured)[0].strip()
        if first and first not in ("direct", "off"):
            return first.rstrip("/")
    return DEFAULT_REGISTRIES.get(ecosystem, "")


def registry_token(ecosystem: str) -> Optional[str]:
    return _env_first(_TOKEN_ENV.get(ecosystem, ()))


def default_cache_path() -> str:
    # platformdirs would be one line, but it'd also be our only dependency.
    env = os.environ.get("DEPH_CACHE_DIR")
    if env:
        base = env
    elif sys.platform == "darwin":
        base = os.path.expanduser("~/Library/Caches/deph")
    elif os.name == "nt":
        base = os.path.join(
            os.environ.get("LOCALAPPDATA", os.path.expanduser("~")),
            "deph", "Cache")
    else:
        base = os.path.join(
            os.environ.get("XDG_CACHE_HOME", os.path.expanduser("~/.cache")),
            "deph")
    return os.path.join(base, "cache.db")


class Cache:
    """sqlite response cache, safe to share across the scan's threads.

    Modes are 0700/0600. The contents are public registry data, but a cache in
    a shared directory shouldn't be another user's to poison.
    """

    def __init__(self, path: Optional[str] = None):
        self.path = path or default_cache_path()
        cache_dir = os.path.dirname(self.path)
        dir_existed = os.path.isdir(cache_dir)
        os.makedirs(cache_dir, exist_ok=True)
        if not dir_existed and os.name != "nt":
            # Only chmod what we created; a caller's DEPH_CACHE_DIR may be a
            # shared dir we have no business tightening (and may not own).
            try:
                os.chmod(cache_dir, 0o700)
            except OSError:
                pass
        self._lock = threading.Lock()
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        if os.name != "nt":
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS http_cache ("
            " key TEXT PRIMARY KEY, value TEXT, fetched_at REAL)")
        self.db.commit()

    def get(self, key: str, max_age: Optional[float] = None) -> Optional[str]:
        with self._lock:
            row = self.db.execute(
                "SELECT value, fetched_at FROM http_cache WHERE key = ?",
                (key,)).fetchone()
        if row is None:
            return None
        value, fetched_at = row
        if max_age is not None and time.time() - fetched_at > max_age:
            return None
        return value

    def put(self, key: str, value: str) -> None:
        with self._lock:
            self.db.execute(
                "INSERT OR REPLACE INTO http_cache (key, value, fetched_at)"
                " VALUES (?, ?, ?)", (key, value, time.time()))
            self.db.commit()

    def close(self) -> None:
        with self._lock:
            self.db.close()


# Version handling proper lives in versions.py, which knows the difference
# between PEP 440 and semver. These stay as the ecosystem-agnostic entry points
# used where the caller genuinely doesn't know the ecosystem.
compare_versions = versions.compare
classify_lag = versions.classify_lag


def version_in_range(version: str, range_expr: str,
                     ecosystem: str = "npm") -> bool:
    return versions.satisfies(version, range_expr, ecosystem)


_TROVE_LICENSES = {
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
    "License :: OSI Approved :: BSD License": "BSD-3-Clause",
    "License :: OSI Approved :: ISC License (ISCL)": "ISC",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "License :: OSI Approved :: GNU General Public License v2 (GPLv2)": "GPL-2.0-only",
    "License :: OSI Approved :: GNU General Public License v3 (GPLv3)": "GPL-3.0-only",
    "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)":
        "GPL-3.0-or-later",
    "License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)":
        "LGPL-2.1-or-later",
    "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)":
        "LGPL-3.0-only",
    "License :: OSI Approved :: GNU Affero General Public License v3": "AGPL-3.0-only",
    "License :: OSI Approved :: Python Software Foundation License": "PSF-2.0",
    "License :: OSI Approved :: The Unlicense (Unlicense)": "Unlicense",
    "License :: OSI Approved :: zlib/libpng License": "Zlib",
}


def pypi_license(info: dict) -> Optional[str]:
    """Best available license id, in descending order of trustworthiness.

    license_expression (PEP 639) is authoritative. The old license field is a
    free-text mess: plenty of packages paste the entire MIT license into it,
    and plenty leave it empty, so it's only usable when it looks like an id.
    Classifiers are the last resort and are coarse ("BSD License").
    """
    expr = info.get("license_expression")
    if isinstance(expr, str) and expr.strip():
        return expr.strip()
    raw = info.get("license")
    if isinstance(raw, str):
        raw = raw.strip()
        if raw and "\n" not in raw and len(raw) <= 60:
            return raw
    for classifier in info.get("classifiers") or []:
        mapped = _TROVE_LICENSES.get(classifier)
        if mapped:
            return mapped
    return None


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Drops Authorization when a redirect changes host, so GITHUB_TOKEN can't
    follow a redirect somewhere it doesn't belong."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = urllib.request.HTTPRedirectHandler.redirect_request(
            self, req, fp, code, msg, headers, newurl)
        if new is None:
            return None
        old_host = urllib.parse.urlsplit(req.full_url).netloc
        new_host = urllib.parse.urlsplit(new.full_url).netloc
        if new_host != old_host:
            for key in list(new.headers):
                if key.lower() == "authorization":
                    del new.headers[key]
        return new


_OPENER = urllib.request.build_opener(_SafeRedirectHandler())


def _urlopen(req: urllib.request.Request, timeout: float):
    # Every HTTP call goes through here: one place to harden, one to stub.
    return _OPENER.open(req, timeout=timeout)


def _neg_key(url: str) -> str:
    return "neg::" + url


def post_cache_key(url: str, payload: dict) -> str:
    """Cache key for a POST. The body is part of it because two different
    dependency batches post to the same URL."""
    body = json.dumps(payload, sort_keys=True)
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()[:16]
    return "post::%s::%s" % (url, digest)


def _go_escape(module: str) -> str:
    """Go module proxy paths lowercase capitals as !x to stay case-safe."""
    return "".join("!" + ch.lower() if ch.isupper() else ch for ch in module)


@dataclass
class PackageMeta:
    latest: Optional[str] = None
    license: Optional[str] = None
    yanked: Optional[str] = None       # reason, when the release was pulled
    deprecated: Optional[str] = None   # message, when the package is deprecated


@dataclass
class Advisory:
    id: str
    severity: str = "unknown"
    fixed: Optional[str] = None        # lowest non-vulnerable version
    summary: str = ""
    cvss: Optional[str] = None
    cwe: Optional[str] = None
    url: Optional[str] = None

    def to_dict(self) -> Dict[str, Optional[str]]:
        return {"id": self.id, "severity": self.severity, "fixed": self.fixed,
                "summary": self.summary, "cvss": self.cvss, "cwe": self.cwe,
                "url": self.url}


class Enricher:
    def __init__(self, cache: Optional[Cache] = None, offline: bool = False,
                 token: Optional[str] = None, retries: int = 3,
                 backoff: float = 1.0, timeout: float = 15.0,
                 source: str = "osv"):
        self.cache = cache or Cache()
        self.offline = offline
        self.token = token if token is not None else os.environ.get("GITHUB_TOKEN")
        self.source = source
        self.retries = retries
        self.backoff = backoff
        self.timeout = timeout
        self.warnings: List[str] = []
        self._advisories_dead = False
        self._lock = threading.Lock()
        self._host_failures: Dict[str, int] = {}   # consecutive, per host

    def _host_dead(self, host: str) -> bool:
        with self._lock:
            return self._host_failures.get(host, 0) >= HOST_FAILURE_LIMIT

    def _record_host(self, host: str, ok: bool) -> None:
        with self._lock:
            if ok:
                self._host_failures[host] = 0
                return
            count = self._host_failures.get(host, 0) + 1
            self._host_failures[host] = count
            if count == HOST_FAILURE_LIMIT:
                self.warnings.append(
                    "%s unreachable after %d consecutive failures; skipping it "
                    "for the rest of this scan (cached data still used)"
                    % (host, count))

    def _get(self, url: str, ttl: float, headers: Optional[dict] = None,
             retriable: Tuple[int, ...] = (403, 429, 500, 502, 503)):
        """GET as JSON through the cache; None if we couldn't get an answer.

        Cost of failure is bounded three ways, because a scan can be thousands
        of URLs and a flapping registry used to mean hours of serial backoff:
        a failure is negative-cached so the next dep doesn't re-pay for it, a
        host that fails HOST_FAILURE_LIMIT times in a row is skipped for the
        rest of the run, and an expired cache entry beats returning nothing.
        """
        stale = self.cache.get(url)              # any age: the last resort
        if stale == _FAILURE:                    # written by older versions
            stale = None
        if self.offline:
            return json.loads(stale) if stale is not None else None
        cached = self.cache.get(url, max_age=ttl)
        if cached is not None and cached != _FAILURE:
            return json.loads(cached)
        if self.cache.get(_neg_key(url), max_age=NEGATIVE_TTL) is not None:
            return json.loads(stale) if stale is not None else None
        host = urllib.parse.urlsplit(url).netloc
        if self._host_dead(host):
            return json.loads(stale) if stale is not None else None
        req_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if headers:
            req_headers.update(headers)
        delay = self.backoff
        for attempt in range(self.retries + 1):
            try:
                req = urllib.request.Request(url, headers=req_headers)
                with _urlopen(req, timeout=self.timeout) as resp:
                    body = resp.read().decode("utf-8")
                self.cache.put(url, body)
                self._record_host(host, ok=True)
                return json.loads(body)
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    self.cache.put(url, "null")   # an answer: no such package
                    self._record_host(host, ok=True)
                    return None
                if e.code in retriable and attempt < self.retries:
                    time.sleep(delay)
                    delay *= 2
                    continue
                break
            except (urllib.error.URLError, OSError, ValueError):
                if attempt < self.retries:
                    time.sleep(delay)
                    delay *= 2
                    continue
                break
        self.cache.put(_neg_key(url), _FAILURE)
        self._record_host(host, ok=False)
        return json.loads(stale) if stale is not None else None

    def _post(self, url: str, payload: dict, ttl: float):
        """POST JSON, cached under a key that includes the request body.

        Only OSV's querybatch needs this. The body is part of the cache key
        because two different dependency batches hit the same URL.
        """
        body = json.dumps(payload, sort_keys=True)
        cache_key = post_cache_key(url, payload)

        stale = self.cache.get(cache_key)
        if self.offline:
            return json.loads(stale) if stale is not None else None
        fresh = self.cache.get(cache_key, max_age=ttl)
        if fresh is not None:
            return json.loads(fresh)
        if self.cache.get(_neg_key(cache_key), max_age=NEGATIVE_TTL) is not None:
            return json.loads(stale) if stale is not None else None
        host = urllib.parse.urlsplit(url).netloc
        if self._host_dead(host):
            return json.loads(stale) if stale is not None else None

        headers = {"User-Agent": USER_AGENT, "Accept": "application/json",
                   "Content-Type": "application/json"}
        delay = self.backoff
        for attempt in range(self.retries + 1):
            try:
                req = urllib.request.Request(
                    url, data=body.encode("utf-8"), headers=headers,
                    method="POST")
                with _urlopen(req, timeout=self.timeout) as resp:
                    text = resp.read().decode("utf-8")
                self.cache.put(cache_key, text)
                self._record_host(host, ok=True)
                return json.loads(text)
            except urllib.error.HTTPError as e:
                if e.code in (403, 429, 500, 502, 503) and attempt < self.retries:
                    time.sleep(delay)
                    delay *= 2
                    continue
                break
            except (urllib.error.URLError, OSError, ValueError):
                if attempt < self.retries:
                    time.sleep(delay)
                    delay *= 2
                    continue
                break
        self.cache.put(_neg_key(cache_key), _FAILURE)
        self._record_host(host, ok=False)
        return json.loads(stale) if stale is not None else None

    def latest_and_license(self, ecosystem: str, name: str
                           ) -> Tuple[Optional[str], Optional[str]]:
        meta = self.package_meta(ecosystem, name, version=None)
        return meta.latest, meta.license

    def package_meta(self, ecosystem: str, name: str,
                     version: Optional[str] = None) -> "PackageMeta":
        """Everything the registry will tell us about one package."""
        handler = {
            "npm": self._npm_meta,
            "pip": self._pypi_meta,
            "cargo": self._crates_meta,
            "go": self._go_meta,
            "gem": self._gem_meta,
            "composer": self._composer_meta,
        }.get(ecosystem)
        if handler is None:
            return PackageMeta()
        try:
            return handler(name, version)
        except Exception:  # noqa: BLE001
            # A registry serving a shape we don't expect must not end the scan.
            return PackageMeta()

    def _registry_headers(self, ecosystem: str) -> Optional[dict]:
        token = registry_token(ecosystem)
        return {"Authorization": "Bearer %s" % token} if token else None

    def _npm_meta(self, name: str, version: Optional[str]) -> "PackageMeta":
        url = "%s/%s" % (registry_base("npm"),
                         urllib.parse.quote(name, safe="@"))
        data = self._get(url, DEFAULT_TTL, headers=self._registry_headers("npm"))
        meta = PackageMeta()
        if not isinstance(data, dict):
            return meta
        latest = (data.get("dist-tags") or {}).get("latest")
        meta.latest = latest if isinstance(latest, str) else None
        license_ = data.get("license")
        versions = data.get("versions") if isinstance(data.get("versions"), dict) else {}
        if isinstance(latest, str) and isinstance(versions.get(latest), dict):
            if versions[latest].get("license"):
                license_ = versions[latest]["license"]
        if isinstance(license_, dict):               # ancient {"type": "MIT"}
            license_ = license_.get("type")
        meta.license = license_ if isinstance(license_, str) else None
        # npm marks a package or a specific release deprecated with a string.
        if isinstance(data.get("deprecated"), str) and data["deprecated"]:
            meta.deprecated = data["deprecated"]
        if version and isinstance(versions.get(version), dict):
            dep = versions[version].get("deprecated")
            if isinstance(dep, str) and dep:
                meta.deprecated = dep
        return meta

    def _pypi_meta(self, name: str, version: Optional[str]) -> "PackageMeta":
        base = registry_base("pip")
        url = "%s/%s/json" % (base, urllib.parse.quote(name))
        data = self._get(url, DEFAULT_TTL, headers=self._registry_headers("pip"))
        meta = PackageMeta()
        if not isinstance(data, dict) or not isinstance(data.get("info"), dict):
            return meta
        info = data["info"]
        meta.latest = info["version"] if isinstance(info.get("version"), str) else None
        meta.license = pypi_license(info)
        if info.get("yanked"):
            meta.yanked = str(info.get("yanked_reason") or "yanked")
        # A yanked *release* is what matters, and that lives per-version.
        releases = data.get("releases")
        if version and isinstance(releases, dict):
            files = releases.get(version)
            if isinstance(files, list) and files:
                first = files[0]
                if isinstance(first, dict) and first.get("yanked"):
                    meta.yanked = str(first.get("yanked_reason") or "yanked")
        return meta

    def _crates_meta(self, name: str, version: Optional[str]) -> "PackageMeta":
        url = "%s/%s" % (registry_base("cargo"), urllib.parse.quote(name))
        data = self._get(url, DEFAULT_TTL,
                         headers=self._registry_headers("cargo"))
        meta = PackageMeta()
        if not isinstance(data, dict) or not isinstance(data.get("crate"), dict):
            return meta
        crate = data["crate"]
        latest = crate.get("max_stable_version") or crate.get("max_version")
        meta.latest = latest if isinstance(latest, str) else None
        versions = data.get("versions")
        if isinstance(versions, list):
            for v in versions:
                if not isinstance(v, dict):
                    continue
                if v.get("num") == latest and isinstance(v.get("license"), str):
                    meta.license = v["license"]
                if version and v.get("num") == version and v.get("yanked"):
                    meta.yanked = "yanked"
            if meta.license is None and versions and isinstance(versions[0], dict):
                lic = versions[0].get("license")
                meta.license = lic if isinstance(lic, str) else None
        return meta

    def _go_meta(self, name: str, version: Optional[str]) -> "PackageMeta":
        # The module proxy serves plain text, not JSON: @v/list is newline
        # separated and @latest is a small JSON document.
        base = registry_base("go")
        url = "%s/%s/@latest" % (base, _go_escape(name))
        data = self._get(url, DEFAULT_TTL, headers=self._registry_headers("go"))
        meta = PackageMeta()
        if isinstance(data, dict) and isinstance(data.get("Version"), str):
            meta.latest = data["Version"]
        # The proxy has no license field; pkg.go.dev does, but not as an API.
        return meta

    def _gem_meta(self, name: str, version: Optional[str]) -> "PackageMeta":
        url = "%s/gems/%s.json" % (registry_base("gem"),
                                   urllib.parse.quote(name))
        data = self._get(url, DEFAULT_TTL, headers=self._registry_headers("gem"))
        meta = PackageMeta()
        if not isinstance(data, dict):
            return meta
        if isinstance(data.get("version"), str):
            meta.latest = data["version"]
        licenses = data.get("licenses")
        if isinstance(licenses, list) and licenses:
            meta.license = " AND ".join(str(x) for x in licenses if x)
        elif isinstance(licenses, str):
            meta.license = licenses
        return meta

    def _composer_meta(self, name: str, version: Optional[str]) -> "PackageMeta":
        url = "%s/p2/%s.json" % (registry_base("composer"),
                                 urllib.parse.quote(name, safe="/"))
        data = self._get(url, DEFAULT_TTL,
                         headers=self._registry_headers("composer"))
        meta = PackageMeta()
        packages = data.get("packages") if isinstance(data, dict) else None
        if not isinstance(packages, dict):
            return meta
        releases = packages.get(name)
        if not isinstance(releases, list):
            return meta
        best: Optional[str] = None
        for release in releases:
            if not isinstance(release, dict):
                continue
            num = release.get("version")
            if not isinstance(num, str) or num.startswith("dev-"):
                continue
            clean = num.lstrip("vV")
            if best is None or versions.compare(clean, best, "composer") > 0:
                best = clean
                lic = release.get("license")
                if isinstance(lic, list) and lic:
                    meta.license = " OR ".join(str(x) for x in lic if x)
                elif isinstance(lic, str):
                    meta.license = lic
        meta.latest = best
        return meta

    BATCH = 30
    OSV_BATCH = 500

    def advisories(self, ecosystem: str, deps: List[Tuple[str, str]]
                   ) -> Dict[Tuple[str, str], List[Advisory]]:
        """-> {(name, version): [Advisory, ...]}.

        If the source stops answering we warn once and return whatever we
        matched: incomplete vulnerability data is worth reporting, and it beats
        aborting the scan.
        """
        result: Dict[Tuple[str, str], List[Advisory]] = {
            (n, v): [] for n, v in deps}
        if not deps or self._advisories_dead:
            return result
        if self.source == "github":
            return self._github_advisories(ecosystem, deps, result)
        return self._osv_advisories(ecosystem, deps, result)

    def _mark_dead(self, ecosystem: str, source: str) -> None:
        if self.offline:
            return
        self._advisories_dead = True
        self.warnings.append(
            "advisories unavailable for %s (%s unreachable or rate-limited); "
            "vulnerability data is incomplete" % (ecosystem, source))

    # -- OSV ---------------------------------------------------------------

    def _osv_advisories(self, ecosystem: str, deps, result):
        osv_eco = OSV_ECOSYSTEMS.get(ecosystem)
        if osv_eco is None:
            return result
        for i in range(0, len(deps), self.OSV_BATCH):
            batch = deps[i:i + self.OSV_BATCH]
            queries = [{"package": {"name": n, "ecosystem": osv_eco},
                        "version": v} for n, v in batch]
            data = self._post("https://api.osv.dev/v1/querybatch",
                              {"queries": queries}, ADVISORY_TTL)
            if data is None:
                self._mark_dead(ecosystem, "OSV")
                return result
            results = data.get("results") if isinstance(data, dict) else None
            if not isinstance(results, list):
                continue
            # querybatch returns ids only, positionally aligned with queries.
            for (name, version), entry in zip(batch, results):
                if not isinstance(entry, dict):
                    continue
                for vuln in entry.get("vulns") or []:
                    if not isinstance(vuln, dict):
                        continue
                    vid = vuln.get("id")
                    if not isinstance(vid, str):
                        continue
                    detail = self._osv_detail(vid)
                    advisory = self._osv_to_advisory(vid, detail, name,
                                                     osv_eco)
                    if not any(a.id == advisory.id
                               for a in result[(name, version)]):
                        result[(name, version)].append(advisory)
        return result

    def _osv_detail(self, vuln_id: str) -> Optional[dict]:
        data = self._get("https://api.osv.dev/v1/vulns/%s"
                         % urllib.parse.quote(vuln_id), ADVISORY_TTL)
        return data if isinstance(data, dict) else None

    @staticmethod
    def _osv_to_advisory(vuln_id: str, detail: Optional[dict],
                         name: str, osv_eco: str) -> Advisory:
        advisory = Advisory(id=vuln_id,
                            url="https://osv.dev/vulnerability/%s" % vuln_id)
        if not detail:
            return advisory
        advisory.summary = str(detail.get("summary") or "")[:200]

        # Prefer the GHSA alias as the primary id: it's what people paste into
        # a waiver and what the advisory pages are keyed on.
        for alias in detail.get("aliases") or []:
            if isinstance(alias, str) and alias.startswith("GHSA-"):
                advisory.id = alias
                advisory.url = "https://github.com/advisories/%s" % alias
                break

        severity = ""
        db = detail.get("database_specific")
        if isinstance(db, dict) and isinstance(db.get("severity"), str):
            severity = db["severity"]
        for sev in detail.get("severity") or []:
            if isinstance(sev, dict) and isinstance(sev.get("score"), str):
                advisory.cvss = sev["score"]
                if not severity:
                    severity = _severity_from_cvss(sev["score"])
        advisory.severity = severity.lower() or "unknown"

        cwes = [c for c in (detail.get("database_specific") or {}).get("cwe_ids", [])
                if isinstance(c, str)] if isinstance(db, dict) else []
        if cwes:
            advisory.cwe = cwes[0]

        advisory.fixed = _osv_fixed_version(detail, name, osv_eco)
        return advisory

    # -- GitHub ------------------------------------------------------------

    def _github_advisories(self, ecosystem: str, deps, result):
        gh_eco = GITHUB_ECOSYSTEMS.get(ecosystem)
        if gh_eco is None:
            return result
        headers = {"X-GitHub-Api-Version": "2022-11-28"}
        if self.token:
            headers["Authorization"] = "Bearer %s" % self.token
        for i in range(0, len(deps), self.BATCH):
            batch = deps[i:i + self.BATCH]
            affects = ",".join("%s@%s" % (n, v) for n, v in batch)
            url = ("https://api.github.com/advisories?ecosystem=%s"
                   "&affects=%s&per_page=100"
                   % (gh_eco, urllib.parse.quote(affects, safe=",@")))
            data = self._get(url, ADVISORY_TTL, headers=headers)
            if data is None:
                self._mark_dead(ecosystem, "the GitHub Advisory API")
                return result
            if not isinstance(data, list):
                continue
            self._match_advisories(data, batch, result, ecosystem)
        return result

    @staticmethod
    def _match_advisories(advisories: List[dict],
                          batch: List[Tuple[str, str]],
                          result: Dict[Tuple[str, str], List[Advisory]],
                          ecosystem: str) -> None:
        by_name: Dict[str, List[Tuple[str, str]]] = {}
        for name, version in batch:
            by_name.setdefault(name.lower(), []).append((name, version))
        for adv in advisories:
            if not isinstance(adv, dict):
                continue
            ghsa = adv.get("ghsa_id")
            if not isinstance(ghsa, str):
                continue
            severity = str(adv.get("severity") or "unknown").lower()
            cvss = None
            if isinstance(adv.get("cvss"), dict):
                cvss = adv["cvss"].get("vector_string")
            cwe = None
            cwes = adv.get("cwes")
            if isinstance(cwes, list) and cwes and isinstance(cwes[0], dict):
                cwe = cwes[0].get("cwe_id")
            for vuln in adv.get("vulnerabilities") or []:
                if not isinstance(vuln, dict):
                    continue
                pkg = (vuln.get("package") or {}).get("name", "")
                rng = vuln.get("vulnerable_version_range") or ""
                fixed = vuln.get("first_patched_version")
                if isinstance(fixed, dict):
                    fixed = fixed.get("identifier")
                for name, version in by_name.get(str(pkg).lower(), []):
                    if not versions.satisfies(version, rng, ecosystem):
                        continue
                    entries = result[(name, version)]
                    if any(e.id == ghsa for e in entries):
                        continue
                    entries.append(Advisory(
                        id=ghsa, severity=severity,
                        fixed=fixed if isinstance(fixed, str) else None,
                        summary=str(adv.get("summary") or "")[:200],
                        cvss=cvss if isinstance(cvss, str) else None,
                        cwe=cwe if isinstance(cwe, str) else None,
                        url="https://github.com/advisories/%s" % ghsa))


def _severity_from_cvss(vector_or_score: str) -> str:
    """Coarse severity from a CVSS vector or numeric score."""
    m = re.search(r"(\d+(?:\.\d+)?)\s*$", vector_or_score.strip())
    if not m:
        return ""
    try:
        score = float(m.group(1))
    except ValueError:
        return ""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return ""


def _osv_fixed_version(detail: dict, name: str, osv_eco: str) -> Optional[str]:
    """Lowest "fixed" bound OSV gives for this package.

    OSV ranges are (introduced, fixed) event pairs. The lowest fixed version
    across the ranges is the upgrade to recommend.
    """
    best: Optional[str] = None
    for affected in detail.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        pkg = affected.get("package")
        if isinstance(pkg, dict):
            if pkg.get("ecosystem") not in (osv_eco, None):
                continue
            if str(pkg.get("name", "")).lower() != name.lower():
                continue
        for rng in affected.get("ranges") or []:
            if not isinstance(rng, dict):
                continue
            for event in rng.get("events") or []:
                if not isinstance(event, dict):
                    continue
                fixed = event.get("fixed")
                if not isinstance(fixed, str) or not fixed:
                    continue
                eco = _osv_language(osv_eco)
                if best is None or versions.compare(fixed, best, eco) < 0:
                    best = fixed
    return best


_OSV_TO_LANGUAGE = {v: k for k, v in OSV_ECOSYSTEMS.items()}


def _osv_language(osv_eco: str) -> str:
    return _OSV_TO_LANGUAGE.get(osv_eco, "npm")
