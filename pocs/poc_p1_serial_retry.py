#!/usr/bin/env python3
"""P1: registry enrichment is serial and retries unboundedly with no
negative-cache. With a down registry, every dep pays 1+2+4=7s of backoff,
serially. Prints PASS if the projected blocking time is pathological.
Safe: time.sleep is stubbed (counted, not slept); no real network I/O.
"""
import os
import sys
import tempfile
import urllib.error

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from deph import enrich  # noqa: E402

slept = {"total": 0.0, "calls": 0}
enrich.time.sleep = lambda s: (slept.__setitem__("total", slept["total"] + s),
                               slept.__setitem__("calls", slept["calls"] + 1))


def boom(*a, **k):
    raise urllib.error.URLError("registry down")


# All deph HTTP goes through the enrich._urlopen seam.
enrich._urlopen = boom
enrich.urllib.request.urlopen = boom  # belt & braces for older revisions

c = enrich.Cache(os.path.join(tempfile.mkdtemp(prefix="deph-poc"), "c.db"))
e = enrich.Enricher(cache=c, offline=False)  # retries=3, backoff=1.0

N = 2000
for i in range(N):
    e.latest_and_license("pip", "pkg%d" % i)  # what cmd_scan does per dep

hours = slept["total"] / 3600
print("deps: %d   sleep() calls: %d   projected blocking: %.0fs (~%.1fh)"
      % (N, slept["calls"], slept["total"], hours))
print("PASS: serial + unbounded-retry path blocks for hours"
      if hours > 1 else "FAIL")
