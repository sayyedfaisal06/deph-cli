#!/usr/bin/env python3
"""C3: deeply nested lockfile / JSON raises RecursionError, which escapes
cmd_scan's `except (OSError, ValueError)` and crashes the whole scan.
Prints PASS if RecursionError (uncaught by that handler) is raised.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from deph.scanners import npm  # noqa: E402

CAUGHT = (OSError, ValueError)  # what cmd_scan actually catches


def check(label, text):
    p = tempfile.mktemp(suffix="package-lock.json")
    open(p, "w").write(text)
    try:
        npm.NpmScanner().scan(p)
        print("%s: FAIL (no error)" % label)
    except CAUGHT:
        print("%s: FAIL (caught by cmd_scan handler)" % label)
    except RecursionError:
        print("%s: PASS (RecursionError escapes handler -> scan crashes)" % label)


N = 4000
nested = ('{"dependencies":' + '{"x":{"version":"1.0.0","dependencies":' * N
          + '{}' + '}' * N + '}')
check("nested npm v1 lockfile", nested)
check("nested JSON array", "[" * 3000 + "]" * 3000)
