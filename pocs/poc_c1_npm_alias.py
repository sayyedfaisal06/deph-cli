#!/usr/bin/env python3
"""C1: npm aliased installs are audited under the alias, not the real package.

`"mychalk": "npm:chalk@^5"` appears in the lockfile as
`node_modules/mychalk` with `"name": "chalk"`. The scanner drops the real
name, so advisory/registry lookups query `mychalk` and miss chalk's CVEs.
Prints PASS if the real name is lost.
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from deph.scanners import npm  # noqa: E402

lock = {
    "lockfileVersion": 3,
    "packages": {
        "": {"dependencies": {"mychalk": "npm:chalk@^5.0.0"}},
        "node_modules/mychalk": {"name": "chalk", "version": "5.3.0"},
    },
}
p = tempfile.mktemp(suffix="package-lock.json")
open(p, "w").write(json.dumps(lock))

names = [d.name for d in npm.NpmScanner().scan(p)]
print("reported names:", names)
print("PASS: real name 'chalk' lost, aliased as 'mychalk'"
      if "chalk" not in names and "mychalk" in names
      else "FAIL: real name preserved")
