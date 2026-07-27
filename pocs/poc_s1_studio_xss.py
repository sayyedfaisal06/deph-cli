#!/usr/bin/env python3
"""S1: reflected XSS in the `deph studio` parse-error page.

A hostile .deph whose STRING token contains HTML is reflected unescaped into
the studio error response (server.py:27-30). Prints PASS if the vuln exists.
Safe: builds the response string in-process, starts no server.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from deph import parser  # noqa: E402
from deph.studio import server  # noqa: E402

PAYLOAD = "<img src=x onerror=alert(document.domain)>"
src = 'policy {\n  fail vuln >= high\n}\n"%s"\n' % PAYLOAD
p = tempfile.mktemp(suffix=".deph")
open(p, "w").write(src)

try:
    parser.parse_file(p)
    print("FAIL: file unexpectedly parsed clean")
except parser.DephSyntaxError as e:
    # The exact page the studio handler serves on a parse error.
    body = server._error_page(e)
    print("error page body:\n ", body)
    print("PASS: unescaped payload reflected into HTML" if PAYLOAD in body
          else "FAIL: payload not reflected (escaped)")
