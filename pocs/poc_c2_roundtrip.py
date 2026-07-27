#!/usr/bin/env python3
"""C2: the writer emits unquoted dep names/versions, so `deph scan` can produce
a .deph file it cannot re-parse. A hostile lockfile key `node_modules/foo bar`
yields the dep name `foo bar`. Prints PASS if the rendered output fails to
round-trip.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from deph import parser  # noqa: E402
from deph.parser import Dep, Document, Project  # noqa: E402

doc = Document(header_text="", has_generated_section=True)
doc.projects = [Project(name="p", ecosystem="npm",
                        deps=[Dep(name="foo bar", version="1.0.0")])]
out = parser.render(doc, timestamp="t")
print("rendered:\n", out)

try:
    parser.parse(out)
    print("FAIL: round-tripped cleanly")
except parser.DephSyntaxError as e:
    print("re-parse error:", e)
    print("PASS: deph wrote a .deph file it cannot read back")
