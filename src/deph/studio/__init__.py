"""Dashboard HTML, built from a parsed Document.

`deph studio` calls this per request and `deph render` calls it once. Same
output either way, which is why the served page works as a CI artifact.
"""

import json
import os

from .. import policy
from ..parser import Document

_TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), "template.html")


def build_payload(doc: Document) -> dict:
    findings = policy.evaluate(doc)
    by_dep = {}
    for f in findings:
        by_dep.setdefault((f.project, f.dep, f.version), []).append(f.to_dict())

    projects = []
    for proj in sorted(doc.projects, key=lambda p: p.name):
        score = policy.project_score(proj, findings)
        deps = []
        for dep in proj.deps:
            deps.append({
                "name": dep.name,
                "version": dep.version,
                "latest": dep.latest,
                "license": dep.license,
                "transitive": dep.transitive,
                "dev": dep.dev,
                "fix": dep.fix,
                "findings": by_dep.get((proj.name, dep.name, dep.version), []),
            })
        projects.append({
            "name": proj.name,
            "ecosystem": proj.ecosystem,
            "manifest": proj.manifest,
            "score": score,
            "grade": policy.grade_for_score(score),
            "coverage": round(policy.coverage(proj), 3),
            "deps": deps,
            "unresolved": [{"spec": u.spec, "reason": u.reason, "name": u.name}
                           for u in proj.unresolved],
        })

    summary = policy.Summary.of(findings)
    return {
        "file": os.path.basename(doc.path),
        "generated_at": doc.generated_at,
        "summary": {"fail": summary.fail, "warn": summary.warn,
                    "waived": summary.waived},
        "coverage": {
            "audited": sum(len(p.deps) for p in doc.projects),
            "unresolved": sum(len(p.unresolved) for p in doc.projects),
        },
        "policy": [{"action": r.action, "subject": r.subject, "op": r.op,
                    "value": r.value, "scopes": r.scopes} for r in doc.policy],
        "waivers": [{"id": w.id, "reason": w.reason, "until": w.until}
                    for w in doc.waivers],
        "projects": projects,
    }


def build_html(doc: Document) -> str:
    with open(_TEMPLATE_PATH, "r", encoding="utf-8") as f:
        template = f.read()
    # A "</" inside the JSON would close the <script> element early, so a
    # waiver reason containing "</script>" could otherwise inject markup.
    payload = json.dumps(build_payload(doc)).replace("</", "<\\/")
    return template.replace("__DEPH_PAYLOAD__", payload)
