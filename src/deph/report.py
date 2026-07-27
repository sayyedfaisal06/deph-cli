"""Machine-readable output: SARIF for code scanning, CycloneDX for SBOMs.

Both are hand-built dicts. The schemas are stable and small enough that a
dependency would buy nothing.
"""

import json
import os
import urllib.parse
from typing import Dict, List, Optional

from . import __version__, policy
from .parser import Dep, Document, Project

SARIF_SCHEMA = ("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
                "master/Schemata/sarif-schema-2.1.0.json")
TOOL_URL = "https://github.com/sayyedfaisal06/deph-cli"

# SARIF only has error/warning/note/none, so waived findings become notes: they
# stay visible in code scanning without failing anything.
_SARIF_LEVEL = {policy.FAIL: "error", policy.WARN: "warning",
                policy.WAIVED: "note"}

# PURL type per ecosystem, for CycloneDX component identity.
_PURL_TYPE = {"npm": "npm", "pip": "pypi", "cargo": "cargo", "go": "golang",
              "gem": "gem", "composer": "composer"}


def purl(ecosystem: str, name: str, version: str) -> str:
    """A Package URL, which is how every SBOM consumer matches components.

    Each path segment is percent-encoded on its own and the segments are
    rejoined with `/`. That matches the canonical form in the purl spec's test
    suite, which requires both halves of this:

        pkg:npm/%40angular/animation@12.3.1     the scope's @ is encoded
        pkg:golang/rsc.io/quote@v1.5.2          the path's / is not

    Encoding matters beyond tidiness: `#` and `?` delimit a purl's subpath and
    qualifiers, so an unescaped one in a name silently truncates the identifier
    that consumers match on.
    """
    kind = _PURL_TYPE.get(ecosystem, ecosystem or "generic")
    path = "/".join(_quote(part) for part in name.split("/"))
    return "pkg:%s/%s@%s" % (kind, path, _quote(version))


def _quote(segment: str) -> str:
    # Unreserved characters only. `+` is left alone because it appears in
    # semver build metadata constantly and every consumer handles it.
    return urllib.parse.quote(segment, safe=".-_~+")


# ---------------------------------------------------------------------------
# SARIF
# ---------------------------------------------------------------------------


def _rule_id(finding: policy.Finding) -> str:
    # Grouped by kind rather than per-advisory, so code scanning shows one
    # rule per class of problem instead of thousands of one-off rules.
    return "deph/%s" % finding.kind


def _rules(findings: List[policy.Finding]) -> List[dict]:
    descriptions = {
        "vuln": "A dependency version with a known published advisory.",
        "lag": "A dependency behind its latest released version.",
        "license": "A dependency whose license the policy disallows.",
        "unresolved": ("A dependency that could not be pinned to a single "
                       "version, and so was not audited."),
    }
    kinds = sorted({f.kind for f in findings})
    return [{
        "id": "deph/%s" % kind,
        "name": "deph.%s" % kind,
        "shortDescription": {"text": descriptions.get(kind, kind)},
        "fullDescription": {"text": descriptions.get(kind, kind)},
        "helpUri": TOOL_URL,
        "defaultConfiguration": {"level": "warning"},
    } for kind in kinds]


def sarif(doc: Document, findings: Optional[List[policy.Finding]] = None,
          deph_file: Optional[str] = None) -> dict:
    findings = policy.evaluate(doc) if findings is None else findings
    path = deph_file or doc.path
    # SARIF wants a repo-relative URI with forward slashes.
    uri = os.path.relpath(path).replace(os.sep, "/")

    manifest_of = {p.name: p.manifest for p in doc.projects}
    results = []
    for f in findings:
        line = _find_line(doc, f)
        result = {
            "ruleId": _rule_id(f),
            "level": _SARIF_LEVEL.get(f.level, "warning"),
            "message": {"text": f.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": max(1, line)},
                },
            }],
            "partialFingerprints": {
                # Stable across scans so code scanning can track a finding
                # rather than reporting it as new every run.
                "dephFindingId": "%s/%s/%s" % (f.project, f.dep or "-", f.id),
            },
            "properties": {
                "project": f.project,
                "manifest": manifest_of.get(f.project, ""),
                "dependency": f.dep,
                "version": f.version,
                "kind": f.kind,
                "detail": f.detail,
                "transitive": f.transitive,
                "dev": f.dev,
            },
        }
        if f.fix:
            result["properties"]["fixedIn"] = f.fix
        if f.cvss:
            result["properties"]["cvss"] = f.cvss
        if f.cwe:
            result["properties"]["cwe"] = f.cwe
        if f.url:
            result["properties"]["advisory"] = f.url
        if f.waived_reason:
            result["properties"]["waivedReason"] = f.waived_reason
        results.append(result)

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "deph",
                "version": __version__,
                "informationUri": TOOL_URL,
                "rules": _rules(findings),
            }},
            "results": results,
        }],
    }


def _find_line(doc: Document, finding: policy.Finding) -> int:
    """Point at the dep line that produced this finding, so annotations land
    on the right row of the .deph file."""
    for project in doc.projects:
        if project.name != finding.project:
            continue
        if finding.kind == "unresolved":
            return project.unresolved[0].line if project.unresolved else project.line
        for dep in project.deps:
            if dep.name == finding.dep and dep.version == finding.version:
                return dep.line
        return project.line
    return 1


# ---------------------------------------------------------------------------
# CycloneDX
# ---------------------------------------------------------------------------


def _component(project: Project, dep: Dep) -> dict:
    ref = purl(project.ecosystem, dep.name, dep.version)
    component: Dict[str, object] = {
        "type": "library",
        "bom-ref": ref,
        "name": dep.name,
        "version": dep.version,
        "purl": ref,
        "scope": "optional" if dep.dev else "required",
    }
    if dep.license:
        # CycloneDX wants either a known id or a free-text expression; we
        # can't tell which without an id list, so expression is the safe field.
        component["licenses"] = [{"expression": dep.license}]
    properties = [{"name": "deph:project", "value": project.name}]
    if project.manifest:
        properties.append({"name": "deph:manifest", "value": project.manifest})
    properties.append({"name": "deph:direct",
                       "value": "false" if dep.transitive else "true"})
    component["properties"] = properties
    return component


def cyclonedx(doc: Document, findings: Optional[List[policy.Finding]] = None,
              timestamp: Optional[str] = None) -> dict:
    """CycloneDX 1.5 BOM with a vulnerabilities section.

    Components come from the file, not a fresh scan, so an SBOM always matches
    the .deph that was reviewed.
    """
    findings = policy.evaluate(doc) if findings is None else findings

    components = []
    for project in sorted(doc.projects, key=lambda p: p.name):
        for dep in project.deps:
            components.append(_component(project, dep))

    ref_of: Dict[str, str] = {}
    for project in doc.projects:
        for dep in project.deps:
            ref_of["%s\0%s\0%s" % (project.name, dep.name, dep.version)] = \
                purl(project.ecosystem, dep.name, dep.version)

    vulnerabilities = []
    for f in findings:
        if f.kind != "vuln":
            continue
        ref = ref_of.get("%s\0%s\0%s" % (f.project, f.dep, f.version))
        entry: Dict[str, object] = {
            "bom-ref": "%s/%s" % (f.id, f.dep),
            "id": f.id,
            "ratings": [{"severity": _cdx_severity(f.detail)}],
            "description": f.message,
            "affects": [{"ref": ref}] if ref else [],
        }
        if f.url:
            entry["source"] = {"name": "deph", "url": f.url}
        if f.cwe:
            digits = "".join(c for c in f.cwe if c.isdigit())
            if digits:
                entry["cwes"] = [int(digits)]
        if f.cvss:
            entry["ratings"] = [{"severity": _cdx_severity(f.detail),
                                 "vector": f.cvss}]
        if f.fix:
            entry["recommendation"] = "Upgrade %s to %s" % (f.dep, f.fix)
        if f.level == policy.WAIVED:
            entry["analysis"] = {
                "state": "not_affected",
                "justification": "protected_by_mitigating_control",
                "detail": f.waived_reason or "waived in the .deph policy",
            }
        vulnerabilities.append(entry)

    metadata: Dict[str, object] = {
        "tools": [{"vendor": "deph", "name": "deph", "version": __version__}],
        "component": {
            "type": "application",
            "bom-ref": "deph:root",
            "name": os.path.basename(os.path.dirname(os.path.abspath(doc.path)))
                    or "repository",
        },
    }
    if timestamp:
        metadata["timestamp"] = timestamp

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": metadata,
        "components": components,
        "vulnerabilities": vulnerabilities,
    }


_CDX_SEVERITY = {"critical": "critical", "high": "high", "medium": "medium",
                 "low": "low"}


def _cdx_severity(detail: str) -> str:
    return _CDX_SEVERITY.get((detail or "").lower(), "unknown")


def dumps(payload: dict) -> str:
    return json.dumps(payload, indent=2, sort_keys=True)
