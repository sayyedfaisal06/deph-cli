"""Policy evaluation: a parsed Document in, findings out.

Four rules that are easy to get wrong, so they're stated here and pinned by
tests in tests/test_policy.py:

- A vulnerability is judged once, at the strongest matching action. A high
  vuln matches both `fail vuln >= high` and `warn vuln >= low`; it must
  produce one fail, not a fail plus a warn.
- Unknown severities rank below `low` and match no threshold. They never
  raise.
- An SPDX allowlist is satisfied by any alternative of an OR-expression, and
  by every part of an AND-expression.
- A waived finding is still reported, at level `waived`, and never fails.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional

from . import spdx
from .parser import (Document, Dep, PolicyRule, Project, VULN_LEVELS,
                     LAG_LEVELS, COMPARATORS)

# The REST advisory API says "medium"; GraphQL and the web UI say "moderate".
SEVERITY_ALIASES = {"moderate": "medium"}

FAIL = "fail"
WARN = "warn"
WAIVED = "waived"

_LEVEL_ORDER = {WARN: 1, FAIL: 2}


def normalize_severity(value: str) -> str:
    v = (value or "").strip().lower()
    return SEVERITY_ALIASES.get(v, v)


def severity_rank(value: str) -> int:
    # -1 for anything unrecognized, so it matches no threshold.
    try:
        return VULN_LEVELS.index(normalize_severity(value))
    except ValueError:
        return -1


def lag_rank(value: str) -> int:
    try:
        return LAG_LEVELS.index((value or "").strip().lower())
    except ValueError:
        return -1


def _compare(rank: int, op: str, threshold: int) -> bool:
    if rank < 0 or threshold < 0:
        return False
    if op == ">=":
        return rank >= threshold
    if op == ">":
        return rank > threshold
    if op == "<=":
        return rank <= threshold
    if op == "<":
        return rank < threshold
    if op == "==":
        return rank == threshold
    if op == "!=":
        return rank != threshold
    return False


def license_allowed(expr: str, allowlist: List[str]) -> bool:
    return spdx.satisfies(expr, allowlist)


def license_in(expr: str, denylist: List[str]) -> bool:
    return spdx.any_of(expr, denylist)


def license_alternatives(expr: str) -> List[List[str]]:
    """Kept for callers that want the flattened AND-groups of OR-alternatives."""
    return spdx.and_groups(expr)


@dataclass
class Finding:
    project: str
    dep: str
    version: str
    kind: str                    # "vuln" | "lag" | "license" | "unresolved"
    level: str                   # "fail" | "warn" | "waived"
    id: str                      # GHSA id, else lag:<name> / license:<name>
    message: str
    detail: str = ""             # severity, lag level, or license expression
    transitive: bool = False
    dev: bool = False
    fix: Optional[str] = None    # lowest version that clears this finding
    url: Optional[str] = None    # advisory page, when there is one
    cvss: Optional[str] = None
    cwe: Optional[str] = None
    waived_reason: Optional[str] = None
    waiver_expired: bool = False

    def to_dict(self) -> Dict[str, object]:
        return {
            "project": self.project,
            "dep": self.dep,
            "version": self.version,
            "kind": self.kind,
            "level": self.level,
            "id": self.id,
            "detail": self.detail,
            "message": self.message,
            "transitive": self.transitive,
            "dev": self.dev,
            "fix": self.fix,
            "url": self.url,
            "cvss": self.cvss,
            "cwe": self.cwe,
            "waived_reason": self.waived_reason,
            "waiver_expired": self.waiver_expired,
        }


def _strongest_action(candidates: List[str]) -> Optional[str]:
    best = None
    for action in candidates:
        if best is None or _LEVEL_ORDER.get(action, 0) > _LEVEL_ORDER.get(best, 0):
            best = action
    return best


def _rules_for(rules: List[PolicyRule], subject: str, dep: Dep,
               ops=COMPARATORS) -> List[PolicyRule]:
    direct = not dep.transitive
    return [r for r in rules
            if r.subject == subject and r.op in ops
            and r.applies_to(direct=direct, dev=dep.dev)]


def _eval_vuln(rules: List[PolicyRule], dep: Dep, project: Project,
               waivers: Dict[str, "Waived"]) -> List[Finding]:
    findings = []
    vuln_rules = _rules_for(rules, "vuln", dep)
    for tag in dep.tags:
        if tag.kind != "vuln":
            continue
        sev = normalize_severity(tag.qualifier or "")
        rank = severity_rank(sev)
        # Once, at the strongest match: see the module docstring.
        matched = [r.action for r in vuln_rules
                   if _compare(rank, r.op, severity_rank(r.value))]
        action = _strongest_action(matched)
        if action is None:
            continue
        vuln_id = tag.ident or ("%s@%s" % (dep.name, dep.version))
        fix = dep.fix
        message = "%s %s has a %s severity vulnerability (%s)" % (
            dep.name, dep.version, sev or "unknown", vuln_id)
        if fix:
            message += "; fixed in %s" % fix
        f = Finding(
            project=project.name, dep=dep.name, version=dep.version,
            kind="vuln", level=action, id=vuln_id, detail=sev or "unknown",
            message=message, transitive=dep.transitive, dev=dep.dev, fix=fix,
            url=advisory_url(vuln_id),
            cvss=dep.attrs.get("cvss"), cwe=dep.attrs.get("cwe"))
        _apply_waiver(f, waivers)
        findings.append(f)
    return findings


def advisory_url(vuln_id: str) -> Optional[str]:
    if vuln_id.startswith("GHSA-"):
        return "https://github.com/advisories/%s" % vuln_id
    if vuln_id.startswith(("CVE-", "PYSEC-", "RUSTSEC-", "GO-", "OSV-")):
        return "https://osv.dev/vulnerability/%s" % vuln_id
    return None


def _eval_lag(rules: List[PolicyRule], dep: Dep, project: Project,
              waivers: Dict[str, "Waived"]) -> List[Finding]:
    findings = []
    lag_rules = _rules_for(rules, "lag", dep)
    if not lag_rules:
        return findings
    for tag in dep.tags:
        if tag.kind != "lag":
            continue
        level = (tag.qualifier or "").lower()
        rank = lag_rank(level)
        matched = [r.action for r in lag_rules
                   if _compare(rank, r.op, lag_rank(r.value))]
        action = _strongest_action(matched)
        if action is None:
            continue
        f = Finding(
            project=project.name, dep=dep.name, version=dep.version,
            kind="lag", level=action, id="lag:%s" % dep.name, detail=level,
            message="%s is a %s version behind (%s -> %s)"
                    % (dep.name, level, dep.version, dep.latest or "?"),
            transitive=dep.transitive, dev=dep.dev, fix=dep.latest)
        _apply_waiver(f, waivers)
        findings.append(f)
    return findings


def _eval_license(rules: List[PolicyRule], dep: Dep, project: Project,
                  waivers: Dict[str, "Waived"]) -> List[Finding]:
    findings = []
    if not dep.license or dep.license.lower() in ("unknown", "none", ""):
        return findings
    matched: List[str] = []
    for rule in _rules_for(rules, "license", dep, ops=("not", "in")):
        if rule.op == "not" and not license_allowed(dep.license, rule.value):
            matched.append(rule.action)
        elif rule.op == "in" and license_in(dep.license, rule.value):
            matched.append(rule.action)
    action = _strongest_action(matched)
    if action is None:
        return findings
    detail = dep.license
    if not spdx.is_valid(detail):
        detail = "%s (unrecognized)" % dep.license
    f = Finding(
        project=project.name, dep=dep.name, version=dep.version,
        kind="license", level=action, id="license:%s" % dep.name,
        detail=detail,
        message="%s %s has disallowed license %r"
                % (dep.name, dep.version, dep.license),
        transitive=dep.transitive, dev=dep.dev)
    _apply_waiver(f, waivers)
    findings.append(f)
    return findings


def _eval_unresolved(rules: List[PolicyRule], project: Project,
                     waivers: Dict[str, "Waived"]) -> List[Finding]:
    """One finding per project when too many lines couldn't be pinned.

    This is the check that stops a scan from shrinking silently: a
    requirements.txt of six ranges used to audit as an empty, clean project.
    """
    count = len(project.unresolved)
    if not count:
        return []
    matched = [r.action for r in rules
               if r.subject == "unresolved" and r.op in COMPARATORS
               and str(r.value).isdigit()
               and _compare_counts(count, r.op, int(r.value))]
    action = _strongest_action(matched)
    if action is None:
        return []
    by_reason: Dict[str, int] = {}
    for entry in project.unresolved:
        by_reason[entry.reason] = by_reason.get(entry.reason, 0) + 1
    breakdown = ", ".join("%d %s" % (n, reason)
                          for reason, n in sorted(by_reason.items()))
    f = Finding(
        project=project.name, dep="", version="", kind="unresolved",
        level=action, id="unresolved:%s" % project.name, detail=str(count),
        message="%d dependenc%s in %s could not be pinned to a version "
                "and were not audited (%s)"
                % (count, "y" if count == 1 else "ies", project.manifest
                   or project.name, breakdown))
    _apply_waiver(f, waivers)
    return [f]


def _compare_counts(count: int, op: str, threshold: int) -> bool:
    if op == ">=":
        return count >= threshold
    if op == ">":
        return count > threshold
    if op == "<=":
        return count <= threshold
    if op == "<":
        return count < threshold
    if op == "==":
        return count == threshold
    if op == "!=":
        return count != threshold
    return False


@dataclass
class Waived:
    reason: str
    expired: bool = False


def _apply_waiver(finding: Finding, waivers: Dict[str, "Waived"]) -> None:
    waived = waivers.get(finding.id)
    if waived is None:
        return
    if waived.expired:
        # The waiver is still in the file, but its date has passed, so the
        # finding counts again. Flagged so `check` can say why it came back.
        finding.waiver_expired = True
        finding.waived_reason = waived.reason
        return
    finding.level = WAIVED
    finding.waived_reason = waived.reason


def today_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def evaluate(doc: Document, today: Optional[str] = None) -> List[Finding]:
    today = today or today_utc()
    waivers = {w.id: Waived(w.reason, w.expired(today)) for w in doc.waivers}
    findings: List[Finding] = []
    for project in doc.projects:
        for dep in project.deps:
            findings.extend(_eval_vuln(doc.policy, dep, project, waivers))
            findings.extend(_eval_lag(doc.policy, dep, project, waivers))
            findings.extend(_eval_license(doc.policy, dep, project, waivers))
        findings.extend(_eval_unresolved(doc.policy, project, waivers))
    return findings


def exit_code(findings: List[Finding]) -> int:
    return 1 if any(f.level == FAIL for f in findings) else 0


@dataclass
class Summary:
    fail: int = 0
    warn: int = 0
    waived: int = 0

    @classmethod
    def of(cls, findings: List[Finding]) -> "Summary":
        s = cls()
        for f in findings:
            if f.level == FAIL:
                s.fail += 1
            elif f.level == WARN:
                s.warn += 1
            elif f.level == WAIVED:
                s.waived += 1
        return s


# Grades for the dashboard. The weights are a judgement call, not a standard:
# one critical vuln should visibly sink a project, stale minors shouldn't.
_VULN_PENALTY = {"critical": 30, "high": 20, "medium": 10, "low": 4}
_LAG_PENALTY = {"major": 5, "minor": 2, "patch": 1, "prerelease": 1}
_LICENSE_PENALTY = 15
_UNRESOLVED_PENALTY = 3        # per unpinned dependency, capped below


def project_score(project: Project, findings: List[Finding]) -> int:
    """0-100. Waived findings cost nothing: that's the point of a waiver."""
    score = 100
    for f in findings:
        if f.project != project.name or f.level == WAIVED:
            continue
        if f.kind == "vuln":
            score -= _VULN_PENALTY.get(f.detail, 4)
        elif f.kind == "lag":
            score -= _LAG_PENALTY.get(f.detail, 1)
        elif f.kind == "license":
            score -= _LICENSE_PENALTY
        elif f.kind == "unresolved":
            # Capped: a project we mostly couldn't read should look bad, but
            # unpinned deps aren't known vulnerabilities.
            count = int(f.detail) if f.detail.isdigit() else 1
            score -= min(20, count * _UNRESOLVED_PENALTY)
    return max(0, score)


def coverage(project: Project) -> float:
    """Share of this project's dependencies deph could actually audit.

    Shown in the dashboard so a project with a high grade and low coverage
    can't be mistaken for a clean one.
    """
    total = len(project.deps) + len(project.unresolved)
    if not total:
        return 1.0
    return len(project.deps) / float(total)


def grade_for_score(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"
