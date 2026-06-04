"""Heuristic risk rules for Update Set changes."""
from __future__ import annotations
from dataclasses import dataclass
from typing import List
from .parse import Change

SEVERITY = {"high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class Finding:
    severity: str
    rule: str
    change: str          # change name
    message: str


def _has(payload: str, *needles: str) -> bool:
    low = payload.lower()
    return any(n.lower() in low for n in needles)


def lint(changes: List[Change]) -> List[Finding]:
    findings: List[Finding] = []
    for c in changes:
        t = c.type.lower()

        # Global-scope business rules with no table filter run on every record op.
        if "business rule" in t and (not c.target or c.target.lower() == "global"):
            findings.append(Finding("high", "global-business-rule", c.name,
                "Business Rule has no/global target table — runs broadly and can hurt performance."))

        # ACL changes are security-sensitive.
        if "acl" in t or c.table == "sys_security_acl":
            findings.append(Finding("high", "acl-change", c.name,
                "Security ACL modified — review who can read/write the affected resource."))

        # Deletes are risky in a promoted set.
        if c.action.upper().startswith("DELETE"):
            findings.append(Finding("medium", "record-delete", c.name,
                f"Deletes a {c.type or 'record'} on promotion — confirm it is intended."))

        # Hardcoded instance URLs / credentials in script payloads.
        if _has(c.payload, "service-now.com", "password=", "gs.getProperty('glide.servlet"):
            findings.append(Finding("medium", "hardcoded-reference", c.name,
                "Payload contains a hardcoded instance URL or credential-like string."))

        # eval / gs.eval is a code-injection smell.
        if _has(c.payload, "gs.eval(", "GlideEvaluator", "new Function("):
            findings.append(Finding("high", "dynamic-eval", c.name,
                "Uses dynamic evaluation (gs.eval / new Function) — injection risk."))

        # setWorkflow(false) skips business rules silently.
        if _has(c.payload, "setworkflow(false)"):
            findings.append(Finding("low", "setworkflow-false", c.name,
                "setWorkflow(false) suppresses business rules — make sure that is deliberate."))

    findings.sort(key=lambda f: -SEVERITY[f.severity])
    return findings
