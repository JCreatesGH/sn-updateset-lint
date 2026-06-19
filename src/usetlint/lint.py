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


# Instance *data* tables that almost never belong in a promoted Update Set (config only).
_DATA_TABLES = {"sys_user", "sys_user_group", "sys_user_role", "sys_user_grmember",
                "incident", "problem", "change_request", "task", "sc_request", "sc_req_item",
                "kb_knowledge", "sys_email"}


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

        # current.update() inside a Business Rule re-triggers rules — classic recursion footgun.
        if "business rule" in t and _has(c.payload, "current.update("):
            findings.append(Finding("medium", "current-update-in-br", c.name,
                "current.update() inside a Business Rule can recurse — set fields and let the engine save."))

        # Scheduled jobs run automatically once promoted.
        if "scheduled" in t:
            findings.append(Finding("medium", "scheduled-job", c.name,
                "Scheduled job/script runs automatically — verify its schedule and active state."))

        # setWorkflow(false) skips business rules silently.
        if _has(c.payload, "setworkflow(false)"):
            findings.append(Finding("low", "setworkflow-false", c.name,
                "setWorkflow(false) suppresses business rules — make sure that is deliberate."))

        # Leftover debug-only logging that does nothing useful in prod.
        if _has(c.payload, "console.log(", "gs.print("):
            findings.append(Finding("info", "debug-logging", c.name,
                "Leftover debug logging (console.log / gs.print) in promoted code."))

        # A GlideRecord.deleteMultiple() in promoted code can wipe a whole table.
        if _has(c.payload, "deletemultiple("):
            findings.append(Finding("high", "mass-delete", c.name,
                "deleteMultiple() in promoted code can delete every matching record — verify the query is scoped."))

        # Instance data records (users, groups, CIs, tickets) usually shouldn't ride a promotion.
        table = c.table.lower()
        if table in _DATA_TABLES or table.startswith("cmdb_ci"):
            findings.append(Finding("medium", "data-record", c.name,
                f"Carries an instance data record ('{c.table}') — promote configuration, not data."))

        # System property changes can flip behavior/security across the whole instance.
        if table == "sys_properties" or "property" in t:
            findings.append(Finding("medium", "property-change", c.name,
                "Changes a system property — it can alter behavior or security instance-wide on promotion."))

    findings.sort(key=lambda f: -SEVERITY[f.severity])
    return findings
