"""Diff two Update Sets by change name, and risk-lint what a promotion introduces."""
from __future__ import annotations
from typing import Dict, List
from .parse import Change
from .lint import lint, Finding


def _sig(c: Change):
    # An entry is "changed" if any of these differ — not just the payload, so a
    # flip to DELETE or a retarget to another table is no longer missed.
    return (c.action, c.type, c.target, c.payload)


def diff_update_sets(old: List[Change], new: List[Change]) -> Dict[str, List[str]]:
    o = {c.name: c for c in old}
    n = {c.name: c for c in new}
    added = [name for name in n if name not in o]
    removed = [name for name in o if name not in n]
    changed = [name for name in n if name in o and _sig(n[name]) != _sig(o[name])]
    return {"added": sorted(added), "removed": sorted(removed), "changed": sorted(changed)}


def lint_diff(old: List[Change], new: List[Change]) -> List[Finding]:
    """Lint only the entries a promotion introduces or modifies (added + changed),
    so review focuses on *new* risk rather than re-flagging what already shipped."""
    d = diff_update_sets(old, new)
    touched = set(d["added"]) | set(d["changed"])
    by_name = {c.name: c for c in new}
    return lint([by_name[name] for name in sorted(touched) if name in by_name])
