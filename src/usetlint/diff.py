"""Diff two Update Sets by change name."""
from __future__ import annotations
from typing import Dict, List
from .parse import Change


def diff_update_sets(old: List[Change], new: List[Change]) -> Dict[str, List[str]]:
    o = {c.name: c for c in old}
    n = {c.name: c for c in new}
    added = [name for name in n if name not in o]
    removed = [name for name in o if name not in n]
    changed = [name for name in n if name in o and n[name].payload != o[name].payload]
    return {"added": sorted(added), "removed": sorted(removed), "changed": sorted(changed)}
