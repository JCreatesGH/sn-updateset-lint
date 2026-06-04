"""CLI: `usetlint update_set.xml` (lint) or `usetlint a.xml b.xml` (diff)."""
from __future__ import annotations
import sys
from .parse import parse_update_set
from .lint import lint, SEVERITY
from .diff import diff_update_sets

COLORS = {"high": "\033[31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[2m"}
RESET = "\033[0m"


def main(argv=None):
    argv = argv or sys.argv[1:]
    if not argv:
        print("usage: usetlint <update_set.xml> [other.xml]"); return 2
    changes = parse_update_set(open(argv[0]).read())
    if len(argv) >= 2:
        d = diff_update_sets(changes, parse_update_set(open(argv[1]).read()))
        for k in ("added", "removed", "changed"):
            print(f"{k}: {len(d[k])}")
            for name in d[k]:
                print(f"  {name}")
        return 0
    findings = lint(changes)
    print(f"{len(changes)} changes, {len(findings)} findings\n")
    for f in findings:
        c = COLORS.get(f.severity, "")
        print(f"  {c}[{f.severity.upper():6}]{RESET} {f.rule}: {f.message}\n           ({f.change})")
    high = sum(1 for f in findings if f.severity == "high")
    return 1 if high else 0


if __name__ == "__main__":
    sys.exit(main())
