"""CLI: `usetlint update_set.xml` (lint) or `usetlint a.xml b.xml` (diff)."""
from __future__ import annotations
import argparse
import json
import sys
from dataclasses import asdict
from xml.etree.ElementTree import ParseError

from .parse import parse_update_set
from .lint import lint, Finding, SEVERITY
from .diff import diff_update_sets, lint_diff

COLORS = {"high": "\033[31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[2m"}
RESET = "\033[0m"


def _load(path: str):
    with open(path, encoding="utf-8") as fh:
        return parse_update_set(fh.read())


def _exit_code(findings: list, fail_on: str) -> int:
    if fail_on == "none":
        return 0
    worst = max((SEVERITY[f.severity] for f in findings), default=-1)
    return 1 if worst >= SEVERITY[fail_on] else 0


def _print_findings(findings: list, min_sev: str, color: bool):
    for f in findings:
        if SEVERITY[f.severity] < SEVERITY[min_sev]:
            continue
        c = COLORS.get(f.severity, "") if color else ""
        reset = RESET if color else ""
        print(f"  {c}[{f.severity.upper():6}]{reset} {f.rule}: {f.message}\n           ({f.change})")


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="usetlint",
        description="Diff and risk-lint ServiceNow Update Set XML exports.",
    )
    p.add_argument("files", nargs="+", metavar="XML",
                   help="one update set to lint, or two to diff (old new)")
    p.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    p.add_argument("--min-severity", choices=["info", "low", "medium", "high"], default="info",
                   help="hide findings below this severity (default: info)")
    p.add_argument("--fail-on", choices=["none", "low", "medium", "high"], default="high",
                   help="exit 1 when a finding at/above this severity exists (default: high)")
    args = p.parse_args(argv)

    if len(args.files) > 2:
        print("usetlint: expected one or two XML files", file=sys.stderr)
        return 2

    try:
        changes = _load(args.files[0])
        other = _load(args.files[1]) if len(args.files) == 2 else None
    except (OSError, ParseError) as e:
        print(f"usetlint: {e}", file=sys.stderr)
        return 2

    color = sys.stdout.isatty()

    if other is not None:                       # diff mode
        d = diff_update_sets(changes, other)
        findings = lint_diff(changes, other)
        if args.json:
            print(json.dumps({"diff": d, "findings": [asdict(f) for f in findings]}, indent=2))
        else:
            for k in ("added", "removed", "changed"):
                print(f"{k}: {len(d[k])}")
                for name in d[k]:
                    print(f"  {name}")
            shown = [f for f in findings if SEVERITY[f.severity] >= SEVERITY[args.min_severity]]
            print(f"\nnew/changed risk: {len(shown)} findings")
            _print_findings(findings, args.min_severity, color)
        return _exit_code(findings, args.fail_on)

    # lint mode
    findings = lint(changes)
    if args.json:
        print(json.dumps({"changes": len(changes), "findings": [asdict(f) for f in findings]}, indent=2))
    else:
        shown = [f for f in findings if SEVERITY[f.severity] >= SEVERITY[args.min_severity]]
        print(f"{len(changes)} changes, {len(shown)} findings\n")
        _print_findings(findings, args.min_severity, color)
    return _exit_code(findings, args.fail_on)


if __name__ == "__main__":
    sys.exit(main())
