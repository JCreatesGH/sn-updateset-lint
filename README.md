# usetlint — ServiceNow Update Set linter

[![CI](https://github.com/JCreatesGH/sn-updateset-lint/actions/workflows/ci.yml/badge.svg)](https://github.com/JCreatesGH/sn-updateset-lint/actions)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Review ServiceNow **Update Sets** before you promote them. `usetlint` parses an exported Update Set (unload XML), flags risky changes, and diffs two sets so code review isn't a guessing game. Zero runtime dependencies — drops straight into CI.

![screenshot](assets/screenshot.png)

## Install

```bash
pip install usetlint
```

## Lint a set

```bash
usetlint promote_to_prod.xml
```

It reports findings by severity and **exits non-zero on any HIGH finding** (tune with `--fail-on {none,low,medium,high}`), so a pipeline can block a risky promotion:

```yaml
- run: pip install usetlint && usetlint update_set.xml
```

Other flags: `--json` (machine-readable for CI), `--min-severity {info,low,medium,high}` (hide noise).

## Diff two sets

```bash
usetlint old.xml new.xml      # added / removed / changed by record
```

The diff also **risk-lints only what the promotion introduces** — the added and changed entries — so review focuses on *new* risk instead of re-flagging what already shipped. Exit code gates on those new findings. A change is detected on any of action / type / target / payload (so a flip to `DELETE` or a retarget is never missed).

## Rules

| Severity | Rule | Catches |
|----------|------|---------|
| HIGH | `global-business-rule` | Business Rules with no/global target table |
| HIGH | `acl-change` | Modified `sys_security_acl` records |
| HIGH | `dynamic-eval` | `gs.eval` / `new Function` injection smells |
| HIGH | `mass-delete` | `deleteMultiple()` in promoted code — can wipe a whole table |
| MEDIUM | `record-delete` | DELETE actions riding along in a promotion |
| MEDIUM | `hardcoded-reference` | Hardcoded instance URLs / credential-like strings |
| MEDIUM | `current-update-in-br` | `current.update()` inside a Business Rule (recursion risk) |
| MEDIUM | `scheduled-job` | Scheduled jobs/scripts that run automatically once promoted |
| MEDIUM | `data-record` | instance data (users, groups, CIs, tickets) shipped as config |
| MEDIUM | `property-change` | a `sys_properties` change that flips behavior/security instance-wide |
| LOW | `setworkflow-false` | `setWorkflow(false)` silently skipping business rules |
| INFO | `debug-logging` | Leftover `console.log` / `gs.print` debug statements |

## Library

```python
from usetlint import parse_update_set, lint, diff_update_sets, lint_diff
findings = lint(parse_update_set(open("set.xml").read()))
new_risk = lint_diff(old_changes, new_changes)   # only added/changed entries
```

## Development

```bash
pip install -e .[dev] && python -m pytest -q   # 20 tests
```

## License

MIT
