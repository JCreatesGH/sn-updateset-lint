# Changelog

All notable changes are documented here, following
[Keep a Changelog](https://keepachangelog.com/) and [SemVer](https://semver.org/).

## [0.3.0]

### Added
- **`mass-delete`** (high) — flags `deleteMultiple()` in promoted code, which can wipe a whole
  table if its query isn't scoped.
- **`data-record`** (medium) — flags instance *data* records (users, groups, roles, CIs, tickets,
  `cmdb_ci*`) riding in an Update Set; promotions should carry configuration, not data.
- **`property-change`** (medium) — flags `sys_properties` changes that can alter behavior or
  security instance-wide on promotion.

## [0.2.0]

- Diff two Update Sets and risk-lint only the added/changed entries (`lint_diff`); change
  detection on action/type/target/payload. Rules: `global-business-rule`, `acl-change`,
  `dynamic-eval`, `record-delete`, `hardcoded-reference`, `current-update-in-br`, `scheduled-job`,
  `setworkflow-false`, `debug-logging`.

## [0.1.0]

- Initial release: parse exported Update Set XML, risk-lint a single set with severity-ranked
  findings, and a CLI that exits non-zero on HIGH findings (`--fail-on`, `--json`, `--min-severity`).
