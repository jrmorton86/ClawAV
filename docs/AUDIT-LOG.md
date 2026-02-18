# Documentation Audit Log

> ℹ️ **This is an internal maintainer reference**, not a user-facing guide. It records errors found and fixed during documentation audits. Looking for user docs? See [INDEX.md](INDEX.md).

**Date:** 2025-07-25
**Auditor:** Claude (subagent docs-audit-1)
**Scope:** All source files in `src/` and `src/bin/` checked against all documentation files.

## Files Checked

### Source Files (20 modules + 1 binary)
`config.rs`, `main.rs`, `admin.rs`, `aggregator.rs`, `alerts.rs`, `api.rs`, `audit_chain.rs`, `auditd.rs`, `behavior.rs`, `cognitive.rs`, `falco.rs`, `firewall.rs`, `journald.rs`, `logtamper.rs`, `netpolicy.rs`, `network.rs`, `policy.rs`, `proxy.rs`, `samhain.rs`, `scanner.rs`, `barnacle.rs`, `sentinel.rs`, `slack.rs`, `tui.rs`, `update.rs`, `bin/clawsudo.rs`

### Documentation Files (12)
`CLAUDE.md`, `README.md`, `docs/ALERT-PIPELINE.md`, `docs/API.md`, `docs/ARCHITECTURE.md`, `docs/CLAWSUDO-AND-POLICY.md`, `docs/CONFIGURATION.md`, `docs/INSTALL.md`, `docs/MONITORING-SOURCES.md`, `docs/POLICIES.md`, `docs/SECURITY-SCANNERS.md`, `docs/SENTINEL.md`

## Errors Found & Fixed

### README.md
| # | Error | Fix |
|---|-------|-----|
| 1 | `clawtower admin keygen` — this CLI subcommand does not exist. Admin key is auto-generated on first run via `admin::init_admin_key()` | Replaced both occurrences with explanation of auto-generation |
| 2 | `clawtower --headless` — `--headless` is a flag on the `run` subcommand, not the root | Changed to `clawtower run --headless` |
| 3 | TUI described as having "scanner results" and "audit chain viewer" tabs — actual tabs are: Alerts, Network, Falco, FIM, System, Config | Updated to list the six actual tab names |
| 4 | `log_file = "/var/log/clawtower/audit.jsonl"` — misleading; this is ClawTower's own log, not audit JSONL | Changed to `"/var/log/clawtower/clawtower.log"` (matches CLAUDE.md example) |
| 5 | "Full configuration reference" link text said "YAML example" — config is TOML | Changed to "TOML example" |

### docs/API.md
| # | Error | Fix |
|---|-------|-----|
| 6 | Missing `/api/health` endpoint — exists in `api.rs` but was not documented | Added full endpoint documentation with example request/response |

### docs/ALERT-PIPELINE.md
| # | Error | Fix |
|---|-------|-----|
| 7 | Update module source tag listed as `"update"` — code uses `"auto-update"` | Changed to `"auto-update"` |

### docs/MONITORING-SOURCES.md
| # | Error | Fix |
|---|-------|-----|
| 8 | "How to Add a New Source" step 2 references `src/lib.rs` — project has no `lib.rs`, it's a binary crate | Changed to `src/main.rs` |

### CLAUDE.md
| # | Error | Fix |
|---|-------|-----|
| 9 | Module table says behavior.rs has "50+ patterns" — code and MONITORING-SOURCES.md say ~200 | Changed to "~200 patterns" |

## Verified Correct (no changes needed)

- **docs/CONFIGURATION.md** — All config field names, types, defaults, and required/optional markers match `src/config.rs` exactly
- **docs/SENTINEL.md** — All defaults (`debounce_ms: 200`, `scan_content: true`, `max_file_size_kb: 1024`, quarantine/shadow dirs) match code
- **docs/CLAWSUDO-AND-POLICY.md** — PolicyRule struct fields, MatchSpec fields, and clawsudo flow match `src/policy.rs` and `src/bin/clawsudo.rs`
- **docs/SECURITY-SCANNERS.md** — Scanner function names (`scan_audit_log_health`, `scan_cognitive_integrity`, `scan_barnacle_patterns`) and descriptions match `src/scanner.rs`, `src/cognitive.rs`, `src/barnacle.rs`
- **docs/POLICIES.md** — Policy YAML structure matches `PolicyFile`/`PolicyRule`/`MatchSpec` deserialization in `src/policy.rs`
- **docs/ARCHITECTURE.md** — Module descriptions and data flow accurately reflect the codebase
- **docs/INSTALL.md** — Installation steps and paths are accurate
- **Cross-references** — All inter-doc links and anchors resolve correctly (verified: SENTINEL→SECURITY-SCANNERS, MONITORING-SOURCES→ALERT-PIPELINE, etc.)
- **BarnacleDefense vendor patterns** — README Contributing section correctly says JSON files (previously fixed)
- **Severity enum** — All docs correctly reference `Critical`, `Warning`, `Info` matching `src/alerts.rs`
- **API port default** — 18791 in docs matches `default_api_port()` in `src/config.rs`
