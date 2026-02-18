# ClawTower → ClawTower Rename Design

**Date:** 2026-02-16
**Status:** Approved
**Problem:** "ClawTower" implies antivirus (signature scanning, malware database) which is misleading. The product is a behavioral security monitor / agent watchdog. "ClawTower" is accurate and honest.

## Rename Scope

### String Replacements (~1,290 occurrences across 78 files)

| Old | New | Context |
|-----|-----|---------|
| `ClawTower` | `ClawTower` | Product name in docs, comments |
| `clawtower` | `clawtower` | Binary name, crate name, paths, config |
| `CLAWTOWER` | `CLAWTOWER` | Env vars, log prefixes, auditd tags |

### NOT Renamed
- `clawsudo` — separate binary, stays as-is
- `barnacle` — vendor dependency
- `openclaw` — separate product

### File Renames
- `src/bin/clawtower-ctl.rs` → `src/bin/clawtower-ctl.rs`
- `src/bin/clawtower-tray.rs` → `src/bin/clawtower-tray.rs`
- `openclawtower.service` → `clawtower.service`
- `apparmor/etc.clawtower.protect` → `apparmor/etc.clawtower.protect`
- `assets/clawtower-tray.desktop` → `assets/clawtower-tray.desktop`
- `assets/com.clawtower.policy` → `assets/com.clawtower.policy`

### System Paths
- `/etc/clawtower/` → `/etc/clawtower/`
- `/var/log/clawtower/` → `/var/log/clawtower/`
- `/var/run/clawtower/` → `/var/run/clawtower/`
- `clawtower.service` → `clawtower.service`

### GitHub
- `ClawTower/ClawTower` → `ClawTower/ClawTower`

## Execution Order

1. Rename GitHub repo (manual, in GitHub settings)
2. Update git remote locally
3. Bulk find/replace all strings
4. File renames (6 files)
5. Update Cargo.toml (crate name, binary names)
6. Build + test
7. Single commit: `chore: rename ClawTower → ClawTower`
8. Tag v0.3.1
9. Uninstall old ClawTower on Pi (step-by-step checklist)
10. Fresh install as ClawTower

## Versioning
- v0.3.1 — this rename
- v0.4.0 — first public release
