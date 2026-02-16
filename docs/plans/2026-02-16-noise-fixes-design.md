# ClawAV Noise Fixes + LD_PRELOAD Detection — Design

**Date:** 2026-02-16
**Goal:** Reduce alert noise by 98.8% (Critical) and plug the LD_PRELOAD detection gap.

## 9 Fixes in 3 Categories

### Config-only (no Rust)
1. **Disable Falco/Samhain** — `enabled = false` in config. Kills 2,608 Info alerts.
2. **Exfil policy allowlist** — Add `wttr.in`, `api.open-meteo.com`, `claw.local`, `localhost` to allowlist.
3. **Create clawav-deny sudoers** — Fix root cause of repeating immutable flag alerts.

### Policy YAML fixes (no Rust)
4. **Fix detect-scheduled-tasks** — Remove `"at "` from `command_contains` (matches `cat`).
5. **Fix deny-clawav-config-write** — Only match write tools, not `cat`/`grep`.
6. **Compiler toolchain allowlist** — Add `cc1`, `collect2`, `ld`, `as` to behavior safe list.

### Rust code changes
7. **Sentinel allowlist** — `exclude_paths` config option, skip content scanning for matched paths.
8. **Scan deduplication** — 24h cooldown per scan result key.
9. **LD_PRELOAD detection** — New behavior pattern + auditd rule.

## Projected Impact
- Total: 16,534 → ~4,000 alerts/18h
- Critical: 2,888 → ~35 (98.8% reduction)
