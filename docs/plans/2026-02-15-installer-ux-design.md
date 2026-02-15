# ClawAV Installer UX Improvements — Design

**Date:** 2026-02-15
**Status:** Approved

## Problem

The oneshot installer has no concept of "already installed." Every run goes through the full 10+ prompt flow. On reinstall:
- Admin key Phase 4 shows a scary "SAVE YOUR KEY" banner then finds nothing
- Auditd immutable mode error looks like a failure
- User must answer 10+ questions they already answered

## Design

### 1. Install Detection (top of script)

Check for three markers: `/usr/local/bin/clawav` + `/etc/clawav/config.toml` + `/etc/clawav/admin.key.hash`

- **All three exist** → existing install detected → offer menu:
  - **Upgrade** — swap binaries, refresh patterns + sudoers policy, keep config + key
  - **Reconfigure** — re-run config wizard (Phase 2 + 3), keep key
  - **Full reinstall** — nuke everything, run full flow
- **Partial** (e.g. binary but no config) → warn about broken state, offer Fresh Install or abort
- **None** → fresh install (current flow)

### 2. Upgrade Path

Minimal prompts:
1. Show current version vs available version
2. "Upgrade to vX.Y.Z? [Y/n]"
3. Stop service → unlock immutable flags → swap binary + clawsudo + tray → update SecureClaw patterns → refresh sudoers allowlist → re-lock → start service
4. "Your existing admin key and config are unchanged."
5. Done.

Sudoers allowlist is regenerated from the latest template (same as fresh install) on every upgrade. This ensures policy improvements ship with new versions.

### 3. Admin Key Fix (Phase 4)

Track whether admin.key.hash existed at script start (capture in variable early).

- **Existed before** → "Your existing admin key is still valid. No new key was generated." Skip "I SAVED MY KEY" ceremony.
- **Did not exist** → current ceremony (generate, display from journalctl, require confirmation)

### 4. Auditd Immutable Mode Fix

Before `augenrules --load`:
- Check `auditctl -s | grep "enabled 2"` 
- **If immutable** → install rules file to `/etc/audit/rules.d/clawav.rules` silently, then: "ℹ️  Auditd is in immutable mode. Rules installed — they'll activate after next reboot."
- **If not immutable** → load rules normally, show current ✓ message

## Implementation Notes

- All changes are in `scripts/oneshot-install.sh`
- Detection block goes right after argument parsing, before Phase 1
- Upgrade path is a new code path (like `--update` but without key requirement)
- `--update` flag still works but now routes to the same upgrade path
- Variable `EXISTING_INSTALL=true/false` and `HAD_ADMIN_KEY=true/false` set early
