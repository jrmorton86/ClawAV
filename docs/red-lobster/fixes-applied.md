# Fixes Applied — 2026-02-18 Session

All changes from the harden debugging + sentinel fix session.

## 1. chattr systemd-run Fallback

**Problem:** `CAP_LINUX_IMMUTABLE` dropped from all sessions by `pam_cap`.
**Files:**

- `src/main.rs:220` — `strip_immutable_flag()`: 3-level fallback (ioctl → chattr → systemd-run)
- `src/main.rs:271` — `pre_harden_cleanup()`: strips immutable flags from all protected paths before harden/uninstall/configure
- `scripts/install.sh:23` — `do_chattr()`: bash wrapper with systemd-run fallback, replaces all 8 chattr calls
- `scripts/enable-preload.sh:16` — `do_chattr()`: same wrapper, replaces 3 chattr calls
- `src/admin.rs:180` — systemd-run fallback for `chattr +i` on admin key hash

## 2. pam_cap Removal

**Problem:** `pam_cap.so` in `/etc/pam.d/common-auth` dropped capabilities from ALL users.
**Files:**

- `scripts/install.sh:179-188` — Removed pam_cap insertion, added stale entry cleanup
- `src/apparmor.rs:294-311` — Removed pam_cap insertion from fallback path, added cleanup
- `src/main.rs:311-322` — `pre_harden_cleanup()` removes stale pam_cap entries

## 3. Sentinel Glob Pattern Fix

**Problem:** `policy_for_path()` used exact string match; `*.json` patterns never matched.
**Files:**

- `src/sentinel.rs:120` — Changed `filename == *pattern` to `glob_match::glob_match(pattern, &filename)`
- `src/sentinel.rs:955-987` — Added 3 new tests for glob matching

## 4. Sentinel Directory Watch for OpenClaw Config

**Problem:** Individual file watches replaced with broader directory coverage.
**Files:**

- `src/config.rs:569-572` — Replaced `device.json` (Protected) + `openclaw.json` (Watched) individual watches with `/home/openclaw/.openclaw` directory watch for `*.json` (Protected)
- `src/config.rs:506` — Added `**/.openclaw/*.json` to content scan exclusion list
- `src/config.rs:903` — Updated test assertion for new directory watch

## 5. Sentinel Permission Fix

**Problem:** clawtower user can't traverse `/home/openclaw` (mode 700), silently skipping all watches.
**Files:**

- `scripts/install.sh:55-68` — Step 1b: `usermod -a -G openclaw clawtower`, `chmod 710` home, `chmod 750` .openclaw

## 6. Sentinel Watch Error Logging

**Problem:** Failed watches were silently skipped with no indication.
**Files:**

- `src/sentinel.rs:540-577` — Watch setup now logs per-path errors as Warning alerts, counts skipped paths, emits summary warning

## 7. Pre-existing Test Fix

**Problem:** Raw string literal `r#"` contained `"#test"` which prematurely closed the delimiter.
**Files:**

- `src/config.rs:1436` — Changed `r#"` to `r##"` and `"#;` to `"##;`

## Build Note

Cross-compile: `cargo build --release --target aarch64-unknown-linux-gnu`
Deploy: `./scripts/deploy.sh`
Then: `sudo clawtower harden` on remote to pick up install.sh changes.
