# Harden Debugging Log — The chattr Saga

How `sudo clawtower harden` went from "Operation not permitted" to working
across 6 deploy-test cycles.

## The Problem

Running `sudo clawtower harden` on a previously hardened machine failed with:
```
cp: cannot create regular file '/etc/clawtower/config.toml': Operation not permitted
```

Protected files had `chattr +i` (immutable flag) from the previous install.
The harden process needs to strip those flags, modify files, then re-apply them.

## Timeline of Diagnosis

### Attempt 1: AppArmor blocking cp
**Hypothesis:** The `etc.clawtower.protect` AppArmor profile denies `/usr/bin/cp`
writes to `/etc/clawtower/**`, and AppArmor `deny` rules are enforced even in
`complain` mode.

**Fix:** Added `apparmor_parser -R` to install.sh before file operations.

**Result:** Same error. AppArmor wasn't the cause.

### Attempt 2: Direct ioctl from Rust binary
**Hypothesis:** Bypass `chattr` entirely with `FS_IOC_GETFLAGS`/`FS_IOC_SETFLAGS`
ioctl calls from the clawtower binary itself (no AppArmor profile on the binary).

**Fix:** Implemented `strip_immutable_flag()` with direct ioctl in `main.rs`,
called from `pre_harden_cleanup()` before running install.sh.

**Result:** ioctl also returned EPERM. Added diagnostics.

### Attempt 3: Capability dump reveals the truth
**Diagnostics added:** Dump `/proc/self/status` capability bitmasks.

**Finding:**
```
CapBnd: 000001fffffffdff
```
Bit 9 (`CAP_LINUX_IMMUTABLE`) is **missing** from the bounding set. This means
no process in this session can use `chattr` — neither ioctl nor the external
command.

**Also found:** AppArmor profile `etc.clawtower.protect` had a syntax error
(`wdl` permission mode requires AppArmor 3.0+). Profiles were **never loaded**
on the remote — ruling out AppArmor entirely.

### Attempt 4: External chattr also fails
Confirmed: direct `chattr -i` command also fails with the same missing capability.

### Attempt 5: Root cause — pam_cap dropping CAP_LINUX_IMMUTABLE

**Root cause identified:** `install.sh` step 6 previously added `pam_cap.so` to
`/etc/pam.d/common-auth`, which runs for ALL user sessions. Combined with
`capability.conf` dropping `!cap_linux_immutable`, this caused the capability
to be dropped from every login session — including root's SSH sessions.

Once dropped from the bounding set via `prctl(PR_CAPBSET_DROP)`, the capability
**cannot be regained** by any child process. The only escape:

**`systemd-run --wait --collect --quiet chattr -i <path>`**

This creates a transient systemd unit that inherits PID 1's full bounding set,
which was never affected by `pam_cap`.

**Fix:** Three-level fallback in `strip_immutable_flag()`:
1. Direct ioctl (fastest, works when capabilities are present)
2. External `chattr` command (works when AppArmor profiles aren't loaded)
3. `systemd-run chattr` (bypasses dropped bounding set)

### Attempt 6: chattr +i also fails in install.sh
**Problem:** Pre-harden cleanup now strips immutable flags via systemd-run
(working!), but install.sh step 4 (`chattr +i`) and step 8 (`chattr +i
sudoers`) also fail — same missing capability.

**Fix:** Created `do_chattr()` bash wrapper in install.sh and enable-preload.sh:
```bash
do_chattr() {
    local flag="$1" path="$2"
    if chattr "$flag" "$path" 2>/dev/null; then return 0; fi
    systemd-run --wait --collect --quiet chattr "$flag" "$path" 2>/dev/null
}
```
Replaced ALL chattr calls in both scripts. Also fixed `admin.rs` chattr call.

**Also fixed:** Removed pam_cap insertion from install.sh and apparmor.rs.
Added cleanup of stale pam_cap entries from `/etc/pam.d/common-auth`.

### Attempt 7: Success
Full harden completed. All immutable flags stripped and re-applied via
systemd-run fallback.

## Key Lessons

1. **`pam_cap` in `common-auth` is system-wide, not per-user.** The
   `capability.conf` file specifies which users lose which capabilities,
   but putting `pam_cap.so` in `common-auth` means it runs for everyone.

2. **Capability bounding set drops are permanent.** Once `prctl(PR_CAPBSET_DROP)`
   removes a capability, no `setuid`, no `sudo`, nothing can restore it in
   the current process tree.

3. **`systemd-run` is the escape hatch.** Transient units inherit PID 1's
   bounding set, not the caller's. This is by design — systemd manages
   capabilities independently of PAM sessions.

4. **AppArmor version compatibility matters.** The `wdl` permission mode is
   AppArmor 3.0+ only. Older systems silently fail to parse profiles.

5. **Always add diagnostics before guessing.** The capability dump immediately
   revealed the missing bit, saving hours of wrong hypotheses.

## Files Modified

| File | Change |
|------|--------|
| `src/main.rs` | `strip_immutable_flag()` (ioctl → chattr → systemd-run), `pre_harden_cleanup()` |
| `scripts/install.sh` | `do_chattr()` wrapper, removed pam_cap insertion, pam_cap cleanup |
| `scripts/enable-preload.sh` | `do_chattr()` wrapper |
| `src/admin.rs` | systemd-run fallback for `chattr +i` on admin key hash |
| `src/apparmor.rs` | Removed pam_cap insertion, added stale pam_cap cleanup |
