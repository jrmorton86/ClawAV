# Red Lobster — Pentest Learnings & Training Data

Collected findings, root causes, and fixes from the Red Lobster automated pentest
suite (v3–v8) run against ClawTower on the `openclaw` target machine (ARM64,
Raspberry Pi, 192.168.1.85).

## Contents

| File | Description |
|------|-------------|
| [v8-results-2026-02-18.md](v8-results-2026-02-18.md) | Latest v8 pentest results (flags 15–17) |
| [harden-debugging-log.md](harden-debugging-log.md) | The `chattr` / capability / pam_cap debugging saga |
| [sentinel-silent-skip.md](sentinel-silent-skip.md) | Why the sentinel silently skipped all openclaw file watches |
| [glob-matching-bug.md](glob-matching-bug.md) | How `*.json` sentinel patterns were silently broken |
| [fixes-applied.md](fixes-applied.md) | Complete list of fixes from this session with file:line references |

## Key Takeaways

1. **Silent failures are the worst failures.** The sentinel skipped inaccessible
   paths without logging. The glob patterns matched nothing without error. Both
   looked like they were working until a pentest proved otherwise.

2. **`pam_cap` in `common-auth` is a footgun.** It drops capabilities from ALL
   user sessions, not just the target user. This broke `chattr` for root,
   making re-hardening impossible.

3. **`systemd-run` bypasses dropped bounding sets.** Transient units inherit
   PID 1's full capability set, providing an escape hatch when `pam_cap` or
   other mechanisms drop capabilities from the current session.

4. **File permissions beat code fixes.** The sentinel glob fix and directory
   watch were correct, but meaningless when the clawtower user couldn't even
   traverse `/home/openclaw` (mode 700).

5. **Pentest → fix → re-test is the only way.** Multiple rounds of deploy →
   test → diagnose → fix were needed. Assumptions about what "should work"
   were wrong repeatedly.
