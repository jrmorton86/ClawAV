# ClawTower Noise Analysis — 18h Production Logs

**Log period:** 2026-02-14 22:27 → 2026-02-15 16:39 EST (~18.2 hours)
**Total alerts:** 16,534

| Severity | Count | % |
|----------|------:|---:|
| Critical | 2,888 | 17.5% |
| Warning | 1,166 | 7.1% |
| Info | 12,480 | 75.5% |

---

## Executive Summary

**~95% of Critical alerts are false positives or self-inflicted noise.** The sentinel module dominates Critical volume (2,847 of 2,888) by repeatedly quarantining the same SKILL.md files in a loop. After applying all recommendations below, estimated alert volume drops from **2,888 → ~35 Critical/18h** and **1,166 → ~150 Warning/18h**.

---

## Critical Patterns — Detailed Analysis

### 1. Sentinel THREAT on SKILL.md files (1,458 alerts — 50.5% of Critical)

**Pattern:** `sentinel: THREAT detected in .../skills/*/SKILL.md, quarantined to /etc/clawtower/quarantine/…`
**Count:** 243 each × 6 skill files = 1,458
**Classification:** ❌ **False positive, code fix**

These are OpenClaw skill definition files (markdown). The sentinel is pattern-matching content inside them (likely keywords like "inject", "sudo", "reverse shell" appearing in security-related skill documentation). The same 6 files are re-quarantined **243 times each** over 18h (~13.5×/hour), meaning sentinel restores them then immediately re-detects and quarantines again.

**Recommended action:**
1. Allowlist `~/.openclaw/workspace/superpowers/skills/` in sentinel watched paths
2. Or fix content-scanning rules to not match markdown documentation
3. Priority: **P0** — this is half of all Critical alerts

### 2. Sentinel protected-file-modified + restored (1,290 alerts — 44.7% of Critical)

**Pattern:** `sentinel: Protected file .../skills/*/SKILL.md modified, quarantined…, restored from shadow`
**Count:** 129 each × 10 skill files = 1,290
**Classification:** ❌ **False positive, code fix (self-referential loop)**

This is the flip side of pattern #1. Sentinel quarantines → restores from shadow → detects modification → quarantines again. It's fighting itself.

**Recommended action:** Same fix as #1. Allowlist the skills directory.
**Priority: P0**

### 3. Immutable flag MISSING alerts (27 alerts)

**Pattern:** `scan:immutable_flags: 🚨 Immutable flag MISSING on: /etc/clawtower/admin.key.hash, /etc/sudoers.d/clawtower-deny`
**Also:** `scan:immutable_flags: Critical files MISSING: /etc/sudoers.d/clawtower-deny` (18 alerts)
**Count:** 27 (flags missing) + 18 (file missing) = 45 total
**Classification:** ⚠️ **True positive, wrong severity** (for repeats)

The first occurrence is a real signal — immutable flags should be set. But repeating every scan cycle (45 times in 18h) makes it noise. The underlying issue (`/etc/sudoers.d/clawtower-deny` missing) is a real config problem that should be fixed once.

**Recommended action:**
1. Fix the root cause: create `/etc/sudoers.d/clawtower-deny` and set immutable flags
2. Deduplicate: only alert once per boot or once per hour for persistent issues
3. **Priority: P1** — real issue, but repeat alerts are noise

### 4. Sentinel THREAT on workspace files (19 alerts)

**Pattern:** `sentinel: THREAT detected in …/MEMORY.md` (12), `SOUL.md` (4), `TOOLS.md` (2), `AGENTS.md` (1)
**Classification:** ❌ **False positive, tunable**

These are OpenClaw agent memory/config files. Content scanning false-positives on security-related vocabulary in agent notes.

**Recommended action:** Allowlist `~/.openclaw/workspace/*.md` or tune content rules.

### 5. curl wttr.in flagged as data exfiltration (9 alerts)

**Pattern:** `policy: [POLICY:block-data-exfiltration] … curl -s -m # https://wttr.in/?format=j#`
**Classification:** ❌ **False positive, tunable**

Weather check. Known benign.

**Recommended action:** Add `wttr.in` to exfiltration policy allowlist.

### 6. curl/wget to legitimate services (5 alerts)

**Patterns:** curl to `api.open-meteo.com` (2), `claw.local` (2), `localhost` (1)
**Classification:** ❌ **False positive, tunable**

All are local or known-good services.

**Recommended action:** Add `api.open-meteo.com`, `claw.local`, `localhost` to allowlist.

### 7. Base64/encoded command detection (6 alerts)

**Pattern:** `policy: [POLICY:detect-encoded-commands] Flag base#-encoded…` — AWS SSM commands
**Classification:** ⚠️ **True positive** (4 of 6), **False positive** (2 of 6)

The AWS SSM commands with base64-encoded SQL are legitimate devops operations BUT they contain real credentials (PGPASSWORD, database connection strings). These should be flagged. The 2 false positives are grep commands that happen to contain `base64` in the pattern.

**Recommended action:** Keep this rule. Reduce grep false positives by requiring minimum base64 string length.

### 8. SecureClaw dangerous command detections (28 alerts)

Breakdown:
- `curl.*|.*python` piped commands (11): **False positive, tunable** — legitimate API checks piped to json.tool
- `sudoers` keyword in filenames (15): **False positive, tunable** — `lsattr`, `ls -la`, `grep` on sudoers files is read-only inspection, not modification
- `sudo` escalation (3): **True positive** — keep
- `rm -rf` (2): **True positive** — keep (was deleting test-malicious dir, correctly flagged)
- `crontab` (4): **True positive** — keep (includes the evil.example.com test)
- `curl -d @-` data exfil (1): **True positive** — keep (exfil test to localhost)

**Recommended action:**
- Tune `sudoers` rule to only match write operations, not reads
- Tune `curl.*|.*python` to allowlist known domains (gottamolt.gg, github.com, localhost)

### 9. Behavior detections at Critical (misc, ~12 alerts)

- `BEHAVIOR:DATA_EXFIL` npm install (1): **False positive** — package manager
- `BEHAVIOR:DATA_EXFIL` base64 (1): **False positive** — encoding utility
- `BEHAVIOR:DATA_EXFIL` curl to local services (4): **False positive** — same as #6
- `BEHAVIOR:PRIV_ESC` cat /etc/shadow (1): **True positive** — keep
- `BEHAVIOR:SEC_TAMPER` crontab (4): **True positive** — keep

### 10. deny-clawtower-config-write false positives (10 alerts)

**Pattern:** `policy: [POLICY:deny-clawtower-config-write] … cat/grep /etc/clawtower/config.toml`
**Classification:** ❌ **False positive, code fix**

Reading config files is not writing. The rule name says "write" but triggers on reads (`cat`, `grep`).

**Recommended action:** Fix the policy regex to only match write operations (not `cat`/`grep`/`clawtower scan --config`).

### 11. Firewall rules changed (1 alert)

**Classification:** ✅ **True positive** — keep. Real signal.

---

## Warning Patterns — Summary

| Pattern | Count | Classification | Action |
|---------|------:|---------------|--------|
| Outbound IPv6 TCP connections | 64 | Noise | Demote to Info or suppress |
| scan:user_accounts (root has shell, no pw) | 45 | True positive, deduplicate | Alert once/day |
| scan:systemd_hardening incomplete | 45 | True positive, deduplicate | Alert once/day |
| scan:swap_tmpfs issues | 45 | True positive, deduplicate | Alert once/day |
| scan:secureclaw last updated (empty) | 45 | True positive, wrong severity | Fix: populate or demote to Info |
| scan:password_policy issues | 45 | True positive, deduplicate | Alert once/day |
| scan:openclaw:tunnel (no VPN) | 45 | True positive, deduplicate | Alert once/day |
| scan:ntp_sync (NTP not enabled) | 45 | True positive, deduplicate | Alert once/day |
| scan:network_interfaces (IPv6 fwd) | 45 | True positive, deduplicate | Alert once/day |
| scan:kernel_modules (high count) | 45 | Noise | Demote to Info |
| scan:integrity (no checksums) | 45 | True positive, deduplicate | Alert once/day |
| scan:dns_resolver (unusual DNS) | 45 | False positive, tunable | Allowlist local DNS |
| scan:auditd (immutable, no rules) | 45 | True positive, deduplicate | Alert once/day |
| scan:apparmor (not loaded) | 45 | True positive, deduplicate | Alert once/day |
| Outbound IPv4 TCP connections | 34 | Noise | Demote to Info |
| scan:listening (unexpected listeners) | 43 | Noise | Demote to Info; tune expected list |
| BEHAVIOR:RECON (id -u, node, npm, etc.) | 60+ | False positive | Allowlist dev tools |
| POLICY:detect-scheduled-tasks (cat) | 100+ | **False positive, code fix** | Rule triggers on `cat` — broken regex |
| BEHAVIOR:SEC_TAMPER (gcc linker) | 22 | False positive | Allowlist compiler toolchain |
| scan:process_health (zombies) | 30+ | True positive, wrong severity | Demote to Info |

**Key finding:** The `detect-scheduled-tasks` policy is **critically broken** — it triggers on nearly every `cat` command (137 alerts). The regex likely matches `cat` thinking it's `crontab` or `at`. This needs an immediate fix.

**Key finding:** The `BEHAVIOR:SEC_TAMPER` rule flags the GCC linker (`collect2`, `ld`) during normal Rust compilation. 22 false positives from building ClawTower itself.

---

## Info Patterns — Summary

| Pattern | Count | Notes |
|---------|------:|-------|
| Outbound UDP traffic | 3,483 | DNS/NTP — expected, could reduce logging |
| Outbound TCP traffic | 2,958 | Normal — could reduce logging |
| Falco waiting for log | 1,720 | Falco not installed — remove or install |
| Samhain waiting for log | 888 | Samhain not installed — remove or install |
| auditd HUMAN events | ~800 | Normal dev activity audit trail — keep |
| ClawTower service startup | 260 | 52 restarts in 18h — investigate stability |
| auditd exec events | ~200 | Normal — keep |

**Key finding:** 52 ClawTower watchdog restarts in 18h suggests the service is crashing/restarting every ~21 minutes. This should be investigated separately.

**Key finding:** 2,608 alerts (Falco + Samhain) are just "waiting for log" — these integrations aren't functional. Disable them or install the tools.

---

## Bottom Line: Projected Volume After Fixes

| Severity | Current (18h) | After fixes (18h) | Reduction |
|----------|-------------:|------------------:|----------:|
| Critical | 2,888 | ~35 | **98.8%** |
| Warning | 1,166 | ~150 | **87.1%** |
| Info | 12,480 | ~7,400 | **40.7%** |
| **Total** | **16,534** | **~7,585** | **54.1%** |

### Priority Fix List

1. **P0 — Sentinel skills loop** (2,748 alerts): Allowlist `~/.openclaw/workspace/superpowers/skills/`
2. **P0 — detect-scheduled-tasks broken regex** (137 alerts): Fix `cat` matching
3. **P1 — Scan deduplication** (540 Warning alerts): Alert once/day for persistent config issues, not every scan cycle
4. **P1 — deny-clawtower-config-write reads** (10 alerts): Only match writes, not reads
5. **P2 — Allowlist known hosts** in exfil policy: `wttr.in`, `api.open-meteo.com`, `claw.local`, `localhost`, `gottamolt.gg`, `github.com`
6. **P2 — Allowlist compiler toolchain** in SEC_TAMPER: `gcc`, `collect2`, `ld`
7. **P2 — Disable or install Falco/Samhain** (2,608 Info alerts wasted)
8. **P3 — Investigate 52 service restarts** in 18h

---

## v0.3.3 Noise Fixes (Post-Analysis)

### Sentinel Noise Fix (`fix/sentinel-noise` branch)

The P0 sentinel skills loop (2,748 Critical alerts) is addressed on the `fix/sentinel-noise` branch with two changes:

1. **Debounce restore** — Sentinel's quarantine→restore→re-detect loop is broken by restoring the debounce window after shadow copy restoration, preventing the immediate re-trigger cycle.
2. **Content scan exclusions** — The `exclude_content_scan` config field allows substring-based path exclusions for SecureClaw content scanning. Skills directories and workspace markdown files can be excluded from content scanning while still receiving file-change alerts.

**Estimated impact:** 2,748 Critical sentinel alerts → **~40** (98.5% reduction). The remaining ~40 are legitimate content scan hits on non-excluded paths.

### Planned Scanner Deduplication

Scanner results that persist across cycles (immutable flags missing, apparmor not loaded, etc.) generate repeat alerts every scan interval. Planned fix:

- **24-hour scan dedup** — Same category + same status results suppressed for 24 hours after first alert.
- **Estimated impact:** 45 persistent scanner warnings per 18h → **~4/day** (one per unique finding per day).
