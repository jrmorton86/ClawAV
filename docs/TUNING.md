# ClawTower Tuning Guide

> **Tip:** Use `/etc/clawtower/config.d/` for all customizations instead of editing
> `config.toml` directly. Your overrides survive updates automatically.
> See [CONFIGURATION.md](CONFIGURATION.md) for details.

Based on the [Noise Analysis](NOISE-ANALYSIS.md) of 18.2 hours of production logs (16,534 total alerts).

---

## Summary: Projected Noise Reduction

| # | Fix | Severity | Alerts Eliminated | Priority |
|---|-----|----------|------------------:|----------|
| 1 | Sentinel skills allowlist | Critical | 2,748 | P0 |
| 2 | Fix `detect-scheduled-tasks` regex | Warning | 137 | P0 |
| 3 | Scan deduplication | Warning | ~540 | P1 |
| 4 | Fix `deny-clawtower-config-write` (reads) | Critical | 10 | P1 |
| 5 | Allowlist known hosts in exfil policy | Critical | 14 | P2 |
| 6 | Allowlist compiler toolchain | Warning | 22 | P2 |
| 7 | Disable Falco/Samhain integrations | Info | 2,608 | P2 |
| 8 | Allowlist workspace markdown files | Critical | 19 | P2 |
| 9 | Allowlist `npm install` / dev tools | Critical/Warning | ~61 | P2 |
| **Total** | | | **~6,159** | |

**After all fixes:** Critical drops from 2,888 → ~35/18h. Warning drops from 1,166 → ~150/18h.

---

## Fix 1 — Sentinel Skills Quarantine Loop (P0)

### Problem
Sentinel repeatedly quarantines SKILL.md files in `~/.openclaw/workspace/superpowers/skills/`, then restores them from shadow, triggering another quarantine. This loop produces **2,748 Critical alerts** (95% of all Critical volume).

### Evidence
- 1,458 `THREAT detected` alerts (243 × 6 files)
- 1,290 `protected-file-modified` + restored alerts (129 × 10 files)
- Files contain security-related vocabulary (e.g., "inject", "sudo") that trips content scanning

### Fix
Add the skills directory to sentinel's allowlist. In `/etc/clawtower/config.toml`, add:

```toml
[sentinel]
exclude_paths = [
  "/home/openclaw/.openclaw/workspace/superpowers/skills/",
]
```

If the sentinel config doesn't support `exclude_paths`, this requires a code change to the sentinel module to skip paths matching a configurable allowlist.

### Expected Impact
Eliminates **2,748 Critical alerts/18h** (~153/hr → ~0/hr from this source).

---

## Fix 2 — Broken `detect-scheduled-tasks` Policy (P0)

### Problem
The `detect-scheduled-tasks` rule in `policies/default.yaml` matches on the command `at` and the pattern `"at "` — which matches every `cat` command (contains "at ").

### Evidence
137 Warning alerts in 18h, nearly all from `cat` commands reading normal files.

### Fix
Edit `policies/default.yaml`:

```yaml
# BEFORE (broken):
  - name: "detect-scheduled-tasks"
    match:
      command: ["at", "atq", "atrm", "batch"]
      command_contains:
        - "at "
        - "batch"
    action: warning

# AFTER (fixed):
  - name: "detect-scheduled-tasks"
    description: "Flag manipulation of scheduled tasks"
    match:
      command: ["at", "atq", "atrm", "batch"]
    action: warning
```

Remove the `command_contains` block entirely. The `command` match already catches `at` as a standalone command. The `"at "` substring match is what's breaking it — it matches `cat`, `lsattr`, `date`, etc. The `"batch"` pattern is also redundant since `batch` is in the command list.

### Expected Impact
Eliminates **~137 Warning alerts/18h**.

---

## Fix 3 — Scan Deduplication (P1)

### Problem
Hourly scans repeat the same warnings every cycle for persistent configuration issues (no AppArmor, no NTP, IPv6 forwarding, missing immutable flags, etc.). These are valid findings but only need to be reported once.

### Evidence
~540 Warning alerts are duplicates across scan cycles (45 alerts × 12 scan categories, repeating every hour for 18h).

### Fix
This requires a **code change** in the scan module. Implement one of:

1. **State file approach:** After each scan, write findings to `/var/lib/clawtower/last-scan-state.json`. On next scan, only alert on *new* findings. Alert once/day for persistent issues.
2. **Quick fix:** Add a `dedup_interval` config option:

```toml
[scans]
interval = 3600
dedup_interval = 86400  # Only re-alert on unchanged findings every 24h
```

### Expected Impact
Eliminates **~540 Warning alerts/18h** (reduces to ~30/18h — one alert per finding per day).

---

## Fix 4 — `deny-clawtower-config-write` Triggers on Reads (P1)

### Problem
The policy `deny-clawtower-config-write` uses `file_access` matching, which fires on *any* access including reads (`cat`, `grep`, `clawtower scan --config`). The rule name says "write" but it catches reads too.

### Evidence
10 Critical alerts from read-only operations on `/etc/clawtower/config.toml`.

### Fix
This requires a **code change** in the policy engine. The `file_access` matcher needs to distinguish read vs write operations. Options:

1. Add a `file_write` matcher type that only triggers on write syscalls (`open` with `O_WRONLY`/`O_RDWR`, `rename`, `unlink`)
2. Or add `exclude_commands` to the rule:

```yaml
  - name: "deny-clawtower-config-write"
    match:
      file_access:
        - "/etc/clawtower/config.toml"
        - "/etc/clawtower/policies/*"
      exclude_commands: ["cat", "grep", "less", "head", "tail", "clawtower"]
    action: critical
```

### Expected Impact
Eliminates **~10 Critical alerts/18h**.

---

## Fix 5 — Allowlist Known Hosts in Exfil Policy (P2)

### Problem
`curl` to `wttr.in`, `api.open-meteo.com`, `claw.local`, and `localhost` flagged as data exfiltration.

### Evidence
- 9 Critical alerts for `wttr.in`
- 5 Critical alerts for `api.open-meteo.com`, `claw.local`, `localhost`

### Fix
The `block-data-exfiltration` rule in `policies/default.yaml` already has `wttr.in`, `api.open-meteo.com`, and `localhost` in `exclude_args`. If alerts are still firing, the issue is likely in the matching logic — `exclude_args` may not be working correctly for URL arguments.

Check that the exclude matching handles full URLs (e.g., `https://wttr.in/?format=j1` should match the `wttr.in` exclusion). Add `claw.local` to the exclude list:

```yaml
exclude_args:
  # ... existing entries ...
  - "claw.local"
```

If `exclude_args` matching is broken, this is a **code fix** in the policy engine.

### Expected Impact
Eliminates **~14 Critical alerts/18h**.

---

## Fix 6 — Allowlist Compiler Toolchain (P2)

### Problem
`BEHAVIOR:SEC_TAMPER` flags GCC linker processes (`collect2`, `ld`) during normal Rust/C compilation.

### Evidence
22 Warning alerts from building ClawTower itself.

### Fix
Add compiler toolchain to behavior allowlist. In config or code:

```toml
[behavior]
sec_tamper_exclude_commands = ["collect2", "ld", "cc1", "as", "rustc", "cargo"]
```

Or if behavior rules are in the barnacle vendor module, add an exclusion there.

### Expected Impact
Eliminates **~22 Warning alerts/18h**.

---

## Fix 7 — Disable Falco and Samhain Integrations (P2)

### Problem
Falco and Samhain are enabled in config but not installed. ClawTower logs "waiting for log" every time it checks their non-existent log files.

### Evidence
- 1,720 Info alerts: Falco waiting for log
- 888 Info alerts: Samhain waiting for log

### Fix
Edit `/etc/clawtower/config.toml`:

```toml
[falco]
enabled = false
# log_path = "/var/log/falco/falco_output.jsonl"

[samhain]
enabled = false
# log_path = "/var/log/samhain/samhain.log"
```

Re-enable when/if these tools are installed.

### Expected Impact
Eliminates **2,608 Info alerts/18h**.

---

## Fix 8 — Allowlist Workspace Markdown Files (P2)

### Problem
Sentinel content-scans workspace files (`MEMORY.md`, `SOUL.md`, `TOOLS.md`, `AGENTS.md`) and flags security-related vocabulary.

### Evidence
19 Critical alerts (12 MEMORY.md, 4 SOUL.md, 2 TOOLS.md, 1 AGENTS.md).

### Fix
Extend the sentinel exclude path (same as Fix 1):

```toml
[sentinel]
exclude_paths = [
  "/home/openclaw/.openclaw/workspace/superpowers/skills/",
  "/home/openclaw/.openclaw/workspace/*.md",
  "/home/openclaw/.openclaw/workspace/memory/",
]
```

### Expected Impact
Eliminates **~19 Critical alerts/18h**.

---

## Fix 9 — Allowlist Dev Tools for RECON/EXFIL Behaviors (P2)

### Problem
Normal development commands (`npm install`, `id -u`, `node`, `npm`) flagged as `BEHAVIOR:RECON` or `BEHAVIOR:DATA_EXFIL`.

### Evidence
- 60+ Warning alerts for RECON on dev tools
- 1 Critical alert for `npm install` as DATA_EXFIL

### Fix
Add dev tool commands to behavior allowlists:

```toml
[behavior]
recon_exclude_commands = ["id", "node", "npm", "npx", "whoami", "uname"]
data_exfil_exclude_commands = ["npm", "pip", "cargo", "apt"]
```

### Expected Impact
Eliminates **~61 alerts/18h**.

---

## Additional Recommendations

### Behavior Detector Shadow Mode (Refactor Migration)

ClawTower now supports an opt-in shadow mode for behavior detector migration.
This is for validating parity between the legacy hardcoded behavior path and
the new detector abstraction path before cutover.

Enable via config overlay:

```toml
# /etc/clawtower/config.d/50-behavior-shadow.toml
[behavior]
detector_shadow_mode = true
```

What it does:

- Keeps production behavior alerts unchanged
- Runs new detector path in parallel
- Emits `parity:behavior` diagnostics only on mismatch
- Deduplicates repeated identical mismatches (30s window)

Monitor counters in:

- `GET /api/status` → `parity.mismatches_total`, `parity.alerts_emitted`, `parity.alerts_suppressed`
- `GET /api/security` → same parity counters

How to interpret:

- High `mismatches_total`, low `alerts_suppressed` → diverse parity drift (investigate logic differences)
- High `alerts_suppressed` relative to emitted → repeated known mismatch signature (likely one hot path)
- Near-zero mismatches over representative workload → candidate for safe cutover planning

### Investigate Service Stability
The noise analysis found **52 ClawTower restarts in 18h** (~1 every 21 minutes). This generates 260 Info alerts and indicates a crash loop. Check `journalctl -u clawtower` for crash reasons.

### Fix Missing System Files
Create `/etc/sudoers.d/clawtower-deny` and set immutable flags on critical files to resolve the 45 legitimate Critical alerts about missing protections.

### Network Logging Volume
3,483 UDP + 2,958 TCP Info-level connection logs dominate the Info tier. Consider:
- Raising `min_alert_level` to `"warning"` if Info volume is overwhelming
- Or adding connection logging rate limits
