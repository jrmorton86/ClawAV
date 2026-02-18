# ClawTower — Day 1 Operations Guide

You just installed ClawTower. Here's what you need to know.

---

## 1. What Just Happened

ClawTower installed the following components:

| Component | Location | Purpose |
|-----------|----------|---------|
| `clawtower` binary | `/usr/local/bin/clawtower` | Main watchdog daemon + CLI |
| `clawsudo` binary | `/usr/local/bin/clawsudo` | Sudo proxy that enforces policies |
| Config | `/etc/clawtower/config.toml` | Main configuration |
| Policies | `/etc/clawtower/policies/` (or `./policies/`) | Detection + enforcement rules |
| Admin key hash | `/etc/clawtower/admin.key.hash` | Immutable admin authentication |
| Quarantine | `/etc/clawtower/quarantine/` | Files flagged by sentinel |
| BarnacleDefense vendor | `/etc/clawtower/barnacle/` | Third-party security rules |
| Config overrides | `/etc/clawtower/config.d/` | Your customizations (never touched by updates) |
| Logs | `/var/log/clawtower/watchdog.log` | Primary log file |
| systemd service | `clawtower.service` | Keeps the watchdog running |

**Immutable files** (set with `chattr +i`): The binary, service file, and admin key hash are made immutable to prevent tampering. Config files are **not** immutable — customize via `/etc/clawtower/config.d/` override files (see [CONFIGURATION.md](CONFIGURATION.md)).

**Log sources ClawTower monitors:**
- `/var/log/audit/audit.log` — auditd syscall events
- `/var/log/syslog` — network events (tagged `CLAWTOWER_NET`)
- Falco / Samhain logs (if installed)

---

## 2. Your First Hour

### Expected Alert Volume (Untuned)

Out of the box, expect approximately:

- **~160 Critical alerts/hr** (mostly false positives — see Section 3)
- **~65 Warning alerts/hr**
- **~690 Info alerts/hr**
- **Total: ~900 alerts/hr**

**Don't panic.** ~95% of Critical alerts are false positives from known patterns. After tuning, this drops to:

- **~2 Critical/hr**
- **~8 Warning/hr**
- **~410 Info/hr**

### Check Status

```bash
# Service status
systemctl status clawtower

# Recent alerts
tail -f /var/log/clawtower/watchdog.log

# Alert counts by severity (last hour)
grep -c "Critical" /var/log/clawtower/watchdog.log
```

### Reading the TUI

If ClawTower has a TUI mode (`clawtower tui`):
- **Red/Critical** — potential threats or broken rules (most are false positives until tuned)
- **Yellow/Warning** — suspicious activity or config issues
- **Blue/Info** — normal operational logging (connections, scans, audit events)
- **Quarantine count** — files sentinel has isolated; check if they're your own files

### Quick Health Check

```bash
# Is auditd running?
systemctl status auditd

# Are immutable flags set?
lsattr /etc/clawtower/admin.key.hash

# Is the API responding?
curl -s http://localhost:18791/health
```

---

## 3. Tuning (Do This First)

**Read [TUNING.md](TUNING.md) now.** It contains specific fixes with copy-paste config changes.

### The Three Urgent Fixes

These three changes eliminate ~95% of false-positive Critical alerts:

**1. Stop the sentinel quarantine loop** — ClawTower's sentinel is quarantining your OpenClaw skill files in a loop (~2,748 Critical alerts/18h). Add sentinel path exclusions per TUNING.md Fix 1.

**2. Fix the broken `detect-scheduled-tasks` rule** — It triggers on every `cat` command (~137 false warnings/18h). Remove the `command_contains` block per TUNING.md Fix 2.

**3. Disable Falco/Samhain if not installed** — If you haven't installed these tools, set `enabled = false` in config. Saves ~2,608 wasted Info alerts per 18h.

### After Tuning

Restart the service:

```bash
sudo systemctl restart clawtower
```

Monitor for 30 minutes and verify alert volume has dropped.

---

## 4. What "Normal" Looks Like

After tuning, these patterns are expected and healthy:

| Source | Expected Pattern | Frequency |
|--------|-----------------|-----------|
| auditd | `HUMAN` events from your agent's commands | Continuous during activity |
| auditd | `EXECVE` events for bash/python/node | Continuous during activity |
| Network | Outbound UDP (DNS/NTP) | Constant, low volume |
| Network | Outbound TCP to known APIs | During agent operations |
| Scans | Config/hardening warnings | Once per scan cycle (hourly) |
| Sentinel | No alerts (after tuning) | Silent unless real threat |
| Policy | Occasional Info-level compilation events | During builds |

**Hourly scans** run by default every 3600 seconds. Each scan checks: immutable flags, user accounts, password policy, AppArmor, auditd, NTP, network config, listening ports, kernel modules, and more. Persistent findings alert once/day (after Fix 3 is applied).

---

## 5. When to Worry

These are **real threat indicators** — investigate immediately:

- **`detect-reverse-shell`** — Any match is serious. Check the command and source.
- **`deny-clawtower-tamper`** — Someone/something is trying to modify ClawTower itself.
- **`deny-firewall-changes`** — Firewall being disabled or flushed.
- **`detect-ssh-key-injection`** — Unauthorized SSH key added.
- **`detect-history-tampering`** — Someone covering their tracks.
- **`detect-log-clearing`** — System logs being deleted or truncated.
- **`deny-shadow-read`** (non-scan context) — Direct access to `/etc/shadow`.
- **Firewall rules changed** — Rare, always worth investigating.
- **New `detect-encoded-commands`** with actual base64 payloads piped to shell.
- **Any alert from an unknown user** (not your watched UID 1000).

### Response Steps

1. Check the full command in the log entry
2. Check who ran it: `ausearch -i -k <key>` or check the UID in the alert
3. If it's your agent: check what prompted it (was the agent compromised?)
4. If it's unknown: isolate the system, check for persistence mechanisms

---

## 6. When NOT to Worry

These are **known benign patterns** you'll see regularly:

- **`BEHAVIOR:RECON`** from `id`, `whoami`, `node`, `npm` — normal dev tool usage
- **`detect-compilation`** (Info level) — building software is fine
- **`detect-package-manager-abuse`** for `npm install`, `pip install`, `cargo install` from known registries — standard package management
- **Outbound connections to `api.anthropic.com`, `github.com`, `hooks.slack.com`** — these are allowlisted services
- **`scan:kernel_modules` high count** — Raspberry Pi loads many modules; this is normal
- **`scan:process_health` zombie processes** — occasional zombies from subprocesses are normal
- **Sentinel quarantine of test/malicious files** you created intentionally
- **`detect-timestomping`** from `touch` commands in build scripts

---

## 7. Your Admin Key

During installation, ClawTower generated an **admin key**. This is critical.

### What It Does
- Authenticates privileged operations via the ClawTower API
- Required to modify immutable configuration
- Required to override enforcement policies
- Used by `clawsudo` for elevated operations

### Where It Lives
- The key hash is stored at `/etc/clawtower/admin.key.hash` (immutable)
- The actual key was shown **once** during installation

### If You Lose It
The admin key hash file is immutable (`chattr +i`). Recovery requires:

1. Boot into single-user mode or live USB
2. Remove the immutable flag: `chattr -i /etc/clawtower/admin.key.hash`
3. Regenerate: `clawtower admin reset-key`
4. Re-set the immutable flag: `chattr +i /etc/clawtower/admin.key.hash`

**Write it down. Store it securely. You will need it.**

---

## 8. Ongoing Operations

### Daily Review Target

After tuning, aim for:
- **Review all Critical alerts** — should be <5/day, each one meaningful
- **Scan Warning alerts** — ~150/day, mostly config reminders; skim for new patterns
- **Ignore Info** unless investigating something specific

### Recommended Routine

| Frequency | Task |
|-----------|------|
| Daily | Check Critical alert count; investigate any new ones |
| Weekly | Review Warning trends; check for new false positive patterns |
| Monthly | Review and update policy allowlists; check for ClawTower updates |
| After changes | Any new software/service → check if it triggers false positives |

### Auto-Updates

ClawTower does not auto-update by default. Check for updates:

```bash
# If installed via git
cd /path/to/ClawTower && git pull

# Rebuild
cargo build --release

# Restart
sudo systemctl restart clawtower
```

### BarnacleDefense Rules

Vendor security rules live in `/etc/clawtower/barnacle/`. These may update separately. Check the `scan:barnacle last updated` warning — if it shows empty, the vendor rules haven't been populated yet.

### Log Rotation

Ensure `/var/log/clawtower/watchdog.log` is covered by logrotate. At ~900 alerts/hr untuned (~420/hr tuned), logs grow fast. Check:

```bash
cat /etc/logrotate.d/clawtower
```

If it doesn't exist, create one:

```
/var/log/clawtower/watchdog.log {
    daily
    rotate 14
    compress
    missingok
    notifempty
    postrotate
        systemctl reload clawtower 2>/dev/null || true
    endscript
}
```

---

## Quick Reference

| What | Command |
|------|---------|
| Service status | `systemctl status clawtower` |
| Live alerts | `tail -f /var/log/clawtower/watchdog.log` |
| TUI | `clawtower tui` |
| Manual scan | `clawtower scan` |
| API health | `curl http://localhost:18791/health` |
| Config (base) | `/etc/clawtower/config.toml` |
| Config overrides | `/etc/clawtower/config.d/*.toml` — see [CONFIGURATION.md](CONFIGURATION.md) |
| Policies | `/etc/clawtower/policies/` or `./policies/` |
| Quarantine | `/etc/clawtower/quarantine/` |
