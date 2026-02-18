# Sentinel: Real-Time File Integrity Monitor

ClawTower's **Sentinel** is a real-time file watcher built on Linux inotify. It detects changes to critical files the instant they happen, generates diffs against shadow copies, scans content for threats via BarnacleDefense, and either quarantines+restores (protected files) or updates its baseline (watched files).

---

## Table of Contents

1. [What the Sentinel Does](#what-the-sentinel-does)
2. [How It Works — The Event Pipeline](#how-it-works)
3. [File Deletion Auto-Restore](#file-deletion-auto-restore)
4. [Persistence-Critical Detection](#persistence-critical-detection)
5. [Protected vs Watched Policies](#protected-vs-watched-policies)
6. [Shadow Copies](#shadow-copies)
7. [Quarantine](#quarantine)
8. [BarnacleDefense Integration](#barnacle-integration)
9. [Content Scan Exclusions](#content-scan-exclusions)
10. [Scan Deduplication](#scan-deduplication)
11. [Log Rotation Detection](#log-rotation-detection)
12. [Configuration](#configuration)
13. [Relationship to Cognitive Monitoring](#relationship-to-cognitive-monitoring)
14. [Troubleshooting](#troubleshooting)

---

## What the Sentinel Does

The Sentinel provides **sub-second threat detection** for files that matter most — your agent's identity files (`SOUL.md`, `AGENTS.md`), configuration, memory, and any custom paths you define.

Key capabilities:

- **Instant detection** — inotify kernel events, not polling
- **Automatic quarantine & restore** — protected files are reverted immediately on unauthorized change
- **Content scanning** — new content is checked against BarnacleDefense pattern databases for injection attacks
- **Diff generation** — unified diffs show exactly what changed
- **Debounced processing** — rapid writes (e.g., editors doing save-tmp-rename) are coalesced into a single event

---

## How It Works

The full event pipeline from file change to resolution:

```
inotify event
    │
    ▼
Filter: is this a watched path?  ──no──▶ ignore
    │ yes
    ▼
Debounce buffer (200ms default)
    │
    ▼
File still exists? Size under limit?  ──no──▶ ignore
    │ yes
    ▼
Log rotation check  ──yes──▶ update shadow, Info alert, done
    │ no
    ▼
Read current file + shadow copy
    │
    ▼
Content identical?  ──yes──▶ ignore
    │ no
    ▼
Generate unified diff (old vs new)
    │
    ▼
BarnacleDefense content scan (if enabled)
    │
    ├── Threat found ──▶ QUARANTINE current → RESTORE from shadow → Critical alert
    │
    ├── Protected policy ──▶ QUARANTINE current → RESTORE from shadow → Critical alert
    │
    └── Watched policy ──▶ UPDATE shadow → Info alert
```

### Step by Step

1. **inotify fires** — the `notify` crate (using `RecommendedWatcher` / inotify on Linux) watches the parent directory of each configured path.

2. **Path filtering** — only events for paths listed in `watch_paths` are processed; everything else is dropped.

3. **Debounce** — events are held in a `HashMap<String, Instant>`. Every 50ms the loop checks for entries older than `debounce_ms` (default 200ms). This prevents duplicate processing when editors write temp files then rename.

4. **Existence & size check** — deleted files and files exceeding `max_file_size_kb` (default 1024 KB) are skipped.

5. **Log rotation detection** — if sibling files like `filename.1`, `filename.0`, or `filename.gz` exist, it's a log rotation. Shadow is updated silently.

6. **Diff generation** — the shadow copy (previous known-good content) is compared line-by-line with the current content, producing a unified diff.

7. **BarnacleDefense scan** — if `scan_content = true` and a `BarnacleDefenseEngine` is loaded, both the full file content and the diff are checked against threat pattern databases.

8. **Action** — based on policy and scan results:
   - **Quarantine + Restore**: the modified file is copied to quarantine, then the shadow copy overwrites it back to its previous state.
   - **Update shadow**: the shadow copy is replaced with the new content.

---

## File Deletion Auto-Restore

When a protected or watched file is deleted, the Sentinel responds immediately — deletions bypass the normal debounce window.

### How It Works

The `handle_deletion()` method in `sentinel.rs` runs whenever a `Remove` event is received from inotify:

1. **Immediate response** — deletion events skip the debounce buffer entirely, since there's no benefit to waiting.
2. **Verify file is actually gone** — if the file still exists on disk (e.g., the event was stale), the handler no-ops.
3. **Restore from shadow** — if a shadow copy exists for the deleted file:
   - Parent directories are created if they were also removed
   - The shadow copy is written back to the original path
   - A **Critical** alert fires: `"File deleted and restored from shadow: {path}"`
4. **No shadow available** — if there's no shadow copy (e.g., the file was added to watch_paths but never initialized), a **Critical** alert fires noting that restore is impossible.

### Why This Matters

File deletion is a common attack vector — an agent might delete `SOUL.md` to remove behavioral constraints, or delete `AGENTS.md` to disable safety rules. Auto-restore ensures protected files reappear within milliseconds.

---

## Persistence-Critical Detection

The Sentinel automatically flags certain file changes as **persistence attempts** — modifications to locations commonly used to survive reboots or gain recurring execution.

### Detected Patterns

The `is_persistence_critical()` method in `sentinel.rs` checks every file change event against these patterns:

| Location | File Pattern | Why It's Suspicious |
|---|---|---|
| `~/.config/systemd/user/` | `.service` or `.timer` files | User-level systemd units execute on login/boot |
| `~/.config/autostart/` | `.desktop` files | XDG autostart entries run on desktop session start |
| `.git/hooks/` | Any file except `.sample` | Git hooks execute automatically on git operations |

### Alert Behavior

When a persistence-critical path is detected:

- Alert level is forced to **Critical** regardless of the file's configured policy
- The alert message is prefixed with `"PERSISTENCE:"` for easy filtering
- Processing continues normally (quarantine/restore still applies based on policy and scan results)

This catches scenarios where an agent creates a systemd timer to phone home, installs a git hook to inject commands, or sets up an autostart entry for a reverse shell.

---

## Protected vs Watched Policies

Each path in `watch_paths` has a **policy** that determines what happens when the file changes:

| Policy | On Change | Alert Level | Use Case |
|---|---|---|---|
| `protected` | Quarantine modified file, restore from shadow | **Critical** | Identity files that should never change at runtime (`SOUL.md`, `AGENTS.md`, `IDENTITY.md`) |
| `watched` | Update shadow copy to new content | **Info** | Mutable working files that legitimately change (`HEARTBEAT.md`, `TOOLS.md`, logs, notes) |

**Exception:** If `scan_content` is enabled and BarnacleDefense detects a threat in a *watched* file, the file is quarantined and restored **regardless of policy**. Threat detection always wins.

### When to Use Which

- **Protected** — for any file whose content defines your agent's identity, behavior, or security posture. Changes to these files likely indicate tampering.
- **Watched** — for files your agent writes to regularly (memory, daily logs, scratch). You want to know when they change and keep diffs, but changes are expected.

---

## Shadow Copies

Shadow copies are the "known-good" baselines the Sentinel compares against.

### Storage Location

Default: `/etc/clawtower/sentinel-shadow/` (configurable via `shadow_dir`)

### Naming Scheme

```
{sha256_prefix}_{original_filename}
```

The path is hashed with SHA-256, truncated to 16 hex characters, then joined with the original filename:

```
shadow_dir/a1b2c3d4e5f67890_SOUL.md
shadow_dir/f9e8d7c6b5a43210_AGENTS.md
```

This ensures uniqueness (two files named `config.toml` in different directories get different shadow names) while keeping the original filename visible for debugging.

### Initialization

On startup, the Sentinel creates shadow copies for any watched file that doesn't already have one. The current file content becomes the initial baseline.

### Updates

- **Protected files**: shadow is never updated (the whole point is to restore from it)
- **Watched files**: shadow is replaced with new content after each change
- **Log rotations**: shadow is updated silently
- **Threats in watched files**: shadow is NOT updated (file is restored instead)

---

## Quarantine

When a protected file is modified or a threat is detected, the modified content is preserved for forensic analysis before being overwritten by the restore.

### Location

Default: `/etc/clawtower/quarantine/` (configurable via `quarantine_dir`)

### File Naming

```
{timestamp}_{original_filename}
```

Example: `20260214_203500_SOUL.md`

The timestamp format is `YYYYMMDD_HHMMSS` in local time, making quarantined files naturally sorted chronologically.

### What Happens

1. The modified (potentially malicious) file is **copied** to the quarantine directory
2. The shadow copy (known-good) **overwrites** the original file location
3. A **Critical alert** is sent with the quarantine path

### Forensic Analysis

Quarantined files retain the exact content that triggered the alert. You can:

```bash
# List quarantined files
ls -la /etc/clawtower/quarantine/

# View what was injected
cat /etc/clawtower/quarantine/20260214_203500_SOUL.md

# Diff against the restored version
diff /etc/clawtower/quarantine/20260214_203500_SOUL.md /home/openclaw/.openclaw/workspace/SOUL.md
```

---

## BarnacleDefense Integration

When `scan_content = true` (the default), the Sentinel feeds file content through BarnacleDefense's pattern matching engine.

### What Gets Scanned

Both the **full file content** and the **generated diff** are checked:

```rust
let content_matches = engine.check_text(&current);
let diff_matches = engine.check_text(&diff);
```

Scanning the diff catches injections even if they're buried in an otherwise clean file.

### What Happens on Match

Any match from either scan triggers the quarantine+restore path, regardless of whether the file's policy is `protected` or `watched`. The alert message explicitly says `THREAT detected`.

### Pattern Databases

BarnacleDefense uses curated pattern databases that detect:
- Prompt injection attempts
- Identity override patterns
- Credential/secret patterns
- Known malicious payloads

These are loaded and managed by the `BarnacleDefenseEngine` — see [SECURITY-SCANNERS.md](SECURITY-SCANNERS.md#barnacle-pattern-engine) for details on pattern databases and management.

---

## Content Scan Exclusions

Some watched paths contain sensitive data (API keys, auth tokens) that would trigger BarnacleDefense's credential-detection patterns on every change. Two config fields let you exclude paths from content scanning while still tracking changes.

### Glob-Based Exclusions

The `content_scan_excludes` config field accepts glob patterns matched via `glob::Pattern`:

```toml
[sentinel]
content_scan_excludes = [
    "**/.openclaw/**/auth-profiles.json",
    "**/secrets/*.env",
]
```

### Substring-Based Exclusions

The `exclude_content_scan` config field uses simple substring matching — if the path contains the string, content scanning is skipped:

```toml
[sentinel]
exclude_content_scan = [
    "superpowers/skills",
    ".openclaw/workspace/edge_whisper",
]
```

### What Gets Skipped

Only BarnacleDefense content pattern matching is bypassed. Everything else still applies:

- ✅ Change detection (inotify events still fire)
- ✅ Diff generation (shadow comparison still happens)
- ✅ Policy enforcement (protected files still quarantine+restore)
- ❌ BarnacleDefense pattern scan (skipped for excluded paths)

This prevents false positives from files that legitimately contain credential-like strings.

---

## Scan Deduplication

Periodic security scans (run by `scanner.rs`) can report the same finding every cycle, generating noise. Scanner-level deduplication suppresses repeated identical findings before they enter the alert pipeline.

### How It Works

In `run_periodic_scans()`, each non-passing finding is fingerprinted as:

`"{category}:{normalized_details}"` (digits normalized to `#`)

A `HashMap<String, Instant>` tracks when each fingerprint was last reported:

- **Same fingerprint within `[scans].dedup_interval_secs`** — suppressed (not forwarded)
- **Changed details/status** — typically produce a new fingerprint and alert immediately
- **After dedup interval** — persistent finding is reported again, resetting its timer
- **Resolution** — when a previously active fingerprint disappears, an Info `[RESOLVED]` alert is emitted

### Effect

This dramatically reduces alert volume from scanners that repeatedly report stable conditions while preserving visibility on state transitions and recoveries.

---

## Log Rotation Detection

Log files often appear "modified" when logrotate runs, creating false positives. The Sentinel detects this by checking for rotation sibling files.

### How It Works

When a file changes, `is_log_rotation()` checks if any of these siblings exist in the same directory:

- `{filename}.1`
- `{filename}.0`
- `{filename}.gz`

If any sibling exists, the change is treated as a routine rotation:
- Shadow copy is updated to the new content
- An **Info** alert is logged (not Critical)
- No quarantine occurs

### Example

If `/var/log/auth.log` changes and `/var/log/auth.log.1` exists, it's classified as a log rotation.

---

## Configuration

The Sentinel is configured in the `[sentinel]` section of `/etc/clawtower/config.toml`.

### Full Schema

```toml
[sentinel]
enabled = true              # Master switch (default: true)
shadow_dir = "/etc/clawtower/sentinel-shadow"   # Where shadow copies live
quarantine_dir = "/etc/clawtower/quarantine"    # Where quarantined files go
debounce_ms = 200           # Coalesce events within this window (default: 200)
scan_content = true         # Run BarnacleDefense on changed content (default: true)
max_file_size_kb = 1024     # Skip files larger than this (default: 1024)

# Protected identity files — quarantine + restore on any change
[[sentinel.watch_paths]]
path = "/home/openclaw/.openclaw/workspace/SOUL.md"
patterns = ["*"]
policy = "protected"

[[sentinel.watch_paths]]
path = "/home/openclaw/.openclaw/workspace/AGENTS.md"
patterns = ["*"]
policy = "protected"

# Protected memory file — quarantine + restore on any change
[[sentinel.watch_paths]]
path = "/home/openclaw/.openclaw/workspace/MEMORY.md"
patterns = ["*"]
policy = "protected"

# Watched mutable files — track changes, update shadow
[[sentinel.watch_paths]]
path = "/home/openclaw/.openclaw/workspace/HEARTBEAT.md"
patterns = ["*"]
policy = "watched"
```

### Default Watch Paths

Out of the box, the Sentinel watches:

| Path | Policy |
|---|---|
| `~/.openclaw/workspace/SOUL.md` | Protected |
| `~/.openclaw/workspace/AGENTS.md` | Protected |
| `~/.openclaw/workspace/MEMORY.md` | Protected |
| `~/.openclaw/workspace/HEARTBEAT.md` | Watched |
| `~/.openclaw/workspace/TOOLS.md` | Watched |

Additional defaults also include OpenClaw credentials/config paths, shell/profile
files commonly used for persistence, selected startup locations (systemd user
units/autostart/git hooks), and targeted system/user spool paths.

### Adding Custom Watch Paths

Watch any file or directory by adding entries:

```toml
# Protect SSH authorized keys from persistence attacks
[[sentinel.watch_paths]]
path = "/home/openclaw/.ssh/authorized_keys"
patterns = ["*"]
policy = "protected"

# Watch a config file for changes (but allow them)
[[sentinel.watch_paths]]
path = "/etc/clawtower/config.toml"
patterns = ["*"]
policy = "watched"

# Watch a whole directory
[[sentinel.watch_paths]]
path = "/home/openclaw/.openclaw/workspace/skills"
patterns = ["*"]
policy = "watched"
```

**Note on directories:** The Sentinel watches the parent directory of each path with `NonRecursive` mode. For directory paths, it watches the directory itself. Files within are matched if their path starts with the configured path string.

### Real-World Configuration Recipes

**Protect Docker configuration from container escape setups:**

```toml
[[sentinel.watch_paths]]
path = "/etc/docker/daemon.json"
patterns = ["*"]
policy = "protected"

[[sentinel.watch_paths]]
path = "/etc/docker/seccomp"
patterns = ["*"]
policy = "protected"

# Watch docker-compose files for supply-chain changes
[[sentinel.watch_paths]]
path = "/opt/docker/docker-compose.yml"
patterns = ["*"]
policy = "watched"
```

**Protect SSH keys and SSH daemon config:**

```toml
# Prevent unauthorized SSH key injection
[[sentinel.watch_paths]]
path = "/home/openclaw/.ssh/authorized_keys"
patterns = ["*"]
policy = "protected"

[[sentinel.watch_paths]]
path = "/root/.ssh/authorized_keys"
patterns = ["*"]
policy = "protected"

# Protect SSH daemon settings
[[sentinel.watch_paths]]
path = "/etc/ssh/sshd_config"
patterns = ["*"]
policy = "protected"
```

**Watch crontabs for persistence mechanisms:**

```toml
# Protect system crontab
[[sentinel.watch_paths]]
path = "/etc/crontab"
patterns = ["*"]
policy = "protected"

# Watch cron directories for new jobs
[[sentinel.watch_paths]]
path = "/etc/cron.d/"
patterns = ["*"]
policy = "watched"

[[sentinel.watch_paths]]
path = "/etc/cron.daily/"
patterns = ["*"]
policy = "watched"

# Protect user crontab spool
[[sentinel.watch_paths]]
path = "/var/spool/cron/crontabs/openclaw"
patterns = ["*"]
policy = "protected"
```

**Protect system authentication files:**

```toml
[[sentinel.watch_paths]]
path = "/etc/passwd"
patterns = ["*"]
policy = "protected"

[[sentinel.watch_paths]]
path = "/etc/shadow"
patterns = ["*"]
policy = "protected"

[[sentinel.watch_paths]]
path = "/etc/sudoers"
patterns = ["*"]
policy = "protected"

[[sentinel.watch_paths]]
path = "/etc/sudoers.d/"
patterns = ["*"]
policy = "protected"
```

---

## Relationship to Cognitive Monitoring

ClawTower has **two layers** of file integrity monitoring:

| | Sentinel (`sentinel.rs`) | Cognitive (`cognitive.rs`) |
|---|---|---|
| **Trigger** | Real-time (inotify events) | Periodic (runs each scan cycle, configured via `[scans].interval`) |
| **Scope** | Any configured path | Hardcoded cognitive files (`SOUL.md`, `IDENTITY.md`, `TOOLS.md`, `AGENTS.md`, `USER.md`, `HEARTBEAT.md`, `MEMORY.md`) |
| **Baseline** | Shadow file copies (full content) | SHA-256 hashes (+ shadow copies for watched files) |
| **Protected action** | Quarantine + restore from shadow | Alert only (Critical) |
| **Watched action** | Update shadow, Info alert | Update hash + shadow, Warn alert with diff |
| **Content scanning** | BarnacleDefense patterns on every change | Hash-only comparison (BarnacleDefense not invoked; watched files skip content scanning to avoid false positives) |
| **Config** | `[sentinel]` in config.toml | Hardcoded file lists |
| **Shadow location** | `/etc/clawtower/sentinel-shadow/` | `/etc/clawtower/cognitive-shadow/` |

### Why Both?

- **Sentinel** is the frontline — catches changes in milliseconds and can **actively restore** protected files before damage spreads.
- **Cognitive** is the safety net — runs on each periodic scan cycle (see [SECURITY-SCANNERS.md](SECURITY-SCANNERS.md#cognitive-integrity)) and catches anything the Sentinel might miss (e.g., if the Sentinel was temporarily stopped, or if a file was changed before the Sentinel started).

They use **separate shadow directories** and operate independently. Together they provide defense in depth.

---

## Troubleshooting

### Is the Sentinel Running?

On startup, the Sentinel sends an Info alert:

```
Sentinel watching N paths
```

Check ClawTower's log file or Slack channel for this message.

### Common Issues

| Symptom | Cause | Fix |
|---|---|---|
| No alerts for file changes | Sentinel disabled | Check `enabled = true` in `[sentinel]` |
| No alerts for file changes | Path not in `watch_paths` | Add the path to config |
| No alerts for file changes | Parent directory doesn't exist | Create the directory first |
| File keeps reverting | Path has `protected` policy | Change to `watched` if edits are intended |
| Too many alerts | Debounce too low | Increase `debounce_ms` (try 500-1000) |
| "Shadow dir" error on startup | Permission denied | Ensure ClawTower can write to `shadow_dir` |
| Large files ignored | Size exceeds limit | Increase `max_file_size_kb` |
| False positives on log files | Missing rotation detection | Ensure rotated files have `.1`/`.0`/`.gz` suffixes |

### Viewing Alerts

Sentinel alerts flow through ClawTower's standard alert pipeline (see [ALERT-PIPELINE.md](ALERT-PIPELINE.md)):

- **Slack** — Critical alerts are forwarded to your configured Slack channel
- **Log file** — All alerts (Info and above) are written to the log at `general.log_file`
- **API** — If the REST API is enabled, alerts are accessible via the API

### Inspecting Shadow and Quarantine State

```bash
# List shadow copies
ls -la /etc/clawtower/sentinel-shadow/

# See which file a shadow belongs to (filename is embedded)
ls /etc/clawtower/sentinel-shadow/
# Output: a1b2c3d4e5f67890_SOUL.md  f9e8d7c6b5a43210_AGENTS.md

# List quarantined files (sorted by time)
ls -lt /etc/clawtower/quarantine/

# Compare quarantined version to current
diff /etc/clawtower/quarantine/20260214_203500_SOUL.md ~/.openclaw/workspace/SOUL.md
```

### Restarting the Sentinel

The Sentinel runs as part of the ClawTower daemon. Restart ClawTower to restart the Sentinel:

```bash
sudo systemctl restart clawtower
```

## See Also

- [SECURITY-SCANNERS.md](SECURITY-SCANNERS.md) — Periodic cognitive integrity scans (complement to real-time Sentinel)
- [CONFIGURATION.md](CONFIGURATION.md) — Full `[sentinel]` config reference
- [MONITORING-SOURCES.md](MONITORING-SOURCES.md) — All real-time data sources including Sentinel
- [ALERT-PIPELINE.md](ALERT-PIPELINE.md) — How Sentinel alerts flow through aggregation
- [INDEX.md](INDEX.md) — Full documentation index
