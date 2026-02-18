# ClawTower Noise Fixes + LD_PRELOAD Detection — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Reduce alert noise by 98.8% (Critical) and plug the LD_PRELOAD detection gap. 9 fixes across config, policy, and Rust code.

**Architecture:** Config-only and policy fixes are file edits (no compilation). Rust changes require `cargo build --release` on the Pi (~10-15 min). All fixes are independent — can be done in any order.

**Tech Stack:** TOML config, YAML policies, Rust (tokio, notify, serde)

---

### Task 1: Disable Falco/Samhain (config-only)

**Files:**
- Modify: `/etc/clawtower/config.toml`

**Step 1: Edit config**

Change these two sections:
```toml
[falco]
enabled = false
log_path = "/var/log/falco/falco_output.jsonl"

[samhain]
enabled = false
log_path = "/var/log/samhain/samhain.log"
```

Note: This requires `sudo` since the config is immutable. The steps are:
```bash
sudo chattr -i /etc/clawtower/config.toml
# make edits
sudo chattr +i /etc/clawtower/config.toml
sudo systemctl restart clawtower
```

**Step 2: Verify**

```bash
sleep 10
tail -5 /var/log/clawtower/alerts.jsonl | jq -r '.source + ": " + .message' | grep -i "falco\|samhain"
```
Expected: No new falco/samhain "Waiting for" messages.

**Step 3: Commit config change to repo**

Also update `config.example.yaml` to note these are optional:
```bash
cd /home/openclaw/.openclaw/workspace/projects/ClawTower
git add -A && git commit -m "config: disable falco/samhain (not installed)"
```

**Impact:** -2,608 Info alerts/18h

---

### Task 2: Fix exfil policy allowlist (policy YAML)

**Files:**
- Modify: `policies/default.yaml` (lines ~10-38, `block-data-exfiltration` rule)

**Step 1: Verify current allowlist**

The `exclude_args` in `block-data-exfiltration` already includes `wttr.in` and `api.open-meteo.com`. The noise analysis says these still fire — check if the exclude is working:

```bash
cd /home/openclaw/.openclaw/workspace/projects/ClawTower
grep -A 30 "block-data-exfiltration" policies/default.yaml | grep -i "wttr\|open-meteo\|claw.local"
```

If `wttr.in` is already in `exclude_args`, the issue may be in the policy engine's matching logic (e.g., full URL vs hostname substring). Check `src/policy.rs` for how `exclude_args` is matched.

**Step 2: Add missing hosts if needed**

Add `claw.local` if not present:
```yaml
exclude_args:
  # ... existing entries ...
  - "claw.local"
```

**Step 3: Copy updated policy to live config**

```bash
sudo chattr -i /etc/clawtower/config.toml
sudo cp policies/default.yaml /etc/clawtower/policies/default.yaml
sudo chattr +i /etc/clawtower/config.toml
```

**Step 4: Commit**

```bash
git add policies/default.yaml && git commit -m "policy: add claw.local to exfil allowlist"
```

**Impact:** -14 Critical alerts/18h

---

### Task 3: Fix detect-scheduled-tasks regex (policy YAML)

**Files:**
- Modify: `policies/default.yaml` (line ~456, `detect-scheduled-tasks` rule)

**Step 1: Read current rule**

```bash
sed -n '456,464p' policies/default.yaml
```

Current:
```yaml
  - name: "detect-scheduled-tasks"
    description: "Flag manipulation of scheduled tasks"
    match:
      command: ["at", "atq", "atrm", "batch"]
      command_contains:
        - "at "
        - "batch"
    action: warning
```

The bug: `command_contains: ["at "]` matches `cat ` (substring). And `"batch"` matches `batch` in any context.

**Step 2: Fix the rule**

Remove `command_contains` entirely — the `command` exact binary match already handles `at`, `atq`, `atrm`, `batch`:

```yaml
  - name: "detect-scheduled-tasks"
    description: "Flag manipulation of scheduled tasks"
    match:
      command: ["at", "atq", "atrm", "batch"]
    action: warning
```

**Step 3: Copy to live and commit**

```bash
sudo cp policies/default.yaml /etc/clawtower/policies/default.yaml
git add policies/default.yaml && git commit -m "policy: fix detect-scheduled-tasks false positive on cat"
```

**Impact:** -137 Warning alerts/18h

---

### Task 4: Fix deny-clawtower-config-write (policy YAML)

**Files:**
- Modify: `policies/default.yaml` (the `deny-clawtower-config-write` rule)

**Step 1: Read current rule**

```bash
grep -A 8 "deny-clawtower-config-write" policies/default.yaml
```

Current uses `file_access` which triggers on ANY access (read or write) to `/etc/clawtower/config.toml`.

**Step 2: Change to command-based detection**

Replace file_access with command_contains that only matches write operations:

```yaml
  - name: "deny-clawtower-config-write"
    description: "Detect writes to ClawTower config files"
    match:
      command_contains:
        - "sed -i /etc/clawtower/"
        - "tee /etc/clawtower/"
        - "vim /etc/clawtower/"
        - "nano /etc/clawtower/"
        - "vi /etc/clawtower/"
        - "cp * /etc/clawtower/"
        - "mv * /etc/clawtower/"
        - "chattr -i /etc/clawtower/"
        - "> /etc/clawtower/"
    action: critical
```

**Step 3: Copy to live and commit**

```bash
sudo cp policies/default.yaml /etc/clawtower/policies/default.yaml
git add policies/default.yaml && git commit -m "policy: fix config-write rule to not trigger on reads"
```

**Impact:** -28 Critical alerts/18h (the BarnacleDefense `sudoers` pattern overlap will also decrease)

---

### Task 5: Sentinel exclude_paths (Rust code change)

**Files:**
- Modify: `src/config.rs:344-363` (SentinelConfig struct)
- Modify: `src/sentinel.rs` (content scanning logic)
- Test: Add unit tests

**Step 1: Add `exclude_content_scan` field to SentinelConfig**

In `src/config.rs`, add to the `SentinelConfig` struct (after `max_file_size_kb`):

```rust
/// Paths to exclude from content scanning (BarnacleDefense pattern matching).
/// Files in these paths are still watched for changes but not scanned for threats.
#[serde(default)]
pub exclude_content_scan: Vec<String>,
```

Also add it to the `Default` impl:
```rust
exclude_content_scan: vec![
    "superpowers/skills".to_string(),
],
```

**Step 2: Use exclude list in sentinel content scanning**

In `src/sentinel.rs`, find where `scan_content` is checked and files are passed to BarnacleDefense scanning. Before scanning, check if the file path contains any of the `exclude_content_scan` patterns:

```rust
// Before content scanning
let should_scan_content = config.sentinel.scan_content 
    && !config.sentinel.exclude_content_scan.iter().any(|excl| path_str.contains(excl));
```

**Step 3: Write test**

```rust
#[test]
fn test_exclude_content_scan_pattern() {
    let mut config = SentinelConfig::default();
    config.exclude_content_scan = vec!["superpowers/skills".to_string()];
    
    let path = "/home/openclaw/.openclaw/workspace/superpowers/skills/brainstorming/SKILL.md";
    let excluded = config.exclude_content_scan.iter().any(|excl| path.contains(excl));
    assert!(excluded, "Skills directory should be excluded from content scan");
    
    let path2 = "/home/openclaw/.openclaw/workspace/SOUL.md";
    let excluded2 = config.exclude_content_scan.iter().any(|excl| path2.contains(excl));
    assert!(!excluded2, "SOUL.md should NOT be excluded from content scan");
}
```

**Step 4: Build and test**

```bash
cd /home/openclaw/.openclaw/workspace/projects/ClawTower
cargo test 2>&1 | tail -5
cargo build --release 2>&1 | tail -5
```

**Step 5: Commit**

```bash
git add src/config.rs src/sentinel.rs
git commit -m "feat: sentinel exclude_content_scan to prevent SKILL.md false positives"
```

**Impact:** -2,748 Critical alerts/18h (this is the P0 fix — 95% of Criticals)

---

### Task 6: Scan deduplication (Rust code change)

**Files:**
- Modify: `src/scanner.rs` (scan loop)
- Test: Add unit test

**Step 1: Add dedup state to scan loop**

In `src/scanner.rs`, find where `run_all_scans()` is called periodically. Add a `HashMap<String, Instant>` to track last-emitted results:

```rust
use std::collections::HashMap;
use std::time::{Duration, Instant};

// In the periodic scan task:
let mut last_emitted: HashMap<String, Instant> = HashMap::new();
let cooldown = Duration::from_secs(24 * 3600); // 24 hours

// After each scan result:
let dedup_key = format!("{}:{}", result.name, result.status_str());
let now = Instant::now();
if let Some(last) = last_emitted.get(&dedup_key) {
    if now.duration_since(*last) < cooldown {
        continue; // Skip duplicate
    }
}
last_emitted.insert(dedup_key, now);
```

Where `status_str()` returns "pass"/"warn"/"fail" — so a scan that changes from warn to pass still fires.

**Step 2: Write test**

```rust
#[test]
fn test_scan_dedup_suppresses_repeats() {
    let mut last_emitted: HashMap<String, Instant> = HashMap::new();
    let cooldown = Duration::from_secs(24 * 3600);
    
    let key = "firewall:warn".to_string();
    // First time: should emit
    assert!(!last_emitted.contains_key(&key));
    last_emitted.insert(key.clone(), Instant::now());
    
    // Second time: should suppress
    let last = last_emitted.get(&key).unwrap();
    assert!(Instant::now().duration_since(*last) < cooldown);
}

#[test]
fn test_scan_dedup_allows_status_change() {
    let mut last_emitted: HashMap<String, Instant> = HashMap::new();
    last_emitted.insert("firewall:warn".to_string(), Instant::now());
    
    // Different status: should emit
    let new_key = "firewall:pass".to_string();
    assert!(!last_emitted.contains_key(&new_key));
}
```

**Step 3: Build and test**

```bash
cargo test 2>&1 | tail -5
cargo build --release 2>&1 | tail -5
```

**Step 4: Commit**

```bash
git add src/scanner.rs
git commit -m "feat: 24h scan deduplication to prevent repeat warnings"
```

**Impact:** -540 Warning alerts/18h

---

### Task 7: Compiler toolchain behavior allowlist (Rust code change)

**Files:**
- Modify: `src/behavior.rs` (~line 413)

**Step 1: Check current suppression logic**

The code at `src/behavior.rs:413` already suppresses `ld`, `collect2`, `cc1`, `cc1plus`, `gcc`, `g++`, `rustc`, `cc` from PRELOAD_BYPASS_PATTERNS. But the noise analysis says compiler toolchain is still flagged as SEC_TAMPER (22 alerts).

Check if there's a separate detection path that isn't suppressed:

```bash
grep -n "SEC_TAMPER\|SecurityTamper" src/behavior.rs | head -20
```

**Step 2: Identify the non-suppressed path**

Look for other SEC_TAMPER triggers that don't have the compiler exclusion. The issue might be in the `sudo` pattern matching (BarnacleDefense `dangerous_commands:config_modification` triggered by `clawsudo` in the command string — already noted in MEMORY.md).

**Step 3: Add compiler binaries to the appropriate exclusion**

If found, add the same `BUILD_TOOL_BASES` check to the additional SEC_TAMPER path. Also add `as` (GNU assembler) to the binary allowlist if not present.

**Step 4: Test and commit**

```bash
cargo test 2>&1 | tail -5
git add src/behavior.rs && git commit -m "fix: suppress SEC_TAMPER for compiler toolchain"
```

**Impact:** -22 Warning alerts/18h

---

### Task 8: LD_PRELOAD environment variable detection (Rust code change)

**Files:**
- Modify: `src/behavior.rs` (add new detection pattern)
- Modify: `src/auditd.rs` (parse environment variables from EXECVE records if available)
- Test: Add unit tests

**Step 1: Understand the gap**

The POC test ran `LD_PRELOAD=/tmp/evil.so ls`. ClawTower's current `PRELOAD_BYPASS_PATTERNS` checks the *command string* for `LD_PRELOAD`. But when `LD_PRELOAD` is set as an environment variable (not part of the command args), auditd logs it differently — in `EXECVE` records the env vars may not appear in the command field.

Check what auditd actually logged:

```bash
grep "LD_PRELOAD" /var/log/audit/audit.log | tail -5
```

**Step 2: Add environment-based detection**

If auditd captures the env var, add a check in `src/auditd.rs` event parsing to extract environment variables and check them.

If auditd doesn't capture env vars by default, add an auditd rule:

```bash
# Add to /etc/audit/rules.d/clawtower.rules
-a always,exit -F arch=b64 -S execve -F key=clawtower_env
```

This won't capture env vars directly, but we can add a check for commands that are commonly used with `LD_PRELOAD`:

In `src/behavior.rs`, add a pattern that checks if the command was invoked with an unusual parent or has `LD_PRELOAD` in the environment. Since auditd EXECVE records may include it:

```rust
// In the command analysis section, check for LD_PRELOAD= in the full audit record
if let Some(ref raw) = event.raw_record {
    if raw.contains("LD_PRELOAD=") && !raw.contains("clawtower") && !raw.contains("clawtower") {
        // Check if this is a build tool
        if !BUILD_TOOL_BASES.iter().any(|t| binary.starts_with(t)) {
            return Some((BehaviorCategory::SecurityTamper, Severity::Critical));
        }
    }
}
```

**Step 3: Write tests**

```rust
#[test]
fn test_ld_preload_env_detected() {
    let event = AuditEvent {
        command: Some("ls".to_string()),
        binary: "ls".to_string(),
        raw_record: Some("LD_PRELOAD=/tmp/evil.so".to_string()),
        ppid_exe: None,
        ..Default::default()
    };
    let result = classify_behavior(&event);
    assert_eq!(result, Some((BehaviorCategory::SecurityTamper, Severity::Critical)));
}

#[test]
fn test_ld_preload_env_suppressed_for_build_tools() {
    let event = AuditEvent {
        command: Some("gcc test.c".to_string()),
        binary: "gcc".to_string(),
        raw_record: Some("LD_PRELOAD=/usr/lib/libasan.so".to_string()),
        ppid_exe: None,
        ..Default::default()
    };
    let result = classify_behavior(&event);
    assert_eq!(result, None, "Build tools using LD_PRELOAD should be suppressed");
}
```

**Step 4: Build and test**

```bash
cargo test 2>&1 | tail -5
cargo build --release 2>&1 | tail -5
```

**Step 5: Commit**

```bash
git add src/behavior.rs src/auditd.rs
git commit -m "feat: detect LD_PRELOAD env var injection (closes POC gap)"
```

**Impact:** Plugs the only detection gap from the POC (9/10 → 10/10)

---

### Task 9: Deploy and verify

**Files:**
- No new files — deployment of compiled binary + config

**Step 1: Deploy new binary**

```bash
sudo systemctl stop clawtower
sudo chattr -i /usr/local/bin/clawtower
sudo cp /home/openclaw/.openclaw/workspace/projects/ClawTower/target/release/clawtower /usr/local/bin/clawtower
sudo chattr +i /usr/local/bin/clawtower
sudo systemctl start clawtower
```

**Step 2: Wait 1 hour and check alert volume**

```bash
# After 1 hour:
BEFORE=$(date -d '1 hour ago' --iso-8601=seconds)
cat /var/log/clawtower/alerts.jsonl | jq -r "select(.timestamp > \"$BEFORE\") | .severity" | sort | uniq -c
```

Expected: ~220 alerts/hr (down from ~900), <2 Critical/hr (down from ~160).

**Step 3: Run POC again**

```bash
sudo bash scripts/poc-attack-sim.sh
```

Expected: 10/10 detection (LD_PRELOAD now caught).

**Step 4: Commit verification results**

Update `docs/POC-RESULTS.md` with v2 results if LD_PRELOAD is now detected.

```bash
git add -A && git commit -m "docs: update POC results after noise fixes"
git push origin main
```

---

## Execution Order

Tasks 1-4 are config/policy only — no Rust builds, can be done immediately.
Tasks 5-8 are Rust code changes — can be done in parallel, single `cargo build` at the end.
Task 9 is deployment — after all code changes are built.

**Suggested batching:**
1. Do Tasks 1-4 first (config + policy, immediate effect after service restart)
2. Do Tasks 5-8 (Rust changes, one build)
3. Task 9 (deploy + verify)

**Estimated time:** Tasks 1-4: ~15 min. Tasks 5-8: ~30 min code + 15 min build. Task 9: ~20 min (includes 1hr soak test).
