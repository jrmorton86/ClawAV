# Exfil Detection Fix — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace hardcoded credential-read detection with configurable per-file allowlists so all 25 Red Lobster exfil methods trigger alerts.

**Architecture:** Add a `[[sensitive_files]]` TOML array to config, parse it into a new `SensitiveFileConfig` struct, generate auditd rules dynamically from it, and rewrite `check_tamper_event`'s cred_read branch to look up the per-file allowlist instead of hardcoding `node`/`openclaw`.

**Tech Stack:** Rust, serde, TOML config, auditd

---

### Task 1: Add `SensitiveFileConfig` struct to `config.rs`

**Files:**
- Modify: `src/config.rs`

**Step 1: Write the failing test**

Add to the `#[cfg(test)]` module at the bottom of `src/config.rs`:

```rust
#[test]
fn test_sensitive_files_config_parsing() {
    let toml_str = r#"
        [general]
        watched_user = "1000"

        [auditd]
        log_path = "/var/log/audit/audit.log"
        enabled = true

        [network]
        log_path = "/var/log/syslog"
        log_prefix = "CLAWTOWER_NET"
        enabled = true

        [[sensitive_files]]
        path = "/home/openclaw/.openclaw/agents/main/agent/auth-profiles.json"
        allow = ["/usr/local/bin/node"]
        severity = "Critical"

        [[sensitive_files]]
        path = "/home/openclaw/.aws/credentials"
        allow = ["/usr/local/bin/node", "/usr/bin/aws"]
        severity = "Critical"
    "#;
    let config: Config = toml::from_str(toml_str).unwrap();
    assert_eq!(config.sensitive_files.len(), 2);
    assert_eq!(config.sensitive_files[0].path, "/home/openclaw/.openclaw/agents/main/agent/auth-profiles.json");
    assert_eq!(config.sensitive_files[0].allow, vec!["/usr/local/bin/node"]);
    assert_eq!(config.sensitive_files[0].severity, "Critical");
    assert_eq!(config.sensitive_files[1].allow.len(), 2);
}

#[test]
fn test_sensitive_files_defaults_when_missing() {
    let toml_str = r#"
        [general]
        watched_user = "1000"

        [auditd]
        log_path = "/var/log/audit/audit.log"
        enabled = true

        [network]
        log_path = "/var/log/syslog"
        log_prefix = "CLAWTOWER_NET"
        enabled = true
    "#;
    let config: Config = toml::from_str(toml_str).unwrap();
    // Should have default sensitive files (auth-profiles, aws creds, gateway.yaml, ssh keys, soul/memory/user)
    assert!(config.sensitive_files.len() >= 6);
    // All defaults should have at least one allowed exe
    for sf in &config.sensitive_files {
        assert!(!sf.allow.is_empty(), "Default sensitive file {} has empty allow list", sf.path);
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cd projects/ClawTower && cargo test test_sensitive_files -- --nocapture`
Expected: FAIL — `Config` has no `sensitive_files` field

**Step 3: Write the implementation**

Add this struct above the `Config` struct in `src/config.rs`:

```rust
/// Configuration for a sensitive file that should trigger alerts on unauthorized reads.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SensitiveFileConfig {
    /// Absolute path to the sensitive file
    pub path: String,
    /// List of absolute exe paths allowed to read this file without alerting
    #[serde(default)]
    pub allow: Vec<String>,
    /// Alert severity: "Critical", "Warning", or "Info"
    #[serde(default = "default_sensitive_severity")]
    pub severity: String,
}

fn default_sensitive_severity() -> String {
    "Critical".to_string()
}

/// Default sensitive files to monitor when none are configured.
pub fn default_sensitive_files() -> Vec<SensitiveFileConfig> {
    vec![
        SensitiveFileConfig {
            path: "/home/openclaw/.openclaw/agents/main/agent/auth-profiles.json".to_string(),
            allow: vec!["/usr/local/bin/node".to_string()],
            severity: "Critical".to_string(),
        },
        SensitiveFileConfig {
            path: "/home/openclaw/.aws/credentials".to_string(),
            allow: vec!["/usr/local/bin/node".to_string(), "/usr/bin/aws".to_string()],
            severity: "Critical".to_string(),
        },
        SensitiveFileConfig {
            path: "/home/openclaw/.aws/config".to_string(),
            allow: vec!["/usr/local/bin/node".to_string(), "/usr/bin/aws".to_string()],
            severity: "Critical".to_string(),
        },
        SensitiveFileConfig {
            path: "/home/openclaw/.ssh/id_ed25519".to_string(),
            allow: vec!["/usr/bin/ssh".to_string(), "/usr/bin/scp".to_string()],
            severity: "Critical".to_string(),
        },
        SensitiveFileConfig {
            path: "/home/openclaw/.ssh/id_rsa".to_string(),
            allow: vec!["/usr/bin/ssh".to_string(), "/usr/bin/scp".to_string()],
            severity: "Critical".to_string(),
        },
        SensitiveFileConfig {
            path: "/home/openclaw/.openclaw/gateway.yaml".to_string(),
            allow: vec!["/usr/local/bin/node".to_string()],
            severity: "Critical".to_string(),
        },
        SensitiveFileConfig {
            path: "/home/openclaw/.openclaw/workspace/SOUL.md".to_string(),
            allow: vec!["/usr/local/bin/node".to_string(), "/usr/local/bin/clawtower".to_string()],
            severity: "Warning".to_string(),
        },
        SensitiveFileConfig {
            path: "/home/openclaw/.openclaw/workspace/MEMORY.md".to_string(),
            allow: vec!["/usr/local/bin/node".to_string(), "/usr/local/bin/clawtower".to_string()],
            severity: "Warning".to_string(),
        },
        SensitiveFileConfig {
            path: "/home/openclaw/.openclaw/workspace/USER.md".to_string(),
            allow: vec!["/usr/local/bin/node".to_string(), "/usr/local/bin/clawtower".to_string()],
            severity: "Warning".to_string(),
        },
    ]
}
```

Add the field to the `Config` struct:

```rust
    #[serde(default = "default_sensitive_files")]
    pub sensitive_files: Vec<SensitiveFileConfig>,
```

**Step 4: Run test to verify it passes**

Run: `cd projects/ClawTower && cargo test test_sensitive_files -- --nocapture`
Expected: PASS (both tests)

**Step 5: Commit**

```bash
cd projects/ClawTower
git add src/config.rs
git commit -m "feat: add SensitiveFileConfig with per-file allowlists and defaults"
```

---

### Task 2: Generate auditd rules dynamically from config

**Files:**
- Modify: `src/auditd.rs`

**Step 1: Write the failing test**

Add to the `#[cfg(test)]` module in `src/auditd.rs`:

```rust
#[test]
fn test_generate_sensitive_file_rules() {
    use crate::config::SensitiveFileConfig;
    let files = vec![
        SensitiveFileConfig {
            path: "/tmp/test-secret.json".to_string(),
            allow: vec!["/usr/local/bin/node".to_string()],
            severity: "Critical".to_string(),
        },
    ];
    let rules = generate_sensitive_file_rules(&files);
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0], "-w /tmp/test-secret.json -p r -k clawtower_sensitive_read");
}

#[test]
fn test_generate_sensitive_file_rules_empty() {
    let rules = generate_sensitive_file_rules(&[]);
    assert!(rules.is_empty());
}
```

**Step 2: Run test to verify it fails**

Run: `cd projects/ClawTower && cargo test test_generate_sensitive_file_rules -- --nocapture`
Expected: FAIL — `generate_sensitive_file_rules` not found

**Step 3: Write the implementation**

Add this function to `src/auditd.rs` (near the top, after `RECOMMENDED_AUDIT_RULES`):

```rust
use crate::config::SensitiveFileConfig;

/// Generate auditd watch rules from the sensitive_files config.
/// These replace the hardcoded `clawtower_cred_read` rules.
pub fn generate_sensitive_file_rules(files: &[SensitiveFileConfig]) -> Vec<String> {
    files.iter().map(|f| {
        format!("-w {} -p r -k clawtower_sensitive_read", f.path)
    }).collect()
}
```

**Step 4: Run test to verify it passes**

Run: `cd projects/ClawTower && cargo test test_generate_sensitive_file_rules -- --nocapture`
Expected: PASS

**Step 5: Commit**

```bash
cd projects/ClawTower
git add src/auditd.rs
git commit -m "feat: generate auditd rules dynamically from sensitive_files config"
```

---

### Task 3: Rewrite cred_read detection to use per-file allowlists

**Files:**
- Modify: `src/auditd.rs`

**Step 1: Write the failing tests**

Add to the `#[cfg(test)]` module in `src/auditd.rs`:

```rust
#[test]
fn test_check_sensitive_read_blocked() {
    use crate::config::SensitiveFileConfig;
    let files = vec![
        SensitiveFileConfig {
            path: "/home/openclaw/.openclaw/agents/main/agent/auth-profiles.json".to_string(),
            allow: vec!["/usr/local/bin/node".to_string()],
            severity: "Critical".to_string(),
        },
    ];
    let event = ParsedEvent {
        syscall_name: "openat".to_string(),
        command: None,
        args: vec![],
        file_path: Some("/home/openclaw/.openclaw/agents/main/agent/auth-profiles.json".to_string()),
        success: true,
        actor: Actor::Agent,
        raw: r#"type=SYSCALL msg=audit(1707849600.123:456): arch=c00000b7 syscall=56 success=yes exe="/usr/bin/cat" key="clawtower_sensitive_read""#.to_string(),
    };
    let alert = check_sensitive_read(&event, &files);
    assert!(alert.is_some());
    let alert = alert.unwrap();
    assert_eq!(alert.severity, Severity::Critical);
    assert!(alert.message.contains("cat"));
}

#[test]
fn test_check_sensitive_read_allowed() {
    use crate::config::SensitiveFileConfig;
    let files = vec![
        SensitiveFileConfig {
            path: "/home/openclaw/.openclaw/agents/main/agent/auth-profiles.json".to_string(),
            allow: vec!["/usr/local/bin/node".to_string()],
            severity: "Critical".to_string(),
        },
    ];
    let event = ParsedEvent {
        syscall_name: "openat".to_string(),
        command: None,
        args: vec![],
        file_path: Some("/home/openclaw/.openclaw/agents/main/agent/auth-profiles.json".to_string()),
        success: true,
        actor: Actor::Agent,
        raw: r#"type=SYSCALL msg=audit(1707849600.123:456): arch=c00000b7 syscall=56 success=yes exe="/usr/local/bin/node" key="clawtower_sensitive_read""#.to_string(),
    };
    let alert = check_sensitive_read(&event, &files);
    assert!(alert.is_some());
    // Allowed exe should produce Info severity, not Critical
    assert_eq!(alert.unwrap().severity, Severity::Info);
}

#[test]
fn test_check_sensitive_read_warning_severity() {
    use crate::config::SensitiveFileConfig;
    let files = vec![
        SensitiveFileConfig {
            path: "/home/openclaw/.openclaw/workspace/SOUL.md".to_string(),
            allow: vec!["/usr/local/bin/node".to_string()],
            severity: "Warning".to_string(),
        },
    ];
    let event = ParsedEvent {
        syscall_name: "openat".to_string(),
        command: None,
        args: vec![],
        file_path: Some("/home/openclaw/.openclaw/workspace/SOUL.md".to_string()),
        success: true,
        actor: Actor::Agent,
        raw: r#"type=SYSCALL msg=audit(1707849600.123:456): arch=c00000b7 syscall=56 success=yes exe="/usr/bin/python3" key="clawtower_sensitive_read""#.to_string(),
    };
    let alert = check_sensitive_read(&event, &files);
    assert!(alert.is_some());
    assert_eq!(alert.unwrap().severity, Severity::Warning);
}

#[test]
fn test_check_sensitive_read_no_match() {
    use crate::config::SensitiveFileConfig;
    let files = vec![
        SensitiveFileConfig {
            path: "/home/openclaw/.aws/credentials".to_string(),
            allow: vec!["/usr/local/bin/node".to_string()],
            severity: "Critical".to_string(),
        },
    ];
    // Event with no sensitive_read key — should return None
    let event = ParsedEvent {
        syscall_name: "openat".to_string(),
        command: None,
        args: vec![],
        file_path: Some("/tmp/harmless.txt".to_string()),
        success: true,
        actor: Actor::Agent,
        raw: r#"type=SYSCALL msg=audit(1707849600.123:456): arch=c00000b7 syscall=56 success=yes exe="/usr/bin/cat" key="some_other_key""#.to_string(),
    };
    let alert = check_sensitive_read(&event, &files);
    assert!(alert.is_none());
}
```

**Step 2: Run test to verify it fails**

Run: `cd projects/ClawTower && cargo test test_check_sensitive_read -- --nocapture`
Expected: FAIL — `check_sensitive_read` not found

**Step 3: Write the implementation**

Add this function to `src/auditd.rs` (right before `check_tamper_event`):

```rust
/// Check if an audit event is an unauthorized read of a sensitive file.
///
/// Returns an alert if the event matches a `clawtower_sensitive_read` audit key
/// and the reading executable is not in the per-file allowlist.
/// Allowed executables get an Info-level alert for audit trail purposes.
pub fn check_sensitive_read(event: &ParsedEvent, sensitive_files: &[SensitiveFileConfig]) -> Option<Alert> {
    let line = &event.raw;
    if !line.contains("key=\"clawtower_sensitive_read\"") && !line.contains("key=clawtower_sensitive_read") {
        return None;
    }

    let exe = extract_field(line, "exe").unwrap_or("unknown");
    let file_path = event.file_path.as_deref()
        .or_else(|| {
            // Try to match by checking which sensitive file paths appear in the raw line
            sensitive_files.iter()
                .find(|sf| line.contains(&sf.path))
                .map(|sf| sf.path.as_str())
        })
        .unwrap_or("unknown");

    // Find the matching sensitive file config
    let config = sensitive_files.iter().find(|sf| file_path.contains(&sf.path) || sf.path.contains(file_path));

    match config {
        Some(sf) => {
            let is_allowed = sf.allow.iter().any(|a| exe.contains(a.as_str()) || a.contains(exe));
            if is_allowed {
                Some(Alert::new(
                    Severity::Info,
                    "auditd:sensitive_read",
                    &format!("🔑 Sensitive file access (expected): {} by {}", file_path, exe),
                ))
            } else {
                let severity = match sf.severity.as_str() {
                    "Critical" => Severity::Critical,
                    "Warning" => Severity::Warning,
                    _ => Severity::Critical,
                };
                Some(Alert::new(
                    severity,
                    "auditd:sensitive_read",
                    &format!("🔑 SENSITIVE FILE READ: {} accessed by {} — possible exfiltration", file_path, exe),
                ))
            }
        }
        None => {
            // Sensitive read key but no matching config — alert as Critical (unknown file)
            Some(Alert::new(
                Severity::Critical,
                "auditd:sensitive_read",
                &format!("🔑 SENSITIVE FILE READ: {} accessed by {} — no config match", file_path, exe),
            ))
        }
    }
}
```

Then update `check_tamper_event` to remove the old `clawtower_cred_read` block (lines 353-375 approximately). Replace it with a comment:

```rust
    // Credential/sensitive file read detection moved to check_sensitive_read()
    // which uses per-file allowlists from config.sensitive_files
```

**Step 4: Run test to verify it passes**

Run: `cd projects/ClawTower && cargo test test_check_sensitive_read -- --nocapture`
Expected: PASS (all 4 tests)

**Step 5: Commit**

```bash
cd projects/ClawTower
git add src/auditd.rs
git commit -m "feat: add check_sensitive_read with per-file allowlists, remove hardcoded cred_read"
```

---

### Task 4: Wire `check_sensitive_read` into the audit pipeline

**Files:**
- Modify: `src/auditd.rs` (the `tail_audit_log_with_behavior_and_policy` function)

**Step 1: Examine the pipeline function**

Read `tail_audit_log_with_behavior_and_policy` to find where `check_tamper_event` is called — add `check_sensitive_read` call adjacent to it.

**Step 2: Add config threading**

The tail function needs access to `Config.sensitive_files`. Add a `sensitive_files: Vec<SensitiveFileConfig>` parameter (or pass the full `Config` / `Arc<Config>`). Thread it through from wherever the tail function is called (likely `src/main.rs`).

**Step 3: Insert the check**

After the `check_tamper_event` call, add:

```rust
if let Some(alert) = check_sensitive_read(&event, &sensitive_files) {
    let _ = alert_tx.send(alert).await;
}
```

**Step 4: Update `RECOMMENDED_AUDIT_RULES`**

Remove the hardcoded `clawtower_cred_read` entries (lines 31-36). The rules are now generated dynamically by `generate_sensitive_file_rules()`. Wherever the rules are installed (startup / rule-loading code), call `generate_sensitive_file_rules(&config.sensitive_files)` and merge with the remaining `RECOMMENDED_AUDIT_RULES`.

**Step 5: Build and run tests**

Run: `cd projects/ClawTower && cargo build 2>&1 | tail -5 && cargo test 2>&1 | tail -10`
Expected: Compiles cleanly, all existing + new tests pass

**Step 6: Commit**

```bash
cd projects/ClawTower
git add src/
git commit -m "feat: wire check_sensitive_read into audit pipeline, remove hardcoded rules"
```

---

### Task 5: Update existing tests for the old cred_read behavior

**Files:**
- Modify: `src/behavior.rs` (tests `test_cred_read_event_unknown_exe` and `test_cred_read_event_openclaw_exe`)

**Step 1: Update or remove old tests**

The two tests in `behavior.rs` at lines ~2468 and ~2487 reference the old `clawtower_cred_read` key. Update them to use `clawtower_sensitive_read` and test through the new `check_sensitive_read` function, OR remove them if the new tests in Task 3 fully cover the behavior.

**Step 2: Run full test suite**

Run: `cd projects/ClawTower && cargo test 2>&1 | tail -20`
Expected: All tests pass, zero warnings about dead code

**Step 3: Commit**

```bash
cd projects/ClawTower
git add src/behavior.rs
git commit -m "test: update cred_read tests for new sensitive_read pipeline"
```

---

### Task 6: Update config files and documentation

**Files:**
- Modify: `config.toml`
- Modify: `config.example.yaml` (if exists, otherwise create a TOML example section)
- Modify: `README.md` or relevant docs

**Step 1: Add sensitive_files section to config.toml**

```toml
[[sensitive_files]]
path = "/home/openclaw/.openclaw/agents/main/agent/auth-profiles.json"
allow = ["/usr/local/bin/node"]
severity = "Critical"

[[sensitive_files]]
path = "/home/openclaw/.aws/credentials"
allow = ["/usr/local/bin/node", "/usr/bin/aws"]
severity = "Critical"

[[sensitive_files]]
path = "/home/openclaw/.openclaw/gateway.yaml"
allow = ["/usr/local/bin/node"]
severity = "Critical"

[[sensitive_files]]
path = "/home/openclaw/.openclaw/workspace/SOUL.md"
allow = ["/usr/local/bin/node", "/usr/local/bin/clawtower"]
severity = "Warning"

[[sensitive_files]]
path = "/home/openclaw/.openclaw/workspace/MEMORY.md"
allow = ["/usr/local/bin/node", "/usr/local/bin/clawtower"]
severity = "Warning"

[[sensitive_files]]
path = "/home/openclaw/.openclaw/workspace/USER.md"
allow = ["/usr/local/bin/node", "/usr/local/bin/clawtower"]
severity = "Warning"
```

**Step 2: Commit**

```bash
cd projects/ClawTower
git add config.toml config.example.yaml docs/
git commit -m "docs: add sensitive_files config section"
```

---

### Task 7: Run Red Lobster exfil test suite

**Step 1: Build release binary**

Run: `cd projects/ClawTower && cargo build --release 2>&1 | tail -3`

**Step 2: Deploy and restart ClawTower** (if running locally)

**Step 3: Run the exfil test script**

Run: `bash scripts/redlobster-exfil.sh`

**Step 4: Review results**

Expected: 25/25 detected (or close — any misses need investigation)

**Step 5: Commit results**

```bash
cd projects/ClawTower
cp /tmp/redlobster/results/exfil.md docs/pentest-results/2026-02-16-redlobster-v5-exfil.md
git add docs/pentest-results/
git commit -m "test: Red Lobster v5 exfil results — configurable sensitive file detection"
```
