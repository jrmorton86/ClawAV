# OpenClaw Security Integration — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make ClawAV the automated enforcement layer for all OpenClaw security best practices — credential monitoring, permission auditing, config drift detection, and advanced attack surface monitoring.

**Architecture:** Three phases. Phase 1 adds OpenClaw audit CLI as a scan source + credential paths to sentinel + expanded permission checks. Phase 2 adds config drift detection with baseline tracking. Phase 3 adds mDNS, plugin, session log, and Control UI monitoring.

**Tech Stack:** Rust, serde_json (config parsing), tokio (async), notify (inotify via sentinel), existing ClawAV scanner/sentinel/config infrastructure.

**Design Doc:** `docs/plans/2026-02-15-openclaw-security-integration-design.md`

---

## Phase 1: Audit Integration + Credential Monitoring

### Task 1: Add OpenClaw config section to config.rs

**Files:**
- Modify: `src/config.rs`
- Test: inline `#[cfg(test)]` in `src/config.rs`

**Step 1: Write the failing test**

Add to the test module in `src/config.rs`:

```rust
#[test]
fn test_openclaw_config_defaults() {
    let config: OpenClawConfig = toml::from_str("").unwrap();
    assert!(config.enabled);
    assert_eq!(config.state_dir, "/home/openclaw/.openclaw");
    assert!(config.audit_on_scan);
    assert!(config.config_drift_check);
}

#[test]
fn test_openclaw_config_custom() {
    let toml_str = r#"
        enabled = false
        config_path = "/tmp/test.json"
        state_dir = "/tmp/openclaw"
        audit_on_scan = false
    "#;
    let config: OpenClawConfig = toml::from_str(toml_str).unwrap();
    assert!(!config.enabled);
    assert_eq!(config.config_path, "/tmp/test.json");
    assert!(!config.audit_on_scan);
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/openclaw/.openclaw/workspace/projects/ClawAV && cargo test test_openclaw_config -- --nocapture`
Expected: FAIL — `OpenClawConfig` doesn't exist

**Step 3: Write minimal implementation**

Add to `src/config.rs` before the `Config` struct:

```rust
/// OpenClaw-specific security monitoring configuration.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct OpenClawConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_openclaw_config_path")]
    pub config_path: String,
    #[serde(default = "default_openclaw_state_dir")]
    pub state_dir: String,
    #[serde(default = "default_openclaw_audit_cmd")]
    pub audit_command: String,
    #[serde(default = "default_true")]
    pub audit_on_scan: bool,
    #[serde(default = "default_true")]
    pub config_drift_check: bool,
    #[serde(default = "default_openclaw_baseline_path")]
    pub baseline_path: String,
    #[serde(default)]
    pub mdns_check: bool,
    #[serde(default)]
    pub plugin_watch: bool,
    #[serde(default)]
    pub session_log_audit: bool,
}

fn default_openclaw_config_path() -> String { "/home/openclaw/.openclaw/openclaw.json".to_string() }
fn default_openclaw_state_dir() -> String { "/home/openclaw/.openclaw".to_string() }
fn default_openclaw_audit_cmd() -> String { "openclaw security audit --deep".to_string() }
fn default_openclaw_baseline_path() -> String { "/etc/clawav/openclaw-config-baseline.json".to_string() }

impl Default for OpenClawConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            config_path: default_openclaw_config_path(),
            state_dir: default_openclaw_state_dir(),
            audit_command: default_openclaw_audit_cmd(),
            audit_on_scan: true,
            config_drift_check: true,
            baseline_path: default_openclaw_baseline_path(),
            mdns_check: false,
            plugin_watch: false,
            session_log_audit: false,
        }
    }
}
```

Add field to `Config` struct:

```rust
#[serde(default)]
pub openclaw: OpenClawConfig,
```

**Step 4: Run test to verify it passes**

Run: `cargo test test_openclaw_config -- --nocapture`
Expected: PASS

**Step 5: Commit**

```bash
git add src/config.rs
git commit -m "feat: add OpenClaw security monitoring config section"
```

---

### Task 2: Expand OpenClaw permission checks in scanner.rs

**Files:**
- Modify: `src/scanner.rs` (the `scan_openclaw_security()` function)
- Test: inline tests in `src/scanner.rs`

**Step 1: Write failing tests**

```rust
#[test]
fn test_check_path_permissions_secure() {
    // Create temp dir with 700 perms
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let result = check_path_permissions(dir.path().to_str().unwrap(), 0o700, "test_dir");
    assert_eq!(result.status, ScanStatus::Pass);
}

#[test]
fn test_check_path_permissions_too_open() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let result = check_path_permissions(dir.path().to_str().unwrap(), 0o700, "test_dir");
    assert_eq!(result.status, ScanStatus::Fail);
}

#[test]
fn test_check_symlink_safety() {
    let dir = tempfile::tempdir().unwrap();
    // No symlinks → pass
    let result = check_symlinks_in_dir(dir.path().to_str().unwrap());
    assert_eq!(result.status, ScanStatus::Pass);
}
```

**Step 2: Run tests to verify failure**

Run: `cargo test test_check_path_permissions -- --nocapture`
Expected: FAIL — functions don't exist

**Step 3: Implement permission check helpers**

Add to `scanner.rs`:

```rust
use std::os::unix::fs::PermissionsExt;

/// Check that a path has permissions no more permissive than `max_mode`.
fn check_path_permissions(path: &str, max_mode: u32, label: &str) -> ScanResult {
    match std::fs::metadata(path) {
        Ok(meta) => {
            let mode = meta.permissions().mode() & 0o777;
            if mode <= max_mode {
                ScanResult::new(
                    &format!("openclaw:perms:{}", label),
                    ScanStatus::Pass,
                    &format!("{} permissions {:o} (max {:o})", path, mode, max_mode),
                )
            } else {
                ScanResult::new(
                    &format!("openclaw:perms:{}", label),
                    ScanStatus::Fail,
                    &format!("{} permissions {:o} — should be {:o} or tighter", path, mode, max_mode),
                )
            }
        }
        Err(_) => ScanResult::new(
            &format!("openclaw:perms:{}", label),
            ScanStatus::Warn,
            &format!("{} not found — skipping permission check", path),
        ),
    }
}

/// Check for symlinks inside a directory that point outside it (symlink attack vector).
fn check_symlinks_in_dir(dir: &str) -> ScanResult {
    let dir_path = std::path::Path::new(dir);
    if !dir_path.exists() {
        return ScanResult::new("openclaw:symlinks", ScanStatus::Warn,
            &format!("{} not found", dir));
    }
    
    let mut suspicious = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir_path) {
        for entry in entries.flatten() {
            if entry.file_type().map(|ft| ft.is_symlink()).unwrap_or(false) {
                if let Ok(target) = std::fs::read_link(entry.path()) {
                    let resolved = entry.path().parent()
                        .unwrap_or(dir_path)
                        .join(&target);
                    if let Ok(canonical) = std::fs::canonicalize(&resolved) {
                        if !canonical.starts_with(dir_path) {
                            suspicious.push(format!("{} → {}",
                                entry.path().display(), canonical.display()));
                        }
                    }
                }
            }
        }
    }
    
    if suspicious.is_empty() {
        ScanResult::new("openclaw:symlinks", ScanStatus::Pass,
            &format!("No suspicious symlinks in {}", dir))
    } else {
        ScanResult::new("openclaw:symlinks", ScanStatus::Fail,
            &format!("Symlinks pointing outside directory: {}", suspicious.join(", ")))
    }
}
```

Then expand `scan_openclaw_security()` to call these:

```rust
// Permission checks (from OpenClaw security docs)
let state_dir = "/home/openclaw/.openclaw";
results.push(check_path_permissions(state_dir, 0o700, "state_dir"));
results.push(check_path_permissions(
    &format!("{}/openclaw.json", state_dir), 0o600, "config"));

// Check credential files aren't group/world readable
let cred_dir = format!("{}/credentials", state_dir);
if std::path::Path::new(&cred_dir).exists() {
    results.push(check_path_permissions(&cred_dir, 0o700, "credentials_dir"));
    if let Ok(entries) = std::fs::read_dir(&cred_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_file() {
                results.push(check_path_permissions(
                    p.to_str().unwrap_or(""), 0o600,
                    &format!("cred:{}", p.file_name().unwrap_or_default().to_string_lossy())));
            }
        }
    }
}

// Session log permissions
let agents_dir = format!("{}/agents", state_dir);
if let Ok(agents) = std::fs::read_dir(&agents_dir) {
    for agent in agents.flatten() {
        let sessions_dir = agent.path().join("sessions");
        if sessions_dir.exists() {
            results.push(check_path_permissions(
                sessions_dir.to_str().unwrap_or(""), 0o700,
                &format!("sessions:{}", agent.file_name().to_string_lossy())));
        }
    }
}

// Symlink safety check
results.push(check_symlinks_in_dir(state_dir));
```

**Step 4: Run tests**

Run: `cargo test test_check_path -- --nocapture && cargo test test_check_symlink -- --nocapture`
Expected: PASS

**Step 5: Commit**

```bash
git add src/scanner.rs
git commit -m "feat: expanded OpenClaw permission and symlink checks"
```

---

### Task 3: Add OpenClaw audit CLI integration

**Files:**
- Modify: `src/scanner.rs`
- Test: inline tests

**Step 1: Write failing test**

```rust
#[test]
fn test_parse_openclaw_audit_output() {
    let output = "⚠ Gateway auth: mode is 'none' — anyone on the network can connect
✓ DM policy: pairing (secure)
⚠ groupPolicy is 'open' for slack — restrict to allowlist
✓ Filesystem permissions: ~/.openclaw is 700
✗ Browser control: CDP port exposed on 0.0.0.0";
    let results = parse_openclaw_audit_output(output);
    assert_eq!(results.len(), 5);
    assert_eq!(results[0].status, ScanStatus::Warn);  // ⚠
    assert_eq!(results[1].status, ScanStatus::Pass);   // ✓
    assert_eq!(results[4].status, ScanStatus::Fail);   // ✗
}

#[test]
fn test_parse_openclaw_audit_empty() {
    let results = parse_openclaw_audit_output("");
    assert!(results.is_empty());
}
```

**Step 2: Run tests**

Run: `cargo test test_parse_openclaw_audit -- --nocapture`
Expected: FAIL

**Step 3: Implement audit output parser**

```rust
/// Parse `openclaw security audit` text output into ScanResults.
///
/// Line format: `✓ description` (pass), `⚠ description` (warn), `✗ description` (fail)
fn parse_openclaw_audit_output(output: &str) -> Vec<ScanResult> {
    let mut results = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }
        
        let (status, detail) = if trimmed.starts_with('✓') || trimmed.starts_with("✓") {
            (ScanStatus::Pass, trimmed.trim_start_matches('✓').trim())
        } else if trimmed.starts_with('⚠') || trimmed.starts_with("⚠") {
            (ScanStatus::Warn, trimmed.trim_start_matches('⚠').trim())
        } else if trimmed.starts_with('✗') || trimmed.starts_with("✗") {
            (ScanStatus::Fail, trimmed.trim_start_matches('✗').trim())
        } else {
            continue; // skip non-finding lines (headers, etc.)
        };
        
        // Extract category from description (first word before colon, or "general")
        let category = detail.split(':').next()
            .unwrap_or("general")
            .trim()
            .to_lowercase()
            .replace(' ', "_");
        
        results.push(ScanResult::new(
            &format!("openclaw:audit:{}", category),
            status,
            detail,
        ));
    }
    results
}

/// Run `openclaw security audit --deep` and parse results.
fn run_openclaw_audit(command: &str) -> Vec<ScanResult> {
    let parts: Vec<&str> = command.split_whitespace().collect();
    if parts.is_empty() {
        return vec![ScanResult::new("openclaw:audit", ScanStatus::Warn,
            "Empty audit command configured")];
    }
    
    match Command::new(parts[0]).args(&parts[1..]).output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let mut results = parse_openclaw_audit_output(&stdout);
            if results.is_empty() && !stderr.is_empty() {
                results.push(ScanResult::new("openclaw:audit", ScanStatus::Warn,
                    &format!("Audit produced no findings. stderr: {}", 
                        stderr.chars().take(200).collect::<String>())));
            }
            if !output.status.success() {
                results.push(ScanResult::new("openclaw:audit", ScanStatus::Warn,
                    &format!("Audit exited with code {}", output.status)));
            }
            results
        }
        Err(e) => vec![ScanResult::new("openclaw:audit", ScanStatus::Warn,
            &format!("Failed to run audit: {} (is openclaw installed?)", e))],
    }
}
```

Add to `run_all_scans()` (conditionally based on config — for now, always run):

```rust
// OpenClaw audit CLI integration
results.extend(run_openclaw_audit("openclaw security audit --deep"));
```

**Step 4: Run tests**

Run: `cargo test test_parse_openclaw_audit -- --nocapture`
Expected: PASS

**Step 5: Commit**

```bash
git add src/scanner.rs
git commit -m "feat: integrate openclaw security audit as scan source"
```

---

### Task 4: Add OpenClaw credential paths to sentinel

**Files:**
- Modify: `src/config.rs` (default sentinel paths)
- Modify: `src/main.rs` or wherever sentinel paths are assembled
- Test: verify sentinel config includes new paths

**Step 1: Write failing test**

```rust
#[test]
fn test_default_sentinel_includes_openclaw_creds() {
    let config = Config::default();
    let paths: Vec<&str> = config.sentinel.watched_paths.iter()
        .map(|w| w.path.as_str()).collect();
    assert!(paths.iter().any(|p| p.contains(".openclaw/credentials")));
    assert!(paths.iter().any(|p| p.contains("openclaw.json")));
}
```

**Step 2: Run test**

Run: `cargo test test_default_sentinel_includes_openclaw -- --nocapture`
Expected: FAIL

**Step 3: Add default OpenClaw paths to sentinel config**

In the `Default` impl for `SentinelConfig`, add to `watched_paths`:

```rust
WatchedPath {
    path: "/home/openclaw/.openclaw/openclaw.json".to_string(),
    policy: WatchPolicy::Watched,
},
WatchedPath {
    path: "/home/openclaw/.openclaw/credentials".to_string(),
    policy: WatchPolicy::Protected,
},
WatchedPath {
    path: "/home/openclaw/.openclaw/agents/main/agent/auth-profiles.json".to_string(),
    policy: WatchPolicy::Protected,
},
```

**Step 4: Run test**

Run: `cargo test test_default_sentinel_includes_openclaw -- --nocapture`
Expected: PASS

**Step 5: Commit**

```bash
git add src/config.rs
git commit -m "feat: add OpenClaw credential paths to sentinel defaults"
```

---

## Phase 2: Config Drift Detection

### Task 5: Create openclaw_config.rs module

**Files:**
- Create: `src/openclaw_config.rs`
- Modify: `src/main.rs` (add `mod openclaw_config;`)
- Test: inline tests

**Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    fn sample_config() -> &'static str {
        r#"{
            "channels": {
                "slack": { "dmPolicy": "pairing", "groupPolicy": "allowlist" }
            },
            "gateway": {
                "auth": { "mode": "token", "token": "secret123" },
                "bind": "loopback"
            },
            "logging": { "redactSensitive": "tools" }
        }"#
    }
    
    #[test]
    fn test_extract_security_fields() {
        let fields = extract_security_fields(sample_config());
        assert_eq!(fields.get("gateway.auth.mode").unwrap(), "token");
        assert_eq!(fields.get("gateway.bind").unwrap(), "loopback");
    }
    
    #[test]
    fn test_detect_drift_no_change() {
        let baseline = extract_security_fields(sample_config());
        let current = extract_security_fields(sample_config());
        let drifts = detect_drift(&baseline, &current);
        assert!(drifts.is_empty());
    }
    
    #[test]
    fn test_detect_drift_regression() {
        let baseline = extract_security_fields(sample_config());
        let mut current = baseline.clone();
        current.insert("gateway.auth.mode".to_string(), "none".to_string());
        let drifts = detect_drift(&baseline, &current);
        assert_eq!(drifts.len(), 1);
        assert!(drifts[0].is_regression);
    }
}
```

**Step 2: Run tests**

Run: `cargo test openclaw_config -- --nocapture`
Expected: FAIL — module doesn't exist

**Step 3: Implement the module**

Create `src/openclaw_config.rs`:

```rust
//! OpenClaw configuration drift detection.
//!
//! Parses `openclaw.json`, extracts security-critical fields, and compares
//! against a stored baseline to detect regressions (e.g., auth disabled,
//! policies loosened, dangerous flags enabled).

use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;

use crate::scanner::{ScanResult, ScanStatus};

/// A detected configuration drift.
#[derive(Debug, Clone)]
pub struct ConfigDrift {
    pub field: String,
    pub baseline_value: String,
    pub current_value: String,
    pub is_regression: bool,
    pub description: String,
}

/// Fields considered security-critical and their "safe" patterns.
const REGRESSION_RULES: &[(&str, &str)] = &[
    ("gateway.auth.mode", "none"),                              // auth disabled
    ("gateway.bind", "0.0.0.0"),                                // public bind
    ("logging.redactSensitive", "off"),                         // logging unredacted
    ("controlUi.dangerouslyDisableDeviceAuth", "true"),         // dangerous flag
    ("controlUi.allowInsecureAuth", "true"),                    // insecure auth
];

/// DM/group policy fields — regression if changed to "open"
const POLICY_OPEN_FIELDS: &[&str] = &[
    "dmPolicy",
    "groupPolicy",
];

/// Extract security-critical fields from OpenClaw JSON config.
pub fn extract_security_fields(json_str: &str) -> HashMap<String, String> {
    let mut fields = HashMap::new();
    
    if let Ok(val) = serde_json::from_str::<Value>(json_str) {
        // Flatten and extract known fields
        extract_recursive(&val, "", &mut fields);
    }
    
    fields
}

fn extract_recursive(val: &Value, prefix: &str, out: &mut HashMap<String, String>) {
    match val {
        Value::Object(map) => {
            for (k, v) in map {
                let key = if prefix.is_empty() { k.clone() } else { format!("{}.{}", prefix, k) };
                extract_recursive(v, &key, out);
            }
        }
        Value::String(s) => { out.insert(prefix.to_string(), s.clone()); }
        Value::Bool(b) => { out.insert(prefix.to_string(), b.to_string()); }
        Value::Number(n) => { out.insert(prefix.to_string(), n.to_string()); }
        _ => {}
    }
}

/// Compare baseline and current fields, returning detected drifts.
pub fn detect_drift(
    baseline: &HashMap<String, String>,
    current: &HashMap<String, String>,
) -> Vec<ConfigDrift> {
    let mut drifts = Vec::new();
    
    for (field, cur_val) in current {
        if let Some(base_val) = baseline.get(field) {
            if base_val != cur_val {
                let is_regression = is_security_regression(field, cur_val);
                drifts.push(ConfigDrift {
                    field: field.clone(),
                    baseline_value: base_val.clone(),
                    current_value: cur_val.clone(),
                    is_regression,
                    description: if is_regression {
                        format!("{} changed from '{}' to '{}' — SECURITY REGRESSION", field, base_val, cur_val)
                    } else {
                        format!("{} changed from '{}' to '{}'", field, base_val, cur_val)
                    },
                });
            }
        }
    }
    
    // Check for removed fields that were in baseline
    for (field, base_val) in baseline {
        if !current.contains_key(field) {
            let key_parts: Vec<&str> = field.split('.').collect();
            let is_security = key_parts.iter().any(|p| 
                ["auth", "policy", "dmPolicy", "groupPolicy", "bind", "sandbox"].contains(p));
            if is_security {
                drifts.push(ConfigDrift {
                    field: field.clone(),
                    baseline_value: base_val.clone(),
                    current_value: "(removed)".to_string(),
                    is_regression: true,
                    description: format!("{} was '{}', now removed — possible security regression", field, base_val),
                });
            }
        }
    }
    
    drifts
}

fn is_security_regression(field: &str, new_value: &str) -> bool {
    // Check direct regression rules
    for (rule_field, bad_value) in REGRESSION_RULES {
        if field.ends_with(rule_field) && new_value == *bad_value {
            return true;
        }
    }
    // Check policy open regressions
    for policy_field in POLICY_OPEN_FIELDS {
        if field.ends_with(policy_field) && new_value == "open" {
            return true;
        }
    }
    false
}

/// Load baseline from file, or return None if it doesn't exist.
pub fn load_baseline(path: &str) -> Option<HashMap<String, String>> {
    std::fs::read_to_string(path).ok()
        .and_then(|s| serde_json::from_str(&s).ok())
}

/// Save current fields as the new baseline.
pub fn save_baseline(path: &str, fields: &HashMap<String, String>) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(fields)?;
    if let Some(parent) = Path::new(path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, json)?;
    Ok(())
}

/// Run config drift scan: load config, compare to baseline, return results.
pub fn scan_config_drift(config_path: &str, baseline_path: &str) -> Vec<ScanResult> {
    let mut results = Vec::new();
    
    let config_str = match std::fs::read_to_string(config_path) {
        Ok(s) => s,
        Err(_) => {
            results.push(ScanResult::new("openclaw:drift", ScanStatus::Warn,
                &format!("Cannot read OpenClaw config at {}", config_path)));
            return results;
        }
    };
    
    let current = extract_security_fields(&config_str);
    
    match load_baseline(baseline_path) {
        Some(baseline) => {
            let drifts = detect_drift(&baseline, &current);
            if drifts.is_empty() {
                results.push(ScanResult::new("openclaw:drift", ScanStatus::Pass,
                    "No config drift detected"));
            } else {
                for drift in &drifts {
                    let status = if drift.is_regression { ScanStatus::Fail } else { ScanStatus::Warn };
                    results.push(ScanResult::new("openclaw:drift", status, &drift.description));
                }
            }
            // Update baseline with current (so non-regression changes don't re-alert)
            let _ = save_baseline(baseline_path, &current);
        }
        None => {
            // First run — save baseline, no alerts
            let _ = save_baseline(baseline_path, &current);
            results.push(ScanResult::new("openclaw:drift", ScanStatus::Pass,
                "Config drift baseline initialized"));
        }
    }
    
    results
}
```

**Step 4: Add module declaration and wire into scanner**

In `src/main.rs`, add: `mod openclaw_config;`

In `src/scanner.rs`, in `run_all_scans()`:

```rust
// Config drift detection (Phase 2)
results.extend(crate::openclaw_config::scan_config_drift(
    "/home/openclaw/.openclaw/openclaw.json",
    "/etc/clawav/openclaw-config-baseline.json",
));
```

**Step 5: Run tests**

Run: `cargo test openclaw_config -- --nocapture`
Expected: PASS

**Step 6: Commit**

```bash
git add src/openclaw_config.rs src/main.rs src/scanner.rs
git commit -m "feat: OpenClaw config drift detection module"
```

---

## Phase 3: Advanced Monitoring

### Task 6: mDNS info leak detection

**Files:**
- Modify: `src/scanner.rs`

**Step 1: Write failing test**

```rust
#[test]
fn test_parse_mdns_openclaw_exposed() {
    let output = "+;eth0;IPv4;OpenClaw Gateway;_http._tcp;local\n";
    let result = check_mdns_openclaw_leak(output);
    assert_eq!(result.status, ScanStatus::Warn);
}

#[test]
fn test_parse_mdns_no_openclaw() {
    let output = "+;eth0;IPv4;Printer;_ipp._tcp;local\n";
    let result = check_mdns_openclaw_leak(output);
    assert_eq!(result.status, ScanStatus::Pass);
}
```

**Step 2: Implement**

```rust
fn check_mdns_openclaw_leak(avahi_output: &str) -> ScanResult {
    let openclaw_services: Vec<&str> = avahi_output.lines()
        .filter(|l| l.to_lowercase().contains("openclaw") || l.to_lowercase().contains("clawav"))
        .collect();
    
    if openclaw_services.is_empty() {
        ScanResult::new("openclaw:mdns", ScanStatus::Pass,
            "No OpenClaw/ClawAV services advertised via mDNS")
    } else {
        ScanResult::new("openclaw:mdns", ScanStatus::Warn,
            &format!("OpenClaw services advertised via mDNS (info leak): {}",
                openclaw_services.join("; ")))
    }
}

fn scan_mdns_leaks() -> Vec<ScanResult> {
    match Command::new("avahi-browse").args(&["-apt", "--no-db-lookup"]).output() {
        Ok(output) => vec![check_mdns_openclaw_leak(
            &String::from_utf8_lossy(&output.stdout))],
        Err(_) => vec![ScanResult::new("openclaw:mdns", ScanStatus::Pass,
            "avahi-browse not available — mDNS check skipped")],
    }
}
```

**Step 3: Run tests, commit**

```bash
cargo test test_parse_mdns -- --nocapture
git add src/scanner.rs
git commit -m "feat: mDNS info leak detection for OpenClaw services"
```

---

### Task 7: Plugin/extension integrity monitoring

**Files:**
- Modify: `src/scanner.rs`

**Step 1: Write failing test**

```rust
#[test]
fn test_scan_openclaw_extensions_none() {
    let dir = tempfile::tempdir().unwrap();
    let result = scan_extensions_dir(dir.path().to_str().unwrap());
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].status, ScanStatus::Pass);
}
```

**Step 2: Implement**

```rust
fn scan_extensions_dir(extensions_path: &str) -> Vec<ScanResult> {
    let path = std::path::Path::new(extensions_path);
    if !path.exists() {
        return vec![ScanResult::new("openclaw:extensions", ScanStatus::Pass,
            "No extensions directory — no plugins installed")];
    }
    
    let mut results = Vec::new();
    let mut count = 0;
    
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                count += 1;
                // Check for package.json (npm-installed plugin)
                let pkg = entry.path().join("package.json");
                if pkg.exists() {
                    results.push(ScanResult::new("openclaw:extension",
                        ScanStatus::Warn,
                        &format!("Plugin installed: {} — verify trusted source",
                            entry.file_name().to_string_lossy())));
                }
            }
        }
    }
    
    if results.is_empty() {
        results.push(ScanResult::new("openclaw:extensions", ScanStatus::Pass,
            &format!("{} extensions found, all appear clean", count)));
    }
    
    results
}
```

**Step 3: Run tests, commit**

```bash
cargo test test_scan_openclaw_extensions -- --nocapture
git add src/scanner.rs
git commit -m "feat: OpenClaw plugin/extension integrity scanning"
```

---

### Task 8: Session log auditd rules + Control UI checks

**Files:**
- Modify: `src/scanner.rs`
- Modify: `src/auditd.rs` (add rules for session log access)

**Step 1: Add session log auditd watch**

In `auditd.rs`, add to the rule generation:

```rust
// Watch OpenClaw session logs for unauthorized reads
"-w /home/openclaw/.openclaw/agents/main/sessions/ -p r -k openclaw_session_read"
```

**Step 2: Add Control UI exposure check to scanner**

```rust
fn scan_control_ui_security(config: &str) -> Vec<ScanResult> {
    let mut results = Vec::new();
    
    if config.contains("dangerouslyDisableDeviceAuth") 
        && (config.contains("\"dangerouslyDisableDeviceAuth\":true") 
            || config.contains("\"dangerouslyDisableDeviceAuth\": true")) {
        results.push(ScanResult::new("openclaw:controlui", ScanStatus::Fail,
            "Control UI: dangerouslyDisableDeviceAuth is TRUE — severe security downgrade"));
    }
    
    if config.contains("allowInsecureAuth")
        && (config.contains("\"allowInsecureAuth\":true")
            || config.contains("\"allowInsecureAuth\": true")) {
        results.push(ScanResult::new("openclaw:controlui", ScanStatus::Warn,
            "Control UI: allowInsecureAuth enabled — token-only auth, no device pairing"));
    }
    
    if results.is_empty() {
        results.push(ScanResult::new("openclaw:controlui", ScanStatus::Pass,
            "Control UI security settings nominal"));
    }
    
    results
}
```

**Step 3: Run tests, commit**

```bash
cargo test -- --nocapture
git add src/scanner.rs src/auditd.rs
git commit -m "feat: session log auditd rules + Control UI exposure checks"
```

---

### Task 9: Wire everything together with config flags

**Files:**
- Modify: `src/scanner.rs` (`run_all_scans`)

**Step 1: Update `run_all_scans` to use config**

The scanner currently doesn't take config. Refactor `run_all_scans` to accept `&Config` (or at minimum the `OpenClawConfig` section) and conditionally run:

```rust
// In run_all_scans, after existing checks:
if config.openclaw.enabled {
    // Phase 1: Permission checks (always)
    results.extend(scan_openclaw_security());
    
    // Phase 1: Audit CLI
    if config.openclaw.audit_on_scan {
        results.extend(run_openclaw_audit(&config.openclaw.audit_command));
    }
    
    // Phase 2: Config drift
    if config.openclaw.config_drift_check {
        results.extend(crate::openclaw_config::scan_config_drift(
            &config.openclaw.config_path, &config.openclaw.baseline_path));
    }
    
    // Phase 3: mDNS
    if config.openclaw.mdns_check {
        results.extend(scan_mdns_leaks());
    }
    
    // Phase 3: Extensions
    if config.openclaw.plugin_watch {
        results.extend(scan_extensions_dir(
            &format!("{}/extensions", config.openclaw.state_dir)));
    }
    
    // Phase 3: Control UI
    if let Ok(cfg_str) = std::fs::read_to_string(&config.openclaw.config_path) {
        results.extend(scan_control_ui_security(&cfg_str));
    }
}
```

**Step 2: Update function signatures to thread config through**

This is a refactor — `SecurityScanner::run_all_scans()` needs to accept config. Change signature to `run_all_scans(config: &Config)` and update `run_periodic_scans` to pass it.

**Step 3: Run full test suite**

Run: `cargo test -- --nocapture`
Expected: ALL PASS

**Step 4: Commit**

```bash
git add src/scanner.rs src/main.rs
git commit -m "feat: wire OpenClaw security checks to config flags"
```

---

### Task 10: Update default config and documentation

**Files:**
- Modify: `config.toml.example` (add `[openclaw]` section)
- Modify: `README.md` or relevant docs (mention OpenClaw integration)
- Modify: `CLAUDE.md` (add OpenClaw integration notes)

**Step 1: Add example config**

```toml
[openclaw]
enabled = true
# config_path = "/home/openclaw/.openclaw/openclaw.json"
# state_dir = "/home/openclaw/.openclaw"
audit_on_scan = true
config_drift_check = true
mdns_check = true
plugin_watch = true
session_log_audit = true
```

**Step 2: Update docs**

Add a section to docs about the OpenClaw security integration — what it monitors, how to configure, what alerts look like.

**Step 3: Commit and tag**

```bash
git add -A
git commit -m "docs: OpenClaw security integration documentation"
```

---

## Summary

| Task | Phase | What | Risk |
|------|-------|------|------|
| 1 | 1 | Config struct for `[openclaw]` | Low |
| 2 | 1 | Permission + symlink checks | Low |
| 3 | 1 | `openclaw security audit` integration | Medium |
| 4 | 1 | Credential paths in sentinel | Low |
| 5 | 2 | Config drift detection module | Medium |
| 6 | 3 | mDNS info leak detection | Low |
| 7 | 3 | Plugin/extension integrity | Low |
| 8 | 3 | Session log auditd + Control UI | Low |
| 9 | — | Wire everything to config | Low |
| 10 | — | Docs + example config | Low |

**Estimated effort:** ~3-4 hours total across all phases.
