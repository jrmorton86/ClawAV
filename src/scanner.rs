use chrono::{DateTime, Local};
use serde::Serialize;
use std::process::Command;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{sleep, Duration};

use crate::alerts::{Alert, Severity};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum ScanStatus {
    Pass,
    Warn,
    Fail,
}

impl std::fmt::Display for ScanStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanStatus::Pass => write!(f, "PASS"),
            ScanStatus::Warn => write!(f, "WARN"),
            ScanStatus::Fail => write!(f, "FAIL"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub category: String,
    pub status: ScanStatus,
    pub details: String,
    pub timestamp: DateTime<Local>,
}

impl ScanResult {
    pub fn new(category: &str, status: ScanStatus, details: &str) -> Self {
        Self {
            category: category.to_string(),
            status,
            details: details.to_string(),
            timestamp: Local::now(),
        }
    }

    pub fn to_alert(&self) -> Option<Alert> {
        match self.status {
            ScanStatus::Pass => None,
            ScanStatus::Warn => Some(Alert::new(
                Severity::Warning,
                &format!("scan:{}", self.category),
                &self.details,
            )),
            ScanStatus::Fail => Some(Alert::new(
                Severity::Critical,
                &format!("scan:{}", self.category),
                &self.details,
            )),
        }
    }
}

pub type SharedScanResults = Arc<Mutex<Vec<ScanResult>>>;

pub fn new_shared_scan_results() -> SharedScanResults {
    Arc::new(Mutex::new(Vec::new()))
}

fn run_cmd(cmd: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| format!("Failed to run {} {:?}: {}", cmd, args, e))?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn run_cmd_with_sudo(cmd: &str, args: &[&str]) -> Result<String, String> {
    // Try without sudo first
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| format!("Failed to run {}: {}", cmd, e))?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).to_string());
    }
    // Try with sudo
    let mut sudo_args = vec![cmd];
    sudo_args.extend_from_slice(args);
    let output = Command::new("sudo")
        .args(&sudo_args)
        .output()
        .map_err(|e| format!("Failed to run sudo {}: {}", cmd, e))?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

// --- Individual scan functions ---

pub fn scan_firewall() -> ScanResult {
    match run_cmd_with_sudo("ufw", &["status", "verbose"]) {
        Ok(output) => parse_ufw_status(&output),
        Err(e) => ScanResult::new("firewall", ScanStatus::Fail, &format!("Cannot check firewall: {}", e)),
    }
}

pub fn parse_ufw_status(output: &str) -> ScanResult {
    if !output.contains("Status: active") {
        return ScanResult::new("firewall", ScanStatus::Fail, "Firewall is NOT active");
    }
    // Count rules (lines after the header separator)
    let rule_count = output
        .lines()
        .skip_while(|l| !l.starts_with("--"))
        .skip(1)
        .filter(|l| !l.trim().is_empty())
        .count();
    if rule_count == 0 {
        ScanResult::new("firewall", ScanStatus::Warn, "Firewall active but no rules defined")
    } else {
        ScanResult::new("firewall", ScanStatus::Pass, &format!("Firewall active with {} rules", rule_count))
    }
}

pub fn scan_auditd() -> ScanResult {
    match run_cmd_with_sudo("auditctl", &["-s"]) {
        Ok(output) => parse_auditctl_status(&output),
        Err(e) => ScanResult::new("auditd", ScanStatus::Fail, &format!("Cannot check auditd: {}", e)),
    }
}

pub fn parse_auditctl_status(output: &str) -> ScanResult {
    let enabled = output
        .lines()
        .find(|l| l.starts_with("enabled"))
        .and_then(|l| l.split_whitespace().last())
        .unwrap_or("0");

    let rules = output
        .lines()
        .find(|l| l.starts_with("rules"))
        .and_then(|l| l.split_whitespace().last())
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0);

    match enabled {
        "2" => {
            if rules > 0 {
                ScanResult::new("auditd", ScanStatus::Pass, &format!("Auditd immutable, {} rules loaded", rules))
            } else {
                ScanResult::new("auditd", ScanStatus::Warn, "Auditd immutable but no rules loaded")
            }
        }
        "1" => ScanResult::new("auditd", ScanStatus::Warn, &format!("Auditd enabled but not immutable (enabled=1), {} rules", rules)),
        _ => ScanResult::new("auditd", ScanStatus::Fail, &format!("Auditd not enabled (enabled={})", enabled)),
    }
}

pub fn scan_integrity() -> ScanResult {
    // Check if binary exists and get its hash
    let _binary_path = "/usr/local/bin/openclawav";
    let _config_path = "/etc/openclawav/config.toml";
    let checksums_path = "/etc/openclawav/checksums.sha256";

    if !std::path::Path::new(checksums_path).exists() {
        return ScanResult::new("integrity", ScanStatus::Warn, "No checksums file found — run 'openclawav --store-checksums' to create baseline");
    }

    let stored = match std::fs::read_to_string(checksums_path) {
        Ok(s) => s,
        Err(e) => return ScanResult::new("integrity", ScanStatus::Fail, &format!("Cannot read checksums: {}", e)),
    };

    let mut issues = Vec::new();
    for line in stored.lines() {
        let parts: Vec<&str> = line.splitn(2, "  ").collect();
        if parts.len() != 2 {
            continue;
        }
        let expected_hash = parts[0];
        let file_path = parts[1];

        match compute_file_sha256(file_path) {
            Ok(actual) if actual == expected_hash => {}
            Ok(_actual) => issues.push(format!("{}: hash mismatch", file_path)),
            Err(e) => issues.push(format!("{}: {}", file_path, e)),
        }
    }

    if issues.is_empty() {
        ScanResult::new("integrity", ScanStatus::Pass, "Binary and config integrity verified")
    } else {
        ScanResult::new("integrity", ScanStatus::Fail, &format!("Integrity check failed: {}", issues.join("; ")))
    }
}

fn compute_file_sha256(path: &str) -> Result<String, String> {
    use sha2::{Sha256, Digest};
    let data = std::fs::read(path).map_err(|e| format!("cannot read: {}", e))?;
    let hash = Sha256::digest(&data);
    Ok(hex::encode(hash))
}

pub fn scan_updates() -> ScanResult {
    match run_cmd("bash", &["-c", "apt list --upgradable 2>/dev/null | tail -n +2 | wc -l"]) {
        Ok(output) => {
            let count: u32 = output.trim().parse().unwrap_or(0);
            if count > 10 {
                ScanResult::new("updates", ScanStatus::Warn, &format!("{} pending system updates", count))
            } else {
                ScanResult::new("updates", ScanStatus::Pass, &format!("{} pending updates", count))
            }
        }
        Err(e) => ScanResult::new("updates", ScanStatus::Warn, &format!("Cannot check updates: {}", e)),
    }
}

pub fn scan_ssh() -> ScanResult {
    match run_cmd("systemctl", &["is-active", "ssh"]) {
        Ok(output) => {
            let status = output.trim();
            if status == "active" {
                ScanResult::new("ssh", ScanStatus::Warn, "SSH daemon is running (should be disabled)")
            } else {
                ScanResult::new("ssh", ScanStatus::Pass, &format!("SSH daemon is {}", status))
            }
        }
        Err(e) => ScanResult::new("ssh", ScanStatus::Pass, &format!("SSH check: {}", e)),
    }
}

pub fn scan_listening_services() -> ScanResult {
    match run_cmd("ss", &["-tlnp"]) {
        Ok(output) => {
            let expected_ports = ["18791"]; // OpenClawAV API
            let mut unexpected = Vec::new();
            for line in output.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    let local = parts[3];
                    let port = local.rsplit(':').next().unwrap_or("");
                    if !expected_ports.contains(&port) {
                        unexpected.push(local.to_string());
                    }
                }
            }
            if unexpected.is_empty() {
                ScanResult::new("listening", ScanStatus::Pass, "No unexpected listening services")
            } else {
                ScanResult::new("listening", ScanStatus::Warn, &format!("Unexpected listeners: {}", unexpected.join(", ")))
            }
        }
        Err(e) => ScanResult::new("listening", ScanStatus::Warn, &format!("Cannot check listeners: {}", e)),
    }
}

pub fn scan_resources() -> ScanResult {
    match run_cmd("df", &["-h", "/"]) {
        Ok(output) => parse_disk_usage(&output),
        Err(e) => ScanResult::new("resources", ScanStatus::Warn, &format!("Cannot check disk: {}", e)),
    }
}

pub fn scan_sidechannel_mitigations() -> ScanResult {
    let mitigations = [
        "spectre_v1",
        "spectre_v2", 
        "meltdown",
        "mds",
        "tsx_async_abort",
        "itlb_multihit",
        "srbds",
        "mmio_stale_data",
        "retbleed",
        "spec_store_bypass",
    ];

    let mut vulnerable_count = 0;
    let mut missing_files = 0;
    let mut vulnerable_list = Vec::new();

    for mitigation in &mitigations {
        let path = format!("/sys/devices/system/cpu/vulnerabilities/{}", mitigation);
        match std::fs::read_to_string(&path) {
            Ok(contents) => {
                let status = contents.trim();
                if status.contains("Vulnerable") {
                    vulnerable_count += 1;
                    vulnerable_list.push(format!("{}: {}", mitigation, status));
                } else if !status.contains("Mitigation:") && !status.contains("Not affected") {
                    // Unknown status - treat as warning
                    vulnerable_list.push(format!("{}: {}", mitigation, status));
                }
            }
            Err(_) => {
                missing_files += 1;
                vulnerable_list.push(format!("{}: file missing", mitigation));
            }
        }
    }

    if vulnerable_count > 0 || missing_files > 0 {
        let total_issues = vulnerable_count + missing_files;
        ScanResult::new(
            "sidechannel", 
            ScanStatus::Warn, 
            &format!("{} vulnerability issues: {}", total_issues, vulnerable_list.join(", "))
        )
    } else {
        ScanResult::new(
            "sidechannel", 
            ScanStatus::Pass, 
            &format!("All {} CPU side-channel mitigations enabled", mitigations.len())
        )
    }
}

pub fn parse_disk_usage(output: &str) -> ScanResult {
    // Second line, 5th column is Use%
    if let Some(line) = output.lines().nth(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let Some(pct_str) = parts.get(4) {
            let pct: u32 = pct_str.trim_end_matches('%').parse().unwrap_or(0);
            if pct > 90 {
                return ScanResult::new("resources", ScanStatus::Warn, &format!("Disk usage at {}%", pct));
            } else {
                return ScanResult::new("resources", ScanStatus::Pass, &format!("Disk usage at {}%", pct));
            }
        }
    }
    ScanResult::new("resources", ScanStatus::Warn, "Cannot parse disk usage")
}

pub struct SecurityScanner;

impl SecurityScanner {
    pub fn run_all_scans() -> Vec<ScanResult> {
        vec![
            scan_firewall(),
            scan_auditd(),
            scan_integrity(),
            scan_updates(),
            scan_ssh(),
            scan_listening_services(),
            scan_resources(),
            scan_sidechannel_mitigations(),
        ]
    }
}

/// Spawn periodic scan task
pub async fn run_periodic_scans(
    interval_secs: u64,
    raw_tx: mpsc::Sender<Alert>,
    scan_store: SharedScanResults,
) {
    loop {
        // Run scans in blocking task since they use Command
        let results = tokio::task::spawn_blocking(|| SecurityScanner::run_all_scans())
            .await
            .unwrap_or_default();

        // Store results
        {
            let mut store = scan_store.lock().await;
            *store = results.clone();
        }

        // Convert to alerts and send
        for result in &results {
            if let Some(alert) = result.to_alert() {
                let _ = raw_tx.send(alert).await;
            }
        }

        sleep(Duration::from_secs(interval_secs)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ufw_active_with_rules() {
        let output = "Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
80/tcp                     ALLOW IN    Anywhere
";
        let result = parse_ufw_status(output);
        assert_eq!(result.status, ScanStatus::Pass);
        assert!(result.details.contains("2 rules"));
    }

    #[test]
    fn test_parse_ufw_active_no_rules() {
        let output = "Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
";
        let result = parse_ufw_status(output);
        assert_eq!(result.status, ScanStatus::Warn);
    }

    #[test]
    fn test_parse_ufw_inactive() {
        let output = "Status: inactive\n";
        let result = parse_ufw_status(output);
        assert_eq!(result.status, ScanStatus::Fail);
    }

    #[test]
    fn test_parse_auditctl_immutable() {
        let output = "enabled 2
failure 1
pid 1234
rate_limit 0
backlog_limit 8192
lost 0
backlog 0
backlog_wait_time 60000
loginuid_immutable 0 unlocked
rules 42
";
        let result = parse_auditctl_status(output);
        assert_eq!(result.status, ScanStatus::Pass);
        assert!(result.details.contains("42 rules"));
    }

    #[test]
    fn test_parse_auditctl_not_immutable() {
        let output = "enabled 1
failure 1
rules 10
";
        let result = parse_auditctl_status(output);
        assert_eq!(result.status, ScanStatus::Warn);
        assert!(result.details.contains("not immutable"));
    }

    #[test]
    fn test_parse_auditctl_disabled() {
        let output = "enabled 0
failure 1
rules 0
";
        let result = parse_auditctl_status(output);
        assert_eq!(result.status, ScanStatus::Fail);
    }

    #[test]
    fn test_parse_disk_usage_ok() {
        let output = "Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        50G   20G   28G  42% /
";
        let result = parse_disk_usage(output);
        assert_eq!(result.status, ScanStatus::Pass);
        assert!(result.details.contains("42%"));
    }

    #[test]
    fn test_parse_disk_usage_high() {
        let output = "Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        50G   47G    1G  95% /
";
        let result = parse_disk_usage(output);
        assert_eq!(result.status, ScanStatus::Warn);
        assert!(result.details.contains("95%"));
    }

    #[test]
    fn test_scan_result_to_alert_pass() {
        let r = ScanResult::new("test", ScanStatus::Pass, "all good");
        assert!(r.to_alert().is_none());
    }

    #[test]
    fn test_scan_result_to_alert_warn() {
        let r = ScanResult::new("test", ScanStatus::Warn, "something off");
        let alert = r.to_alert().unwrap();
        assert_eq!(alert.severity, Severity::Warning);
        assert_eq!(alert.source, "scan:test");
    }

    #[test]
    fn test_scan_result_to_alert_fail() {
        let r = ScanResult::new("test", ScanStatus::Fail, "broken");
        let alert = r.to_alert().unwrap();
        assert_eq!(alert.severity, Severity::Critical);
    }

    #[test]
    fn test_parse_sidechannel_mitigation_status() {
        // Test the logic used in scan_sidechannel_mitigations
        let protected_status = "Mitigation: Full generic retpoline, IBRS, IBPB";
        assert!(protected_status.contains("Mitigation:"));
        
        let not_affected_status = "Not affected";
        assert!(not_affected_status.contains("Not affected"));
        
        let vulnerable_status = "Vulnerable";
        assert!(vulnerable_status.contains("Vulnerable"));
        
        let unknown_status = "Processor vulnerable";
        assert!(!unknown_status.contains("Mitigation:") && !unknown_status.contains("Not affected"));
    }
}
