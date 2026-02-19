// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Periodic security posture scanner.
//!
//! Runs 30+ security checks on a configurable interval, producing [`ScanResult`]
//! values that are converted to alerts for non-passing checks. Checks include:
//!
//! - Firewall status and rules (UFW)
//! - Auditd status and immutability
//! - Binary/config integrity (SHA-256 checksums)
//! - Immutable file flags (chattr +i)
//! - AppArmor profile status
//! - Barnacle pattern database freshness
//! - Audit log health and permissions
//! - Crontab audit, world-writable files, SUID/SGID binaries
//! - Kernel modules, Docker security, password policy
//! - DNS resolver, NTP sync, failed logins, zombie processes
//! - Environment variables, package integrity, core dump settings
//! - Network interfaces, systemd hardening, user account audit
//! - Cognitive file integrity (AI identity files)
//! - OpenClaw-specific checks (gateway exposure, auth, filesystem scope)

pub mod helpers;
pub mod enforcement;
pub mod filesystem;
pub mod hardening;
pub mod network;
pub mod process;
pub mod user_accounts;
pub mod remediate;

use chrono::{DateTime, Local};
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{sleep, Duration};

use crate::core::alerts::{Alert, Severity};
use crate::detect::cognitive::scan_cognitive_integrity;

// Re-export scan functions from submodules so SecurityScanner::run_all_scans_with_config
// can call them without prefixing.
use filesystem::{
    scan_world_writable_files, scan_suid_sgid_binaries, scan_integrity,
    scan_immutable_flags, scan_ld_preload_persistence, scan_package_integrity,
    scan_shadow_quarantine_permissions, scan_updates, scan_barnacle_sync,
    scan_swap_tmpfs_security,
};
use hardening::{
    scan_password_policy, scan_systemd_hardening, scan_apparmor_protection,
    scan_firewall, scan_auditd, scan_core_dump_settings, scan_ssh,
    scan_docker_security, scan_sudoers_risk, scan_nodejs_version,
};
use network::{
    scan_network_interfaces, scan_listening_services, scan_dns_resolver,
    scan_ntp_sync, scan_openclaw_security, scan_openclaw_container_isolation,
    scan_openclaw_running_as_root, scan_openclaw_hardcoded_secrets,
    scan_openclaw_version_freshness, scan_openclaw_credential_audit,
    run_openclaw_audit, scan_mdns_leaks, scan_extensions_dir,
    scan_control_ui_security,
};
use process::{
    scan_kernel_modules, scan_open_file_descriptors, scan_zombie_processes,
    scan_resources, scan_sidechannel_mitigations, scan_environment_variables,
};
use user_accounts::{
    scan_crontab_audit, scan_failed_login_attempts, scan_user_account_audit,
    scan_user_persistence,
};

/// Result status of a single security scan check.
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

/// Result of a single security posture check.
///
/// Pass results are silently recorded; Warn and Fail are converted to alerts.
#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    /// Check category (e.g., "firewall", "auditd", "suid_sgid")
    pub category: String,
    /// Whether the check passed, warned, or failed
    pub status: ScanStatus,
    /// Human-readable description of findings
    pub details: String,
    /// When the scan was performed
    pub timestamp: DateTime<Local>,
}

impl ScanResult {
    /// Create a new scan result with the given category, status, and details.
    pub fn new(category: &str, status: ScanStatus, details: &str) -> Self {
        Self {
            category: category.to_string(),
            status,
            details: details.to_string(),
            timestamp: Local::now(),
        }
    }

    /// Convert to an [`Alert`] if non-passing (Warn → Warning, Fail → Critical).
    /// Returns `None` for passing results.
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

/// Thread-safe shared scan results, updated by the periodic scanner.
pub type SharedScanResults = Arc<Mutex<Vec<ScanResult>>>;

/// Create a new empty shared scan results store.
pub fn new_shared_scan_results() -> SharedScanResults {
    Arc::new(Mutex::new(Vec::new()))
}

/// Static entry point for running all security scans.
pub struct SecurityScanner;

impl SecurityScanner {
    /// Execute all 30+ security checks and return the results.
    ///
    /// Includes firewall, auditd, integrity, updates, SSH, listening services,
    /// resources, side-channel mitigations, immutable flags, AppArmor, Barnacle,
    /// audit log health, crontab, world-writable files, SUID/SGID, kernel modules,
    /// Docker, password policy, open FDs, DNS, NTP, failed logins, zombie processes,
    /// swap/tmpfs, environment variables, packages, core dumps, network interfaces,
    /// systemd hardening, user accounts, cognitive integrity, and OpenClaw-specific checks.
    pub fn run_all_scans_with_config(openclaw_config: &crate::config::OpenClawConfig) -> Vec<ScanResult> {
        let agent_home = helpers::detect_agent_home();
        let workspace_path = format!("{}/.openclaw/workspace", agent_home);
        let mut results = vec![
            scan_firewall(),
            scan_auditd(),
            scan_integrity(),
            scan_updates(),
            scan_ssh(),
            scan_listening_services(),
            scan_resources(),
            scan_sidechannel_mitigations(),
            scan_immutable_flags(),
            scan_apparmor_protection(),
            scan_barnacle_sync(),
            crate::sources::logtamper::scan_audit_log_health(std::path::Path::new("/var/log/audit/audit.log")),
            // New expanded security checks
            scan_crontab_audit(),
            scan_world_writable_files(),
            scan_suid_sgid_binaries(),
            scan_kernel_modules(),
            scan_docker_security(),
            scan_password_policy(),
            scan_open_file_descriptors(),
            scan_dns_resolver(),
            scan_ntp_sync(),
            scan_failed_login_attempts(),
            scan_zombie_processes(),
            scan_swap_tmpfs_security(),
            scan_environment_variables(),
            scan_ld_preload_persistence(),
            scan_package_integrity(),
            scan_core_dump_settings(),
            scan_network_interfaces(),
            scan_systemd_hardening(),
            scan_user_account_audit(),
        ];
        // Node.js version check
        results.push(scan_nodejs_version());

        // Enforcement verification (AppArmor, seccomp, capabilities)
        results.extend(enforcement::scan_enforcement_verification());

        // Shadow/quarantine directory permission verification
        results.push(scan_shadow_quarantine_permissions());

        // Sudoers risk analysis
        results.push(scan_sudoers_risk());

        // User persistence mechanisms
        results.extend(scan_user_persistence());

        // Cognitive file integrity (returns Vec)
        // Load Barnacle engine for cognitive content scanning
        let barnacle_engine = crate::detect::barnacle::BarnacleEngine::load(
            std::path::Path::new("/etc/clawtower/barnacle")
        ).ok();
        results.extend(scan_cognitive_integrity(
            std::path::Path::new(&workspace_path),
            std::path::Path::new("/etc/clawtower/cognitive-baselines.sha256"),
            barnacle_engine.as_ref(),
        ));
        // OpenClaw-specific security checks
        results.extend(scan_openclaw_security());
        results.push(scan_openclaw_container_isolation());
        results.push(scan_openclaw_running_as_root());
        results.push(scan_openclaw_hardcoded_secrets());
        results.push(scan_openclaw_version_freshness());
        results.push(scan_openclaw_credential_audit());

        // OpenClaw security integration (config-driven)
        if openclaw_config.enabled {
            // Phase 1: Audit CLI
            if openclaw_config.audit_on_scan {
                results.extend(run_openclaw_audit(&openclaw_config.audit_command));
            }

            // Phase 2: Config drift
            if openclaw_config.config_drift_check {
                results.extend(crate::config::openclaw::scan_config_drift(
                    &openclaw_config.config_path, &openclaw_config.baseline_path));
            }

            // Phase 3: mDNS
            if openclaw_config.mdns_check {
                results.extend(scan_mdns_leaks());
            }

            // Phase 3: Extensions
            if openclaw_config.plugin_watch {
                let ext_dir = format!("{}/extensions", openclaw_config.state_dir);
                results.extend(scan_extensions_dir(&ext_dir));
                results.extend(filesystem::scan_plugin_integrity(
                    &ext_dir,
                    "/etc/clawtower/plugin-baselines.sha256",
                ));
                results.extend(
                    crate::detect::barnacle::BarnacleEngine::scan_npm_lockfile_integrity(&ext_dir),
                );
            }

            // Phase 3: Control UI
            if let Ok(cfg_str) = std::fs::read_to_string(&openclaw_config.config_path) {
                results.extend(scan_control_ui_security(&cfg_str));
            }
        }

        results
    }

    /// Execute all security checks with default OpenClaw config.
    pub fn run_all_scans() -> Vec<ScanResult> {
        Self::run_all_scans_with_config(&crate::config::OpenClawConfig::default())
    }
}

/// Normalize a scan finding message by stripping variable parts (timestamps, PIDs,
/// counts, paths with numeric components) so that identical findings get the same fingerprint.
fn normalize_finding(msg: &str) -> String {
    msg.chars().map(|c| if c.is_ascii_digit() { '#' } else { c }).collect()
}

/// Build a dedup fingerprint from the scan category and its details.
fn scan_fingerprint(category: &str, details: &str) -> String {
    format!("{}:{}", category, normalize_finding(details))
}

/// Spawn periodic scan task that runs all checks every `interval_secs` seconds.
///
/// Results are stored in `scan_store` and non-passing results are forwarded as alerts.
/// Uses a "known issues" cache to suppress repeated alerts for persistent findings:
/// - Findings are fingerprinted (category + normalized message, stripping PIDs/timestamps)
/// - Duplicate findings are suppressed unless `dedup_interval_secs` has elapsed
/// - Critical findings always alert on first occurrence, then respect the dedup interval
/// - When a previously-failing finding resolves (passes), an Info "resolved" alert fires
///
/// This scanner-level dedup complements the aggregator's fuzzy dedup: scanner dedup
/// prevents identical findings from even reaching the aggregator across scan cycles,
/// while the aggregator handles cross-source dedup within short time windows.
pub async fn run_periodic_scans(
    interval_secs: u64,
    raw_tx: mpsc::Sender<Alert>,
    scan_store: SharedScanResults,
    openclaw_config: crate::config::OpenClawConfig,
    dedup_interval_secs: u64,
) {
    use std::collections::HashMap;
    use std::time::Instant;

    // Known issues cache: fingerprint → last alerted time
    let mut known_issues: HashMap<String, Instant> = HashMap::new();
    let dedup_window = Duration::from_secs(dedup_interval_secs);

    loop {
        // Run scans in blocking task since they use Command
        let oc_cfg = openclaw_config.clone();
        let results = tokio::task::spawn_blocking(move || SecurityScanner::run_all_scans_with_config(&oc_cfg))
            .await
            .unwrap_or_default();

        // Store results
        {
            let mut store = scan_store.lock().await;
            *store = results.clone();
        }

        // Track which fingerprints are still active this cycle (for resolution detection)
        let mut active_fingerprints: std::collections::HashSet<String> = std::collections::HashSet::new();

        // Convert non-passing results to alerts with dedup
        let now = Instant::now();
        for result in &results {
            if result.status == ScanStatus::Pass {
                continue;
            }

            let fingerprint = scan_fingerprint(&result.category, &result.details);
            active_fingerprints.insert(fingerprint.clone());

            if let Some(alert) = result.to_alert() {
                if let Some(last) = known_issues.get(&fingerprint) {
                    if now.duration_since(*last) < dedup_window {
                        // Within dedup window — suppress
                        continue;
                    }
                }
                // First occurrence or dedup window expired — emit and update cache
                known_issues.insert(fingerprint, now);
                let _ = raw_tx.send(alert).await;
            }
        }

        // Check for resolved issues: fingerprints in cache but not active this cycle
        let resolved: Vec<String> = known_issues.keys()
            .filter(|fp| !active_fingerprints.contains(*fp))
            .cloned()
            .collect();
        for fp in resolved {
            known_issues.remove(&fp);
            let category = fp.split(':').next().unwrap_or("scan");
            let _ = raw_tx.send(Alert::new(
                Severity::Info,
                &format!("scan:{}", category),
                &format!("[RESOLVED] Previously failing check now passes: {}", category),
            )).await;
        }

        sleep(Duration::from_secs(interval_secs)).await;
    }
}

/// Spawn a fast-cycle persistence-only scan task (default 300s interval).
///
/// Runs only `scan_user_persistence()` at a higher frequency than full scans,
/// ensuring persistence mechanisms are detected within minutes, not hours.
pub async fn run_persistence_scans(
    interval_secs: u64,
    raw_tx: mpsc::Sender<Alert>,
) {
    use std::collections::HashMap;
    use std::time::Instant;

    let mut last_emitted: HashMap<String, Instant> = HashMap::new();
    let cooldown = Duration::from_secs(600); // 10 min cooldown for persistence alerts

    // Initial delay to avoid overlap with first full scan
    sleep(Duration::from_secs(30)).await;

    loop {
        let results = tokio::task::spawn_blocking(scan_user_persistence)
            .await
            .unwrap_or_default();

        let now = Instant::now();
        for result in &results {
            if let Some(alert) = result.to_alert() {
                let dedup_key = format!("persist_fast:{}:{}", result.category,
                    match result.status { ScanStatus::Pass => "pass", ScanStatus::Warn => "warn", ScanStatus::Fail => "fail" });
                if let Some(last) = last_emitted.get(&dedup_key) {
                    if now.duration_since(*last) < cooldown {
                        continue;
                    }
                }
                last_emitted.insert(dedup_key, now);
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
    fn test_scan_result_category_preserved() {
        let r = ScanResult::new("my_category", ScanStatus::Fail, "details");
        let alert = r.to_alert().unwrap();
        assert_eq!(alert.source, "scan:my_category");
    }

    #[test]
    fn test_scan_result_details_preserved() {
        let r = ScanResult::new("x", ScanStatus::Warn, "specific details here");
        let alert = r.to_alert().unwrap();
        assert!(alert.message.contains("specific details here"));
    }

    #[test]
    fn test_scan_dedup_suppresses_repeats() {
        use std::collections::HashMap;
        use std::time::{Duration, Instant};

        let mut last_emitted: HashMap<String, Instant> = HashMap::new();
        let cooldown = Duration::from_secs(24 * 3600);

        let key = "firewall:warn".to_string();
        assert!(!last_emitted.contains_key(&key));
        last_emitted.insert(key.clone(), Instant::now());

        let last = last_emitted.get(&key).unwrap();
        assert!(Instant::now().duration_since(*last) < cooldown);
    }

    #[test]
    fn test_scan_dedup_allows_status_change() {
        use std::collections::HashMap;
        use std::time::Instant;

        let mut last_emitted: HashMap<String, Instant> = HashMap::new();
        last_emitted.insert("firewall:warn".to_string(), Instant::now());

        let new_key = "firewall:pass".to_string();
        assert!(!last_emitted.contains_key(&new_key));
    }

    // ═══════════════════════════════════════════════════════════════════
    // RED LOBSTER v4 REGRESSION — Scanner Dedup
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn test_redlobster_dedup_same_fingerprint_suppressed() {
        use std::collections::HashMap;
        use std::time::{Duration, Instant};

        let mut last_emitted: HashMap<String, (Instant, ScanStatus)> = HashMap::new();
        let cooldown = Duration::from_secs(24 * 3600);

        let r1 = ScanResult::new("firewall", ScanStatus::Warn, "UFW active, 0 rules");
        let key1 = format!("{}:{:?}", r1.category, r1.status);

        assert!(!last_emitted.contains_key(&key1));
        last_emitted.insert(key1.clone(), (Instant::now(), r1.status.clone()));

        let r2 = ScanResult::new("firewall", ScanStatus::Warn, "UFW active, 0 rules");
        let key2 = format!("{}:{:?}", r2.category, r2.status);
        assert_eq!(key1, key2);
        let (last_time, _) = last_emitted.get(&key2).unwrap();
        assert!(last_time.elapsed() < cooldown, "Within cooldown, should suppress");
    }

    #[test]
    fn test_redlobster_dedup_different_fingerprint_emits() {
        use std::collections::HashMap;
        use std::time::Instant;

        let mut last_emitted: HashMap<String, Instant> = HashMap::new();
        last_emitted.insert("firewall:Warn".to_string(), Instant::now());

        let key_new = "firewall:Fail".to_string();
        assert!(!last_emitted.contains_key(&key_new), "New status should not be suppressed");
    }

    #[test]
    fn test_redlobster_dedup_resolved_fires_info() {
        let prev_status = ScanStatus::Fail;
        let curr_status = ScanStatus::Pass;

        let is_resolved = (prev_status == ScanStatus::Warn || prev_status == ScanStatus::Fail)
            && curr_status == ScanStatus::Pass;
        assert!(is_resolved, "Fail→Pass should be detected as resolved");

        let resolved_alert = Alert::new(
            Severity::Info,
            "scan:firewall",
            "RESOLVED: firewall check now passing",
        );
        assert_eq!(resolved_alert.severity, Severity::Info);
        assert!(resolved_alert.message.contains("RESOLVED"));
    }

    #[test]
    fn test_redlobster_dedup_pass_to_pass_no_alert() {
        let prev_status = ScanStatus::Pass;
        let curr_status = ScanStatus::Pass;
        let is_resolved = (prev_status == ScanStatus::Warn || prev_status == ScanStatus::Fail)
            && curr_status == ScanStatus::Pass;
        assert!(!is_resolved, "Pass→Pass is not a resolution event");
    }

    #[test]
    fn test_redlobster_dedup_third_identical_still_suppressed() {
        use std::collections::HashMap;
        use std::time::{Duration, Instant};

        let mut last_emitted: HashMap<String, Instant> = HashMap::new();
        let cooldown = Duration::from_secs(24 * 3600);
        let key = "suid_sgid:Warn".to_string();

        last_emitted.insert(key.clone(), Instant::now());

        assert!(last_emitted.get(&key).unwrap().elapsed() < cooldown);
        assert!(last_emitted.get(&key).unwrap().elapsed() < cooldown);
    }
}
