// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! System hardening security scanners.
//!
//! Password policy, systemd hardening, AppArmor status, firewall/UFW,
//! auditd, core dumps, SSH config, sudoers, Docker security.

use super::{ScanResult, ScanStatus};
use super::helpers::{run_cmd, run_cmd_with_sudo, command_available};

/// Check `/etc/login.defs` and PAM configuration for password policy strength.
pub fn scan_password_policy() -> ScanResult {
    let mut issues = Vec::new();

    // Check /etc/login.defs
    if let Ok(content) = std::fs::read_to_string("/etc/login.defs") {
        let mut pass_max_days = None;
        let mut _pass_min_days = None;
        let mut _pass_warn_age = None;

        for line in content.lines() {
            if line.starts_with("PASS_MAX_DAYS") {
                if let Some(value) = line.split_whitespace().nth(1) {
                    if let Ok(days) = value.parse::<u32>() {
                        pass_max_days = Some(days);
                        if days > 90 || days == 99999 {
                            issues.push(format!("Password expiry too long: {} days", days));
                        }
                    }
                }
            } else if line.starts_with("PASS_MIN_DAYS") {
                if let Some(value) = line.split_whitespace().nth(1) {
                    if let Ok(days) = value.parse::<u32>() {
                        _pass_min_days = Some(days);
                    }
                }
            } else if line.starts_with("PASS_WARN_AGE") {
                if let Some(value) = line.split_whitespace().nth(1) {
                    if let Ok(days) = value.parse::<u32>() {
                        _pass_warn_age = Some(days);
                    }
                }
            }
        }

        if pass_max_days.is_none() {
            issues.push("PASS_MAX_DAYS not configured".to_string());
        }
    } else {
        issues.push("Cannot read /etc/login.defs".to_string());
    }

    // Check PAM password requirements (distro-dependent paths)
    let pam_candidates = [
        "/etc/pam.d/common-password",   // Debian/Ubuntu
        "/etc/pam.d/system-auth",       // RHEL/Amazon Linux/Fedora
        "/etc/pam.d/password-auth",     // RHEL-family split config
    ];
    let mut pam_checked = false;
    let mut pam_quality_found = false;
    for path in &pam_candidates {
        if let Ok(content) = std::fs::read_to_string(path) {
            pam_checked = true;
            if content.contains("pam_pwquality") || content.contains("pam_cracklib") {
                pam_quality_found = true;
                break;
            }
        }
    }
    if pam_checked && !pam_quality_found {
        issues.push("No password quality checking configured in PAM".to_string());
    }

    if issues.is_empty() {
        ScanResult::new("password_policy", ScanStatus::Pass, "Password policy configured appropriately")
    } else {
        ScanResult::new("password_policy", ScanStatus::Warn, &format!("Password policy issues: {}", issues.join("; ")))
    }
}

/// Verify that the ClawTower systemd service has security hardening directives (NoNewPrivileges, ProtectSystem, etc.).
pub fn scan_systemd_hardening() -> ScanResult {
    let mut issues = Vec::new();

    // Check if ClawTower service has security hardening enabled
    let service_file = "/etc/systemd/system/clawtower.service";
    if let Ok(content) = std::fs::read_to_string(service_file) {
        let security_features = [
            "NoNewPrivileges=true",
            "ProtectSystem=strict",
            "ProtectHome=true",
            "PrivateTmp=true",
            "ProtectKernelTunables=true",
            "ProtectControlGroups=true",
            "RestrictRealtime=true",
            "MemoryDenyWriteExecute=true"
        ];

        for feature in &security_features {
            if !content.contains(feature) {
                issues.push(format!("Missing systemd hardening: {}", feature));
            }
        }
    } else {
        issues.push("ClawTower service file not found".to_string());
    }

    // Check systemd version supports security features
    if let Ok(output) = run_cmd("systemctl", &["--version"]) {
        if let Some(first_line) = output.lines().next() {
            if let Some(version_str) = first_line.split_whitespace().nth(1) {
                if let Ok(version) = version_str.parse::<u32>() {
                    if version < 231 {
                        issues.push(format!("Old systemd version ({}), security features limited", version));
                    }
                }
            }
        }
    }

    if issues.is_empty() {
        ScanResult::new("systemd_hardening", ScanStatus::Pass, "Systemd service properly hardened")
    } else if issues.len() > 5 {
        ScanResult::new("systemd_hardening", ScanStatus::Warn, &format!("Service hardening incomplete: {} missing features", issues.len()))
    } else {
        ScanResult::new("systemd_hardening", ScanStatus::Warn, &format!("Hardening issues: {}", issues.join("; ")))
    }
}

/// Check that the AppArmor config protection profile is loaded and enforced
pub fn scan_apparmor_protection() -> ScanResult {
    // Check if AppArmor is available
    match run_cmd("aa-enabled", &["--quiet"]) {
        Ok(_) => {}
        Err(_) => {
            return ScanResult::new(
                "apparmor_protection",
                ScanStatus::Pass, // Not a failure — AppArmor is optional
                "AppArmor not available (chattr +i and auditd provide primary protection)",
            );
        }
    }

    match run_cmd_with_sudo("aa-status", &[]) {
        Ok(output) => {
            let has_openclaw_profile = output.contains("openclaw")
                || output.contains("clawtower.deny-openclaw");
            let has_protect_profile = output.contains("clawtower.protect");

            if has_openclaw_profile && has_protect_profile {
                ScanResult::new(
                    "apparmor_protection",
                    ScanStatus::Pass,
                    "AppArmor profiles loaded: openclaw restriction + config protection",
                )
            } else if has_openclaw_profile {
                ScanResult::new(
                    "apparmor_protection",
                    ScanStatus::Warn,
                    "AppArmor openclaw restriction loaded, but config protection profile missing",
                )
            } else {
                ScanResult::new(
                    "apparmor_protection",
                    ScanStatus::Warn,
                    "AppArmor profiles not loaded — run 'clawtower setup-apparmor'",
                )
            }
        }
        Err(e) => ScanResult::new(
            "apparmor_protection",
            ScanStatus::Warn,
            &format!("Cannot check AppArmor status: {}", e),
        ),
    }
}

/// Check UFW firewall status and rule count.
pub fn scan_firewall() -> ScanResult {
    if command_available("ufw") {
        return match run_cmd_with_sudo("ufw", &["status", "verbose"]) {
            Ok(output) => parse_ufw_status(&output),
            Err(e) => ScanResult::new("firewall", ScanStatus::Fail, &format!("Cannot check UFW firewall: {}", e)),
        };
    }

    if command_available("firewall-cmd") {
        return match run_cmd_with_sudo("firewall-cmd", &["--state"]) {
            Ok(state) if state.trim() == "running" => {
                let zones = run_cmd_with_sudo("firewall-cmd", &["--list-all-zones"]).unwrap_or_default();
                let has_rules = zones.contains("services:") || zones.contains("ports:") || zones.contains("rich rules:");
                if has_rules {
                    ScanResult::new("firewall", ScanStatus::Pass, "firewalld running with configured zones/rules")
                } else {
                    ScanResult::new("firewall", ScanStatus::Warn, "firewalld running but no obvious rules/services configured")
                }
            }
            Ok(_) => ScanResult::new("firewall", ScanStatus::Fail, "firewalld installed but not running"),
            Err(e) => ScanResult::new("firewall", ScanStatus::Warn, &format!("Cannot query firewalld: {}", e)),
        };
    }

    if command_available("nft") {
        return match run_cmd_with_sudo("nft", &["list", "ruleset"]) {
            Ok(output) => {
                let chain_count = output.lines().filter(|l| l.trim_start().starts_with("chain ")).count();
                if chain_count > 0 {
                    ScanResult::new("firewall", ScanStatus::Pass, &format!("nftables active with {} chains", chain_count))
                } else {
                    ScanResult::new("firewall", ScanStatus::Warn, "nftables available but no chains/rules found")
                }
            }
            Err(e) => ScanResult::new("firewall", ScanStatus::Warn, &format!("Cannot query nftables ruleset: {}", e)),
        };
    }

    if command_available("iptables") {
        return match run_cmd_with_sudo("iptables", &["-S"]) {
            Ok(output) => {
                let rules = output.lines().filter(|l| l.starts_with("-A ")).count();
                if rules > 0 {
                    ScanResult::new("firewall", ScanStatus::Pass, &format!("iptables active with {} rules", rules))
                } else {
                    ScanResult::new("firewall", ScanStatus::Warn, "iptables available but no rules found")
                }
            }
            Err(e) => ScanResult::new("firewall", ScanStatus::Warn, &format!("Cannot query iptables rules: {}", e)),
        };
    }

    ScanResult::new("firewall", ScanStatus::Warn, "No supported firewall backend detected (ufw/firewalld/nftables/iptables)")
}

/// Parse `ufw status verbose` output into a scan result (testable helper).
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

/// Check auditd status: enabled, immutable mode, and loaded rule count.
pub fn scan_auditd() -> ScanResult {
    match run_cmd_with_sudo("auditctl", &["-s"]) {
        Ok(output) => parse_auditctl_status(&output),
        Err(e) => ScanResult::new("auditd", ScanStatus::Fail, &format!("Cannot check auditd: {}", e)),
    }
}

/// Parse `auditctl -s` output into a scan result (testable helper).
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

/// Check that core dumps are disabled (systemd-coredump, ulimit, core_pattern) and flag recent dumps.
pub fn scan_core_dump_settings() -> ScanResult {
    let mut issues = Vec::new();

    // Check systemd coredump settings
    if let Ok(output) = run_cmd("systemctl", &["is-enabled", "systemd-coredump"]) {
        if output.trim() == "enabled" {
            issues.push("Core dumps are enabled system-wide".to_string());
        }
    }

    // Check ulimit core dump settings
    if let Ok(output) = run_cmd("ulimit", &["-c"]) {
        if output.trim() != "0" && output.trim() != "unlimited"
            && output.trim().parse::<u64>().unwrap_or(0) > 0 {
                issues.push(format!("Core dumps allowed: ulimit -c = {}", output.trim()));
        }
    }

    // Check /proc/sys/kernel/core_pattern
    if let Ok(pattern) = std::fs::read_to_string("/proc/sys/kernel/core_pattern") {
        let pattern = pattern.trim();
        if !pattern.starts_with("|/bin/false") && pattern != "core"
            && pattern.contains("/") && !pattern.contains("/dev/null") {
                issues.push(format!("Core dumps directed to: {}", pattern));
        }
    }

    // Check coredumpctl for recent dumps
    if let Ok(output) = run_cmd("coredumpctl", &["--since", "1 week ago", "--no-pager"]) {
        let dump_count = output.lines().filter(|l| l.contains("COREDUMP")).count();
        if dump_count > 0 {
            issues.push(format!("Recent core dumps found: {}", dump_count));
        }
    }

    if issues.is_empty() {
        ScanResult::new("core_dumps", ScanStatus::Pass, "Core dumps properly disabled")
    } else {
        ScanResult::new("core_dumps", ScanStatus::Warn, &format!("Core dump concerns: {}", issues.join("; ")))
    }
}

/// Check whether the SSH daemon is running (warns if active — should be disabled on hardened hosts).
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

/// Check Docker for privileged containers, world-writable sockets, and host-network usage.
pub fn scan_docker_security() -> ScanResult {
    // First check if Docker is running
    match run_cmd("systemctl", &["is-active", "docker"]) {
        Ok(status) if status.trim() == "active" => {
            let mut issues = Vec::new();

            // Check for privileged containers
            if let Ok(output) = run_cmd("docker", &["ps", "--format", "table {{.Names}}\t{{.Status}}", "--filter", "status=running"]) {
                for line in output.lines().skip(1) { // Skip header
                    if let Some(container_name) = line.split('\t').next() {
                        if let Ok(inspect) = run_cmd("docker", &["inspect", container_name, "--format", "{{.HostConfig.Privileged}}"]) {
                            if inspect.trim() == "true" {
                                issues.push(format!("Privileged container: {}", container_name));
                            }
                        }
                    }
                }
            }

            // Check if Docker socket is exposed
            if std::path::Path::new("/var/run/docker.sock").exists() {
                if let Ok(output) = run_cmd("ls", &["-la", "/var/run/docker.sock"]) {
                    if output.contains("rw-rw-rw-") || output.contains("666") {
                        issues.push("Docker socket is world-writable".to_string());
                    }
                }
            }

            // Check for containers with host network
            if let Ok(output) = run_cmd("docker", &["ps", "-q"]) {
                for container_id in output.lines() {
                    if let Ok(network) = run_cmd("docker", &["inspect", container_id.trim(), "--format", "{{.HostConfig.NetworkMode}}"]) {
                        if network.trim() == "host" {
                            issues.push(format!("Container using host network: {}", container_id.trim()));
                        }
                    }
                }
            }

            // Check for read-only root filesystem
            if let Ok(output) = run_cmd("docker", &["ps", "-q"]) {
                for container_id in output.lines() {
                    let cid = container_id.trim();
                    if cid.is_empty() { continue; }
                    if let Ok(ro) = run_cmd("docker", &["inspect", cid, "--format", "{{.HostConfig.ReadonlyRootfs}}"]) {
                        if ro.trim() == "false" {
                            issues.push(format!("Container {} has writable root filesystem", cid));
                        }
                    }
                    // Check for non-root user
                    if let Ok(user) = run_cmd("docker", &["inspect", cid, "--format", "{{.Config.User}}"]) {
                        let u = user.trim();
                        if u.is_empty() || u == "root" || u == "0" {
                            issues.push(format!("Container {} running as root", cid));
                        }
                    }
                    // Check for dangerous capabilities not dropped
                    if let Ok(caps) = run_cmd("docker", &["inspect", cid, "--format", "{{.HostConfig.CapDrop}}"]) {
                        let cap_str = caps.trim();
                        for dangerous_cap in &["SYS_ADMIN", "NET_ADMIN", "LINUX_IMMUTABLE"] {
                            if !cap_str.contains(dangerous_cap) {
                                issues.push(format!("Container {} missing CapDrop: {}", cid, dangerous_cap));
                            }
                        }
                    }
                }
            }

            if issues.is_empty() {
                ScanResult::new("docker_security", ScanStatus::Pass, "Docker security checks passed")
            } else {
                ScanResult::new("docker_security", ScanStatus::Warn, &format!("Docker security issues: {}", issues.join("; ")))
            }
        }
        Ok(_) | Err(_) => ScanResult::new("docker_security", ScanStatus::Pass, "Docker not running"),
    }
}

/// Parse Docker container inspect data for security checks (testable helper).
///
/// Checks read-only rootfs, non-root user, and dangerous capabilities.
pub fn parse_docker_security_inspect(
    readonly_rootfs: &str,
    user: &str,
    cap_drop: &str,
) -> Vec<String> {
    let mut issues = Vec::new();

    if readonly_rootfs.trim() == "false" {
        issues.push("writable root filesystem".to_string());
    }

    let u = user.trim();
    if u.is_empty() || u == "root" || u == "0" {
        issues.push("running as root".to_string());
    }

    for cap in &["SYS_ADMIN", "NET_ADMIN", "LINUX_IMMUTABLE"] {
        if !cap_drop.contains(cap) {
            issues.push(format!("missing CapDrop: {}", cap));
        }
    }

    issues
}

/// Check the Node.js runtime version against the minimum required by OpenClaw SECURITY.md.
pub fn scan_nodejs_version() -> ScanResult {
    match run_cmd("node", &["--version"]) {
        Ok(output) => check_node_version(output.trim(), 22, 12, 0),
        Err(_) => ScanResult::new("nodejs_version", ScanStatus::Warn,
            "Node.js not found — cannot verify version"),
    }
}

/// Parse `node --version` output and compare against minimum semver.
pub fn check_node_version(version_output: &str, min_major: u32, min_minor: u32, min_patch: u32) -> ScanResult {
    let stripped = version_output.strip_prefix('v').unwrap_or(version_output);
    let parts: Vec<&str> = stripped.split('.').collect();

    if parts.len() < 3 {
        return ScanResult::new("nodejs_version", ScanStatus::Warn,
            &format!("Cannot parse Node.js version: {}", version_output));
    }

    let major = match parts[0].parse::<u32>() {
        Ok(v) => v,
        Err(_) => return ScanResult::new("nodejs_version", ScanStatus::Warn,
            &format!("Cannot parse Node.js major version: {}", version_output)),
    };
    let minor = match parts[1].parse::<u32>() {
        Ok(v) => v,
        Err(_) => return ScanResult::new("nodejs_version", ScanStatus::Warn,
            &format!("Cannot parse Node.js minor version: {}", version_output)),
    };
    let patch = match parts[2].parse::<u32>() {
        Ok(v) => v,
        Err(_) => return ScanResult::new("nodejs_version", ScanStatus::Warn,
            &format!("Cannot parse Node.js patch version: {}", version_output)),
    };

    if (major, minor, patch) >= (min_major, min_minor, min_patch) {
        ScanResult::new("nodejs_version", ScanStatus::Pass,
            &format!("Node.js {} meets minimum {}.{}.{}", version_output, min_major, min_minor, min_patch))
    } else {
        ScanResult::new("nodejs_version", ScanStatus::Fail,
            &format!("Node.js {} below minimum {}.{}.{} — security features missing",
                version_output, min_major, min_minor, min_patch))
    }
}

/// GTFOBins-capable binaries that are dangerous with NOPASSWD sudo access.
const GTFOBINS_DANGEROUS: &[&str] = &[
    "find", "sed", "tee", "cp", "mv", "chmod", "chown", "vim", "vi",
    "python3", "python", "perl", "ruby", "env", "awk", "nmap", "less",
    "more", "man", "ftp", "gdb", "git", "pip", "apt", "apt-get",
    "docker", "tar", "zip", "rsync", "ssh", "scp", "curl", "wget",
    "nc", "ncat", "bash", "sh", "zsh", "dash", "lua", "php", "node",
];

/// Parse sudoers content and return (critical_risks, warnings).
pub fn parse_sudoers_risks(content: &str, source_path: &str) -> (Vec<String>, Vec<String>) {
    let mut critical = Vec::new();
    let mut warnings = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Check env_keep on Defaults lines before skipping them
        if trimmed.starts_with("Defaults") {
            if trimmed.to_lowercase().contains("env_keep") {
                let dangerous_vars = ["LD_PRELOAD", "LD_LIBRARY_PATH", "PATH", "IFS", "PYTHONPATH"];
                for var in &dangerous_vars {
                    if trimmed.contains(var) {
                        warnings.push(format!(
                            "{}: env_keep preserves dangerous variable {}",
                            source_path, var
                        ));
                    }
                }
            }
            continue;
        }

        let has_nopasswd = trimmed.contains("NOPASSWD");
        let has_all_all = trimmed.contains("ALL=(ALL)") || trimmed.contains("ALL=(ALL:ALL)");

        // CRITICAL: NOPASSWD with ALL=(ALL) ALL - passwordless root
        if has_nopasswd && has_all_all {
            let after_colon = trimmed.rsplit(':').next().unwrap_or("");
            if after_colon.trim() == "ALL" || after_colon.contains(" ALL") {
                critical.push(format!(
                    "{}: NOPASSWD ALL - passwordless unrestricted root access",
                    source_path
                ));
                continue;
            }
        }

        // CRITICAL: NOPASSWD with GTFOBins-capable binaries
        let mut line_has_critical = false;
        if has_nopasswd {
            for bin in GTFOBINS_DANGEROUS {
                let slash_bin = format!("/{}", bin);
                if trimmed.contains(&slash_bin) {
                    critical.push(format!(
                        "{}: NOPASSWD on GTFOBins-capable binary '{}'",
                        source_path, bin
                    ));
                    line_has_critical = true;
                }
            }
        }

        // WARNING: NOPASSWD with restricted scope (may be acceptable)
        if has_nopasswd && !line_has_critical {
            warnings.push(format!(
                "{}: NOPASSWD with restricted scope (verify commands are safe)",
                source_path
            ));
        }

        // WARNING: Dangerous env_keep variables
        if trimmed.to_lowercase().contains("env_keep") {
            let dangerous_vars = ["LD_PRELOAD", "LD_LIBRARY_PATH", "PATH", "IFS", "PYTHONPATH"];
            for var in &dangerous_vars {
                if trimmed.contains(var) {
                    warnings.push(format!(
                        "{}: env_keep preserves dangerous variable {}",
                        source_path, var
                    ));
                }
            }
        }
    }

    (critical, warnings)
}

/// Prefix used to mark lines disabled by ClawTower auto-remediation.
/// The uninstall script reverses this by stripping this prefix.
pub const CLAWTOWER_DISABLED_PREFIX: &str = "# CLAWTOWER-DISABLED: ";

/// Directory for backing up sudoers files before remediation.
const SUDOERS_BACKUP_DIR: &str = "/var/lib/clawtower/sudoers-backups";

/// Remediate dangerous lines in sudoers content by commenting them out.
///
/// Returns (new_content, descriptions) where descriptions lists what was disabled
/// (e.g., "NOPASSWD ALL", "find, sh, apt").
/// Lines already disabled (prefixed with `CLAWTOWER_DISABLED_PREFIX`) are skipped.
///
/// Only disables lines with critical risks: NOPASSWD ALL or NOPASSWD with
/// GTFOBins-capable binaries. Warning-level issues are left untouched.
pub fn remediate_sudoers_content(content: &str) -> (String, Vec<String>) {
    let mut output_lines = Vec::new();
    let mut descriptions = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();

        // Skip empty, comments (including already-disabled), and Defaults lines
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("Defaults") {
            output_lines.push(line.to_string());
            continue;
        }

        let has_nopasswd = trimmed.contains("NOPASSWD");
        if !has_nopasswd {
            output_lines.push(line.to_string());
            continue;
        }

        let has_all_all = trimmed.contains("ALL=(ALL)") || trimmed.contains("ALL=(ALL:ALL)");
        let mut is_critical = false;
        let mut desc = String::new();

        // Check NOPASSWD ALL (passwordless unrestricted root)
        if has_all_all {
            let after_colon = trimmed.rsplit(':').next().unwrap_or("");
            if after_colon.trim() == "ALL" || after_colon.contains(" ALL") {
                is_critical = true;
                desc = "NOPASSWD ALL".to_string();
            }
        }

        // Check GTFOBins-capable binaries
        if !is_critical {
            let mut found_bins = Vec::new();
            for bin in GTFOBINS_DANGEROUS {
                let slash_bin = format!("/{}", bin);
                if trimmed.contains(&slash_bin) {
                    found_bins.push(*bin);
                }
            }
            if !found_bins.is_empty() {
                is_critical = true;
                desc = found_bins.join(", ");
            }
        }

        if is_critical {
            output_lines.push(format!("{}{}", CLAWTOWER_DISABLED_PREFIX, line));
            descriptions.push(desc);
        } else {
            output_lines.push(line.to_string());
        }
    }

    // Preserve trailing newline if original had one
    let mut result = output_lines.join("\n");
    if content.ends_with('\n') {
        result.push('\n');
    }

    (result, descriptions)
}

/// Validate a sudoers file using `visudo -cf`.
fn validate_sudoers_file(path: &str) -> Result<(), String> {
    let output = std::process::Command::new("visudo")
        .args(["-cf", path])
        .output()
        .map_err(|e| format!("visudo not available: {}", e))?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("visudo rejected file: {}", stderr.trim()))
    }
}

/// Back up a sudoers file and write remediated content.
///
/// Returns the list of remediation descriptions on success.
/// Restores from backup if `visudo` validation fails.
fn remediate_sudoers_file(path: &str, content: &str) -> Result<Vec<String>, String> {
    let (new_content, descriptions) = remediate_sudoers_content(content);

    if descriptions.is_empty() {
        return Ok(descriptions);
    }

    // TOCTOU guard: re-read to detect concurrent modification
    let current = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot re-read {} before remediation: {}", path, e))?;
    if current != content {
        return Err(format!(
            "file {} was modified between scan and remediation; skipping to prevent data loss",
            path
        ));
    }

    // Create backup directory
    std::fs::create_dir_all(SUDOERS_BACKUP_DIR)
        .map_err(|e| format!("cannot create backup dir: {}", e))?;

    // Write backup (millisecond precision to avoid collision)
    let filename = std::path::Path::new(path)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let backup_path = format!("{}/{}.{}", SUDOERS_BACKUP_DIR, filename, timestamp);
    std::fs::write(&backup_path, content)
        .map_err(|e| format!("cannot write backup to {}: {}", backup_path, e))?;

    // Write remediated content
    std::fs::write(path, &new_content)
        .map_err(|e| {
            // Try to restore on write failure
            if let Err(re) = std::fs::write(path, content) {
                eprintln!(
                    "CRITICAL: sudoers write failed ({}) AND restore failed ({}) for {}. \
                     Manual recovery needed from {}",
                    e, re, path, backup_path
                );
            }
            format!("cannot write remediated file: {}", e)
        })?;

    // Validate with visudo (if available)
    match validate_sudoers_file(path) {
        Ok(()) => Ok(descriptions),
        Err(e) => {
            // Restore from backup — never leave a broken sudoers file
            match std::fs::write(path, content) {
                Ok(()) => {
                    Err(format!("restored original after validation failure: {}", e))
                }
                Err(re) => {
                    eprintln!(
                        "CRITICAL: visudo rejected remediation ({}) AND restore failed ({}) for {}. \
                         Manual recovery needed from {}",
                        e, re, path, backup_path
                    );
                    Err(format!(
                        "CRITICAL: validation failed ({}) AND restore failed ({}). \
                         Manual recovery needed from {}",
                        e, re, backup_path
                    ))
                }
            }
        }
    }
}

pub fn scan_sudoers_risk() -> ScanResult {
    let mut all_critical = Vec::new();
    let mut all_warnings = Vec::new();
    let mut remediation_notes: Vec<String> = Vec::new();

    // Read /etc/sudoers (detect only — never remediate the main sudoers file)
    match std::fs::read_to_string("/etc/sudoers") {
        Ok(content) => {
            let (c, w) = parse_sudoers_risks(&content, "/etc/sudoers");
            all_critical.extend(c);
            all_warnings.extend(w);
        }
        Err(e) => {
            all_warnings.push(format!(
                "/etc/sudoers: cannot read ({}); scan results may be incomplete", e
            ));
        }
    }

    // Read /etc/sudoers.d/* drop-in files (detect + auto-remediate critical risks)
    if let Ok(entries) = std::fs::read_dir("/etc/sudoers.d") {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    let path_str = path.display().to_string();
                    let (c, w) = parse_sudoers_risks(&content, &path_str);
                    let has_critical = !c.is_empty();
                    all_critical.extend(c);
                    all_warnings.extend(w);

                    // Auto-remediate sudoers.d files with critical risks
                    if has_critical {
                        match remediate_sudoers_file(&path_str, &content) {
                            Ok(descriptions) if !descriptions.is_empty() => {
                                remediation_notes.push(format!(
                                    "commented out {} line(s) in {} ({})",
                                    descriptions.len(),
                                    path_str,
                                    descriptions.join(", ")
                                ));
                            }
                            Ok(_) => {
                                // Detection found critical risks but remediation found
                                // nothing to disable — logic divergence, treat as failure
                                eprintln!(
                                    "WARNING: sudoers scan found critical risks in {} but \
                                     remediation found no lines to disable",
                                    path_str
                                );
                                remediation_notes.push(format!(
                                    "FAILED to remediate {}: no lines matched for remediation \
                                     despite critical risks detected",
                                    path_str
                                ));
                            }
                            Err(e) => {
                                remediation_notes.push(format!(
                                    "FAILED to remediate {}: {}",
                                    path_str, e
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    if !all_critical.is_empty() {
        let tag = if !remediation_notes.is_empty() {
            let failures = remediation_notes.iter().filter(|r| r.starts_with("FAILED")).count();
            let successes = remediation_notes.len() - failures;
            if failures == 0 {
                " [AUTO-REMEDIATED]"
            } else if successes == 0 {
                " [REMEDIATION FAILED]"
            } else {
                " [PARTIAL REMEDIATION]"
            }
        } else {
            ""
        };

        let mut detail = format!(
            "{} critical sudoers risk(s){}: {}",
            all_critical.len(), tag, all_critical.join("; ")
        );

        if !remediation_notes.is_empty() {
            detail.push_str(&format!(
                ". Remediation: {}. Backups: {}",
                remediation_notes.join("; "),
                SUDOERS_BACKUP_DIR,
            ));
        }

        ScanResult::new("sudoers_risk", ScanStatus::Fail, &detail)
    } else if !all_warnings.is_empty() {
        ScanResult::new(
            "sudoers_risk",
            ScanStatus::Warn,
            &format!("{} sudoers warning(s): {}",
                all_warnings.len(), all_warnings.join("; ")),
        )
    } else {
        ScanResult::new(
            "sudoers_risk",
            ScanStatus::Pass,
            "Sudoers configuration hardened - no NOPASSWD risks found",
        )
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
    fn test_parse_ufw_with_ipv6_rules() {
        let output = "Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing)\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW IN    Anywhere\n22/tcp (v6)                ALLOW IN    Anywhere (v6)\n";
        let result = parse_ufw_status(output);
        assert_eq!(result.status, ScanStatus::Pass);
        assert!(result.details.contains("2 rules"));
    }

    #[test]
    fn test_parse_ufw_many_rules() {
        let mut output = "Status: active\nLogging: on (low)\nDefault: deny\n\nTo                         Action      From\n--                         ------      ----\n".to_string();
        for port in 1..=50 {
            output.push_str(&format!("{}/tcp                     ALLOW IN    Anywhere\n", port));
        }
        let result = parse_ufw_status(&output);
        assert_eq!(result.status, ScanStatus::Pass);
        assert!(result.details.contains("50 rules"));
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
    fn test_parse_auditctl_immutable_zero_rules() {
        let output = "enabled 2\nfailure 1\nrules 0\n";
        let result = parse_auditctl_status(output);
        assert_eq!(result.status, ScanStatus::Warn);
        assert!(result.details.contains("no rules"));
    }

    #[test]
    fn test_parse_auditctl_garbage_input() {
        let output = "some random garbage output\n";
        let result = parse_auditctl_status(output);
        assert_eq!(result.status, ScanStatus::Fail);
    }

    #[test]
    fn test_parse_auditctl_empty() {
        let result = parse_auditctl_status("");
        assert_eq!(result.status, ScanStatus::Fail);
    }

    #[test]
    fn test_password_policy_pass_max_days_threshold() {
        let days_ok = 90u32;
        let days_bad = 91u32;
        let days_default = 99999u32;
        assert!(!(days_ok > 90 || days_ok == 99999));
        assert!(days_bad > 90 || days_bad == 99999);
        assert!(days_default > 90 || days_default == 99999);
    }

    #[test]
    fn test_sudoers_nopasswd_all_critical() {
        let content = "openclaw ALL=(ALL) NOPASSWD: ALL";
        let (critical, _) = parse_sudoers_risks(content, "/etc/sudoers");
        assert!(!critical.is_empty());
        assert!(critical[0].contains("passwordless unrestricted root"));
    }

    #[test]
    fn test_sudoers_nopasswd_gtfobins_critical() {
        let content = "openclaw ALL=(ALL) NOPASSWD: /usr/bin/find, /usr/bin/python3";
        let (critical, _) = parse_sudoers_risks(content, "/etc/sudoers");
        assert!(critical.iter().any(|c| c.contains("find")));
        assert!(critical.iter().any(|c| c.contains("python3")));
    }

    #[test]
    fn test_sudoers_nopasswd_safe_command_warning() {
        let content = "openclaw ALL=(ALL) NOPASSWD: /usr/bin/clawtower";
        let (critical, warnings) = parse_sudoers_risks(content, "/etc/sudoers");
        assert!(critical.is_empty());
        assert!(!warnings.is_empty());
    }

    #[test]
    fn test_sudoers_env_keep_dangerous() {
        let content = "Defaults env_keep += \"LD_PRELOAD PATH\"";
        let (_, warnings) = parse_sudoers_risks(content, "/etc/sudoers");
        assert!(warnings.iter().any(|w| w.contains("LD_PRELOAD")));
    }

    #[test]
    fn test_sudoers_clean_config_passes() {
        let content = "# This is a comment\nDefaults requiretty\n";
        let (critical, warnings) = parse_sudoers_risks(content, "/etc/sudoers");
        assert!(critical.is_empty());
        assert!(warnings.is_empty());
    }

    // ── Remediation tests ────────────────────────────────────────────────

    #[test]
    fn test_remediate_nopasswd_all() {
        let content = "jr ALL=(ALL) NOPASSWD: ALL\n";
        let (result, descriptions) = remediate_sudoers_content(content);
        assert!(result.starts_with(CLAWTOWER_DISABLED_PREFIX));
        assert_eq!(descriptions, vec!["NOPASSWD ALL"]);
        // Original line is preserved after the prefix
        assert!(result.contains("jr ALL=(ALL) NOPASSWD: ALL"));
    }

    #[test]
    fn test_remediate_gtfobins() {
        let content = "openclaw ALL=(ALL) NOPASSWD: /usr/bin/find, /bin/sh\n";
        let (result, descriptions) = remediate_sudoers_content(content);
        assert!(result.starts_with(CLAWTOWER_DISABLED_PREFIX));
        assert_eq!(descriptions.len(), 1);
        assert!(descriptions[0].contains("find"));
        assert!(descriptions[0].contains("sh"));
    }

    #[test]
    fn test_remediate_safe_nopasswd_untouched() {
        let content = "openclaw ALL=(ALL) NOPASSWD: /usr/bin/clawtower\n";
        let (result, descriptions) = remediate_sudoers_content(content);
        assert!(descriptions.is_empty());
        assert_eq!(result, content);
    }

    #[test]
    fn test_remediate_already_disabled_idempotent() {
        let content = "# CLAWTOWER-DISABLED: jr ALL=(ALL) NOPASSWD: ALL\n";
        let (result, descriptions) = remediate_sudoers_content(content);
        assert!(descriptions.is_empty());
        assert_eq!(result, content);
    }

    #[test]
    fn test_remediate_mixed_content() {
        let content = "\
# Comment
Defaults requiretty
openclaw ALL=(ALL) NOPASSWD: /usr/bin/find, /usr/bin/clawtower
jr ALL=(ALL) NOPASSWD: ALL
backup ALL=(ALL) NOPASSWD: /usr/bin/restic
";
        let (result, descriptions) = remediate_sudoers_content(content);
        assert_eq!(descriptions.len(), 2);
        // Comment and Defaults untouched
        assert!(result.contains("# Comment\n"));
        assert!(result.contains("Defaults requiretty\n"));
        // Safe NOPASSWD untouched
        assert!(result.contains("\nbackup ALL=(ALL) NOPASSWD: /usr/bin/restic\n"));
        // Dangerous lines disabled
        assert!(result.contains(&format!(
            "{}openclaw ALL=(ALL) NOPASSWD: /usr/bin/find, /usr/bin/clawtower",
            CLAWTOWER_DISABLED_PREFIX
        )));
        assert!(result.contains(&format!(
            "{}jr ALL=(ALL) NOPASSWD: ALL",
            CLAWTOWER_DISABLED_PREFIX
        )));
    }

    #[test]
    fn test_remediate_roundtrip_reversible() {
        let original = "openclaw ALL=(ALL) NOPASSWD: /usr/bin/find\njr ALL=(ALL) NOPASSWD: ALL\n";
        let (remediated, descriptions) = remediate_sudoers_content(original);
        assert_eq!(descriptions.len(), 2);

        // Simulate uninstall: strip the prefix
        let restored: String = remediated
            .lines()
            .map(|line| {
                line.strip_prefix(CLAWTOWER_DISABLED_PREFIX)
                    .unwrap_or(line)
                    .to_string()
            })
            .collect::<Vec<_>>()
            .join("\n");
        // Preserve trailing newline
        let restored = if original.ends_with('\n') && !restored.ends_with('\n') {
            format!("{}\n", restored)
        } else {
            restored
        };
        assert_eq!(restored, original);
    }

    #[test]
    fn test_remediate_preserves_trailing_newline() {
        let with_newline = "jr ALL=(ALL) NOPASSWD: ALL\n";
        let (result, _) = remediate_sudoers_content(with_newline);
        assert!(result.ends_with('\n'));

        let without_newline = "jr ALL=(ALL) NOPASSWD: ALL";
        let (result, _) = remediate_sudoers_content(without_newline);
        assert!(!result.ends_with('\n'));
    }

    #[test]
    fn test_remediate_nopasswd_all_all_variant() {
        let content = "user ALL=(ALL:ALL) NOPASSWD: ALL\n";
        let (result, descriptions) = remediate_sudoers_content(content);
        assert_eq!(descriptions, vec!["NOPASSWD ALL"]);
        assert!(result.starts_with(CLAWTOWER_DISABLED_PREFIX));
    }

    #[test]
    fn test_remediate_multiple_gtfobins_one_line() {
        let content = "openclaw ALL=(ALL) NOPASSWD: /usr/bin/find, /usr/bin/apt, /usr/bin/apt-get, /bin/sh\n";
        let (result, descriptions) = remediate_sudoers_content(content);
        assert_eq!(descriptions.len(), 1);
        assert!(descriptions[0].contains("find"));
        assert!(descriptions[0].contains("apt"));
        assert!(descriptions[0].contains("sh"));
        assert!(result.starts_with(CLAWTOWER_DISABLED_PREFIX));
    }

    #[test]
    fn test_remediate_empty_content() {
        let content = "";
        let (result, descriptions) = remediate_sudoers_content(content);
        assert!(descriptions.is_empty());
        assert_eq!(result, "");
    }

    #[test]
    fn test_remediate_comments_only() {
        let content = "# Just a comment\n# Another comment\n";
        let (result, descriptions) = remediate_sudoers_content(content);
        assert!(descriptions.is_empty());
        assert_eq!(result, content);
    }

    // ── Docker security inspect parse tests ────────────────────────────

    #[test]
    fn test_docker_inspect_all_secure() {
        let issues = parse_docker_security_inspect(
            "true", "appuser", "[SYS_ADMIN NET_ADMIN LINUX_IMMUTABLE]",
        );
        assert!(issues.is_empty());
    }

    #[test]
    fn test_docker_inspect_writable_rootfs() {
        let issues = parse_docker_security_inspect(
            "false", "appuser", "[SYS_ADMIN NET_ADMIN LINUX_IMMUTABLE]",
        );
        assert!(issues.iter().any(|i| i.contains("writable root filesystem")));
    }

    #[test]
    fn test_docker_inspect_running_as_root() {
        let issues = parse_docker_security_inspect("true", "", "[SYS_ADMIN NET_ADMIN LINUX_IMMUTABLE]");
        assert!(issues.iter().any(|i| i.contains("running as root")));

        let issues2 = parse_docker_security_inspect("true", "root", "[SYS_ADMIN NET_ADMIN LINUX_IMMUTABLE]");
        assert!(issues2.iter().any(|i| i.contains("running as root")));

        let issues3 = parse_docker_security_inspect("true", "0", "[SYS_ADMIN NET_ADMIN LINUX_IMMUTABLE]");
        assert!(issues3.iter().any(|i| i.contains("running as root")));
    }

    #[test]
    fn test_docker_inspect_missing_cap_drop() {
        let issues = parse_docker_security_inspect("true", "appuser", "[]");
        assert!(issues.iter().any(|i| i.contains("SYS_ADMIN")));
        assert!(issues.iter().any(|i| i.contains("NET_ADMIN")));
        assert!(issues.iter().any(|i| i.contains("LINUX_IMMUTABLE")));
    }

    #[test]
    fn test_docker_inspect_partial_cap_drop() {
        let issues = parse_docker_security_inspect("true", "appuser", "[SYS_ADMIN]");
        assert!(!issues.iter().any(|i| i.contains("SYS_ADMIN")));
        assert!(issues.iter().any(|i| i.contains("NET_ADMIN")));
        assert!(issues.iter().any(|i| i.contains("LINUX_IMMUTABLE")));
    }

    #[test]
    fn test_docker_inspect_all_bad() {
        let issues = parse_docker_security_inspect("false", "root", "[]");
        assert!(issues.len() >= 5); // writable + root + 3 missing caps
    }

    // ── Node.js version tests ──────────────────────────────────────────

    #[test]
    fn test_node_version_good() {
        let result = check_node_version("v22.12.0", 22, 12, 0);
        assert_eq!(result.status, ScanStatus::Pass);
    }

    #[test]
    fn test_node_version_newer() {
        let result = check_node_version("v23.1.0", 22, 12, 0);
        assert_eq!(result.status, ScanStatus::Pass);
    }

    #[test]
    fn test_node_version_old() {
        let result = check_node_version("v20.11.1", 22, 12, 0);
        assert_eq!(result.status, ScanStatus::Fail);
    }

    #[test]
    fn test_node_version_v_prefix() {
        let result = check_node_version("v22.12.0", 22, 12, 0);
        assert_eq!(result.status, ScanStatus::Pass);
        // Also without v prefix
        let result2 = check_node_version("22.12.0", 22, 12, 0);
        assert_eq!(result2.status, ScanStatus::Pass);
    }

    #[test]
    fn test_node_version_parse_error() {
        let result = check_node_version("not-a-version", 22, 12, 0);
        assert_eq!(result.status, ScanStatus::Warn);
    }

    #[test]
    fn test_node_version_exact_boundary() {
        // Exactly at minimum should pass
        let result = check_node_version("v22.12.0", 22, 12, 0);
        assert_eq!(result.status, ScanStatus::Pass);
        // One patch below should fail
        let result2 = check_node_version("v22.11.9", 22, 12, 0);
        assert_eq!(result2.status, ScanStatus::Fail);
    }
}
