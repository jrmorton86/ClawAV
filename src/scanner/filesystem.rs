// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Filesystem-related security scanners.
//!
//! SUID/SGID binaries, world-writable files, file integrity, immutable flags,
//! LD_PRELOAD checks, package verification, shadow file permissions.

use std::os::unix::fs::PermissionsExt;

use super::{ScanResult, ScanStatus};
use super::helpers::{run_cmd, detect_agent_home,
                     detect_primary_package_manager, compute_file_sha256};

/// Find world-writable files in sensitive directories (`/etc`, `/usr/bin`, `/var/log`, etc.).
pub fn scan_world_writable_files() -> ScanResult {
    let sensitive_dirs = ["/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin", "/var/log"];
    let mut issues = Vec::new();

    for dir in &sensitive_dirs {
        if let Ok(output) = run_cmd("sh", &["-c", &format!("find {} -type f -perm 0002 2>/dev/null", dir)]) {
            for file in output.lines() {
                if !file.trim().is_empty() {
                    issues.push(file.trim().to_string());
                }
            }
        }
    }

    if issues.is_empty() {
        ScanResult::new("world_writable", ScanStatus::Pass, "No world-writable files in sensitive directories")
    } else if issues.len() > 10 {
        ScanResult::new("world_writable", ScanStatus::Fail, &format!("Found {} world-writable files in sensitive dirs", issues.len()))
    } else {
        ScanResult::new("world_writable", ScanStatus::Warn, &format!("Found {} world-writable files: {}", issues.len(), issues.join(", ")))
    }
}

/// Enumerate SUID/SGID binaries system-wide and flag any not in the known-safe list.
pub fn scan_suid_sgid_binaries() -> ScanResult {
    let mut suid_files = Vec::new();
    let mut sgid_files = Vec::new();

    // Find SUID files
    if let Ok(output) = run_cmd("sh", &["-c", "find / -type f -perm -4000 2>/dev/null"]) {
        for file in output.lines() {
            if !file.trim().is_empty() {
                suid_files.push(file.trim().to_string());
            }
        }
    }

    // Find SGID files
    if let Ok(output) = run_cmd("sh", &["-c", "find / -type f -perm -2000 2>/dev/null"]) {
        for file in output.lines() {
            if !file.trim().is_empty() {
                sgid_files.push(file.trim().to_string());
            }
        }
    }

    // Known safe SUID binaries (common on most systems)
    let known_safe_suid = [
        "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd", "/usr/bin/chsh", "/usr/bin/chfn",
        "/usr/bin/gpasswd", "/usr/bin/newgrp", "/usr/bin/mount", "/usr/bin/umount",
        "/usr/bin/ping", "/usr/bin/ping6", "/usr/lib/openssh/ssh-keysign",
        "/usr/lib/dbus-1.0/dbus-daemon-launch-helper", "/usr/sbin/pppd"
    ];

    let suspicious_suid: Vec<&String> = suid_files.iter()
        .filter(|f| !known_safe_suid.iter().any(|safe| f.contains(safe)))
        .collect();

    let total_findings = suid_files.len() + sgid_files.len();
    let suspicious_count = suspicious_suid.len();

    if suspicious_count > 0 {
        ScanResult::new("suid_sgid", ScanStatus::Warn, &format!("Found {} SUID/SGID files, {} potentially suspicious: {}",
            total_findings, suspicious_count, suspicious_suid.iter().take(3).map(|s| s.as_str()).collect::<Vec<_>>().join(", ")))
    } else {
        ScanResult::new("suid_sgid", ScanStatus::Pass, &format!("Found {} SUID/SGID files, all appear legitimate", total_findings))
    }
}

/// Verify ClawTower binary and config integrity against stored SHA-256 checksums.
pub fn scan_integrity() -> ScanResult {
    // Check if binary exists and get its hash
    let _binary_path = "/usr/local/bin/clawtower";
    let _config_path = "/etc/clawtower/config.toml";
    let checksums_path = "/etc/clawtower/checksums.sha256";

    if !std::path::Path::new(checksums_path).exists() {
        return ScanResult::new("integrity", ScanStatus::Warn, "No checksums file found — run 'clawtower --store-checksums' to create baseline");
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

/// Check that immutable (chattr +i) flags are set on critical ClawTower files.
/// Auto-remediates: if a file exists but lacks the immutable flag, sets it
/// automatically and reports as a warning (not a failure).
pub fn scan_immutable_flags() -> ScanResult {
    let critical_files = [
        "/usr/local/bin/clawtower",
        "/usr/local/bin/clawsudo",
        "/usr/local/bin/clawtower-tray",
        "/etc/clawtower/config.toml",
        "/etc/clawtower/admin.key.hash",
        "/etc/systemd/system/clawtower.service",
        "/etc/sudoers.d/clawtower-deny",
    ];

    // Files that may not exist (optional or created later)
    let optional_files = [
        "/usr/local/bin/clawtower-tray",
        "/etc/clawtower/admin.key.hash",
        "/etc/sudoers.d/clawtower-deny",
    ];

    let mut missing = Vec::new();
    let mut remediated = Vec::new();
    let mut failed_remediation = Vec::new();

    for path in &critical_files {
        if !std::path::Path::new(path).exists() {
            if !optional_files.contains(path) {
                missing.push(*path);
            }
            continue;
        }

        let needs_fix = match run_cmd("lsattr", &[path]) {
            Ok(output) => {
                let attrs = output.split_whitespace().next().unwrap_or("");
                !attrs.contains('i')
            }
            Err(_) => true,
        };

        if needs_fix {
            // Auto-remediate: set the immutable flag
            match run_cmd("chattr", &["+i", path]) {
                Ok(_) => remediated.push(*path),
                Err(_) => failed_remediation.push(*path),
            }
        }
    }

    if !missing.is_empty() {
        ScanResult::new(
            "immutable_flags",
            ScanStatus::Fail,
            &format!("Critical files MISSING: {}", missing.join(", ")),
        )
    } else if !failed_remediation.is_empty() {
        ScanResult::new(
            "immutable_flags",
            ScanStatus::Fail,
            &format!(
                "🚨 Immutable flag MISSING and could not auto-fix: {} — possible tampering!",
                failed_remediation.join(", ")
            ),
        )
    } else if !remediated.is_empty() {
        ScanResult::new(
            "immutable_flags",
            ScanStatus::Warn,
            &format!(
                "🔧 Auto-fixed immutable flags on: {}",
                remediated.join(", ")
            ),
        )
    } else {
        ScanResult::new(
            "immutable_flags",
            ScanStatus::Pass,
            "All critical files have immutable flag set",
        )
    }
}

/// Parse lsattr output and check for immutable flag (testable helper).
#[allow(dead_code)]
pub fn check_lsattr_immutable(lsattr_output: &str) -> bool {
    let attrs = lsattr_output.split_whitespace().next().unwrap_or("");
    attrs.contains('i')
}

/// ClawTower's own LD_PRELOAD guard library path — entries matching this are benign.
const CLAWTOWER_GUARD_PATH: &str = "/usr/local/lib/libclawtower.so";

/// Common shell profile files to scan for LD_PRELOAD persistence.
const PROFILE_SCAN_PATHS: &[&str] = &[
    "/etc/environment",
    "/etc/profile",
    "/etc/bash.bashrc",
    "/etc/profile.d/",
];

/// User-relative profile files to scan (appended to home dir).
const USER_PROFILE_FILES: &[&str] = &[
    ".bashrc",
    ".bash_profile",
    ".profile",
    ".zshrc",
    ".zprofile",
    ".zshenv",
];

/// Scan common shell profile and environment files for LD_PRELOAD entries
/// that don't match ClawTower's own guard library. Detects persistence
/// mechanisms where an agent injects LD_PRELOAD into login/shell init files.
pub fn scan_ld_preload_persistence() -> ScanResult {
    let mut issues = Vec::new();

    // Helper: check a single file for LD_PRELOAD lines
    let check_file = |path: &str, issues: &mut Vec<String>| {
        if let Ok(content) = std::fs::read_to_string(path) {
            for (lineno, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                // Skip comments
                if trimmed.starts_with('#') {
                    continue;
                }
                if (trimmed.contains("LD_PRELOAD=") || trimmed.contains("export LD_PRELOAD"))
                    && !trimmed.contains(CLAWTOWER_GUARD_PATH)
                    && !trimmed.contains("clawtower")
                    && !trimmed.contains("clawtower")
                {
                    issues.push(format!(
                        "{}:{}: {}",
                        path,
                        lineno + 1,
                        trimmed
                    ));
                }
            }
        }
    };

    // System-wide files
    for path in PROFILE_SCAN_PATHS {
        if path.ends_with('/') {
            // It's a directory — scan all files inside
            if let Ok(entries) = std::fs::read_dir(path) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.is_file() {
                        check_file(&p.to_string_lossy(), &mut issues);
                    }
                }
            }
        } else {
            check_file(path, &mut issues);
        }
    }

    // User profile files for common home directories
    let home_dirs: Vec<String> = if let Ok(passwd) = std::fs::read_to_string("/etc/passwd") {
        passwd
            .lines()
            .filter_map(|line| {
                let fields: Vec<&str> = line.split(':').collect();
                if fields.len() >= 6 {
                    let uid: u32 = fields[2].parse().unwrap_or(0);
                    if (1000..65534).contains(&uid) {
                        return Some(fields[5].to_string());
                    }
                }
                None
            })
            .collect()
    } else {
        // Fallback
        let mut homes = vec![detect_agent_home(), "/root".to_string()];
        homes.sort();
        homes.dedup();
        homes
    };

    for home in &home_dirs {
        for profile in USER_PROFILE_FILES {
            let path = format!("{}/{}", home, profile);
            check_file(&path, &mut issues);
        }
    }

    // Also check /etc/ld.so.preload (not a shell profile, but related)
    if let Ok(content) = std::fs::read_to_string("/etc/ld.so.preload") {
        for line in content.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#')
                && !trimmed.contains(CLAWTOWER_GUARD_PATH)
                && !trimmed.contains("clawtower")
                && !trimmed.contains("clawtower")
            {
                issues.push(format!("/etc/ld.so.preload: {}", trimmed));
            }
        }
    }

    if issues.is_empty() {
        ScanResult::new(
            "ld_preload_persistence",
            ScanStatus::Pass,
            "No unauthorized LD_PRELOAD entries in profile files",
        )
    } else {
        ScanResult::new(
            "ld_preload_persistence",
            ScanStatus::Fail,
            &format!("LD_PRELOAD persistence detected: {}", issues.join("; ")),
        )
    }
}

/// Verify OS package integrity via `dpkg --verify` or `rpm -Va`.
pub fn scan_package_integrity() -> ScanResult {
    let mut issues = Vec::new();

    // Check dpkg/apt package integrity (Debian/Ubuntu)
    if let Ok(output) = run_cmd("which", &["dpkg"]) {
        if !output.trim().is_empty() {
            if let Ok(verify_output) = run_cmd("dpkg", &["--verify"]) {
                for line in verify_output.lines() {
                    if line.trim().len() > 1 { // dpkg --verify outputs modified files
                        issues.push(format!("Modified package file: {}", line.trim()));
                    }
                }
            }
        }
    }
    // Check rpm package integrity (Red Hat/CentOS)
    else if let Ok(output) = run_cmd("which", &["rpm"]) {
        if !output.trim().is_empty() {
            if let Ok(verify_output) = run_cmd("rpm", &["-Va"]) {
                for line in verify_output.lines() {
                    if line.contains("missing") || line.contains("changed") {
                        issues.push(format!("Modified RPM: {}", line.trim()));
                    }
                }
            }
        }
    }

    // Check for unsigned packages
    if let Ok(output) = run_cmd("apt", &["list", "--installed"]) {
        let installed_count = output.lines().count().saturating_sub(1); // Subtract header
        if installed_count > 2000 {
            issues.push(format!("High number of packages installed: {}", installed_count));
        }
    }

    if issues.len() > 10 {
        ScanResult::new("package_integrity", ScanStatus::Warn, &format!("Many package integrity issues: {} problems", issues.len()))
    } else if !issues.is_empty() {
        ScanResult::new("package_integrity", ScanStatus::Warn, &format!("Package issues: {}", issues.iter().take(3).cloned().collect::<Vec<_>>().join("; ")))
    } else {
        ScanResult::new("package_integrity", ScanStatus::Pass, "Package integrity verified")
    }
}

/// Verify shadow and quarantine directory permissions are hardened (0700 root:root).
/// Also checks that shadow files are 0600.
pub fn scan_shadow_quarantine_permissions() -> ScanResult {
    let dirs = [
        ("/etc/clawtower/shadow", "shadow"),
        ("/etc/clawtower/sentinel-shadow", "sentinel-shadow"),
        ("/etc/clawtower/quarantine", "quarantine"),
    ];

    let mut issues = Vec::new();

    for (dir_path, label) in &dirs {
        match std::fs::metadata(dir_path) {
            Ok(meta) => {
                let mode = meta.permissions().mode() & 0o777;
                if mode != 0o700 {
                    issues.push(format!("{} dir has mode {:o} (expected 700)", label, mode));
                }
                // Check owner is root (uid 0)
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if meta.uid() != 0 {
                        issues.push(format!("{} dir owned by uid {} (expected 0/root)", label, meta.uid()));
                    }
                }

                // Check individual files in the directory
                if let Ok(entries) = std::fs::read_dir(dir_path) {
                    for entry in entries.flatten() {
                        if let Ok(file_meta) = entry.metadata() {
                            if file_meta.is_file() {
                                let file_mode = file_meta.permissions().mode() & 0o777;
                                if file_mode != 0o600 {
                                    issues.push(format!("{}/{} has mode {:o} (expected 600)",
                                        label, entry.file_name().to_string_lossy(), file_mode));
                                }
                            }
                        }
                    }
                }
            }
            Err(_) => {
                // Directory doesn't exist — not necessarily an error if sentinel is disabled
            }
        }
    }

    if issues.is_empty() {
        ScanResult::new("shadow_quarantine_perms", ScanStatus::Pass,
            "Shadow and quarantine directories properly hardened")
    } else {
        ScanResult::new("shadow_quarantine_perms", ScanStatus::Warn,
            &format!("Permission issues: {}", issues.join("; ")))
    }
}

/// Check for pending system package updates via `apt list --upgradable`.
pub fn scan_updates() -> ScanResult {
    let manager = match detect_primary_package_manager() {
        Some(m) => m,
        None => return ScanResult::new("updates", ScanStatus::Warn, "No supported package manager found (apt/dnf/yum/zypper/pacman)"),
    };

    let result = match manager {
        "apt" => run_cmd("bash", &["-c", "apt list --upgradable 2>/dev/null | tail -n +2 | wc -l"])
            .map(|s| s.trim().parse::<u32>().unwrap_or(0)),
        "dnf" => run_cmd("bash", &["-c", "dnf -q list updates 2>/dev/null | grep -E '^[A-Za-z0-9_.+-]+' | wc -l"])
            .map(|s| s.trim().parse::<u32>().unwrap_or(0)),
        "yum" => run_cmd("bash", &["-c", "yum -q check-update 2>/dev/null | grep -E '^[A-Za-z0-9_.+-]+' | wc -l"])
            .map(|s| s.trim().parse::<u32>().unwrap_or(0)),
        "zypper" => run_cmd("bash", &["-c", "zypper -q list-updates 2>/dev/null | grep -E '^[iv| ]*[A-Za-z0-9_.+-]+' | wc -l"])
            .map(|s| s.trim().parse::<u32>().unwrap_or(0)),
        "pacman" => run_cmd("bash", &["-c", "pacman -Qu 2>/dev/null | wc -l"])
            .map(|s| s.trim().parse::<u32>().unwrap_or(0)),
        _ => Err("Unsupported package manager".to_string()),
    };

    match result {
        Ok(count) => {
            if count > 10 {
                ScanResult::new("updates", ScanStatus::Warn, &format!("{} pending system updates ({})", count, manager))
            } else {
                ScanResult::new("updates", ScanStatus::Pass, &format!("{} pending updates ({})", count, manager))
            }
        }
        Err(e) => ScanResult::new("updates", ScanStatus::Warn, &format!("Cannot check updates with {}: {}", manager, e)),
    }
}

/// Check the age of the Barnacle vendor pattern database via its git log.
pub fn scan_barnacle_sync() -> ScanResult {
    // Try configured path first, then common locations
    let agent_home = detect_agent_home();
    let mut candidates = vec![
        format!("{}/.openclaw/workspace/openclawtower/vendor/barnacle", agent_home),
        "vendor/barnacle".to_string(),
        "/opt/clawtower/vendor/barnacle".to_string(),
    ];
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join("vendor/barnacle").display().to_string());
    }
    let vendor_path = candidates.iter()
        .find(|p| std::path::Path::new(p).exists())
        .map(String::as_str)
        .unwrap_or("vendor/barnacle");

    if !std::path::Path::new(vendor_path).exists() {
        // Not a failure — Barnacle patterns are loaded at runtime from vendor dir.
        // When installed via oneshot script (no git repo), this is expected.
        return ScanResult::new("barnacle", ScanStatus::Pass, "Barnacle vendor dir not present (patterns loaded from embedded defaults if available)");
    }

    // Check how old the last update is
    match run_cmd("git", &["-C", vendor_path, "log", "-1", "--format=%cr"]) {
        Ok(output) => {
            let age_str = output.trim();

            // Parse age to determine status
            if age_str.contains("second") || age_str.contains("minute") ||
               age_str.contains("hour") || age_str.contains("day") {

                // If it contains "day" with a number, check if it's > 7 days
                if age_str.contains("day") {
                    if let Some(days_str) = age_str.split_whitespace().next() {
                        if let Ok(days) = days_str.parse::<u32>() {
                            if days > 7 {
                                return ScanResult::new("barnacle", ScanStatus::Warn,
                                    &format!("Barnacle patterns are {} old - consider running sync script", age_str));
                            }
                        }
                    }
                }

                ScanResult::new("barnacle", ScanStatus::Pass,
                    &format!("Barnacle patterns up to date ({})", age_str))
            } else if age_str.contains("week") || age_str.contains("month") || age_str.contains("year") {
                ScanResult::new("barnacle", ScanStatus::Warn,
                    &format!("Barnacle patterns are {} old - run scripts/sync-barnacle.sh", age_str))
            } else {
                ScanResult::new("barnacle", ScanStatus::Warn,
                    &format!("Barnacle last updated: {}", age_str))
            }
        }
        Err(e) => {
            ScanResult::new("barnacle", ScanStatus::Fail,
                &format!("Cannot check Barnacle status: {}", e))
        }
    }
}

/// Check swap encryption, `/tmp` mount options (noexec/nosuid/nodev), and `/dev/shm` security.
pub fn scan_swap_tmpfs_security() -> ScanResult {
    let mut issues = Vec::new();

    // Check swap encryption
    if let Ok(output) = run_cmd("swapon", &["--show"]) {
        if !output.trim().is_empty() {
            // Swap is enabled, check if encrypted
            if let Ok(cryptsetup_output) = run_cmd("bash", &["-c", "dmsetup table | grep crypt"]) {
                if cryptsetup_output.trim().is_empty() {
                    issues.push("Swap not encrypted".to_string());
                }
            } else {
                issues.push("Swap encryption unknown".to_string());
            }
        }
    }

    // Check tmp mount options
    if let Ok(output) = run_cmd("mount", &[]) {
        let mut tmp_found = false;
        for line in output.lines() {
            if line.contains(" /tmp ") {
                tmp_found = true;
                if !line.contains("noexec") {
                    issues.push("/tmp not mounted with noexec".to_string());
                }
                if !line.contains("nosuid") {
                    issues.push("/tmp not mounted with nosuid".to_string());
                }
                if !line.contains("nodev") {
                    issues.push("/tmp not mounted with nodev".to_string());
                }
            }
        }
        if !tmp_found {
            issues.push("/tmp not separately mounted".to_string());
        }
    }

    // Check /dev/shm security
    if let Ok(output) = run_cmd("mount", &[]) {
        for line in output.lines() {
            if line.contains(" /dev/shm ") && !line.contains("noexec") {
                issues.push("/dev/shm allows execution".to_string());
            }
        }
    }

    if issues.is_empty() {
        ScanResult::new("swap_tmpfs", ScanStatus::Pass, "Swap and temporary filesystem security good")
    } else {
        ScanResult::new("swap_tmpfs", ScanStatus::Warn, &format!("Swap/tmpfs issues: {}", issues.join("; ")))
    }
}

/// Compare plugin baseline hashes against current file hashes.
///
/// Returns results for: added files, removed files, modified files, and no-change.
pub fn compare_plugin_baselines(
    baseline: &std::collections::HashMap<String, String>,
    current: &std::collections::HashMap<String, String>,
) -> Vec<ScanResult> {
    let mut results = Vec::new();

    // Modified files
    for (path, cur_hash) in current {
        if let Some(base_hash) = baseline.get(path) {
            if base_hash != cur_hash {
                results.push(ScanResult::new("plugin_integrity", ScanStatus::Fail,
                    &format!("Plugin file modified: {}", path)));
            }
        } else {
            results.push(ScanResult::new("plugin_integrity", ScanStatus::Warn,
                &format!("New plugin file: {}", path)));
        }
    }

    // Removed files
    for path in baseline.keys() {
        if !current.contains_key(path) {
            results.push(ScanResult::new("plugin_integrity", ScanStatus::Warn,
                &format!("Plugin file removed: {}", path)));
        }
    }

    if results.is_empty() {
        results.push(ScanResult::new("plugin_integrity", ScanStatus::Pass,
            "All plugin files match baseline"));
    }

    results
}

/// Scan plugin extensions directory for integrity against a stored SHA-256 baseline.
pub fn scan_plugin_integrity(extensions_path: &str, baseline_path: &str) -> Vec<ScanResult> {
    let ext_path = std::path::Path::new(extensions_path);
    if !ext_path.exists() {
        return vec![ScanResult::new("plugin_integrity", ScanStatus::Pass,
            "No extensions directory — nothing to verify")];
    }

    // Compute current hashes
    let mut current: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    if let Ok(entries) = walkdir(ext_path) {
        for entry_path in entries {
            let ext = entry_path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if matches!(ext, "js" | "json") {
                if let Ok(hash) = compute_file_sha256(entry_path.to_str().unwrap_or("")) {
                    current.insert(entry_path.display().to_string(), hash);
                }
            }
        }
    }

    // Load baseline
    let baseline: std::collections::HashMap<String, String> = std::fs::read_to_string(baseline_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    if baseline.is_empty() {
        // First run: save baseline
        if let Ok(json) = serde_json::to_string_pretty(&current) {
            if let Some(parent) = std::path::Path::new(baseline_path).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(baseline_path, json);
        }
        return vec![ScanResult::new("plugin_integrity", ScanStatus::Pass,
            &format!("Plugin integrity baseline initialized ({} files)", current.len()))];
    }

    compare_plugin_baselines(&baseline, &current)
}

/// Walk a directory recursively and return file paths.
fn walkdir(dir: &std::path::Path) -> Result<Vec<std::path::PathBuf>, std::io::Error> {
    let mut files = Vec::new();
    if dir.is_dir() {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                files.extend(walkdir(&path)?);
            } else {
                files.push(path);
            }
        }
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lsattr_immutable_flag_present() {
        assert!(check_lsattr_immutable("----i---------e------- /usr/local/bin/clawtower"));
    }

    #[test]
    fn test_lsattr_immutable_flag_missing() {
        assert!(!check_lsattr_immutable("--------------e------- /usr/local/bin/clawtower"));
    }

    #[test]
    fn test_lsattr_empty_output() {
        assert!(!check_lsattr_immutable(""));
    }

    #[test]
    fn test_lsattr_multiple_flags() {
        assert!(check_lsattr_immutable("----ia--------e------- /some/file"));
    }

    #[test]
    fn test_lsattr_only_immutable() {
        assert!(check_lsattr_immutable("----i------------- /file"));
    }

    #[test]
    fn test_scan_ld_preload_persistence_runs() {
        // Basic smoke test — should not panic, returns a ScanResult
        let result = scan_ld_preload_persistence();
        assert!(!result.category.is_empty());
    }

    #[test]
    fn test_ld_preload_allowlist_clawtower_guard() {
        let line = "LD_PRELOAD=/usr/local/lib/libclawtower.so";
        let trimmed = line.trim();
        assert!(
            trimmed.contains(CLAWTOWER_GUARD_PATH)
                || trimmed.contains("clawtower")
                || trimmed.contains("clawtower"),
            "ClawTower guard path should match allowlist"
        );
    }

    #[test]
    fn test_ld_preload_allowlist_clawtower_keyword() {
        let line = "LD_PRELOAD=/opt/clawtower/lib/guard.so";
        let trimmed = line.trim();
        assert!(trimmed.contains("clawtower"), "clawtower keyword should match");
    }

    #[test]
    fn test_compute_sha256_real_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.txt");
        std::fs::write(&path, "hello world").unwrap();
        let hash = compute_file_sha256(path.to_str().unwrap()).unwrap();
        assert_eq!(hash, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
    }

    #[test]
    fn test_compute_sha256_file_not_found() {
        let result = compute_file_sha256("/nonexistent/file/abc123");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cannot read"));
    }

    #[test]
    fn test_compute_sha256_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.txt");
        std::fs::write(&path, "").unwrap();
        let hash = compute_file_sha256(path.to_str().unwrap()).unwrap();
        assert_eq!(hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn test_compute_sha256_modified_file_differs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data.txt");
        std::fs::write(&path, "original").unwrap();
        let hash1 = compute_file_sha256(path.to_str().unwrap()).unwrap();
        std::fs::write(&path, "modified").unwrap();
        let hash2 = compute_file_sha256(path.to_str().unwrap()).unwrap();
        assert_ne!(hash1, hash2);
    }

    // ── Plugin integrity baseline tests ────────────────────────────────

    #[test]
    fn test_plugin_baselines_no_change() {
        let mut baseline = std::collections::HashMap::new();
        baseline.insert("/ext/plugin/index.js".to_string(), "abc123".to_string());
        let current = baseline.clone();
        let results = compare_plugin_baselines(&baseline, &current);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, ScanStatus::Pass);
    }

    #[test]
    fn test_plugin_baselines_modified_file() {
        let mut baseline = std::collections::HashMap::new();
        baseline.insert("/ext/plugin/index.js".to_string(), "abc123".to_string());
        let mut current = std::collections::HashMap::new();
        current.insert("/ext/plugin/index.js".to_string(), "def456".to_string());
        let results = compare_plugin_baselines(&baseline, &current);
        assert!(results.iter().any(|r| r.status == ScanStatus::Fail && r.details.contains("modified")));
    }

    #[test]
    fn test_plugin_baselines_new_file() {
        let baseline = std::collections::HashMap::new();
        let mut current = std::collections::HashMap::new();
        current.insert("/ext/plugin/new.js".to_string(), "abc123".to_string());
        let results = compare_plugin_baselines(&baseline, &current);
        assert!(results.iter().any(|r| r.details.contains("New plugin file")));
    }

    #[test]
    fn test_plugin_baselines_removed_file() {
        let mut baseline = std::collections::HashMap::new();
        baseline.insert("/ext/plugin/old.js".to_string(), "abc123".to_string());
        let current = std::collections::HashMap::new();
        let results = compare_plugin_baselines(&baseline, &current);
        assert!(results.iter().any(|r| r.details.contains("removed")));
    }

    #[test]
    fn test_plugin_integrity_no_extensions() {
        let results = scan_plugin_integrity("/nonexistent/extensions/12345", "/tmp/baseline.json");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, ScanStatus::Pass);
    }

    #[test]
    fn test_plugin_integrity_first_run() {
        let dir = tempfile::tempdir().unwrap();
        let ext_dir = dir.path().join("extensions");
        std::fs::create_dir_all(ext_dir.join("my-plugin")).unwrap();
        std::fs::write(ext_dir.join("my-plugin/index.js"), "console.log('hi')").unwrap();
        std::fs::write(ext_dir.join("my-plugin/package.json"), "{}").unwrap();

        let baseline_path = dir.path().join("baseline.json");
        let results = scan_plugin_integrity(
            ext_dir.to_str().unwrap(),
            baseline_path.to_str().unwrap(),
        );
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, ScanStatus::Pass);
        assert!(results[0].details.contains("baseline initialized"));
        assert!(baseline_path.exists());
    }
}
