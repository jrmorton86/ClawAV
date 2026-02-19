// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Enforcement verification scanner.
//!
//! Verifies that OS-level enforcement mechanisms (AppArmor, seccomp, capabilities)
//! are actually active on the OpenClaw process, not just configured.

use super::{ScanResult, ScanStatus};
use super::helpers::run_cmd_with_sudo;

/// Parse `aa-status` output to check if the openclaw profile is in enforce mode.
pub fn parse_aa_status(output: &str) -> ScanResult {
    let lower = output.to_lowercase();

    // Look for openclaw profile in enforce section
    let mut in_enforce = false;
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.contains("enforce") && trimmed.contains("mode") {
            in_enforce = true;
            continue;
        }
        if trimmed.contains("complain") && trimmed.contains("mode") {
            in_enforce = false;
            continue;
        }
        if in_enforce && (lower.contains("openclaw") || trimmed.contains("openclaw")) {
            return ScanResult::new("enforcement:apparmor", ScanStatus::Pass,
                "OpenClaw AppArmor profile is in enforce mode");
        }
    }

    // Simpler check: look for openclaw anywhere with enforce context
    if lower.contains("openclaw") {
        if lower.contains("enforce") {
            return ScanResult::new("enforcement:apparmor", ScanStatus::Pass,
                "OpenClaw AppArmor profile detected in enforce mode");
        }
        ScanResult::new("enforcement:apparmor", ScanStatus::Warn,
            "OpenClaw AppArmor profile found but not in enforce mode")
    } else {
        ScanResult::new("enforcement:apparmor", ScanStatus::Warn,
            "No OpenClaw AppArmor profile loaded")
    }
}

/// Parse `/proc/<pid>/status` content for the Seccomp field.
///
/// Returns Pass if Seccomp: 2 (filter mode), Warn otherwise.
pub fn parse_proc_status_seccomp(content: &str) -> ScanResult {
    for line in content.lines() {
        if line.starts_with("Seccomp:") {
            let value = line.split_whitespace().nth(1).unwrap_or("");
            return match value {
                "2" => ScanResult::new("enforcement:seccomp", ScanStatus::Pass,
                    "Seccomp BPF filter active on OpenClaw process"),
                "1" => ScanResult::new("enforcement:seccomp", ScanStatus::Warn,
                    "Seccomp in strict mode (not filter) on OpenClaw process"),
                "0" => ScanResult::new("enforcement:seccomp", ScanStatus::Warn,
                    "Seccomp not active on OpenClaw process"),
                _ => ScanResult::new("enforcement:seccomp", ScanStatus::Warn,
                    &format!("Unknown seccomp status: {}", value)),
            };
        }
    }
    ScanResult::new("enforcement:seccomp", ScanStatus::Warn,
        "Seccomp field not found in process status")
}

/// Parse `/proc/<pid>/status` content for the CapEff field.
///
/// Verifies that dangerous capabilities (SYS_ADMIN=21, NET_ADMIN=12,
/// LINUX_IMMUTABLE=9) are not present in the effective capability set.
pub fn parse_proc_status_caps(content: &str) -> ScanResult {
    for line in content.lines() {
        if line.starts_with("CapEff:") {
            let hex_str = line.split_whitespace().nth(1).unwrap_or("ffffffffffffffff");
            let caps = u64::from_str_radix(hex_str.trim(), 16).unwrap_or(u64::MAX);

            let mut dangerous = Vec::new();
            // CAP_SYS_ADMIN = 21
            if caps & (1u64 << 21) != 0 { dangerous.push("SYS_ADMIN"); }
            // CAP_NET_ADMIN = 12
            if caps & (1u64 << 12) != 0 { dangerous.push("NET_ADMIN"); }
            // CAP_LINUX_IMMUTABLE = 9
            if caps & (1u64 << 9) != 0 { dangerous.push("LINUX_IMMUTABLE"); }
            // CAP_SYS_PTRACE = 19
            if caps & (1u64 << 19) != 0 { dangerous.push("SYS_PTRACE"); }

            return if dangerous.is_empty() {
                ScanResult::new("enforcement:caps", ScanStatus::Pass,
                    &format!("OpenClaw process has no dangerous capabilities (CapEff: {})", hex_str.trim()))
            } else {
                ScanResult::new("enforcement:caps", ScanStatus::Warn,
                    &format!("OpenClaw process has dangerous capabilities: {} (CapEff: {})",
                        dangerous.join(", "), hex_str.trim()))
            };
        }
    }
    ScanResult::new("enforcement:caps", ScanStatus::Warn,
        "CapEff field not found in process status")
}

/// Run all enforcement verification checks against the live OpenClaw process.
pub fn scan_enforcement_verification() -> Vec<ScanResult> {
    let mut results = Vec::new();

    // 1. AppArmor profile status
    match run_cmd_with_sudo("aa-status", &[]) {
        Ok(output) => results.push(parse_aa_status(&output)),
        Err(_) => results.push(ScanResult::new("enforcement:apparmor", ScanStatus::Pass,
            "AppArmor not available (not required)")),
    }

    // Find openclaw PID
    let pid = match super::helpers::run_cmd("pgrep", &["-x", "openclaw"]) {
        Ok(p) if !p.trim().is_empty() => {
            p.trim().lines().next().unwrap_or("").to_string()
        }
        _ => {
            results.push(ScanResult::new("enforcement:seccomp", ScanStatus::Warn,
                "OpenClaw process not found — cannot verify enforcement"));
            results.push(ScanResult::new("enforcement:caps", ScanStatus::Warn,
                "OpenClaw process not found — cannot verify enforcement"));
            return results;
        }
    };

    // 2. Seccomp filter status
    let status_path = format!("/proc/{}/status", pid);
    match std::fs::read_to_string(&status_path) {
        Ok(content) => {
            results.push(parse_proc_status_seccomp(&content));
            results.push(parse_proc_status_caps(&content));
        }
        Err(e) => {
            results.push(ScanResult::new("enforcement:seccomp", ScanStatus::Warn,
                &format!("Cannot read {}: {}", status_path, e)));
            results.push(ScanResult::new("enforcement:caps", ScanStatus::Warn,
                &format!("Cannot read {}: {}", status_path, e)));
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── AppArmor parse tests ───────────────────────────────────────────

    #[test]
    fn test_aa_status_enforce_mode() {
        let output = "apparmor module is loaded.\n18 profiles are loaded.\n18 profiles are in enforce mode.\n   /usr/bin/openclaw\n   /usr/sbin/ntpd\n0 profiles are in complain mode.\n";
        let result = parse_aa_status(output);
        assert_eq!(result.status, ScanStatus::Pass);
    }

    #[test]
    fn test_aa_status_no_openclaw_profile() {
        let output = "apparmor module is loaded.\n5 profiles are loaded.\n5 profiles are in enforce mode.\n   /usr/sbin/ntpd\n0 profiles are in complain mode.\n";
        let result = parse_aa_status(output);
        assert_eq!(result.status, ScanStatus::Warn);
    }

    #[test]
    fn test_aa_status_empty() {
        let result = parse_aa_status("");
        assert_eq!(result.status, ScanStatus::Warn);
    }

    // ── Seccomp parse tests ────────────────────────────────────────────

    #[test]
    fn test_seccomp_filter_active() {
        let content = "Name:\topenclaw\nState:\tS (sleeping)\nSeccomp:\t2\nSeccomp_filters:\t1\n";
        let result = parse_proc_status_seccomp(content);
        assert_eq!(result.status, ScanStatus::Pass);
    }

    #[test]
    fn test_seccomp_disabled() {
        let content = "Name:\topenclaw\nSeccomp:\t0\n";
        let result = parse_proc_status_seccomp(content);
        assert_eq!(result.status, ScanStatus::Warn);
    }

    #[test]
    fn test_seccomp_strict_mode() {
        let content = "Name:\topenclaw\nSeccomp:\t1\n";
        let result = parse_proc_status_seccomp(content);
        assert_eq!(result.status, ScanStatus::Warn);
        assert!(result.details.contains("strict"));
    }

    #[test]
    fn test_seccomp_missing_field() {
        let content = "Name:\topenclaw\nState:\tR (running)\n";
        let result = parse_proc_status_seccomp(content);
        assert_eq!(result.status, ScanStatus::Warn);
    }

    // ── Capabilities parse tests ───────────────────────────────────────

    #[test]
    fn test_caps_no_dangerous() {
        // CapEff with no dangerous bits set (just CAP_NET_BIND_SERVICE=10)
        let content = "Name:\topenclaw\nCapEff:\t0000000000000400\n";
        let result = parse_proc_status_caps(content);
        assert_eq!(result.status, ScanStatus::Pass);
    }

    #[test]
    fn test_caps_sys_admin_present() {
        // CAP_SYS_ADMIN = bit 21 = 0x200000
        let content = "Name:\topenclaw\nCapEff:\t0000000000200000\n";
        let result = parse_proc_status_caps(content);
        assert_eq!(result.status, ScanStatus::Warn);
        assert!(result.details.contains("SYS_ADMIN"));
    }

    #[test]
    fn test_caps_multiple_dangerous() {
        // CAP_SYS_ADMIN(21) + CAP_NET_ADMIN(12) + CAP_LINUX_IMMUTABLE(9)
        // = 0x200000 + 0x1000 + 0x200 = 0x201200
        let content = "Name:\topenclaw\nCapEff:\t0000000000201200\n";
        let result = parse_proc_status_caps(content);
        assert_eq!(result.status, ScanStatus::Warn);
        assert!(result.details.contains("SYS_ADMIN"));
        assert!(result.details.contains("NET_ADMIN"));
        assert!(result.details.contains("LINUX_IMMUTABLE"));
    }

    #[test]
    fn test_caps_all_capabilities() {
        // Full capabilities = all bits set
        let content = "Name:\topenclaw\nCapEff:\tffffffffffffffff\n";
        let result = parse_proc_status_caps(content);
        assert_eq!(result.status, ScanStatus::Warn);
        assert!(result.details.contains("SYS_ADMIN"));
        assert!(result.details.contains("SYS_PTRACE"));
    }

    #[test]
    fn test_caps_missing_field() {
        let content = "Name:\topenclaw\nState:\tS\n";
        let result = parse_proc_status_caps(content);
        assert_eq!(result.status, ScanStatus::Warn);
    }

    #[test]
    fn test_caps_zero() {
        let content = "Name:\topenclaw\nCapEff:\t0000000000000000\n";
        let result = parse_proc_status_caps(content);
        assert_eq!(result.status, ScanStatus::Pass);
    }
}
