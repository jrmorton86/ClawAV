//! Firewall state monitor.
//!
//! Captures a baseline of the available firewall backend, then polls every 30
//! seconds for changes. Backends are tried in this order:
//! - UFW (`ufw status verbose`)
//! - firewalld (`firewall-cmd --state` + `--list-all`)
//! - nftables (`nft list ruleset`)
//! - iptables (`iptables -S`)
//!
//! Any disablement or ruleset change triggers a Critical alert.

use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};
use std::time::Duration as StdDuration;

use crate::alerts::{Alert, Severity};
use crate::safe_cmd::SafeCommand;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FirewallBackend {
    Ufw,
    Firewalld,
    Nftables,
    Iptables,
}

impl FirewallBackend {
    fn as_str(&self) -> &'static str {
        match self {
            FirewallBackend::Ufw => "ufw",
            FirewallBackend::Firewalld => "firewalld",
            FirewallBackend::Nftables => "nftables",
            FirewallBackend::Iptables => "iptables",
        }
    }
}

fn command_exists<'a>(candidates: &'a [&'a str]) -> Option<&'a str> {
    for c in candidates {
        if std::path::Path::new(c).exists() {
            return Some(*c);
        }
    }
    None
}

fn detect_firewall_backend() -> Option<FirewallBackend> {
    if command_exists(&["/usr/sbin/ufw", "/usr/bin/ufw"]).is_some() {
        return Some(FirewallBackend::Ufw);
    }
    if command_exists(&["/usr/bin/firewall-cmd", "/usr/sbin/firewall-cmd"]).is_some() {
        return Some(FirewallBackend::Firewalld);
    }
    if command_exists(&["/usr/sbin/nft", "/usr/bin/nft"]).is_some() {
        return Some(FirewallBackend::Nftables);
    }
    if command_exists(&["/usr/sbin/iptables", "/usr/bin/iptables"]).is_some() {
        return Some(FirewallBackend::Iptables);
    }
    None
}

async fn run_output_with_optional_sudo(path: &str, args: &[&str]) -> Result<String, String> {
    let cmd = SafeCommand::new(path)
        .map_err(|e| format!("Failed to create command {}: {}", path, e))?
        .args(args)
        .timeout(StdDuration::from_secs(15));

    match cmd.run_output().await {
        Ok(output) => Ok(String::from_utf8_lossy(&output.stdout).to_string()),
        Err(_direct_err) => {
            let sudo_cmd = SafeCommand::new("/usr/bin/sudo")
                .map_err(|e| format!("Failed to create sudo command: {}", e))?
                .args(&[path])
                .args(args)
                .timeout(StdDuration::from_secs(15));

            sudo_cmd
                .run_output()
                .await
                .map(|output| String::from_utf8_lossy(&output.stdout).to_string())
                .map_err(|e| format!("Failed to run {} (direct and sudo): {}", path, e))
        }
    }
}

/// Capture current firewall status for the selected backend.
async fn get_firewall_status(backend: FirewallBackend) -> Result<String, String> {
    match backend {
        FirewallBackend::Ufw => {
            let ufw_path = command_exists(&["/usr/sbin/ufw", "/usr/bin/ufw"])
                .ok_or_else(|| "ufw not found".to_string())?;
            run_output_with_optional_sudo(ufw_path, &["status", "verbose"]).await
        }
        FirewallBackend::Firewalld => {
            let fw_path = command_exists(&["/usr/bin/firewall-cmd", "/usr/sbin/firewall-cmd"])
                .ok_or_else(|| "firewall-cmd not found".to_string())?;
            let state = run_output_with_optional_sudo(fw_path, &["--state"]).await?;
            let list_all = run_output_with_optional_sudo(fw_path, &["--list-all"]).await
                .unwrap_or_default();
            Ok(format!("STATE={}\n{}", state.trim(), list_all))
        }
        FirewallBackend::Nftables => {
            let nft_path = command_exists(&["/usr/sbin/nft", "/usr/bin/nft"])
                .ok_or_else(|| "nft not found".to_string())?;
            run_output_with_optional_sudo(nft_path, &["list", "ruleset"]).await
        }
        FirewallBackend::Iptables => {
            let ipt_path = command_exists(&["/usr/sbin/iptables", "/usr/bin/iptables"])
                .ok_or_else(|| "iptables not found".to_string())?;
            run_output_with_optional_sudo(ipt_path, &["-S"]).await
        }
    }
}

fn is_firewall_active(status: &str, backend: FirewallBackend) -> bool {
    match backend {
        FirewallBackend::Ufw => status.contains("Status: active"),
        FirewallBackend::Firewalld => status.contains("STATE=running"),
        FirewallBackend::Nftables => status.lines().any(|l| l.trim_start().starts_with("table ")),
        FirewallBackend::Iptables => status.lines().any(|l| l.starts_with("-P") || l.starts_with("-A")),
    }
}

/// Generate a simple diff between two status strings
fn diff_status(baseline: &str, current: &str) -> String {
    let old_lines: Vec<&str> = baseline.lines().collect();
    let new_lines: Vec<&str> = current.lines().collect();

    let mut diff = String::new();
    // Show removed lines
    for line in &old_lines {
        if !new_lines.contains(line) {
            diff.push_str(&format!("- {}\n", line));
        }
    }
    // Show added lines
    for line in &new_lines {
        if !old_lines.contains(line) {
            diff.push_str(&format!("+ {}\n", line));
        }
    }
    if diff.is_empty() {
        diff = "(no visible diff)".to_string();
    }
    diff
}

/// Monitor firewall state periodically and send alerts on changes
pub async fn monitor_firewall(tx: mpsc::Sender<Alert>) {
    let Some(backend) = detect_firewall_backend() else {
        let _ = tx.send(Alert::new(
            Severity::Warning,
            "firewall",
            "Cannot monitor firewall: no supported backend found (ufw/firewalld/nftables/iptables)",
        )).await;
        return;
    };

    // Capture baseline
    let baseline = match get_firewall_status(backend).await {
        Ok(s) => s,
        Err(e) => {
            let _ = tx.send(Alert::new(
                Severity::Warning,
                "firewall",
                &format!("Cannot monitor firewall ({}): {}", backend.as_str(), e),
            )).await;
            return;
        }
    };

    if !is_firewall_active(&baseline, backend) {
        let _ = tx.send(Alert::new(
            Severity::Critical,
            "firewall",
            &format!("Firewall is NOT active on startup! (backend={})", backend.as_str()),
        )).await;
    } else {
        let _ = tx.send(Alert::new(
            Severity::Info,
            "firewall",
            &format!("Firewall baseline captured (active, backend={})", backend.as_str()),
        )).await;
    }

    let mut last_status = baseline;

    loop {
        sleep(Duration::from_secs(30)).await;

        let current = match get_firewall_status(backend).await {
            Ok(s) => s,
            Err(_) => continue,
        };

        if current == last_status {
            continue;
        }

        // Status changed!
        if !is_firewall_active(&current, backend) {
            let diff = diff_status(&last_status, &current);
            let _ = tx.send(Alert::new(
                Severity::Critical,
                "firewall",
                &format!("🚨 FIREWALL DISABLED! (backend={})\nDiff:\n{}", backend.as_str(), diff),
            )).await;
        } else {
            let diff = diff_status(&last_status, &current);
            let _ = tx.send(Alert::new(
                Severity::Critical,
                "firewall",
                &format!("🚨 Firewall rules changed! (backend={})\nDiff:\n{}", backend.as_str(), diff),
            )).await;
        }

        last_status = current;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_firewall_active_detection() {
        let active = "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW       Anywhere\n";
        assert!(is_firewall_active(active, FirewallBackend::Ufw));

        let inactive = "Status: inactive\n";
        assert!(!is_firewall_active(inactive, FirewallBackend::Ufw));
    }

    #[test]
    fn test_firewalld_active_detection() {
        assert!(is_firewall_active("STATE=running\npublic (active)", FirewallBackend::Firewalld));
        assert!(!is_firewall_active("STATE=not running", FirewallBackend::Firewalld));
    }

    #[test]
    fn test_nftables_active_detection() {
        assert!(is_firewall_active("table inet filter\nchain input { }", FirewallBackend::Nftables));
        assert!(!is_firewall_active("", FirewallBackend::Nftables));
    }

    #[test]
    fn test_iptables_active_detection() {
        assert!(is_firewall_active("-P INPUT DROP\n-A INPUT -j ACCEPT", FirewallBackend::Iptables));
        assert!(!is_firewall_active("", FirewallBackend::Iptables));
    }

    #[test]
    fn test_diff_detects_changes() {
        let old = "Status: active\nRule1\nRule2\n";
        let new = "Status: active\nRule1\nRule3\n";
        let diff = diff_status(old, new);
        assert!(diff.contains("- Rule2"));
        assert!(diff.contains("+ Rule3"));
    }

    #[test]
    fn test_diff_no_change() {
        let s = "Status: active\nRule1\n";
        let diff = diff_status(s, s);
        assert!(diff.contains("no visible diff"));
    }
}
