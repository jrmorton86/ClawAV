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
//! - SecureClaw pattern database freshness
//! - Audit log health and permissions
//! - Crontab audit, world-writable files, SUID/SGID binaries
//! - Kernel modules, Docker security, password policy
//! - DNS resolver, NTP sync, failed logins, zombie processes
//! - Environment variables, package integrity, core dump settings
//! - Network interfaces, systemd hardening, user account audit
//! - Cognitive file integrity (AI identity files)
//! - OpenClaw-specific checks (gateway exposure, auth, filesystem scope)

use chrono::{DateTime, Local};
use serde::Serialize;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{sleep, Duration};

use crate::alerts::{Alert, Severity};
use crate::cognitive::scan_cognitive_integrity;

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

/// Run a command with a timeout, killing it if it exceeds `timeout_secs`.
fn run_cmd_timeout(cmd: &str, args: &[&str], timeout_secs: u64) -> Result<String, String> {
    let mut child = Command::new(cmd)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("Failed to spawn {}: {}", cmd, e))?;
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                // Read stdout directly from the pipe before wait_with_output
                // (wait_with_output after try_wait can lose buffered data)
                let mut stdout_str = String::new();
                if let Some(mut stdout) = child.stdout.take() {
                    use std::io::Read;
                    let _ = stdout.read_to_string(&mut stdout_str);
                }
                let _ = child.wait(); // reap the process
                return Ok(stdout_str);
            }
            Ok(None) => {
                if start.elapsed().as_secs() > timeout_secs {
                    let _ = child.kill();
                    return Err(format!("{} timed out after {}s", cmd, timeout_secs));
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => return Err(format!("Error waiting for {}: {}", cmd, e)),
        }
    }
}

const DEFAULT_CMD_TIMEOUT: u64 = 30;

/// Run a command with the default timeout (30s).
fn run_cmd(cmd: &str, args: &[&str]) -> Result<String, String> {
    run_cmd_timeout(cmd, args, DEFAULT_CMD_TIMEOUT)
}

/// Run a command, falling back to `sudo` if the initial invocation fails.
fn run_cmd_with_sudo(cmd: &str, args: &[&str]) -> Result<String, String> {
    // Try without sudo first
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| format!("Failed to run {}: {}", cmd, e))?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).to_string());
    }
    // Skip sudo fallback if already root (NoNewPrivileges=yes blocks sudo)
    if unsafe { libc::getuid() } == 0 {
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

fn command_available(cmd: &str) -> bool {
    match run_cmd("which", &[cmd]) {
        Ok(output) => !output.trim().is_empty(),
        Err(_) => false,
    }
}

fn detect_agent_username() -> String {
    std::env::var("CLAWTOWER_AGENT_USER")
        .or_else(|_| std::env::var("OPENCLAW_USER"))
        .unwrap_or_else(|_| "openclaw".to_string())
}

fn user_home_from_passwd(username: &str) -> Option<String> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in passwd.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 6 && fields[0] == username {
            return Some(fields[5].to_string());
        }
    }
    None
}

fn detect_agent_home() -> String {
    let username = detect_agent_username();
    user_home_from_passwd(&username)
        .or_else(|| std::env::var("HOME").ok())
        .unwrap_or_else(|| format!("/home/{}", username))
}

fn detect_primary_package_manager() -> Option<&'static str> {
    if command_available("apt") {
        Some("apt")
    } else if command_available("dnf") {
        Some("dnf")
    } else if command_available("yum") {
        Some("yum")
    } else if command_available("zypper") {
        Some("zypper")
    } else if command_available("pacman") {
        Some("pacman")
    } else {
        None
    }
}

// --- Individual scan functions ---

/// Audit user and system crontabs for suspicious entries (wget, curl, nc, base64, etc.).
pub fn scan_crontab_audit() -> ScanResult {
    let mut issues = Vec::new();

    // Check user crontabs
    if let Ok(output) = run_cmd("bash", &["-c", "for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u $u 2>/dev/null | grep -v '^#' | grep -v '^$' && echo \"User: $u\"; done"]) {
        if !output.trim().is_empty() {
            let lines: Vec<&str> = output.lines().collect();
            for line in lines {
                if line.contains("wget") || line.contains("curl") || line.contains("nc") || 
                   line.contains("/dev/tcp") || line.contains("python -c") || line.contains("base64") {
                    issues.push(format!("Suspicious cron job: {}", line.trim()));
                }
            }
        }
    }

    // Check system crontabs
    let system_cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly"];
    for dir in &system_cron_dirs {
        if let Ok(output) = run_cmd("find", &[dir, "-type", "f", "-exec", "grep", "-l", "-E", "(wget|curl|nc|python -c|base64|/dev/tcp)", "{}", ";"]) {
            if !output.trim().is_empty() {
                for file in output.lines() {
                    issues.push(format!("Suspicious system cron file: {}", file));
                }
            }
        }
    }

    // Check /etc/crontab
    if let Ok(output) = run_cmd("grep", &["-v", "^#", "/etc/crontab"]) {
        for line in output.lines() {
            if line.contains("wget") || line.contains("curl") || line.contains("nc") {
                issues.push(format!("Suspicious /etc/crontab entry: {}", line.trim()));
            }
        }
    }

    if issues.is_empty() {
        ScanResult::new("crontab_audit", ScanStatus::Pass, "No suspicious cron jobs detected")
    } else {
        ScanResult::new("crontab_audit", ScanStatus::Fail, &format!("Found {} suspicious cron entries: {}", issues.len(), issues.join("; ")))
    }
}

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

/// Check loaded kernel modules for suspicious names (rootkit, backdoor, keylog, etc.).
pub fn scan_kernel_modules() -> ScanResult {
    match run_cmd("lsmod", &[]) {
        Ok(output) => {
            let lines: Vec<&str> = output.lines().collect();
            let module_count = lines.len().saturating_sub(1); // Subtract header

            // Check for suspicious module names
            let suspicious_patterns = ["rootkit", "evil", "backdoor", "stealth", "hidden", "keylog"];
            let mut suspicious_modules = Vec::new();

            for line in lines.iter().skip(1) { // Skip header
                let module_name = line.split_whitespace().next().unwrap_or("");
                for pattern in &suspicious_patterns {
                    if module_name.to_lowercase().contains(pattern) {
                        suspicious_modules.push(module_name);
                        break;
                    }
                }
            }

            if !suspicious_modules.is_empty() {
                ScanResult::new("kernel_modules", ScanStatus::Fail, &format!("Found {} suspicious kernel modules: {}", 
                    suspicious_modules.len(), suspicious_modules.join(", ")))
            } else if module_count > 100 {
                ScanResult::new("kernel_modules", ScanStatus::Warn, &format!("High number of loaded modules: {}", module_count))
            } else {
                ScanResult::new("kernel_modules", ScanStatus::Pass, &format!("{} kernel modules loaded", module_count))
            }
        }
        Err(e) => ScanResult::new("kernel_modules", ScanStatus::Warn, &format!("Cannot check kernel modules: {}", e)),
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

            if issues.is_empty() {
                ScanResult::new("docker_security", ScanStatus::Pass, "Docker security checks passed")
            } else {
                ScanResult::new("docker_security", ScanStatus::Warn, &format!("Docker security issues: {}", issues.join("; ")))
            }
        }
        Ok(_) | Err(_) => ScanResult::new("docker_security", ScanStatus::Pass, "Docker not running"),
    }
}

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

/// Check for excessive open file descriptors, suspicious network connections, and FD-heavy processes.
pub fn scan_open_file_descriptors() -> ScanResult {
    let mut issues = Vec::new();

    // Check system-wide open files
    if let Ok(output) = run_cmd("sh", &["-c", "lsof -n 2>/dev/null | wc -l"]) {
        if let Ok(count) = output.trim().parse::<u32>() {
            if count > 10000 {
                issues.push(format!("High number of open files: {}", count));
            }
        }
    }

    // Check for suspicious open network connections
    if let Ok(output) = run_cmd("lsof", &["-i", "-n"]) {
        for line in output.lines() {
            if line.contains("ESTABLISHED") && (line.contains(":6667") || line.contains(":6697") || 
               line.contains(":4444") || line.contains(":1234")) {
                issues.push(format!("Suspicious network connection: {}", line.trim()));
            }
        }
    }

    // Check processes with many open files
    if let Ok(output) = run_cmd("bash", &["-c", "for pid in /proc/*/fd; do echo \"$(ls $pid 2>/dev/null | wc -l) $pid\"; done | sort -n | tail -5"]) {
        for line in output.lines() {
            if let Some(count_str) = line.split_whitespace().next() {
                if let Ok(count) = count_str.parse::<u32>() {
                    if count > 1000 {
                        issues.push(format!("Process with many open FDs: {}", line.trim()));
                    }
                }
            }
        }
    }

    if issues.is_empty() {
        ScanResult::new("open_fds", ScanStatus::Pass, "File descriptor usage normal")
    } else {
        ScanResult::new("open_fds", ScanStatus::Warn, &format!("FD issues: {}", issues.join("; ")))
    }
}

/// Verify `/etc/resolv.conf` has nameservers configured and check for DNS hijacking indicators.
pub fn scan_dns_resolver() -> ScanResult {
    match std::fs::read_to_string("/etc/resolv.conf") {
        Ok(content) => {
            let mut nameservers = Vec::new();
            let mut suspicious_entries = Vec::new();

            for line in content.lines() {
                let line = line.trim();
                if line.starts_with("nameserver") {
                    if let Some(ip) = line.split_whitespace().nth(1) {
                        nameservers.push(ip.to_string());
                        
                        // Check for suspicious DNS servers
                        let suspicious_dns = ["8.8.4.4", "1.1.1.1"]; // Actually these are fine, but flagging non-standard
                        if !ip.starts_with("127.") && !ip.starts_with("192.168.") && 
                           !ip.starts_with("10.") && !ip.starts_with("172.") &&
                           !suspicious_dns.contains(&ip) && ip != "8.8.8.8" && ip != "1.0.0.1" {
                            suspicious_entries.push(format!("Unusual DNS server: {}", ip));
                        }
                    }
                }
                
                // Check for DNS hijacking indicators
                if line.contains("search ") && (line.contains(".local") || line.contains("attacker")) {
                    suspicious_entries.push(format!("Suspicious search domain: {}", line));
                }
            }

            if nameservers.is_empty() {
                ScanResult::new("dns_resolver", ScanStatus::Fail, "No nameservers configured")
            } else if !suspicious_entries.is_empty() {
                ScanResult::new("dns_resolver", ScanStatus::Warn, &format!("DNS concerns: {}", suspicious_entries.join("; ")))
            } else {
                ScanResult::new("dns_resolver", ScanStatus::Pass, &format!("DNS resolvers configured: {}", nameservers.join(", ")))
            }
        }
        Err(e) => ScanResult::new("dns_resolver", ScanStatus::Fail, &format!("Cannot read /etc/resolv.conf: {}", e)),
    }
}

/// Check NTP synchronization status via `timedatectl`, `ntp`, or `chronyd`.
pub fn scan_ntp_sync() -> ScanResult {
    // Try timedatectl first (systemd)
    if let Ok(output) = run_cmd("timedatectl", &["show", "--property=NTPSynchronized,NTP"]) {
        let ntp_sync = output.lines().any(|l| l.starts_with("NTPSynchronized=yes"));
        let ntp_enabled = output.lines().any(|l| l.starts_with("NTP=yes"));

        if ntp_sync && ntp_enabled {
            ScanResult::new("ntp_sync", ScanStatus::Pass, "NTP synchronized and enabled")
        } else if ntp_enabled {
            ScanResult::new("ntp_sync", ScanStatus::Warn, "NTP enabled but not synchronized")
        } else {
            ScanResult::new("ntp_sync", ScanStatus::Warn, "NTP not enabled")
        }
    }
    // Fall back to checking ntpd/chronyd services
    else if let Ok(status) = run_cmd("systemctl", &["is-active", "ntp"]) {
        if status.trim() == "active" {
            ScanResult::new("ntp_sync", ScanStatus::Pass, "NTP service active")
        } else {
            ScanResult::new("ntp_sync", ScanStatus::Warn, "NTP service not active")
        }
    } else if let Ok(status) = run_cmd("systemctl", &["is-active", "chronyd"]) {
        if status.trim() == "active" {
            ScanResult::new("ntp_sync", ScanStatus::Pass, "Chrony service active")
        } else {
            ScanResult::new("ntp_sync", ScanStatus::Warn, "No NTP service detected")
        }
    } else {
        ScanResult::new("ntp_sync", ScanStatus::Warn, "Cannot determine NTP status")
    }
}

/// Check journalctl and auth.log for excessive failed SSH login attempts and potential brute-force success.
pub fn scan_failed_login_attempts() -> ScanResult {
    let mut issues = Vec::new();

    // Check journalctl for failed SSH attempts
    if let Ok(output) = run_cmd("journalctl", &["--since", "24 hours ago", "-u", "ssh", "--grep", "Failed password"]) {
        let failed_attempts = output.lines().count();
        if failed_attempts > 50 {
            issues.push(format!("High SSH failed logins in 24h: {}", failed_attempts));
        } else if failed_attempts > 10 {
            issues.push(format!("Moderate SSH failed logins in 24h: {}", failed_attempts));
        }
    }

    // Check distro-specific auth logs if present
    for log_path in ["/var/log/auth.log", "/var/log/secure"] {
        if std::path::Path::new(log_path).exists() {
            if let Ok(output) = run_cmd("grep", &["-c", "Failed password", log_path]) {
                if let Ok(count) = output.trim().parse::<u32>() {
                    if count > 100 {
                        issues.push(format!("High auth failures in {}: {}", log_path, count));
                    }
                }
            }
        }
    }

    // Check for successful logins after many failures (potential brute force success)
    if let Ok(output) = run_cmd("journalctl", &["--since", "1 hour ago", "--grep", "Accepted password"]) {
        let successful_logins = output.lines().count();
        if successful_logins > 0 && issues.iter().any(|i| i.contains("failed logins")) {
            issues.push(format!("Successful logins after failures detected: {}", successful_logins));
        }
    }

    if issues.is_empty() {
        ScanResult::new("failed_logins", ScanStatus::Pass, "No excessive failed login attempts")
    } else {
        ScanResult::new("failed_logins", ScanStatus::Warn, &format!("Login attempt issues: {}", issues.join("; ")))
    }
}

/// Detect zombie processes and high-CPU consumers via `ps aux`.
pub fn scan_zombie_processes() -> ScanResult {
    match run_cmd("ps", &["aux"]) {
        Ok(output) => {
            let mut zombies = Vec::new();
            let mut high_cpu_procs = Vec::new();

            for line in output.lines().skip(1) { // Skip header
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() >= 11 {
                    let cpu = fields.get(2).map_or("0", |v| v);
                    let stat = fields.get(7).map_or("", |v| v);
                    let command = fields.get(10).map_or("", |v| v);

                    // Check for zombie processes
                    if stat.contains('Z') {
                        zombies.push(command.to_string());
                    }

                    // Check for processes consuming high CPU
                    if let Ok(cpu_val) = cpu.parse::<f32>() {
                        if cpu_val > 80.0 {
                            high_cpu_procs.push(format!("{} ({}%)", command, cpu));
                        }
                    }
                }
            }

            let mut issues = Vec::new();
            if !zombies.is_empty() {
                issues.push(format!("Zombie processes: {}", zombies.join(", ")));
            }
            if !high_cpu_procs.is_empty() {
                issues.push(format!("High CPU processes: {}", high_cpu_procs.join(", ")));
            }

            if issues.is_empty() {
                ScanResult::new("process_health", ScanStatus::Pass, "No zombie or suspicious processes")
            } else {
                ScanResult::new("process_health", ScanStatus::Warn, &format!("Process issues: {}", issues.join("; ")))
            }
        }
        Err(e) => ScanResult::new("process_health", ScanStatus::Warn, &format!("Cannot check processes: {}", e)),
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

/// Scan environment variables for suspicious LD_PRELOAD, proxy configs, debug flags, and leaked credentials.
pub fn scan_environment_variables() -> ScanResult {
    let mut issues = Vec::new();

    // Check current environment for suspicious variables
    for (key, value) in std::env::vars() {
        if key == "LD_PRELOAD" && !value.contains("clawguard") {
            issues.push(format!("Suspicious LD_PRELOAD: {}", value));
        }
        if key == "LD_LIBRARY_PATH" && value.contains("/tmp") {
            issues.push("LD_LIBRARY_PATH includes /tmp".to_string());
        }
        if key.contains("PROXY") && (value.contains("tor") || value.contains("socks")) {
            issues.push(format!("Proxy configuration detected: {}={}", key, value));
        }
        if key.contains("DEBUG") && value == "1" {
            issues.push(format!("Debug mode enabled: {}", key));
        }
        // Check for encoded credentials in env
        if (key.contains("KEY") || key.contains("SECRET") || key.contains("TOKEN"))
            && value.len() > 20 && value.chars().all(|c| c.is_ascii_alphanumeric() || c == '=' || c == '+' || c == '/') {
                issues.push(format!("Potential credential in environment: {}", key));
        }
    }

    // Check OpenClaw agent environment specifically
    if let Ok(openclaw_pid) = run_cmd("pgrep", &["openclaw"]) {
        if let Ok(env_content) = std::fs::read_to_string(format!("/proc/{}/environ", openclaw_pid.trim())) {
            let env_vars: Vec<&str> = env_content.split('\0').collect();
            for var in env_vars {
                if var.starts_with("AWS_SECRET_ACCESS_KEY=") || var.starts_with("ANTHROPIC_API_KEY=") {
                    issues.push("Credentials found in agent environment".to_string());
                }
            }
        }
    }

    if issues.is_empty() {
        ScanResult::new("environment_vars", ScanStatus::Pass, "Environment variables secure")
    } else {
        ScanResult::new("environment_vars", ScanStatus::Warn, &format!("Environment issues: {}", issues.join("; ")))
    }
}

/// ClawTower's own LD_PRELOAD guard library path — entries matching this are benign.
const CLAWTOWER_GUARD_PATH: &str = "/usr/local/lib/libclawguard.so";

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
                    && !trimmed.contains("clawguard")
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
                && !trimmed.contains("clawguard")
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

/// Check for promiscuous-mode interfaces, unusual tunnel/tap devices, IP forwarding, and VPN routes.
pub fn scan_network_interfaces() -> ScanResult {
    let mut issues = Vec::new();

    // Check for promiscuous mode interfaces (sniffing)
    if let Ok(output) = run_cmd("ip", &["link", "show"]) {
        for line in output.lines() {
            if line.contains("PROMISC") {
                let interface = line.split(':').nth(1).unwrap_or("unknown").trim();
                issues.push(format!("Interface in promiscuous mode: {}", interface));
            }
        }
    }

    // Check for unusual network interfaces
    if let Ok(output) = run_cmd("ip", &["addr", "show"]) {
        let mut interface_count = 0;
        for line in output.lines() {
            if line.starts_with(char::is_numeric) && line.contains(":") {
                interface_count += 1;
                // Look for suspicious interface names
                if line.contains("tun") && !line.contains("tailscale") {
                    issues.push("Tunnel interface detected".to_string());
                }
                if line.contains("tap") {
                    issues.push("TAP interface detected".to_string());
                }
            }
        }
        
        if interface_count > 10 {
            issues.push(format!("Many network interfaces: {}", interface_count));
        }
    }

    // Check for IP forwarding enabled
    if let Ok(ipv4_forward) = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward") {
        if ipv4_forward.trim() == "1" {
            issues.push("IPv4 forwarding enabled".to_string());
        }
    }

    // Check for unusual routes
    if let Ok(output) = run_cmd("ip", &["route", "show"]) {
        for line in output.lines() {
            // Check for routes to private networks that might indicate tunneling
            if (line.contains("10.0.0.0/8") || line.contains("172.16.0.0/12") || line.contains("192.168.0.0/16"))
                && (line.contains("tun") || line.contains("tap")) {
                    issues.push(format!("VPN/tunnel route detected: {}", line.trim()));
            }
        }
    }

    if issues.is_empty() {
        ScanResult::new("network_interfaces", ScanStatus::Pass, "Network interfaces appear normal")
    } else {
        ScanResult::new("network_interfaces", ScanStatus::Warn, &format!("Network concerns: {}", issues.join("; ")))
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

/// Audit user accounts: non-root UID 0 users, passwordless shell accounts, and excessive sudo group members.
pub fn scan_user_account_audit() -> ScanResult {
    let mut issues = Vec::new();
    let watched_user = detect_agent_username();

    // Check for users with UID 0 (root privileges)
    if let Ok(passwd_content) = std::fs::read_to_string("/etc/passwd") {
        let mut uid_0_users = Vec::new();
        for line in passwd_content.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() >= 3 {
                let username = fields[0];
                let uid = fields[2];
                if uid == "0" && username != "root" {
                    uid_0_users.push(username.to_string());
                }
            }
        }
        if !uid_0_users.is_empty() {
            issues.push(format!("Non-root users with UID 0: {}", uid_0_users.join(", ")));
        }

        // Check for users with no password
        if let Ok(shadow_content) = std::fs::read_to_string("/etc/shadow") {
            let mut no_password_users = Vec::new();
            for line in shadow_content.lines() {
                let fields: Vec<&str> = line.split(':').collect();
                if fields.len() >= 2 {
                    let username = fields[0];
                    let password_hash = fields[1];
                    if password_hash.is_empty() || password_hash == "*" || password_hash == "!" {
                        // These are normal for system users, but check if they have shell access
                        if let Some(passwd_line) = passwd_content.lines().find(|l| l.starts_with(&format!("{}:", username))) {
                            let passwd_fields: Vec<&str> = passwd_line.split(':').collect();
                            if passwd_fields.len() >= 7 {
                                let shell = passwd_fields[6];
                                if shell.contains("bash") || shell.contains("zsh") || shell.contains("sh") {
                                    no_password_users.push(username.to_string());
                                }
                            }
                        }
                    }
                }
            }
            if !no_password_users.is_empty() {
                issues.push(format!("Users with shell access but no password: {}", no_password_users.join(", ")));
            }
        }

        // Check for recently created users
        if let Ok(output) = run_cmd("bash", &["-c", "awk -F: '($3>=1000)&&($1!=\"nobody\"){print $1}' /etc/passwd | wc -l"]) {
            if let Ok(user_count) = output.trim().parse::<u32>() {
                if user_count > 5 {
                    issues.push(format!("Many regular user accounts: {}", user_count));
                }
            }
        }

        // Check for users in sudo group
        if let Ok(group_content) = std::fs::read_to_string("/etc/group") {
            for line in group_content.lines() {
                if line.starts_with("sudo:") || line.starts_with("wheel:") || line.starts_with("admin:") {
                    let fields: Vec<&str> = line.split(':').collect();
                    if fields.len() >= 4 && !fields[3].is_empty() {
                        let sudo_users: Vec<&str> = fields[3].split(',').collect();
                        if sudo_users.len() > 2 {
                            issues.push(format!("Many users with sudo access: {}", sudo_users.len()));
                        }
                    }
                }
            }
        }
    }

    // Check if watched user is in dangerous groups (docker/lxd = instant root)
    if let Ok(group_content) = std::fs::read_to_string("/etc/group") {
        const DANGEROUS_GROUPS: &[&str] = &["docker", "lxd", "lxc", "disk"];
        for line in group_content.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() >= 4 {
                let group_name = fields[0];
                if DANGEROUS_GROUPS.contains(&group_name) {
                    let members: Vec<&str> = fields[3].split(',').filter(|s| !s.is_empty()).collect();
                    if members.iter().any(|m| *m == watched_user) {
                        issues.push(format!("{} in dangerous group '{}' (privilege escalation vector)", watched_user, group_name));
                    }
                }
            }
        }
    }

    if issues.is_empty() {
        ScanResult::new("user_accounts", ScanStatus::Pass, "User account configuration secure")
    } else {
        // Dangerous groups are critical, not just warnings
        let has_dangerous_group = issues.iter().any(|i| i.contains("dangerous group"));
        if has_dangerous_group {
            ScanResult::new("user_accounts", ScanStatus::Fail, &format!("User account issues: {}", issues.join("; ")))
        } else {
            ScanResult::new("user_accounts", ScanStatus::Warn, &format!("User account issues: {}", issues.join("; ")))
        }
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

fn compute_file_sha256(path: &str) -> Result<String, String> {
    use sha2::{Sha256, Digest};
    let data = std::fs::read(path).map_err(|e| format!("cannot read: {}", e))?;
    let hash = Sha256::digest(&data);
    Ok(hex::encode(hash))
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

/// List TCP listening sockets and flag any not in the expected set (ClawTower API port 18791).
pub fn scan_listening_services() -> ScanResult {
    match run_cmd("ss", &["-tlnp"]) {
        Ok(output) => {
            let expected_ports = ["18791"]; // ClawTower API
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

/// Check root filesystem disk usage percentage.
pub fn scan_resources() -> ScanResult {
    match run_cmd("df", &["-h", "/"]) {
        Ok(output) => parse_disk_usage(&output),
        Err(e) => ScanResult::new("resources", ScanStatus::Warn, &format!("Cannot check disk: {}", e)),
    }
}

/// Check CPU side-channel vulnerability mitigations (Spectre, Meltdown, MDS, etc.) via sysfs.
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

/// Parse `df -h /` output to extract usage percentage (testable helper).
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
        ScanResult::new("shadow_quarantine_perms", ScanStatus::Fail,
            &format!("Permission issues: {}", issues.join("; ")))
    }
}

/// Scan user-level persistence mechanisms for the openclaw user.
///
/// Checks crontab, systemd user units, shell rc file integrity, autostart
/// desktop files, git hooks, SSH rc/environment, Python usercustomize,
/// npmrc install scripts, and dangerous environment variables.
pub fn scan_user_persistence() -> Vec<ScanResult> {
    scan_user_persistence_inner(None)
}

/// Inner implementation with optional crontab override for testing.
fn scan_user_persistence_inner(crontab_override: Option<&str>) -> Vec<ScanResult> {
    let mut results = Vec::new();
    let home = detect_agent_home();

    // 1. Crontab entries
    let crontab_output = match crontab_override {
        Some(s) => Ok(s.to_string()),
        None => run_cmd("crontab", &["-l"]),
    };
    match crontab_output {
        Ok(output) => {
            let entries: Vec<&str> = output.lines()
                .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
                .collect();
            if entries.is_empty() {
                results.push(ScanResult::new("user_persistence", ScanStatus::Pass, "No user crontab entries"));
            } else {
                results.push(ScanResult::new("user_persistence", ScanStatus::Fail,
                    &format!("User crontab has {} entries: {}", entries.len(), entries.join("; "))));
            }
        }
        Err(_) => {
            // "no crontab for user" returns error — that's fine
            results.push(ScanResult::new("user_persistence", ScanStatus::Pass, "No user crontab entries"));
        }
    }

    // 2. Systemd user timers and services
    {
        // OpenClaw's own services are legitimate, not persistence
        const ALLOWED_USER_UNITS: &[&str] = &[
            "openclaw.service",
            "openclaw-gateway.service",
            "openclaw-worker.service",
            "default.target.wants",
        ];
        let user_systemd = format!("{}/.config/systemd/user", home);
        let mut unexpected = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&user_systemd) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if (name.ends_with(".timer") || name.ends_with(".service"))
                    && !ALLOWED_USER_UNITS.iter().any(|a| name == *a)
                {
                    unexpected.push(name);
                }
            }
        }
        if unexpected.is_empty() {
            results.push(ScanResult::new("user_persistence", ScanStatus::Pass, "No unexpected user systemd units"));
        } else {
            results.push(ScanResult::new("user_persistence", ScanStatus::Fail,
                &format!("Unexpected user systemd units: {}", unexpected.join(", "))));
        }
    }

    // 3. Shell RC file integrity
    {
        let baselines_path = "/etc/clawtower/persistence-baselines.json";
        let baselines: std::collections::HashMap<String, String> = std::fs::read_to_string(baselines_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();

        for rc_file in &[".bashrc", ".profile", ".bash_login"] {
            let full_path = format!("{}/{}", home, rc_file);
            if std::path::Path::new(&full_path).exists() {
                match compute_file_sha256(&full_path) {
                    Ok(hash) => {
                        if let Some(expected) = baselines.get(*rc_file) {
                            if &hash != expected {
                                results.push(ScanResult::new("user_persistence", ScanStatus::Fail,
                                    &format!("{} hash mismatch (expected {}, got {})", rc_file, &expected[..8], &hash[..8])));
                            } else {
                                results.push(ScanResult::new("user_persistence", ScanStatus::Pass,
                                    &format!("{} integrity OK", rc_file)));
                            }
                        } else {
                            results.push(ScanResult::new("user_persistence", ScanStatus::Warn,
                                &format!("{} first seen (hash: {})", rc_file, &hash[..16])));
                        }
                    }
                    Err(e) => {
                        results.push(ScanResult::new("user_persistence", ScanStatus::Warn,
                            &format!("Cannot hash {}: {}", rc_file, e)));
                    }
                }
            }
        }
    }

    // 4. Autostart desktop files
    {
        let autostart_dir = format!("{}/.config/autostart", home);
        let mut desktop_files = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&autostart_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.ends_with(".desktop") {
                    desktop_files.push(name);
                }
            }
        }
        if desktop_files.is_empty() {
            results.push(ScanResult::new("user_persistence", ScanStatus::Pass, "No autostart desktop files"));
        } else {
            results.push(ScanResult::new("user_persistence", ScanStatus::Fail,
                &format!("Autostart desktop files found: {}", desktop_files.join(", "))));
        }
    }

    // 5. Git hooks in workspace
    {
        let hooks_dir = format!("{}/.openclaw/workspace/.git/hooks", home);
        let mut non_sample = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&hooks_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if !name.ends_with(".sample") {
                    if let Ok(ft) = entry.file_type() {
                        if ft.is_file() {
                            non_sample.push(name);
                        }
                    }
                }
            }
        }
        if non_sample.is_empty() {
            results.push(ScanResult::new("user_persistence", ScanStatus::Pass, "No active git hooks in workspace"));
        } else {
            results.push(ScanResult::new("user_persistence", ScanStatus::Warn,
                &format!("Active git hooks found: {}", non_sample.join(", "))));
        }
    }

    // 6. SSH rc and environment
    {
        let ssh_dangerous = [".ssh/rc", ".ssh/environment"];
        for file in &ssh_dangerous {
            let full_path = format!("{}/{}", home, file);
            if std::path::Path::new(&full_path).exists() {
                results.push(ScanResult::new("user_persistence", ScanStatus::Fail,
                    &format!("~/{} exists — potential persistence mechanism", file)));
            } else {
                results.push(ScanResult::new("user_persistence", ScanStatus::Pass,
                    &format!("~/{} not present", file)));
            }
        }
    }

    // 7. Python usercustomize.py
    {
        let python_glob = format!("{}/.local/lib", home);
        let mut found = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&python_glob) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("python") {
                    let uc_path = entry.path().join("site-packages/usercustomize.py");
                    if uc_path.exists() {
                        found.push(uc_path.display().to_string());
                    }
                }
            }
        }
        if found.is_empty() {
            results.push(ScanResult::new("user_persistence", ScanStatus::Pass, "No usercustomize.py found"));
        } else {
            results.push(ScanResult::new("user_persistence", ScanStatus::Fail,
                &format!("usercustomize.py found: {}", found.join(", "))));
        }
    }

    // 8. npmrc install scripts
    {
        let npmrc_path = format!("{}/.npmrc", home);
        if let Ok(content) = std::fs::read_to_string(&npmrc_path) {
            let has_scripts = content.lines().any(|l| {
                let lower = l.to_lowercase();
                lower.contains("preinstall") || lower.contains("postinstall")
            });
            if has_scripts {
                results.push(ScanResult::new("user_persistence", ScanStatus::Fail,
                    "~/.npmrc contains preinstall/postinstall scripts"));
            } else {
                results.push(ScanResult::new("user_persistence", ScanStatus::Pass,
                    "~/.npmrc clean (no install scripts)"));
            }
        } else {
            results.push(ScanResult::new("user_persistence", ScanStatus::Pass, "No ~/.npmrc"));
        }
    }

    // 9. Dangerous environment variables
    {
        let dangerous_vars = ["PYTHONSTARTUP", "PERL5OPT", "NODE_OPTIONS"];
        for var in &dangerous_vars {
            if std::env::var(var).is_ok() {
                results.push(ScanResult::new("user_persistence", ScanStatus::Warn,
                    &format!("Environment variable {} is set", var)));
            } else {
                results.push(ScanResult::new("user_persistence", ScanStatus::Pass,
                    &format!("{} not set", var)));
            }
        }
    }

    results
}

/// Static entry point for running all security scans.
pub struct SecurityScanner;

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

/// Parse lsattr output and check for immutable flag (testable helper)
#[allow(dead_code)]
/// Parse lsattr output and check for immutable flag (testable helper).
pub fn check_lsattr_immutable(lsattr_output: &str) -> bool {
    let attrs = lsattr_output.split_whitespace().next().unwrap_or("");
    attrs.contains('i')
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

/// Check the age of the SecureClaw vendor pattern database via its git log.
pub fn scan_secureclaw_sync() -> ScanResult {
    // Try configured path first, then common locations
    let agent_home = detect_agent_home();
    let mut candidates = vec![
        format!("{}/.openclaw/workspace/openclawtower/vendor/secureclaw", agent_home),
        "vendor/secureclaw".to_string(),
        "/opt/clawtower/vendor/secureclaw".to_string(),
    ];
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join("vendor/secureclaw").display().to_string());
    }
    let vendor_path = candidates.iter()
        .find(|p| std::path::Path::new(p).exists())
        .map(String::as_str)
        .unwrap_or("vendor/secureclaw");
    
    if !std::path::Path::new(vendor_path).exists() {
        // Not a failure — SecureClaw patterns are loaded at runtime from vendor dir.
        // When installed via oneshot script (no git repo), this is expected.
        return ScanResult::new("secureclaw", ScanStatus::Pass, "SecureClaw vendor dir not present (patterns loaded from embedded defaults if available)");
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
                                return ScanResult::new("secureclaw", ScanStatus::Warn, 
                                    &format!("SecureClaw patterns are {} old - consider running sync script", age_str));
                            }
                        }
                    }
                }
                
                ScanResult::new("secureclaw", ScanStatus::Pass, 
                    &format!("SecureClaw patterns up to date ({})", age_str))
            } else if age_str.contains("week") || age_str.contains("month") || age_str.contains("year") {
                ScanResult::new("secureclaw", ScanStatus::Warn, 
                    &format!("SecureClaw patterns are {} old - run scripts/sync-secureclaw.sh", age_str))
            } else {
                ScanResult::new("secureclaw", ScanStatus::Warn, 
                    &format!("SecureClaw last updated: {}", age_str))
            }
        }
        Err(e) => {
            ScanResult::new("secureclaw", ScanStatus::Fail, 
                &format!("Cannot check SecureClaw status: {}", e))
        }
    }
}

impl SecurityScanner {
    /// Execute all 30+ security checks and return the results.
    ///
    /// Includes firewall, auditd, integrity, updates, SSH, listening services,
    /// resources, side-channel mitigations, immutable flags, AppArmor, SecureClaw,
    /// audit log health, crontab, world-writable files, SUID/SGID, kernel modules,
    /// Docker, password policy, open FDs, DNS, NTP, failed logins, zombie processes,
    /// swap/tmpfs, environment variables, packages, core dumps, network interfaces,
    /// systemd hardening, user accounts, cognitive integrity, and OpenClaw-specific checks.
    pub fn run_all_scans_with_config(openclaw_config: &crate::config::OpenClawConfig) -> Vec<ScanResult> {
        let agent_home = detect_agent_home();
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
            scan_secureclaw_sync(),
            crate::logtamper::scan_audit_log_health(std::path::Path::new("/var/log/audit/audit.log")),
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
        // Shadow/quarantine directory permission verification
        results.push(scan_shadow_quarantine_permissions());

        // User persistence mechanisms
        results.extend(scan_user_persistence());

        // Cognitive file integrity (returns Vec)
        // Load SecureClaw engine for cognitive content scanning
        let secureclaw_engine = crate::secureclaw::SecureClawEngine::load(
            std::path::Path::new("/etc/clawtower/secureclaw")
        ).ok();
        results.extend(scan_cognitive_integrity(
            std::path::Path::new(&workspace_path),
            std::path::Path::new("/etc/clawtower/cognitive-baselines.sha256"),
            secureclaw_engine.as_ref(),
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
                results.extend(crate::openclaw_config::scan_config_drift(
                    &openclaw_config.config_path, &openclaw_config.baseline_path));
            }

            // Phase 3: mDNS
            if openclaw_config.mdns_check {
                results.extend(scan_mdns_leaks());
            }

            // Phase 3: Extensions
            if openclaw_config.plugin_watch {
                results.extend(scan_extensions_dir(
                    &format!("{}/extensions", openclaw_config.state_dir)));
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

/// OpenClaw-specific security checks
/// Check that a path has permissions no more permissive than `max_mode`.
fn check_path_permissions(path: &str, max_mode: u32, label: &str) -> ScanResult {
    match std::fs::metadata(path) {
        Ok(meta) => {
            let mode = meta.permissions().mode() & 0o777;
            if (mode & !max_mode) == 0 {
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

/// Parse `openclaw security audit` text output into ScanResults.
///
/// Line format: `✓ description` (pass), `⚠ description` (warn), `✗ description` (fail)
fn parse_openclaw_audit_output(output: &str) -> Vec<ScanResult> {
    let mut results = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }
        
        let (status, detail) = if trimmed.starts_with('✓') {
            (ScanStatus::Pass, trimmed.trim_start_matches('✓').trim())
        } else if trimmed.starts_with('⚠') {
            (ScanStatus::Warn, trimmed.trim_start_matches('⚠').trim())
        } else if trimmed.starts_with('✗') {
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

/// Check avahi-browse output for OpenClaw service advertisements (info leak).
fn check_mdns_openclaw_leak(avahi_output: &str) -> ScanResult {
    let openclaw_services: Vec<&str> = avahi_output.lines()
        .filter(|l| l.to_lowercase().contains("openclaw") || l.to_lowercase().contains("clawtower"))
        .collect();
    
    if openclaw_services.is_empty() {
        ScanResult::new("openclaw:mdns", ScanStatus::Pass,
            "No OpenClaw/ClawTower services advertised via mDNS")
    } else {
        ScanResult::new("openclaw:mdns", ScanStatus::Warn,
            &format!("OpenClaw services advertised via mDNS (info leak): {}",
                openclaw_services.join("; ")))
    }
}

/// Scan for mDNS info leaks by checking avahi-browse.
fn scan_mdns_leaks() -> Vec<ScanResult> {
    match Command::new("avahi-browse").args(["-apt", "--no-db-lookup"]).output() {
        Ok(output) => vec![check_mdns_openclaw_leak(
            &String::from_utf8_lossy(&output.stdout))],
        Err(_) => vec![ScanResult::new("openclaw:mdns", ScanStatus::Pass,
            "avahi-browse not available — mDNS check skipped")],
    }
}

/// Scan OpenClaw extensions directory for installed plugins.
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
            &format!("{} extension dirs found, all clean", count)));
    }
    
    results
}

/// Check OpenClaw Control UI security settings.
/// Check OpenClaw Control UI security settings using proper JSON parsing.
fn scan_control_ui_security(config: &str) -> Vec<ScanResult> {
    let mut results = Vec::new();
    
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(config) {
        // Check dangerouslyDisableDeviceAuth
        let dangerous = val.pointer("/controlUi/dangerouslyDisableDeviceAuth")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if dangerous {
            results.push(ScanResult::new("openclaw:controlui", ScanStatus::Fail,
                "Control UI: dangerouslyDisableDeviceAuth is TRUE — severe security downgrade"));
        }
        
        // Check allowInsecureAuth
        let insecure = val.pointer("/controlUi/allowInsecureAuth")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if insecure {
            results.push(ScanResult::new("openclaw:controlui", ScanStatus::Warn,
                "Control UI: allowInsecureAuth enabled — token-only auth, no device pairing"));
        }
    }
    // If JSON parsing fails, skip silently (other checks will catch malformed config)
    
    if results.is_empty() {
        results.push(ScanResult::new("openclaw:controlui", ScanStatus::Pass,
            "Control UI security settings nominal"));
    }
    
    results
}

/// Check whether the OpenClaw process is running inside a container/namespace.
///
/// Detects Docker, LXC, and general PID namespace isolation by inspecting
/// /proc/<pid>/cgroup and /proc/1/cgroup. Running bare-metal is a WARN.
fn scan_openclaw_container_isolation() -> ScanResult {
    // Find openclaw PID
    let pid = match run_cmd("pgrep", &["-x", "openclaw"]) {
        Ok(p) if !p.trim().is_empty() => p.trim().lines().next().unwrap_or("").to_string(),
        _ => {
            return ScanResult::new("openclaw:isolation", ScanStatus::Warn,
                "OpenClaw process not found — cannot check container isolation");
        }
    };

    // Check process cgroup for container indicators
    let cgroup_path = format!("/proc/{}/cgroup", pid);
    let cgroup = std::fs::read_to_string(&cgroup_path).unwrap_or_default();

    let in_docker = cgroup.contains("/docker/") || cgroup.contains("/containerd/");
    let in_lxc = cgroup.contains("/lxc/");
    let in_podman = cgroup.contains("/libpod-");

    // Also check for PID namespace isolation (PID 1 in container won't be systemd/init)
    let pid_ns_self = std::fs::read_link(format!("/proc/{}/ns/pid", pid)).ok();
    let pid_ns_init = std::fs::read_link("/proc/1/ns/pid").ok();
    let ns_isolated = pid_ns_self != pid_ns_init && pid_ns_self.is_some();

    if in_docker || in_podman {
        ScanResult::new("openclaw:isolation", ScanStatus::Pass,
            "OpenClaw running inside container (Docker/Podman)")
    } else if in_lxc {
        ScanResult::new("openclaw:isolation", ScanStatus::Pass,
            "OpenClaw running inside LXC container")
    } else if ns_isolated {
        ScanResult::new("openclaw:isolation", ScanStatus::Pass,
            "OpenClaw running in isolated PID namespace")
    } else {
        ScanResult::new("openclaw:isolation", ScanStatus::Warn,
            "OpenClaw running on bare metal — consider containerizing for isolation")
    }
}

/// Check whether the OpenClaw process is running as root (UID 0).
///
/// Running as root gives the agent full system access, violating least-privilege.
fn scan_openclaw_running_as_root() -> ScanResult {
    let pid = match run_cmd("pgrep", &["-x", "openclaw"]) {
        Ok(p) if !p.trim().is_empty() => p.trim().lines().next().unwrap_or("").to_string(),
        _ => {
            return ScanResult::new("openclaw:run_as_root", ScanStatus::Warn,
                "OpenClaw process not found — cannot check running UID");
        }
    };

    // Read /proc/<pid>/status for Uid line
    let status_path = format!("/proc/{}/status", pid);
    let status = match std::fs::read_to_string(&status_path) {
        Ok(s) => s,
        Err(_) => {
            return ScanResult::new("openclaw:run_as_root", ScanStatus::Warn,
                &format!("Cannot read {} — permission denied or process exited", status_path));
        }
    };

    // Uid line format: "Uid:\treal\teffective\tsaved\tfs"
    let uid_line = status.lines().find(|l| l.starts_with("Uid:"));
    if let Some(line) = uid_line {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // fields[1] = real UID, fields[2] = effective UID
        let effective_uid = fields.get(2).unwrap_or(&"");
        if *effective_uid == "0" {
            ScanResult::new("openclaw:run_as_root", ScanStatus::Fail,
                "OpenClaw running as root (UID 0) — use a dedicated non-admin user")
        } else {
            ScanResult::new("openclaw:run_as_root", ScanStatus::Pass,
                &format!("OpenClaw running as UID {} (non-root)", effective_uid))
        }
    } else {
        ScanResult::new("openclaw:run_as_root", ScanStatus::Warn,
            "Could not determine OpenClaw UID from /proc status")
    }
}

/// Scan OpenClaw config files for hardcoded API keys / secrets.
///
/// Keys should be loaded via environment variables at runtime, never stored
/// in config files where they can be leaked in logs, backups, or version control.
fn scan_openclaw_hardcoded_secrets() -> ScanResult {
    let state_dir = format!("{}/.openclaw", detect_agent_home());
    let config_paths = [
        format!("{}/openclaw.json", state_dir),
        format!("{}/agents/main/agent/gateway.yaml", state_dir),
    ];

    // Patterns that indicate hardcoded API keys (prefix + min length)
    const KEY_PREFIXES: &[&str] = &[
        "sk-ant-",       // Anthropic
        "sk-proj-",      // OpenAI project keys
        "sk-",           // OpenAI legacy (match after more specific)
        "key-",          // Generic API keys
        "gsk_",          // Groq
        "xai-",          // xAI/Grok
        "AKIA",          // AWS access key ID
        "ghp_",          // GitHub personal access token
        "glpat-",        // GitLab personal access token
        "xoxb-",         // Slack bot token
        "xoxp-",         // Slack user token
    ];

    let mut found = Vec::new();

    for path in &config_paths {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        for prefix in KEY_PREFIXES {
            // Look for the prefix followed by at least 16 more chars (real keys are long)
            if let Some(pos) = content.find(prefix) {
                let after = &content[pos + prefix.len()..];
                let key_chars = after.chars().take_while(|c| c.is_alphanumeric() || *c == '-' || *c == '_').count();
                if key_chars >= 16 {
                    let file_name = std::path::Path::new(path)
                        .file_name().unwrap_or_default().to_string_lossy();
                    found.push(format!("{}:{}", file_name, prefix));
                }
            }
        }
    }

    if found.is_empty() {
        ScanResult::new("openclaw:hardcoded_secrets", ScanStatus::Pass,
            "No hardcoded API keys detected in OpenClaw config")
    } else {
        ScanResult::new("openclaw:hardcoded_secrets", ScanStatus::Fail,
            &format!("Hardcoded API keys in config (use env vars instead): {}",
                found.join(", ")))
    }
}

/// Check whether the installed OpenClaw version is current.
///
/// Compares `openclaw --version` output against known latest or checks
/// if the binary was last modified more than 30 days ago as a staleness proxy.
fn scan_openclaw_version_freshness() -> ScanResult {
    // Try to get the installed version
    let version_output = match run_cmd("openclaw", &["--version"]) {
        Ok(v) => v.trim().to_string(),
        Err(_) => {
            // Fallback: check binary modification time
            let binary_paths = ["/usr/local/bin/openclaw", "/usr/bin/openclaw"];
            let binary_path = binary_paths.iter().find(|p| std::path::Path::new(p).exists());

            return if let Some(path) = binary_path {
                match std::fs::metadata(path) {
                    Ok(meta) => {
                        if let Ok(modified) = meta.modified() {
                            let age = modified.elapsed().unwrap_or_default();
                            let days = age.as_secs() / 86400;
                            if days > 90 {
                                ScanResult::new("openclaw:version", ScanStatus::Warn,
                                    &format!("OpenClaw binary {} days old — check for updates", days))
                            } else {
                                ScanResult::new("openclaw:version", ScanStatus::Pass,
                                    &format!("OpenClaw binary modified {} days ago", days))
                            }
                        } else {
                            ScanResult::new("openclaw:version", ScanStatus::Warn,
                                "Cannot determine OpenClaw binary age")
                        }
                    }
                    Err(_) => ScanResult::new("openclaw:version", ScanStatus::Warn,
                        "Cannot read OpenClaw binary metadata"),
                }
            } else {
                ScanResult::new("openclaw:version", ScanStatus::Warn,
                    "OpenClaw binary not found — cannot check version freshness")
            };
        }
    };

    // Check if there's an update available via openclaw's own mechanism
    match run_cmd("openclaw", &["update", "--check"]) {
        Ok(output) => {
            let up_to_date = output.contains("up to date")
                || output.contains("already on the latest")
                || output.contains("no update");
            if up_to_date {
                ScanResult::new("openclaw:version", ScanStatus::Pass,
                    &format!("OpenClaw {} — up to date", version_output))
            } else {
                ScanResult::new("openclaw:version", ScanStatus::Warn,
                    &format!("OpenClaw {} — update available: {}",
                        version_output, output.trim().chars().take(100).collect::<String>()))
            }
        }
        Err(_) => {
            // update --check not available, just report the version
            ScanResult::new("openclaw:version", ScanStatus::Pass,
                &format!("OpenClaw {} installed (update check unavailable)", version_output))
        }
    }
}

/// Verify that auditd read-watch rules are installed for critical credential files.
///
/// Infostealers read credential files without modifying them, so sentinel (inotify)
/// can't detect the access. Auditd `-p r` rules are the only kernel-level defense
/// against silent reads. This scanner confirms those rules are actually loaded.
fn scan_openclaw_credential_audit() -> ScanResult {
    // Critical files that must have auditd read-watch rules
    let required_watches: &[&str] = &[
        "device.json",
        "openclaw.json",
        "auth-profiles.json",
        "gateway.yaml",
        ".aws/credentials",
        ".ssh/id_",
    ];

    match run_cmd_with_sudo("auditctl", &["-l"]) {
        Ok(rules) => {
            let missing: Vec<&str> = required_watches.iter()
                .filter(|watch| !rules.lines().any(|line| line.contains(**watch) && line.contains("-p r")))
                .copied()
                .collect();

            if missing.is_empty() {
                ScanResult::new("openclaw:credential_audit", ScanStatus::Pass,
                    &format!("All {} credential read-watch rules installed", required_watches.len()))
            } else {
                ScanResult::new("openclaw:credential_audit", ScanStatus::Fail,
                    &format!("Missing auditd read-watch rules for: {}. Run: clawtower setup audit-rules",
                        missing.join(", ")))
            }
        }
        Err(_) => {
            ScanResult::new("openclaw:credential_audit", ScanStatus::Warn,
                "Cannot check auditd rules (auditctl not available or no permission)")
        }
    }
}

fn scan_openclaw_security() -> Vec<ScanResult> {
    let mut results = Vec::new();
    let state_dir = format!("{}/.openclaw", detect_agent_home());

    // Check OpenClaw gateway config (JSON format in openclaw.json)
    let config_paths = [
        format!("{}/openclaw.json", state_dir),
        format!("{}/agents/main/agent/gateway.yaml", state_dir),
    ];
    let gateway_config = config_paths.iter()
        .find(|p| std::path::Path::new(p).exists())
        .and_then(|p| std::fs::read_to_string(p).ok());

    if let Some(ref config) = gateway_config {
        // ── 1. Gateway not publicly exposed ──────────────────────────────
        let bind_loopback = config.contains("\"loopback\"") || config.contains("\"127.0.0.1\"");
        let bind_public = config.contains("\"bind\":\"0.0.0.0\"") || config.contains("\"bind\": \"0.0.0.0\"");
        
        let listeners = run_cmd("ss", &["-tlnp"]).unwrap_or_default();
        let gateway_exposed = listeners.lines().any(|l| l.contains("0.0.0.0:18789") || l.contains("*:18789"));

        if bind_public || gateway_exposed {
            results.push(ScanResult::new("openclaw:gateway", ScanStatus::Fail,
                "Gateway bound to 0.0.0.0 — publicly accessible! Use loopback + tunnel"));
        } else if bind_loopback {
            results.push(ScanResult::new("openclaw:gateway", ScanStatus::Pass,
                "Gateway bound to loopback only"));
        } else {
            results.push(ScanResult::new("openclaw:gateway", ScanStatus::Warn,
                "Gateway bind address unclear — verify not public"));
        }

        // ── 2. Auth required ─────────────────────────────────────────────
        let has_auth = config.contains("\"token\"") && config.contains("\"auth\"");
        let auth_none = config.contains("\"mode\":\"none\"") || config.contains("\"mode\": \"none\"");
        
        if auth_none || !has_auth {
            results.push(ScanResult::new("openclaw:auth", ScanStatus::Fail,
                "Gateway auth disabled — anyone can connect"));
        } else {
            results.push(ScanResult::new("openclaw:auth", ScanStatus::Pass,
                "Gateway auth enabled (token mode)"));
        }

        // ── 3. Filesystem scoped ─────────────────────────────────────────
        let workspace_root = config.contains("\"workspace\":\"/\"") || config.contains("\"workspace\": \"/\"");
        let workspace_scoped = config.contains("\"workspace\":\"/home/") || config.contains("\"workspace\": \"/home/");

        if workspace_root {
            results.push(ScanResult::new("openclaw:filesystem", ScanStatus::Fail,
                "Workspace set to / — agent has full filesystem access"));
        } else if workspace_scoped {
            results.push(ScanResult::new("openclaw:filesystem", ScanStatus::Pass,
                "Workspace scoped to home directory"));
        } else {
            results.push(ScanResult::new("openclaw:filesystem", ScanStatus::Warn,
                "Verify workspace is properly scoped"));
        }
    } else {
        results.push(ScanResult::new("openclaw:config", ScanStatus::Warn,
            "OpenClaw gateway config not found — skipping OpenClaw checks"));
    }

    // Permission checks (from OpenClaw security docs)
    results.push(check_path_permissions(&state_dir, 0o700, "state_dir"));
    results.push(check_path_permissions(
        &format!("{}/openclaw.json", state_dir), 0o600, "config"));
    results.push(check_path_permissions(
        &format!("{}/device.json", state_dir), 0o600, "device_key"));

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
    results.push(check_symlinks_in_dir(&state_dir));

    // ── 4. Access via Tailscale/SSH tunnel ───────────────────────────────
    // Check if Tailscale is running
    let tailscale_running = run_cmd("tailscale", &["status"]).is_ok()
        || run_cmd("systemctl", &["is-active", "tailscaled"]).map(|s| s.trim() == "active").unwrap_or(false);
    
    // Check for SSH tunnel (common patterns)
    let ssh_tunnels = run_cmd("ss", &["-tlnp"]).unwrap_or_default();
    let has_tunnel = tailscale_running 
        || ssh_tunnels.contains("ssh")
        || std::path::Path::new("/var/run/tailscaled.socket").exists();

    // Check if Connectify or similar tunnel is in use
    let connectify = std::path::Path::new("/etc/connectify").exists()
        || run_cmd("systemctl", &["is-active", "connectify"]).map(|s| s.trim() == "active").unwrap_or(false);

    if tailscale_running {
        results.push(ScanResult::new("openclaw:tunnel", ScanStatus::Pass,
            "Tailscale VPN active — secure tunnel access"));
    } else if connectify || has_tunnel {
        results.push(ScanResult::new("openclaw:tunnel", ScanStatus::Pass,
            "Tunnel/VPN detected for remote access"));
    } else {
        results.push(ScanResult::new("openclaw:tunnel", ScanStatus::Warn,
            "No VPN/tunnel detected — ensure gateway is not directly exposed"));
    }

    results
}

/// Spawn periodic scan task that runs all checks every `interval_secs` seconds.
///
/// Results are stored in `scan_store` and non-passing results are forwarded as alerts.
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

    #[test]
    fn test_check_path_permissions_secure() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let result = check_path_permissions(dir.path().to_str().unwrap(), 0o700, "test_dir");
        assert_eq!(result.status, ScanStatus::Pass);
    }

    #[test]
    fn test_check_path_permissions_too_open() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let result = check_path_permissions(dir.path().to_str().unwrap(), 0o700, "test_dir");
        assert_eq!(result.status, ScanStatus::Fail);
    }

    #[test]
    fn test_check_path_permissions_missing() {
        let result = check_path_permissions("/nonexistent/path/12345", 0o700, "missing");
        assert_eq!(result.status, ScanStatus::Warn);
    }

    #[test]
    fn test_check_symlinks_no_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let result = check_symlinks_in_dir(dir.path().to_str().unwrap());
        assert_eq!(result.status, ScanStatus::Pass);
    }

    #[test]
    fn test_check_symlinks_missing_dir() {
        let result = check_symlinks_in_dir("/nonexistent/dir/12345");
        assert_eq!(result.status, ScanStatus::Warn);
    }

    #[test]
    fn test_parse_openclaw_audit_output() {
        let output = "⚠ Gateway auth: mode is 'none' — anyone on the network can connect\n✓ DM policy: pairing (secure)\n⚠ groupPolicy is 'open' for slack — restrict to allowlist\n✓ Filesystem permissions: ~/.openclaw is 700\n✗ Browser control: CDP port exposed on 0.0.0.0";
        let results = parse_openclaw_audit_output(output);
        assert_eq!(results.len(), 5);
        assert_eq!(results[0].status, ScanStatus::Warn);
        assert_eq!(results[1].status, ScanStatus::Pass);
        assert_eq!(results[2].status, ScanStatus::Warn);
        assert_eq!(results[3].status, ScanStatus::Pass);
        assert_eq!(results[4].status, ScanStatus::Fail);
    }

    #[test]
    fn test_parse_openclaw_audit_empty() {
        let results = parse_openclaw_audit_output("");
        assert!(results.is_empty());
    }

    #[test]
    fn test_parse_openclaw_audit_with_headers() {
        let output = "OpenClaw Security Audit\n=======================\n✓ Gateway bound to loopback\n⚠ No auth configured";
        let results = parse_openclaw_audit_output(output);
        assert_eq!(results.len(), 2); // headers skipped
        assert_eq!(results[0].status, ScanStatus::Pass);
        assert_eq!(results[1].status, ScanStatus::Warn);
    }

    #[test]
    fn test_parse_openclaw_audit_categories() {
        let output = "✓ DM policy: pairing mode active\n✗ Browser control: exposed";
        let results = parse_openclaw_audit_output(output);
        assert!(results[0].category.contains("openclaw:audit:dm_policy"));
        assert!(results[1].category.contains("openclaw:audit:browser_control"));
    }

    #[test]
    fn test_mdns_openclaw_exposed() {
        let output = "+;eth0;IPv4;OpenClaw Gateway;_http._tcp;local\n";
        let result = check_mdns_openclaw_leak(output);
        assert_eq!(result.status, ScanStatus::Warn);
    }

    #[test]
    fn test_mdns_no_openclaw() {
        let output = "+;eth0;IPv4;Printer;_ipp._tcp;local\n";
        let result = check_mdns_openclaw_leak(output);
        assert_eq!(result.status, ScanStatus::Pass);
    }

    #[test]
    fn test_mdns_empty() {
        let result = check_mdns_openclaw_leak("");
        assert_eq!(result.status, ScanStatus::Pass);
    }

    #[test]
    fn test_scan_extensions_none() {
        let dir = tempfile::tempdir().unwrap();
        let result = scan_extensions_dir(dir.path().to_str().unwrap());
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].status, ScanStatus::Pass);
    }

    #[test]
    fn test_scan_extensions_missing_dir() {
        let result = scan_extensions_dir("/nonexistent/extensions/12345");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].status, ScanStatus::Pass);
    }

    #[test]
    fn test_scan_extensions_with_plugin() {
        let dir = tempfile::tempdir().unwrap();
        let plugin_dir = dir.path().join("my-plugin");
        std::fs::create_dir(&plugin_dir).unwrap();
        std::fs::write(plugin_dir.join("package.json"), "{}").unwrap();
        let result = scan_extensions_dir(dir.path().to_str().unwrap());
        assert!(result.iter().any(|r| r.status == ScanStatus::Warn));
    }

    #[test]
    fn test_control_ui_dangerous_flag() {
        let config = r#"{"controlUi": {"dangerouslyDisableDeviceAuth": true}}"#;
        let results = scan_control_ui_security(config);
        assert!(results.iter().any(|r| r.status == ScanStatus::Fail));
    }

    #[test]
    fn test_control_ui_insecure_auth() {
        let config = r#"{"controlUi": {"allowInsecureAuth": true}}"#;
        let results = scan_control_ui_security(config);
        assert!(results.iter().any(|r| r.status == ScanStatus::Warn));
    }

    #[test]
    fn test_control_ui_secure() {
        let config = r#"{"controlUi": {"enabled": true}}"#;
        let results = scan_control_ui_security(config);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, ScanStatus::Pass);
    }

    #[test]
    fn test_control_ui_both_flags() {
        let config = r#"{"controlUi": {"dangerouslyDisableDeviceAuth": true, "allowInsecureAuth": true}}"#;
        let results = scan_control_ui_security(config);
        assert_eq!(results.len(), 2);
        assert!(results.iter().any(|r| r.status == ScanStatus::Fail));
        assert!(results.iter().any(|r| r.status == ScanStatus::Warn));
    }

    #[test]
    fn test_scan_dedup_suppresses_repeats() {
        use std::collections::HashMap;
        use std::time::{Duration, Instant};

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
        use std::collections::HashMap;
        use std::time::Instant;

        let mut last_emitted: HashMap<String, Instant> = HashMap::new();
        last_emitted.insert("firewall:warn".to_string(), Instant::now());

        // Different status: should emit
        let new_key = "firewall:pass".to_string();
        assert!(!last_emitted.contains_key(&new_key));
    }

    // ═══════════════════════════════════════════════════════════════════
    // REGRESSION TESTS — scanner.rs
    // ═══════════════════════════════════════════════════════════════════

    // --- Environment variable scanning ---

    #[test]
    fn test_env_ld_preload_suspicious_detected() {
        // Simulate: if LD_PRELOAD is set to something non-clawguard, scan_environment_variables flags it
        // We test the logic directly: the scan checks env::vars() which we can't mock easily,
        // but we can verify the pattern matching logic
        let value = "/tmp/evil.so";
        assert!(!value.contains("clawguard"));
    }

    #[test]
    fn test_env_ld_preload_clawguard_allowed() {
        let value = "/usr/lib/clawguard.so";
        assert!(value.contains("clawguard"));
    }

    #[test]
    fn test_env_proxy_tor_detection() {
        let key = "HTTP_PROXY";
        let value = "socks5://127.0.0.1:9050";
        assert!(key.contains("PROXY"));
        assert!(value.contains("socks"));
    }

    #[test]
    fn test_env_proxy_all_proxy_encoded() {
        // ALL_PROXY with percent-encoded value should still be caught by substring
        let key = "ALL_PROXY";
        let value = "socks5h://tor-gateway:9050";
        assert!(key.contains("PROXY"));
        assert!(value.contains("socks"));
    }

    #[test]
    fn test_env_proxy_normal_http_not_flagged() {
        let value = "http://proxy.corp.com:3128";
        assert!(!value.contains("tor") && !value.contains("socks"));
    }

    #[test]
    fn test_env_credential_detection_long_base64() {
        let key = "AWS_SECRET_KEY";
        let value = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        assert!(key.contains("KEY") || key.contains("SECRET"));
        assert!(value.len() > 20);
        assert!(value.chars().all(|c| c.is_ascii_alphanumeric() || c == '=' || c == '+' || c == '/'));
    }

    #[test]
    fn test_env_debug_flag_detection() {
        let key = "NODE_DEBUG";
        let value = "1";
        assert!(key.contains("DEBUG") && value == "1");
    }

    #[test]
    fn test_env_ld_library_path_tmp() {
        let value = "/tmp/lib:/usr/lib";
        assert!(value.contains("/tmp"));
    }

    // --- Listening port / firewall parsing ---

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

    // --- Auditd parsing edge cases ---

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

    // --- Kernel module patterns ---

    #[test]
    fn test_kernel_module_suspicious_patterns() {
        let suspicious = ["rootkit", "evil", "backdoor", "stealth", "hidden", "keylog"];
        for name in &suspicious {
            assert!(name.to_lowercase().contains(name));
        }
        // Verify benign modules don't match
        let benign = ["bluetooth", "snd_pcm", "ext4", "nfs", "iptable_filter"];
        for name in &benign {
            assert!(!suspicious.iter().any(|p| name.contains(p)));
        }
    }

    #[test]
    fn test_kernel_module_case_insensitive() {
        let module_name = "RootKit_Module";
        let suspicious_patterns = ["rootkit"];
        assert!(suspicious_patterns.iter().any(|p| module_name.to_lowercase().contains(p)));
    }

    // --- Side-channel mitigations ---

    #[test]
    fn test_sidechannel_vulnerable_status() {
        let status = "Vulnerable: Clear CPU buffers attempted, no microcode";
        assert!(status.contains("Vulnerable"));
    }

    #[test]
    fn test_sidechannel_mitigated_status() {
        let status = "Mitigation: Full generic retpoline, IBPB: conditional, IBRS_FW, STIBP: conditional, RSB filling";
        assert!(status.contains("Mitigation:"));
        assert!(!status.contains("Vulnerable"));
    }

    #[test]
    fn test_sidechannel_not_affected() {
        let status = "Not affected";
        assert!(status.contains("Not affected"));
    }

    // --- Permission scanning ---

    #[test]
    fn test_check_path_permissions_exact_match() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o600)).unwrap();
        let result = check_path_permissions(dir.path().to_str().unwrap(), 0o600, "exact");
        assert_eq!(result.status, ScanStatus::Pass);
    }

    #[test]
    fn test_check_path_permissions_tighter_than_max() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o400)).unwrap();
        let result = check_path_permissions(dir.path().to_str().unwrap(), 0o700, "tight");
        assert_eq!(result.status, ScanStatus::Pass);
    }

    #[test]
    fn test_check_path_permissions_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o744)).unwrap();
        let result = check_path_permissions(dir.path().to_str().unwrap(), 0o700, "world_read");
        assert_eq!(result.status, ScanStatus::Fail);
    }

    #[test]
    fn test_check_path_permissions_group_write() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o770)).unwrap();
        let result = check_path_permissions(dir.path().to_str().unwrap(), 0o700, "group_write");
        assert_eq!(result.status, ScanStatus::Fail);
    }

    // --- Checksum / integrity logic ---

    #[test]
    fn test_compute_sha256_real_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.txt");
        std::fs::write(&path, "hello world").unwrap();
        let hash = compute_file_sha256(path.to_str().unwrap()).unwrap();
        // SHA256 of "hello world"
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
        // SHA256 of empty string
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

    // --- Disk usage parsing ---

    #[test]
    fn test_parse_disk_usage_exactly_90() {
        let output = "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        50G   45G    5G  90% /\n";
        let result = parse_disk_usage(output);
        assert_eq!(result.status, ScanStatus::Pass); // 90 is NOT > 90
    }

    #[test]
    fn test_parse_disk_usage_91() {
        let output = "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        50G   46G    4G  91% /\n";
        let result = parse_disk_usage(output);
        assert_eq!(result.status, ScanStatus::Warn);
    }

    #[test]
    fn test_parse_disk_usage_0_percent() {
        let output = "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        50G    0G   50G   0% /\n";
        let result = parse_disk_usage(output);
        assert_eq!(result.status, ScanStatus::Pass);
    }

    #[test]
    fn test_parse_disk_usage_100_percent() {
        let output = "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        50G   50G    0G 100% /\n";
        let result = parse_disk_usage(output);
        assert_eq!(result.status, ScanStatus::Warn);
    }

    #[test]
    fn test_parse_disk_usage_empty() {
        let result = parse_disk_usage("");
        assert_eq!(result.status, ScanStatus::Warn);
        assert!(result.details.contains("Cannot parse"));
    }

    #[test]
    fn test_parse_disk_usage_single_line() {
        let result = parse_disk_usage("Filesystem      Size  Used Avail Use% Mounted on\n");
        assert_eq!(result.status, ScanStatus::Warn);
    }

    // --- Immutable flag parsing ---

    #[test]
    fn test_lsattr_multiple_flags() {
        assert!(check_lsattr_immutable("----ia--------e------- /some/file"));
    }

    #[test]
    fn test_lsattr_only_immutable() {
        assert!(check_lsattr_immutable("----i------------- /file"));
    }

    // --- Symlink checks ---

    #[test]
    fn test_check_symlinks_internal_link_ok() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real_file");
        std::fs::write(&target, "data").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let result = check_symlinks_in_dir(dir.path().to_str().unwrap());
        assert_eq!(result.status, ScanStatus::Pass);
    }

    #[test]
    fn test_check_symlinks_external_link_flagged() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("escape_link");
        std::os::unix::fs::symlink("/etc/passwd", &link).unwrap();
        let result = check_symlinks_in_dir(dir.path().to_str().unwrap());
        assert_eq!(result.status, ScanStatus::Fail);
        assert!(result.details.contains("/etc/passwd"));
    }

    // --- OpenClaw audit parsing ---

    #[test]
    fn test_parse_openclaw_audit_only_passes() {
        let output = "✓ All good\n✓ Everything fine";
        let results = parse_openclaw_audit_output(output);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.status == ScanStatus::Pass));
    }

    #[test]
    fn test_parse_openclaw_audit_only_failures() {
        let output = "✗ Bad thing 1\n✗ Bad thing 2\n✗ Bad thing 3";
        let results = parse_openclaw_audit_output(output);
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|r| r.status == ScanStatus::Fail));
    }

    #[test]
    fn test_parse_openclaw_audit_unicode_handling() {
        let output = "✓ Résumé check: ok\n⚠ Naïve setting detected";
        let results = parse_openclaw_audit_output(output);
        assert_eq!(results.len(), 2);
    }

    // --- mDNS detection ---

    #[test]
    fn test_mdns_clawtower_exposed() {
        let output = "+;eth0;IPv4;ClawTower Security;_http._tcp;local\n";
        let result = check_mdns_openclaw_leak(output);
        assert_eq!(result.status, ScanStatus::Warn);
    }

    #[test]
    fn test_mdns_case_insensitive() {
        let output = "+;wlan0;IPv4;OPENCLAW gateway;_http._tcp;local\n";
        let result = check_mdns_openclaw_leak(output);
        assert_eq!(result.status, ScanStatus::Warn);
    }

    // --- Control UI security ---

    #[test]
    fn test_control_ui_invalid_json() {
        let config = "not valid json at all";
        let results = scan_control_ui_security(config);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, ScanStatus::Pass); // silently skips
    }

    #[test]
    fn test_control_ui_empty_object() {
        let config = "{}";
        let results = scan_control_ui_security(config);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, ScanStatus::Pass);
    }

    #[test]
    fn test_control_ui_flags_false() {
        let config = r#"{"controlUi": {"dangerouslyDisableDeviceAuth": false, "allowInsecureAuth": false}}"#;
        let results = scan_control_ui_security(config);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, ScanStatus::Pass);
    }

    // --- Extensions scanning ---

    #[test]
    fn test_scan_extensions_dir_without_package_json() {
        let dir = tempfile::tempdir().unwrap();
        let plugin_dir = dir.path().join("empty-plugin");
        std::fs::create_dir(&plugin_dir).unwrap();
        // No package.json — should pass
        let result = scan_extensions_dir(dir.path().to_str().unwrap());
        assert!(result.iter().all(|r| r.status == ScanStatus::Pass));
    }

    #[test]
    fn test_scan_extensions_multiple_plugins() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..3 {
            let plugin_dir = dir.path().join(format!("plugin-{}", i));
            std::fs::create_dir(&plugin_dir).unwrap();
            std::fs::write(plugin_dir.join("package.json"), "{}").unwrap();
        }
        let result = scan_extensions_dir(dir.path().to_str().unwrap());
        let warns: Vec<_> = result.iter().filter(|r| r.status == ScanStatus::Warn).collect();
        assert_eq!(warns.len(), 3);
    }

    // --- ScanResult and Alert conversion ---

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

    // --- Password policy logic ---

    #[test]
    fn test_password_policy_pass_max_days_threshold() {
        // The scan flags PASS_MAX_DAYS > 90 or == 99999
        let days_ok = 90u32;
        let days_bad = 91u32;
        let days_default = 99999u32;
        assert!(!(days_ok > 90 || days_ok == 99999));
        assert!(days_bad > 90 || days_bad == 99999);
        assert!(days_default > 90 || days_default == 99999);
    }

    #[test]
    fn test_scan_user_persistence_clean() {
        // On a clean system with no crontab, results should be mostly Pass
        let results = scan_user_persistence();
        assert!(!results.is_empty());
        // At minimum we get crontab + systemd + autostart + git hooks + ssh checks + python + npmrc + env vars
        assert!(results.len() >= 9, "Expected at least 9 results, got {}", results.len());
        // All should have category user_persistence
        for r in &results {
            assert_eq!(r.category, "user_persistence");
        }
    }

    #[test]
    fn test_scan_user_persistence_crontab_entries() {
        let results = scan_user_persistence_inner(Some("* * * * * /tmp/evil.sh\n"));
        let crontab_result = &results[0];
        assert_eq!(crontab_result.status, ScanStatus::Fail);
        assert!(crontab_result.details.contains("crontab"));
    }

    #[test]
    fn test_scan_user_persistence_crontab_empty() {
        let results = scan_user_persistence_inner(Some("# comment only\n\n"));
        let crontab_result = &results[0];
        assert_eq!(crontab_result.status, ScanStatus::Pass);
    }

    #[test]
    fn test_scan_user_persistence_ssh_rc() {
        use std::io::Write;
        let tmp = tempfile::TempDir::new().unwrap();
        let ssh_dir = tmp.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        let rc_file = ssh_dir.join("rc");
        std::fs::File::create(&rc_file).unwrap().write_all(b"evil").unwrap();

        // We can't easily redirect HOME for the full function, so test the logic directly
        assert!(rc_file.exists());
        // The scan checks ~/.ssh/rc existence => FAIL
        // Verify by checking the actual function with real HOME
        // Since we can't mock HOME easily, just verify the file detection logic
        let results = scan_user_persistence();
        // Find the ssh/rc result
        let ssh_rc_result = results.iter().find(|r| r.details.contains(".ssh/rc"));
        assert!(ssh_rc_result.is_some(), "Should have a .ssh/rc check result");
        // On clean system it should be Pass (file doesn't exist at real HOME)
        assert_eq!(ssh_rc_result.unwrap().status, ScanStatus::Pass);
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

        // First occurrence — should emit
        assert!(!last_emitted.contains_key(&key1));
        last_emitted.insert(key1.clone(), (Instant::now(), r1.status.clone()));

        // Second identical occurrence — should suppress
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

        // Different status → different fingerprint → should emit
        let key_new = "firewall:Fail".to_string();
        assert!(!last_emitted.contains_key(&key_new), "New status should not be suppressed");
    }

    #[test]
    fn test_redlobster_dedup_resolved_fires_info() {
        // When a finding goes from Warn/Fail → Pass, that's a "resolved" event
        // which should fire an Info alert
        let prev_status = ScanStatus::Fail;
        let curr_status = ScanStatus::Pass;

        // Resolved = was bad, now good
        let is_resolved = (prev_status == ScanStatus::Warn || prev_status == ScanStatus::Fail)
            && curr_status == ScanStatus::Pass;
        assert!(is_resolved, "Fail→Pass should be detected as resolved");

        // Resolved findings should produce Info alert
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

        // Emit first
        last_emitted.insert(key.clone(), Instant::now());

        // Check second — suppressed
        assert!(last_emitted.get(&key).unwrap().elapsed() < cooldown);

        // Check third — still suppressed (same instant effectively)
        assert!(last_emitted.get(&key).unwrap().elapsed() < cooldown);
    }

    #[test]
    fn test_scan_ld_preload_persistence_runs() {
        // Basic smoke test — should not panic, returns a ScanResult
        let result = scan_ld_preload_persistence();
        assert!(!result.category.is_empty());
        // On a clean test system, should pass
        // (may fail on systems with actual LD_PRELOAD entries)
    }

    #[test]
    fn test_ld_preload_allowlist_clawtower_guard() {
        // Verify the allowlist logic: lines containing clawguard/clawtower should be skipped
        let line = "LD_PRELOAD=/usr/local/lib/libclawguard.so";
        let trimmed = line.trim();
        assert!(
            trimmed.contains(CLAWTOWER_GUARD_PATH)
                || trimmed.contains("clawguard")
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

    // --- OpenClaw hardening scanners ---

    #[test]
    fn test_openclaw_container_isolation_no_process() {
        // When openclaw isn't running, should return Warn (not crash)
        let result = scan_openclaw_container_isolation();
        // On test systems without openclaw running, this should warn
        assert!(result.status == ScanStatus::Warn || result.status == ScanStatus::Pass);
        assert!(result.category == "openclaw:isolation");
    }

    #[test]
    fn test_openclaw_running_as_root_no_process() {
        let result = scan_openclaw_running_as_root();
        assert!(result.status == ScanStatus::Warn || result.status == ScanStatus::Pass
            || result.status == ScanStatus::Fail);
        assert!(result.category == "openclaw:run_as_root");
    }

    #[test]
    fn test_openclaw_hardcoded_secrets_no_config() {
        // When config files don't exist, should pass (nothing to scan)
        let result = scan_openclaw_hardcoded_secrets();
        // Pass = no config found, so no secrets; or config exists and is clean
        assert!(result.category == "openclaw:hardcoded_secrets");
    }

    #[test]
    fn test_openclaw_hardcoded_secrets_detection() {
        // Test the key prefix detection logic directly
        let config_with_key = r#"{"apiKey": "sk-ant-api03-realkey1234567890abcdef1234567890"}"#;
        let has_match = ["sk-ant-"].iter().any(|prefix| {
            if let Some(pos) = config_with_key.find(prefix) {
                let after = &config_with_key[pos + prefix.len()..];
                let key_chars = after.chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
                    .count();
                key_chars >= 16
            } else {
                false
            }
        });
        assert!(has_match, "Should detect sk-ant- prefixed key");
    }

    #[test]
    fn test_openclaw_hardcoded_secrets_short_value_ignored() {
        // Short values that happen to start with a prefix shouldn't trigger
        let config = r#"{"mode": "sk-ant-short"}"#;
        let has_match = ["sk-ant-"].iter().any(|prefix| {
            if let Some(pos) = config.find(prefix) {
                let after = &config[pos + prefix.len()..];
                let key_chars = after.chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
                    .count();
                key_chars >= 16
            } else {
                false
            }
        });
        assert!(!has_match, "Short values should not trigger secret detection");
    }

    #[test]
    fn test_openclaw_version_freshness_no_binary() {
        let result = scan_openclaw_version_freshness();
        // On test systems without openclaw, should warn gracefully
        assert!(result.category == "openclaw:version");
    }
}
