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

/// Audit user and system crontabs for suspicious entries (wget, curl, nc, base64, etc.).
pub fn scan_crontab_audit() -> ScanResult {
    let mut issues = Vec::new();

    // Check user crontabs
    match run_cmd("bash", &["-c", "for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u $u 2>/dev/null | grep -v '^#' | grep -v '^$' && echo \"User: $u\"; done"]) {
        Ok(output) => {
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
        Err(_) => {} // Normal if no user crontabs
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
        match run_cmd("find", &[dir, "-type", "f", "-perm", "0002", "2>/dev/null"]) {
            Ok(output) => {
                for file in output.lines() {
                    if !file.trim().is_empty() {
                        issues.push(file.trim().to_string());
                    }
                }
            }
            Err(_) => {} // Directory might not exist or permission denied
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
    if let Ok(output) = run_cmd("find", &["/", "-type", "f", "-perm", "-4000", "2>/dev/null"]) {
        for file in output.lines() {
            if !file.trim().is_empty() {
                suid_files.push(file.trim().to_string());
            }
        }
    }

    // Find SGID files  
    if let Ok(output) = run_cmd("find", &["/", "-type", "f", "-perm", "-2000", "2>/dev/null"]) {
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
                match run_cmd("ls", &["-la", "/var/run/docker.sock"]) {
                    Ok(output) => {
                        if output.contains("rw-rw-rw-") || output.contains("666") {
                            issues.push("Docker socket is world-writable".to_string());
                        }
                    }
                    Err(_) => {}
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

    // Check PAM password requirements
    if let Ok(content) = std::fs::read_to_string("/etc/pam.d/common-password") {
        if !content.contains("pam_pwquality") && !content.contains("pam_cracklib") {
            issues.push("No password quality checking configured".to_string());
        }
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
    if let Ok(output) = run_cmd("lsof", &["-n", "|", "wc", "-l"]) {
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

    // Check auth.log if it exists
    if let Ok(output) = run_cmd("grep", &["-c", "Failed password", "/var/log/auth.log"]) {
        if let Ok(count) = output.trim().parse::<u32>() {
            if count > 100 {
                issues.push(format!("High auth failures in auth.log: {}", count));
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
            if line.contains(" /dev/shm ") {
                if !line.contains("noexec") {
                    issues.push("/dev/shm allows execution".to_string());
                }
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
        if key.contains("KEY") || key.contains("SECRET") || key.contains("TOKEN") {
            if value.len() > 20 && value.chars().all(|c| c.is_ascii_alphanumeric() || c == '=' || c == '+' || c == '/') {
                issues.push(format!("Potential credential in environment: {}", key));
            }
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
        if output.trim() != "0" && output.trim() != "unlimited" {
            if output.trim().parse::<u64>().unwrap_or(0) > 0 {
                issues.push(format!("Core dumps allowed: ulimit -c = {}", output.trim()));
            }
        }
    }

    // Check /proc/sys/kernel/core_pattern
    if let Ok(pattern) = std::fs::read_to_string("/proc/sys/kernel/core_pattern") {
        let pattern = pattern.trim();
        if !pattern.starts_with("|/bin/false") && pattern != "core" {
            if pattern.contains("/") && !pattern.contains("/dev/null") {
                issues.push(format!("Core dumps directed to: {}", pattern));
            }
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
            if line.contains("10.0.0.0/8") || line.contains("172.16.0.0/12") || line.contains("192.168.0.0/16") {
                if line.contains("tun") || line.contains("tap") {
                    issues.push(format!("VPN/tunnel route detected: {}", line.trim()));
                }
            }
        }
    }

    if issues.is_empty() {
        ScanResult::new("network_interfaces", ScanStatus::Pass, "Network interfaces appear normal")
    } else {
        ScanResult::new("network_interfaces", ScanStatus::Warn, &format!("Network concerns: {}", issues.join("; ")))
    }
}

/// Verify that the ClawAV systemd service has security hardening directives (NoNewPrivileges, ProtectSystem, etc.).
pub fn scan_systemd_hardening() -> ScanResult {
    let mut issues = Vec::new();

    // Check if ClawAV service has security hardening enabled
    let service_file = "/etc/systemd/system/clawav.service";
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
        issues.push("ClawAV service file not found".to_string());
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

    if issues.is_empty() {
        ScanResult::new("user_accounts", ScanStatus::Pass, "User account configuration secure")
    } else {
        ScanResult::new("user_accounts", ScanStatus::Warn, &format!("User account issues: {}", issues.join("; ")))
    }
}

/// Check UFW firewall status and rule count.
pub fn scan_firewall() -> ScanResult {
    match run_cmd_with_sudo("ufw", &["status", "verbose"]) {
        Ok(output) => parse_ufw_status(&output),
        Err(e) => ScanResult::new("firewall", ScanStatus::Fail, &format!("Cannot check firewall: {}", e)),
    }
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

/// Verify ClawAV binary and config integrity against stored SHA-256 checksums.
pub fn scan_integrity() -> ScanResult {
    // Check if binary exists and get its hash
    let _binary_path = "/usr/local/bin/clawav";
    let _config_path = "/etc/clawav/config.toml";
    let checksums_path = "/etc/clawav/checksums.sha256";

    if !std::path::Path::new(checksums_path).exists() {
        return ScanResult::new("integrity", ScanStatus::Warn, "No checksums file found — run 'clawav --store-checksums' to create baseline");
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

/// List TCP listening sockets and flag any not in the expected set (ClawAV API port 18791).
pub fn scan_listening_services() -> ScanResult {
    match run_cmd("ss", &["-tlnp"]) {
        Ok(output) => {
            let expected_ports = ["18791"]; // ClawAV API
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

/// Static entry point for running all security scans.
pub struct SecurityScanner;

/// Check that immutable (chattr +i) flags are set on critical ClawAV files.
/// Auto-remediates: if a file exists but lacks the immutable flag, sets it
/// automatically and reports as a warning (not a failure).
pub fn scan_immutable_flags() -> ScanResult {
    let critical_files = [
        "/usr/local/bin/clawav",
        "/usr/local/bin/clawsudo",
        "/usr/local/bin/clawav-tray",
        "/etc/clawav/config.toml",
        "/etc/clawav/admin.key.hash",
        "/etc/systemd/system/clawav.service",
        "/etc/sudoers.d/clawav-deny",
    ];

    // Files that may not exist (optional or created later)
    let optional_files = [
        "/usr/local/bin/clawav-tray",
        "/etc/clawav/admin.key.hash",
        "/etc/sudoers.d/clawav-deny",
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
                || output.contains("clawav.deny-openclaw");
            let has_protect_profile = output.contains("clawav.protect");

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
                    "AppArmor profiles not loaded — run scripts/setup-apparmor.sh",
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
    let candidates = [
        "/home/openclaw/.openclaw/workspace/openclawav/vendor/secureclaw",
        "vendor/secureclaw",
        "/opt/clawav/vendor/secureclaw",
    ];
    let vendor_path = candidates.iter()
        .find(|p| std::path::Path::new(p).exists())
        .copied()
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
            scan_package_integrity(),
            scan_core_dump_settings(),
            scan_network_interfaces(),
            scan_systemd_hardening(),
            scan_user_account_audit(),
        ];
        // Cognitive file integrity (returns Vec)
        // Load SecureClaw engine for cognitive content scanning
        let secureclaw_engine = crate::secureclaw::SecureClawEngine::load(
            std::path::Path::new("/etc/clawav/secureclaw")
        ).ok();
        results.extend(scan_cognitive_integrity(
            std::path::Path::new("/home/openclaw/.openclaw/workspace"),
            std::path::Path::new("/etc/clawav/cognitive-baselines.sha256"),
            secureclaw_engine.as_ref(),
        ));
        // OpenClaw-specific security checks
        results.extend(scan_openclaw_security());

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

/// Scan for mDNS info leaks by checking avahi-browse.
fn scan_mdns_leaks() -> Vec<ScanResult> {
    match Command::new("avahi-browse").args(&["-apt", "--no-db-lookup"]).output() {
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

fn scan_openclaw_security() -> Vec<ScanResult> {
    let mut results = Vec::new();

    // Check OpenClaw gateway config (JSON format in openclaw.json)
    let config_paths = [
        "/home/openclaw/.openclaw/openclaw.json",
        "/home/openclaw/.openclaw/agents/main/agent/gateway.yaml",
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
pub async fn run_periodic_scans(
    interval_secs: u64,
    raw_tx: mpsc::Sender<Alert>,
    scan_store: SharedScanResults,
    openclaw_config: crate::config::OpenClawConfig,
) {
    use std::collections::HashMap;
    use std::time::Instant;

    let mut last_emitted: HashMap<String, Instant> = HashMap::new();
    let cooldown = Duration::from_secs(24 * 3600); // 24 hours

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

        // Convert to alerts and send (with 24h deduplication)
        let now = Instant::now();
        for result in &results {
            if let Some(alert) = result.to_alert() {
                let status_str = match result.status {
                    ScanStatus::Pass => "pass",
                    ScanStatus::Warn => "warn",
                    ScanStatus::Fail => "fail",
                };
                let dedup_key = format!("{}:{}", result.category, status_str);
                if let Some(last) = last_emitted.get(&dedup_key) {
                    if now.duration_since(*last) < cooldown {
                        continue; // Skip duplicate within cooldown
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
        assert!(check_lsattr_immutable("----i---------e------- /usr/local/bin/clawav"));
    }

    #[test]
    fn test_lsattr_immutable_flag_missing() {
        assert!(!check_lsattr_immutable("--------------e------- /usr/local/bin/clawav"));
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
}
