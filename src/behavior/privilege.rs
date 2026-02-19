// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Privilege escalation detection helpers.
//!
//! Sensitive file reads/writes, sudo abuse, container escape,
//! kernel module loading, SSH key injection, process injection,
//! and SUID/capability manipulation detection.

use crate::core::alerts::Severity;
use super::BehaviorCategory;
use super::patterns::{
    CONTAINER_ESCAPE_BINARIES, CONTAINER_ESCAPE_PATTERNS,
    KERNEL_MODULE_COMMANDS, SSH_KEY_INJECTION_PATTERNS,
    PROCESS_INJECTION_PATTERNS,
    CRITICAL_READ_PATHS, CRITICAL_WRITE_PATHS,
    AGENT_SENSITIVE_PATHS, RECON_PATHS,
    NETWORK_CAPABLE_RUNTIMES,
    AUTH_PROFILES_FILENAME, record_cred_read,
};

/// Check for container escape binaries and patterns (EXECVE events).
///
/// Detects direct invocation of container escape binaries (nsenter, unshare,
/// runc, ctr, crictl) and command-line patterns indicating escape attempts
/// (--privileged, /proc/1/root, docker.sock, cgroup release_agent, etc.).
///
/// `binary` is the base name, `cmd` is the full command string.
pub(crate) fn check_container_escape(binary: &str, cmd: &str) -> Option<(BehaviorCategory, Severity)> {
    if CONTAINER_ESCAPE_BINARIES.iter().any(|&c| binary.eq_ignore_ascii_case(c)) {
        return Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical));
    }

    for pattern in CONTAINER_ESCAPE_PATTERNS {
        if cmd.contains(pattern) {
            return Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical));
        }
    }

    None
}

/// Check for direct sudo abuse patterns (EXECVE events where binary == "sudo").
///
/// Detects:
/// - sudo + network-capable runtime (python, node, etc.) with setuid/server patterns (Critical)
/// - sudo + network-capable runtime (Warning)
/// - sudo reading critical/agent-sensitive/recon paths
/// - sudo find with -exec (Critical)
/// - sudo systemctl on clawtower (Critical)
/// - sudo systemctl enable/start (Warning)
/// - sudo journalctl/ss/lsof/ps (Recon Warning)
/// - Any other sudo invocation (Priv Esc Warning)
///
/// `args` is the full argument vector (args[0] == "sudo").
pub(crate) fn check_sudo_abuse(args: &[String]) -> Option<(BehaviorCategory, Severity)> {
    if args.len() <= 1 {
        return None;
    }

    let full_cmd = args.join(" ");
    let sudo_target = args[1].rsplit('/').next().unwrap_or(&args[1]);
    let full_cmd_lower = full_cmd.to_lowercase();

    // Sudo + network-capable runtime
    if NETWORK_CAPABLE_RUNTIMES.iter().any(|&r| sudo_target.eq_ignore_ascii_case(r)) {
        if full_cmd.contains("setuid") || full_cmd.contains("seteuid")
            || full_cmd.contains("setreuid") || full_cmd.contains("os.setuid")
            || full_cmd.contains("Process.euid") || full_cmd.contains("Process::UID") {
            return Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical));
        }
        if full_cmd.contains("createServer") || full_cmd.contains("http.server")
            || full_cmd.contains("HTTPServer") || full_cmd.contains(".listen(")
            || full_cmd.contains("bind(") || full_cmd.contains("TCPServer")
            || full_cmd.contains("SimpleHTTPServer") {
            return Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical));
        }
        return Some((BehaviorCategory::PrivilegeEscalation, Severity::Warning));
    }

    // Sudo reading critical paths
    if CRITICAL_READ_PATHS.iter().any(|p| full_cmd.contains(p)) {
        return Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical));
    }
    if AGENT_SENSITIVE_PATHS.iter().any(|p| full_cmd.contains(p)) {
        return Some((BehaviorCategory::DataExfiltration, Severity::Critical));
    }
    if RECON_PATHS.iter().any(|p| full_cmd.contains(p)) {
        return Some((BehaviorCategory::Reconnaissance, Severity::Warning));
    }

    // Sudo find with exec
    if sudo_target.eq_ignore_ascii_case("find")
        && (full_cmd_lower.contains("-exec")
            || full_cmd_lower.contains("-execdir")
            || full_cmd_lower.contains("-ok ")
            || full_cmd_lower.contains("-okdir")) {
        return Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical));
    }

    // Sudo systemctl targeting clawtower
    if full_cmd_lower.contains("systemctl restart clawtower")
        || full_cmd_lower.contains("systemctl stop clawtower")
        || full_cmd_lower.contains("systemctl disable clawtower") {
        return Some((BehaviorCategory::SecurityTamper, Severity::Critical));
    }
    if full_cmd_lower.contains("systemctl enable")
        || full_cmd_lower.contains("systemctl start") {
        return Some((BehaviorCategory::SecurityTamper, Severity::Warning));
    }

    // Sudo recon commands
    if full_cmd_lower.contains("journalctl")
        || full_cmd_lower.contains(" ss ")
        || full_cmd_lower.contains(" lsof")
        || full_cmd_lower.contains(" ps ") {
        return Some((BehaviorCategory::Reconnaissance, Severity::Warning));
    }

    // Default: any other sudo usage
    Some((BehaviorCategory::PrivilegeEscalation, Severity::Warning))
}

/// Check for kernel module loading commands (insmod, modprobe).
pub(crate) fn check_kernel_module_loading(binary: &str) -> Option<(BehaviorCategory, Severity)> {
    if KERNEL_MODULE_COMMANDS.iter().any(|&c| binary.eq_ignore_ascii_case(c)) {
        return Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical));
    }
    None
}

/// Check for SSH key injection via file-writing tools.
///
/// Detects tee/echo/cp/mv writing to `.ssh/authorized_keys` paths.
pub(crate) fn check_ssh_key_injection(binary: &str, args: &[String]) -> Option<(BehaviorCategory, Severity)> {
    if ["tee", "echo", "cp", "mv"].contains(&binary) {
        for arg in args.iter().skip(1) {
            for pattern in SSH_KEY_INJECTION_PATTERNS {
                if arg.contains(pattern) {
                    return Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical));
                }
            }
        }
    }
    None
}

/// Check for process injection patterns (ptrace, /proc/*/mem, PTRACE_ATTACH, etc.).
pub(crate) fn check_process_injection(cmd: &str) -> Option<(BehaviorCategory, Severity)> {
    for pattern in PROCESS_INJECTION_PATTERNS {
        if cmd.contains(pattern) {
            return Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical));
        }
    }
    None
}

/// Check for reading sensitive files (EXECVE events).
///
/// Detects file readers (cat, less, more, head, tail, xxd, base64, cp, etc.)
/// accessing critical system files (/etc/shadow, /etc/sudoers, etc.) or
/// agent-sensitive files (credentials, gateway.yaml, etc.).
///
/// Returns PrivilegeEscalation for critical paths, DataExfiltration for
/// agent-sensitive paths.
pub(crate) fn check_sensitive_file_reads(binary: &str, args: &[String]) -> Option<(BehaviorCategory, Severity)> {
    if ["cat", "less", "more", "head", "tail", "xxd", "base64", "cp", "scp", "dd", "tar", "rsync", "sed", "tee", "script"].contains(&binary) {
        for arg in args.iter().skip(1) {
            for path in CRITICAL_READ_PATHS {
                if arg.contains(path) {
                    return Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical));
                }
            }
            // auth-profiles.json: rate-based severity (Warning unless rapid access)
            if arg.contains(AUTH_PROFILES_FILENAME) {
                let severity = record_cred_read();
                return Some((BehaviorCategory::DataExfiltration, severity));
            }
            for path in AGENT_SENSITIVE_PATHS {
                if arg.contains(path) {
                    return Some((BehaviorCategory::DataExfiltration, Severity::Critical));
                }
            }
        }
    }
    None
}

/// Check for `dd` reading critical system files via `if=` argument.
pub(crate) fn check_dd_sensitive_reads(args: &[String]) -> Option<(BehaviorCategory, Severity)> {
    for arg in args.iter() {
        if let Some(path) = arg.strip_prefix("if=") {
            for crit_path in CRITICAL_READ_PATHS {
                if path.contains(crit_path) {
                    return Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical));
                }
            }
        }
    }
    None
}

/// Check for writing to sensitive system files (tee, cp, mv, install).
pub(crate) fn check_sensitive_file_writes(binary: &str, args: &[String]) -> Option<(BehaviorCategory, Severity)> {
    if ["tee", "cp", "mv", "install"].contains(&binary) {
        for arg in args.iter().skip(1) {
            for path in CRITICAL_WRITE_PATHS {
                if arg.contains(path) {
                    return Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical));
                }
            }
        }
    }
    None
}

/// Check for editors on sensitive system files (vi, vim, nano, sed, ed).
pub(crate) fn check_editors_on_sensitive_files(binary: &str, args: &[String]) -> Option<(BehaviorCategory, Severity)> {
    if ["vi", "vim", "nano", "sed", "ed"].contains(&binary) {
        for arg in args.iter().skip(1) {
            for path in CRITICAL_WRITE_PATHS {
                if arg.contains(path) {
                    return Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical));
                }
            }
        }
    }
    None
}
