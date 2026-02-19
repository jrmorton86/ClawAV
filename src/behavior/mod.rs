// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Hardcoded behavioral threat detection engine.
//!
//! Classifies parsed audit events against ~200 static patterns organized into
//! categories: data exfiltration, privilege escalation, security tampering,
//! reconnaissance, and side-channel attacks.
//!
//! Patterns include network exfil tools, DNS tunneling, container escapes,
//! LD_PRELOAD bypasses, SSH key injection, history tampering, log clearing,
//! binary replacement, and more. Build-tool child processes (cargo, gcc, etc.)
//! are allowlisted to reduce false positives.
//!
//! This is the "hardcoded" detection layer -- for user-configurable rules,
//! see the `policy` module.
//!
//! ## Module structure
//!
//! Detection logic is distributed across category-specific submodules:
//! - `patterns`: static pattern arrays (constants) used by all detection code
//! - `privilege`: privilege escalation detection (sudo abuse, container escape, sensitive files)
//! - `recon`: reconnaissance detection (env enumeration, config reads, system probing)
//! - `financial`: financial theft detection (crypto wallets, private keys)
//! - `exfiltration`: data exfiltration detection (network tools, DNS tunneling, data staging)
//! - `tamper`: security tamper helpers (LD_PRELOAD persistence)
//! - `social`: social engineering detection (pipe-to-shell, paste services)
//!
//! `classify_behavior()` in this module acts as the dispatcher, calling each
//! submodule's checker functions in priority order.

mod patterns;
mod exfiltration;
mod tamper;
mod social;
mod privilege;
mod recon;
mod financial;
pub(crate) mod plugin;

use std::fmt;

use crate::core::alerts::Severity;
use crate::sources::auditd::ParsedEvent;

// Re-export public API from submodules
pub use social::{check_social_engineering, check_social_engineering_content};
pub use tamper::{check_ld_preload_persistence, is_ld_preload_persistence_line};

// Import patterns still used directly by classify_behavior for
// checks that haven't been extracted to submodules yet (security tamper,
// persistence, side-channel, syscall-level path checks, etc.)
use patterns::*;

/// Categories of suspicious behavior detected by the hardcoded rules engine.
///
/// Each category maps to a class of attack technique (MITRE ATT&CK inspired).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BehaviorCategory {
    DataExfiltration,
    PrivilegeEscalation,
    SecurityTamper,
    Reconnaissance,
    SideChannel,
    FinancialTheft,
    #[allow(dead_code)]
    SocialEngineering,
    #[allow(dead_code)]
    BarnacleMatch,
}

impl fmt::Display for BehaviorCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BehaviorCategory::DataExfiltration => write!(f, "DATA_EXFIL"),
            BehaviorCategory::PrivilegeEscalation => write!(f, "PRIV_ESC"),
            BehaviorCategory::SecurityTamper => write!(f, "SEC_TAMPER"),
            BehaviorCategory::Reconnaissance => write!(f, "RECON"),
            BehaviorCategory::SideChannel => write!(f, "SIDE_CHAN"),
            BehaviorCategory::FinancialTheft => write!(f, "FIN_THEFT"),
            BehaviorCategory::SocialEngineering => write!(f, "SOCIAL_ENG"),
            BehaviorCategory::BarnacleMatch => write!(f, "BARNACLE_MATCH"),
        }
    }
}

/// Classify a parsed audit event against known attack patterns.
/// Returns Some((category, severity)) if the event matches a rule, None otherwise.
///
/// This function acts as a dispatcher, calling category-specific detection
/// helpers from submodules in priority order. The check order matters --
/// earlier matches take precedence.
pub fn classify_behavior(event: &ParsedEvent) -> Option<(BehaviorCategory, Severity)> {
    // ─── Phase 1: Raw audit record checks (pre-EXECVE) ────────────────

    // Check raw audit record for LD_PRELOAD environment variable injection.
    if !event.raw.is_empty() && event.raw.contains("LD_PRELOAD=") {
        if !event.raw.contains("clawtower") && !event.raw.contains("clawsudo") {
            let raw_binary = event.args.first().map(|s| {
                s.rsplit('/').next().unwrap_or(s).to_string()
            }).unwrap_or_default();
            if !BUILD_TOOL_BASES.iter().any(|t| raw_binary.starts_with(t)) {
                let parent_suppressed = if let Some(ref ppid_exe) = event.ppid_exe {
                    let parent_base = ppid_exe.rsplit('/').next().unwrap_or(ppid_exe);
                    BUILD_TOOL_BASES.iter().any(|t| parent_base.starts_with(t))
                } else {
                    false
                };
                if !parent_suppressed {
                    return Some((BehaviorCategory::SecurityTamper, Severity::Critical));
                }
            }
        }
    }

    // ─── Phase 2: Social engineering (pipe-to-shell, paste services) ──

    {
        let full_cmd = if event.args.is_empty() {
            event.command.clone().unwrap_or_default()
        } else {
            event.args.join(" ")
        };
        if !full_cmd.is_empty() {
            if let Some((_, severity)) = check_social_engineering(&full_cmd) {
                return Some((BehaviorCategory::SocialEngineering, severity));
            }
        }
    }

    // ─── Phase 3: LD_PRELOAD persistence in shell profiles ───────────

    if let Some(ref cmd) = event.command {
        if let result @ Some(_) = check_ld_preload_persistence(cmd, event.file_path.as_deref()) {
            return result;
        }
    }

    // ─── Phase 4: EXECVE command analysis ────────────────────────────

    if let Some(ref cmd) = event.command {
        let cmd_lower = cmd.to_lowercase();
        let args = &event.args;
        let binary = args.first().map(|s| {
            s.rsplit('/').next().unwrap_or(s)
        }).unwrap_or("");

        // --- Security tamper patterns (firewall disable, service stop, etc.) ---
        for pattern in SECURITY_TAMPER_PATTERNS {
            if cmd_lower.contains(pattern) || cmd.contains(pattern) {
                return Some((BehaviorCategory::SecurityTamper, Severity::Critical));
            }
        }

        // --- exec -a process name masking (stealth technique) ---
        if (binary == "bash" || binary == "sh" || binary == "zsh")
            && (cmd.contains("exec -a") || cmd.contains("exec  -a")) {
                return Some((BehaviorCategory::SecurityTamper, Severity::Warning));
        }

        // --- Bare shell invocation (pipe receiver / interactive shell) ---
        if matches!(binary, "bash" | "sh" | "zsh" | "dash" | "ksh" | "fish") {
            let has_command_or_script = args.iter().skip(1).any(|a| {
                a == "-c" || (!a.starts_with('-') && !a.is_empty())
            });
            if !has_command_or_script {
                return Some((BehaviorCategory::SocialEngineering, Severity::Warning));
            }
        }

        // --- Wrapper binaries executing sensitive commands ---
        if binary == "script"
            && args.iter().any(|a| a == "-c" || a.starts_with("-c") || a.contains("c")) {
                let has_sensitive = args.iter().skip(1).any(|a| {
                    CRITICAL_READ_PATHS.iter().any(|p| a.contains(p)) ||
                    AGENT_SENSITIVE_PATHS.iter().any(|p| a.contains(p))
                });
                if has_sensitive {
                    return Some((BehaviorCategory::DataExfiltration, Severity::Critical));
                }
                return Some((BehaviorCategory::SecurityTamper, Severity::Warning));
        }

        // --- xargs executing sensitive-file readers ---
        if binary == "xargs" {
            let has_reader = args.iter().skip(1).any(|a| {
                let base = a.rsplit('/').next().unwrap_or(a);
                ["cat", "less", "more", "head", "tail", "xxd", "base64", "cp", "scp", "dd", "tar", "rsync", "sed", "tee"].contains(&base)
            });
            if has_reader {
                return Some((BehaviorCategory::DataExfiltration, Severity::Warning));
            }
        }

        // --- Persistence mechanisms ---
        if PERSISTENCE_BINARIES.iter().any(|&c| binary.eq_ignore_ascii_case(c)) {
            if binary.eq_ignore_ascii_case("crontab") && args.iter().any(|a| a == "-l") {
                // Skip -- listing crontabs is harmless
            } else {
                return Some((BehaviorCategory::SecurityTamper, Severity::Critical));
            }
        }

        // systemd timer/service creation
        if binary == "systemctl" && args.iter().any(|a| a == "enable" || a == "start") {
            if args.iter().any(|a| a == "--user") {
                return Some((BehaviorCategory::SecurityTamper, Severity::Critical));
            }
            return Some((BehaviorCategory::SecurityTamper, Severity::Warning));
        }

        // --- Container escape (delegated to privilege submodule) ---
        if let result @ Some(_) = privilege::check_container_escape(binary, cmd) {
            return result;
        }

        // --- Direct sudo abuse (delegated to privilege submodule) ---
        if binary == "sudo" && args.len() > 1 {
            if let result @ Some(_) = privilege::check_sudo_abuse(args) {
                return result;
            }
        }

        // --- Kernel module loading (delegated to privilege submodule) ---
        if let result @ Some(_) = privilege::check_kernel_module_loading(binary) {
            return result;
        }

        // --- Process identity masking ---
        if NETWORK_CAPABLE_RUNTIMES.iter().any(|&c| binary.eq_ignore_ascii_case(c)) {
            if let Some(ref cmd) = event.command {
                if PROCESS_MASKING_PATTERNS.iter().any(|p| cmd.contains(p)) {
                    return Some((BehaviorCategory::SecurityTamper, Severity::Warning));
                }
                if cmd.contains("memfd_create") || cmd.contains("MFD_CLOEXEC") {
                    return Some((BehaviorCategory::SecurityTamper, Severity::Critical));
                }
            }
        }

        // --- LD_PRELOAD bypass attempts ---
        if let Some(ref cmd) = event.command {
            for pattern in PRELOAD_BYPASS_PATTERNS {
                if cmd.contains(pattern) {
                    if !cmd.contains("clawtower") && !cmd.contains("clawsudo") {
                        if ["ld", "collect2", "cc1", "cc1plus", "gcc", "g++", "rustc", "cc"].contains(&binary) {
                            // Normal compilation
                        } else if let Some(ref ppid_exe) = event.ppid_exe {
                            let parent_base = ppid_exe.rsplit('/').next().unwrap_or(ppid_exe);
                            if BUILD_TOOL_BASES.iter().any(|t| parent_base.starts_with(t)) {
                                // Parent is a build tool -- suppress
                            } else {
                                return Some((BehaviorCategory::SecurityTamper, Severity::Critical));
                            }
                        } else {
                            return Some((BehaviorCategory::SecurityTamper, Severity::Critical));
                        }
                    }
                }
            }

            for pattern in STATIC_COMPILE_PATTERNS {
                if cmd.contains(pattern) {
                    if BUILD_TOOL_BASES.iter().any(|t| binary.starts_with(t)) {
                        break;
                    }
                    if let Some(ref ppid_exe) = event.ppid_exe {
                        let parent_base = ppid_exe.rsplit('/').next().unwrap_or(ppid_exe);
                        if BUILD_TOOL_BASES.iter().any(|t| parent_base.starts_with(t)) {
                            break;
                        }
                    }
                    return Some((BehaviorCategory::SecurityTamper, Severity::Warning));
                }
            }
        }

        // Direct invocation of the dynamic linker (bypass LD_PRELOAD)
        if binary == "ld-linux-aarch64.so.1" || binary == "ld-linux-x86-64.so.2" || binary.starts_with("ld-linux") || binary == "ld.so" {
            if let Some(ref ppid_exe) = event.ppid_exe {
                let parent_base = ppid_exe.rsplit('/').next().unwrap_or(ppid_exe);
                if BUILD_TOOL_BASES.iter().any(|t| parent_base.starts_with(t)) {
                    return None;
                }
            }
            return Some((BehaviorCategory::SecurityTamper, Severity::Critical));
        }

        // ptrace can be used to bypass LD_PRELOAD by injecting code directly
        if ["strace", "ltrace", "gdb", "lldb", "ptrace"].contains(&binary) {
            return Some((BehaviorCategory::SecurityTamper, Severity::Critical));
        }

        // --- SSH key injection (delegated to privilege submodule) ---
        if let result @ Some(_) = privilege::check_ssh_key_injection(binary, args) {
            return result;
        }

        // --- History tampering ---
        if ["rm", "mv", "cp", "ln", "truncate", "unset", "export"].contains(&binary) ||
           cmd_lower.contains("histsize=0") || cmd_lower.contains("histfilesize=0") {
            for pattern in HISTORY_TAMPER_PATTERNS {
                if cmd.contains(pattern) {
                    return Some((BehaviorCategory::SecurityTamper, Severity::Critical));
                }
            }
        }

        // --- Process injection (delegated to privilege submodule) ---
        if let Some(ref cmd) = event.command {
            if let result @ Some(_) = privilege::check_process_injection(cmd) {
                return result;
            }
        }

        // --- Timestomping ---
        if binary == "touch" {
            for pattern in TIMESTOMPING_PATTERNS {
                if cmd.contains(pattern) {
                    return Some((BehaviorCategory::SecurityTamper, Severity::Warning));
                }
            }
        }

        // --- Log clearing ---
        if let Some(ref cmd) = event.command {
            for pattern in LOG_CLEARING_PATTERNS {
                if cmd.contains(pattern) {
                    return Some((BehaviorCategory::SecurityTamper, Severity::Critical));
                }
            }
        }

        // --- Binary replacement in system directories ---
        if ["cp", "mv", "install", "dd"].contains(&binary) {
            for arg in args.iter().skip(1) {
                for pattern in BINARY_REPLACEMENT_PATTERNS {
                    if arg.starts_with(pattern) && args.len() > 2 {
                        return Some((BehaviorCategory::SecurityTamper, Severity::Critical));
                    }
                }
            }
        }

        // --- Kernel parameter changes ---
        if binary == "sysctl" || cmd.contains("echo > /proc/sys/") {
            for pattern in KERNEL_PARAM_PATTERNS {
                if cmd.contains(pattern) {
                    return Some((BehaviorCategory::SecurityTamper, Severity::Warning));
                }
            }
        }

        // --- Service creation/modification ---
        if binary == "systemctl" {
            for pattern in SERVICE_CREATION_PATTERNS {
                if cmd.contains(pattern) && !cmd.contains("clawtower") {
                    return Some((BehaviorCategory::SecurityTamper, Severity::Warning));
                }
            }
        }

        // --- Network tunnel creation (delegated to exfiltration submodule) ---
        if let result @ Some(_) = exfiltration::check_tunnel_creation(binary, cmd) {
            return result;
        }

        // --- Package manager abuse ---
        for pattern in PACKAGE_MANAGER_ABUSE_PATTERNS {
            if cmd.contains(pattern) {
                if cmd.contains("git+") || cmd.contains("http://") || cmd.contains("--index-url") {
                    return Some((BehaviorCategory::SecurityTamper, Severity::Warning));
                }
            }
        }

        // --- Compiler invocation ---
        for pattern in COMPILER_PATTERNS {
            if binary == *pattern || cmd.contains(pattern) {
                if let Some(ref ppid_exe) = event.ppid_exe {
                    let parent_base = ppid_exe.rsplit('/').next().unwrap_or(ppid_exe);
                    if BUILD_TOOL_BASES.iter().any(|t| parent_base.starts_with(t)) {
                        break;
                    }
                }
                if args.iter().any(|a| a.contains("/tmp/") || a.contains("socket") || a.contains("network")) {
                    return Some((BehaviorCategory::SecurityTamper, Severity::Warning));
                }
                return Some((BehaviorCategory::Reconnaissance, Severity::Info));
            }
        }

        // --- Memory dump tools (delegated to exfiltration submodule) ---
        if let result @ Some(_) = exfiltration::check_memory_dumps(cmd) {
            return result;
        }

        // --- Scheduled task manipulation ---
        for pattern in SCHEDULED_TASK_BINARIES {
            if binary == *pattern {
                if binary == "crontab" && args.iter().any(|a| a == "-l") {
                    continue;
                }
                return Some((BehaviorCategory::SecurityTamper, Severity::Warning));
            }
        }

        // --- Encoding/obfuscation tools (delegated to exfiltration submodule) ---
        if let result @ Some(_) = exfiltration::check_encoding_exfil(binary, cmd, args) {
            return result;
        }

        // --- Large file exfiltration (delegated to exfiltration submodule) ---
        if let result @ Some(_) = exfiltration::check_large_file_exfil(cmd, args) {
            return result;
        }

        // --- AWS credential theft (delegated to exfiltration submodule) ---
        if let result @ Some(_) = exfiltration::check_aws_credential_theft(cmd) {
            return result;
        }

        // --- Git credential exposure (delegated to exfiltration submodule) ---
        if let result @ Some(_) = exfiltration::check_git_credential_exposure(cmd) {
            return result;
        }

        // --- Financial / Crypto theft (delegated to financial submodule) ---
        if let result @ Some(_) = financial::check_financial_theft(cmd, &cmd_lower) {
            return result;
        }

        // --- Data exfiltration via network tools (delegated to exfiltration submodule) ---
        if let result @ Some(_) = exfiltration::check_network_exfil(binary, args) {
            return result;
        }

        // --- Remote file transfer (delegated to exfiltration submodule) ---
        if let result @ Some(_) = exfiltration::check_remote_transfer(binary, args) {
            return result;
        }

        // --- DNS exfiltration (delegated to exfiltration submodule) ---
        if let result @ Some(_) = exfiltration::check_dns_exfil(binary, args) {
            return result;
        }

        // --- Scripted DNS exfiltration (delegated to exfiltration submodule) ---
        if let Some(ref cmd) = event.command {
            if let result @ Some(_) = exfiltration::check_scripted_dns_exfil(binary, cmd) {
                return result;
            }
        }

        // --- Interpreter credential access / scripted exfil (delegated to exfiltration) ---
        if let result @ Some(_) = exfiltration::check_interpreter_exfil(binary, args) {
            return result;
        }

        // --- ICMP exfiltration via ping (delegated to exfiltration submodule) ---
        if let result @ Some(_) = exfiltration::check_icmp_exfil(binary, args) {
            return result;
        }

        // --- Git push / remote add (delegated to exfiltration submodule) ---
        if let result @ Some(_) = exfiltration::check_git_exfil(binary, args) {
            return result;
        }

        // --- Side-channel attack tools ---
        if SIDECHANNEL_TOOLS.iter().any(|&c| binary.eq_ignore_ascii_case(c)) {
            return Some((BehaviorCategory::SideChannel, Severity::Critical));
        }

        // --- Sensitive file reads (delegated to privilege submodule) ---
        if let result @ Some(_) = privilege::check_sensitive_file_reads(binary, args) {
            return result;
        }

        // --- dd sensitive reads (delegated to privilege submodule) ---
        if binary == "dd" {
            if let result @ Some(_) = privilege::check_dd_sensitive_reads(args) {
                return result;
            }
            // dd recon paths (delegated to recon submodule)
            if let result @ Some(_) = recon::check_dd_recon(args) {
                return result;
            }
        }

        // --- Sensitive file writes (delegated to privilege submodule) ---
        if let result @ Some(_) = privilege::check_sensitive_file_writes(binary, args) {
            return result;
        }

        // --- Editors on sensitive files (delegated to privilege submodule) ---
        if let result @ Some(_) = privilege::check_editors_on_sensitive_files(binary, args) {
            return result;
        }

        // --- Reconnaissance commands (delegated to recon submodule) ---
        if let result @ Some(_) = recon::check_recon_commands(binary, args) {
            return result;
        }

        // --- Reading recon-sensitive files (delegated to recon submodule) ---
        if let result @ Some(_) = recon::check_recon_file_reads(binary, args) {
            return result;
        }

        // --- base64 encoding (delegated to exfiltration submodule) ---
        if let result @ Some(_) = exfiltration::check_base64_encoding(binary) {
            return result;
        }

        // --- Memory/environ dumping tools (delegated to exfiltration submodule) ---
        if let result @ Some(_) = exfiltration::check_memory_environ_dump(binary, args) {
            return result;
        }
    }

    // ─── Phase 5: Syscall-level checks (non-EXECVE) ─────────────────

    // memfd_create syscall (fileless execution)
    if event.syscall_name == "memfd_create" && event.success {
        return Some((BehaviorCategory::SecurityTamper, Severity::Critical));
    }

    // sendfile/copy_file_range/sendto from interpreters
    if ["sendfile", "copy_file_range", "sendto"].contains(&event.syscall_name.as_str()) && event.success {
        let is_interpreter = |exe: &str| -> bool {
            let base = exe.rsplit('/').next().unwrap_or(exe);
            NETWORK_CAPABLE_RUNTIMES.iter().any(|&r| base.starts_with(r))
        };
        let exe_suspicious = event.args.first()
            .map(|a| is_interpreter(a))
            .unwrap_or(false);
        let parent_suspicious = event.ppid_exe.as_deref()
            .map(|p| is_interpreter(p))
            .unwrap_or(false);
        if exe_suspicious || parent_suspicious {
            return Some((BehaviorCategory::DataExfiltration, Severity::Critical));
        }
    }

    // Syscall-level file access to sensitive paths
    if let Some(ref path) = event.file_path {
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
            for persist_path in PERSISTENCE_WRITE_PATHS {
                if path.contains(persist_path) {
                    return Some((BehaviorCategory::SecurityTamper, Severity::Warning));
                }
            }
        }

        if ["unlinkat", "renameat"].contains(&event.syscall_name.as_str()) {
            for crit_path in CRITICAL_WRITE_PATHS {
                if path.contains(crit_path) {
                    return Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical));
                }
            }
            for persist_path in PERSISTENCE_WRITE_PATHS {
                if path.contains(persist_path) {
                    return Some((BehaviorCategory::SecurityTamper, Severity::Critical));
                }
            }
        }

        if ["openat", "newfstatat", "statx", "connect"].contains(&event.syscall_name.as_str()) && event.success {
            let container_escape_paths = ["/var/run/docker.sock", "/proc/1/root", "/proc/sysrq-trigger"];
            for escape_path in &container_escape_paths {
                if path.contains(escape_path) {
                    return Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical));
                }
            }
        }

        if path.contains("/proc/") && path.contains("/environ") {
            return Some((BehaviorCategory::DataExfiltration, Severity::Critical));
        }

        if path.contains("/proc/") && path.ends_with("/mem") {
            return Some((BehaviorCategory::DataExfiltration, Severity::Critical));
        }

        for pattern in SSH_KEY_INJECTION_PATTERNS {
            if path.contains(pattern) && ["openat", "write", "writev"].contains(&event.syscall_name.as_str()) {
                return Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical));
            }
        }

        for pattern in HISTORY_TAMPER_PATTERNS {
            if path.contains(pattern) && ["unlinkat", "truncate", "write"].contains(&event.syscall_name.as_str()) {
                return Some((BehaviorCategory::SecurityTamper, Severity::Critical));
            }
        }

        if path.starts_with("/tmp/") {
            for ext in SUSPICIOUS_TEMP_EXTENSIONS {
                if path.ends_with(ext) && ["openat", "creat"].contains(&event.syscall_name.as_str()) {
                    return Some((BehaviorCategory::SecurityTamper, Severity::Warning));
                }
            }
        }

        for pattern in BINARY_REPLACEMENT_PATTERNS {
            if path.starts_with(pattern) && ["write", "writev", "renameat"].contains(&event.syscall_name.as_str()) {
                return Some((BehaviorCategory::SecurityTamper, Severity::Critical));
            }
        }

        if path.starts_with("/var/log/") && ["unlinkat", "truncate", "write"].contains(&event.syscall_name.as_str()) {
            return Some((BehaviorCategory::SecurityTamper, Severity::Critical));
        }

        if (path.contains("/etc/systemd/system/") || path.contains("/etc/init.d/")) &&
           ["openat", "creat", "write"].contains(&event.syscall_name.as_str()) {
            return Some((BehaviorCategory::SecurityTamper, Severity::Warning));
        }

        if (path.contains("/etc/cron") || path.contains("/var/spool/cron")) &&
           ["openat", "write", "writev"].contains(&event.syscall_name.as_str()) {
            return Some((BehaviorCategory::SecurityTamper, Severity::Critical));
        }
    }

    if event.syscall_name == "perf_event_open" {
        return Some((BehaviorCategory::SideChannel, Severity::Warning));
    }

    // ─── Phase 6: MCP tampering & external actions ───────────────────

    // MCP config tampering via command
    if let Some(ref cmd) = event.command {
        for pattern in MCP_TAMPER_PATTERNS {
            if cmd.contains(pattern) {
                let is_write = ["echo", "tee", "sed", "mv", "cp", "cat >", ">>", "install"]
                    .iter().any(|w| cmd.contains(w));
                if is_write {
                    return Some((BehaviorCategory::SecurityTamper, Severity::Warning));
                }
            }
        }
    }

    // MCP config tampering via file operations
    if event.syscall_name == "openat" || event.syscall_name == "rename" || event.syscall_name == "unlink" {
        if let Some(ref fp) = event.file_path {
            for pattern in MCP_TAMPER_PATTERNS {
                if fp.contains(pattern) {
                    return Some((BehaviorCategory::SecurityTamper, Severity::Warning));
                }
            }
        }
    }

    // ─── Phase 7: Plugin abuse detection ─────────────────────────────

    if let Some(ref cmd) = event.command {
        if plugin::is_plugin_config_tampering(cmd) {
            return Some((BehaviorCategory::SecurityTamper, Severity::Critical));
        }
        if plugin::is_plugin_network_listener(cmd) {
            return Some((BehaviorCategory::SecurityTamper, Severity::Critical));
        }
    }

    if let Some(ref fp) = event.file_path {
        if let Some(ref cmd) = event.command {
            if plugin::is_inter_plugin_modification(cmd, fp) {
                return Some((BehaviorCategory::SecurityTamper, Severity::Warning));
            }
        }
        if plugin::is_node_module_poisoning(fp) {
            if ["openat", "creat", "write", "writev", "renameat"].contains(&event.syscall_name.as_str()) {
                return Some((BehaviorCategory::SecurityTamper, Severity::Warning));
            }
        }
    }

    // Unauthorized external actions
    if let Some(ref cmd) = event.command {
        for pattern in DESTRUCTIVE_EXTERNAL_TOOLS {
            if cmd.contains(pattern) {
                return Some((BehaviorCategory::DataExfiltration, Severity::Warning));
            }
        }
        for pattern in EXTERNAL_MESSAGING_TOOLS {
            if cmd.contains(pattern) {
                return Some((BehaviorCategory::DataExfiltration, Severity::Info));
            }
        }
    }

    None
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
