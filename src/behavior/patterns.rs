// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Static pattern arrays for behavioral threat detection.
//!
//! All `const` arrays used by the behavior engine are centralized here.
//! These include command lists, file paths, and substring patterns organized
//! by threat category.

use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use crate::core::alerts::Severity;

// ─── Credential read rate tracking ──────────────────────────────────────────

/// Filename that triggers rate-based severity (downgraded from unconditional CRIT).
pub(crate) const AUTH_PROFILES_FILENAME: &str = "auth-profiles.json";

/// Sliding-window tracker for auth-profiles.json reads.
/// Tracks timestamps of recent reads within a 60s window.
/// < 3 reads → Warning; >= 3 reads → Critical (rapid access escalation).
struct CredReadTracker {
    timestamps: VecDeque<Instant>,
}

impl CredReadTracker {
    const WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
    const ESCALATION_THRESHOLD: usize = 3;

    fn new() -> Self {
        Self { timestamps: VecDeque::new() }
    }
}

static CRED_READ_TRACKER: OnceLock<Mutex<CredReadTracker>> = OnceLock::new();

fn cred_read_tracker() -> &'static Mutex<CredReadTracker> {
    CRED_READ_TRACKER.get_or_init(|| Mutex::new(CredReadTracker::new()))
}

/// Record an auth-profiles.json read and return the appropriate severity.
/// Uses a 60s sliding window: < 3 reads → Warning, >= 3 reads → Critical.
pub(crate) fn record_cred_read() -> Severity {
    let mut tracker = cred_read_tracker()
        .lock()
        .expect("cred_read_tracker mutex poisoned");
    let now = Instant::now();

    // Prune entries older than the window
    while let Some(&front) = tracker.timestamps.front() {
        if now.duration_since(front) > CredReadTracker::WINDOW {
            tracker.timestamps.pop_front();
        } else {
            break;
        }
    }

    tracker.timestamps.push_back(now);

    if tracker.timestamps.len() >= CredReadTracker::ESCALATION_THRESHOLD {
        Severity::Critical
    } else {
        Severity::Warning
    }
}

#[cfg(test)]
pub(crate) fn reset_cred_read_tracker() {
    let mut tracker = cred_read_tracker()
        .lock()
        .expect("cred_read_tracker mutex poisoned");
    tracker.timestamps.clear();
}

// ─── Sensitive file paths ───────────────────────────────────────────────────

/// Sensitive files that should never be read by the watched user
pub(crate) const CRITICAL_READ_PATHS: &[&str] = &[
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/gshadow",
    "/etc/master.passwd",
    "/proc/kcore",
    "/proc/self/environ",
    "/proc/1/environ",
];

/// Agent-specific sensitive files (credentials, config with secrets)
pub(crate) const AGENT_SENSITIVE_PATHS: &[&str] = &[
    "auth-profiles.json",
    "gateway.yaml",
    "device.json",
    "settings.json",
    "openclaw.json",
    ".aws/credentials",
    ".ssh/id_ed25519",
    ".ssh/id_rsa",
];

/// Wrapper binaries that execute other commands (used for stealth detection)
#[allow(dead_code)]
pub(crate) const WRAPPER_BINARIES: &[&str] = &["script", "stdbuf", "timeout", "env", "nice", "nohup"];

/// Sensitive files that should never be written by the watched user
pub(crate) const CRITICAL_WRITE_PATHS: &[&str] = &[
    "/etc/passwd",
    "/etc/hosts",
    "/etc/crontab",
    "/etc/sudoers",
    "/etc/shadow",
    "/etc/rc.local",
    "/etc/ld.so.preload",
];

/// Reconnaissance-indicative file paths
pub(crate) const RECON_PATHS: &[&str] = &[
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

// ─── Exfiltration patterns ──────────────────────────────────────────────────

/// Network exfiltration tools (unconditionally suspicious when run by agent)
pub(crate) const EXFIL_COMMANDS: &[&str] = &[
    "curl", "wget",           // HTTP transfer
    "nc", "ncat", "netcat", "socat",  // Raw connections
    "rsync",                  // File transfer (always remote-capable)
];

/// File transfer tools that are only suspicious with remote targets (contain '@')
pub(crate) const REMOTE_TRANSFER_COMMANDS: &[&str] = &["scp", "sftp", "ssh"];

/// Network-capable interpreters/runtimes that can make outbound connections
pub(crate) const NETWORK_CAPABLE_RUNTIMES: &[&str] = &[
    "node", "nodejs",
    "python3", "python",
    "perl", "ruby",
    "php", "lua",
];

/// Patterns indicating scripted exfiltration via interpreters
pub(crate) const SCRIPTED_EXFIL_PATTERNS: &[&str] = &[
    "http.server",           // python3 -m http.server
    "SimpleHTTPServer",      // python -m SimpleHTTPServer
    "http.client",           // python3 http.client
    "urllib.request",        // python3 urllib
    "requests.post",         // python requests lib
    "requests.get",
    "socket.connect",        // raw socket
    "net.createServer",      // node.js server
    "net.createConnection",  // node.js client
    "IO::Socket",            // perl socket
    "TCPSocket",             // ruby socket
    "fsockopen",             // php socket
];

/// DNS exfiltration tools
pub(crate) const DNS_EXFIL_COMMANDS: &[&str] = &["dig", "nslookup", "host", "drill", "resolvectl"];

/// Large file exfiltration patterns
pub(crate) const LARGE_FILE_EXFIL_PATTERNS: &[&str] = &[
    "tar -czf",
    "tar -cf",
    "zip -r",
    "7z a",
    "gzip",
    "bzip2",
];

/// AWS credential theft patterns
pub(crate) const AWS_CREDENTIAL_PATTERNS: &[&str] = &[
    "aws sts get-session-token",
    "aws sts assume-role",
    "aws configure get",
    "aws configure list",
    ".aws/credentials",
    ".aws/config",
];

/// Git credential exposure patterns
pub(crate) const GIT_CREDENTIAL_PATTERNS: &[&str] = &[
    "git config credential",
    "git config user.token",
    "git config --global credential",
    ".git/config",
    ".gitconfig",
];

/// Network tunnel creation patterns
pub(crate) const TUNNEL_CREATION_PATTERNS: &[&str] = &[
    "ssh -R",
    "ssh -L",
    "ssh -D",
    "chisel",
    "ngrok",
    "socat",
    "proxytunnel",
    "stunnel",
];

// ─── Security tamper patterns ───────────────────────────────────────────────

/// Security-disabling commands (matched as substrings of full command)
pub(crate) const SECURITY_TAMPER_PATTERNS: &[&str] = &[
    "ufw disable",
    "iptables -f",
    "iptables --flush",
    "iptables -F",
    "nft flush",
    "systemctl stop apparmor",
    "systemctl disable apparmor",
    "systemctl stop auditd",
    "systemctl disable auditd",
    "systemctl stop clawtower",
    "systemctl disable clawtower",
    "systemctl stop samhain",
    "systemctl disable samhain",
    "systemctl stop fail2ban",
    "systemctl disable fail2ban",
    "aa-teardown",
    "setenforce 0",
];

/// Patterns that indicate LD_PRELOAD bypass attempts
pub(crate) const PRELOAD_BYPASS_PATTERNS: &[&str] = &[
    "ld.so.preload",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "ld-linux",
    "/lib/ld-",
];

/// Shell profile / rc files where LD_PRELOAD persistence is suspicious
pub(crate) const SHELL_PROFILE_PATHS: &[&str] = &[
    ".bashrc",
    ".bash_profile",
    ".zshrc",
    ".zprofile",
    ".zshenv",
    ".profile",
    "/etc/environment",
    "/etc/profile",
    "/etc/bash.bashrc",
    "/etc/profile.d/",
];

/// Known install paths for ClawTower's LD_PRELOAD guard library.
pub(crate) const CLAWTOWER_GUARD_PATHS: &[&str] = &[
    "/usr/local/lib/libclawtower.so",
    "/usr/local/lib/clawtower/libclawtower.so",
];

/// Tools commonly used to compile static binaries or bypass dynamic linking
pub(crate) const STATIC_COMPILE_PATTERNS: &[&str] = &[
    "-static",
    "-static-libgcc",
    "musl-gcc",
    "musl-cc",
];

/// SSH key injection patterns
pub(crate) const SSH_KEY_INJECTION_PATTERNS: &[&str] = &[
    ".ssh/authorized_keys",
    "/root/.ssh/authorized_keys",
    "/home/*/.ssh/authorized_keys",
];

/// History tampering patterns
pub(crate) const HISTORY_TAMPER_PATTERNS: &[&str] = &[
    ".bash_history",
    ".zsh_history",
    ".history",
    "HISTSIZE=0",
    "HISTFILESIZE=0",
    "unset HISTFILE",
];

/// Process injection patterns
pub(crate) const PROCESS_INJECTION_PATTERNS: &[&str] = &[
    "ptrace",
    "/proc/*/mem",
    "/proc/*/maps",
    "PTRACE_ATTACH",
    "PTRACE_POKETEXT",
];

/// Timestomping patterns
pub(crate) const TIMESTOMPING_PATTERNS: &[&str] = &[
    "touch -t",
    "touch --date",
    "touch -d",
    "touch -r",
];

/// Log clearing patterns
pub(crate) const LOG_CLEARING_PATTERNS: &[&str] = &[
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
pub(crate) const BINARY_REPLACEMENT_PATTERNS: &[&str] = &[
    "/usr/bin/",
    "/usr/sbin/",
    "/bin/",
    "/sbin/",
];

/// Kernel parameter modification patterns
pub(crate) const KERNEL_PARAM_PATTERNS: &[&str] = &[
    "sysctl -w",
    "echo > /proc/sys/",
    "/proc/sys/kernel/",
    "/proc/sys/net/",
];

/// Service creation patterns
pub(crate) const SERVICE_CREATION_PATTERNS: &[&str] = &[
    "systemctl enable",
    "systemctl start",
    "/etc/systemd/system/",
    "/usr/lib/systemd/system/",
    "/etc/init.d/",
    "update-rc.d",
    "chkconfig",
];

/// Package manager abuse patterns
pub(crate) const PACKAGE_MANAGER_ABUSE_PATTERNS: &[&str] = &[
    "pip install",
    "npm install",
    "gem install",
    "go get",
    "cargo install",
    "easy_install",
];

/// Compiler invocation patterns (could be building exploits)
pub(crate) const COMPILER_PATTERNS: &[&str] = &[
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
pub(crate) const MEMORY_DUMP_PATTERNS: &[&str] = &[
    "gdb attach",
    "gdb -p",
    "lldb -p",
    "/proc/kcore",
    "dd if=/proc/kcore",
    "volatility",
    "memdump",
];

// ─── Privilege escalation patterns ──────────────────────────────────────────

/// Container escape command patterns
pub(crate) const CONTAINER_ESCAPE_PATTERNS: &[&str] = &[
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
pub(crate) const CONTAINER_ESCAPE_BINARIES: &[&str] = &["nsenter", "unshare", "runc", "ctr", "crictl"];

/// Kernel module loading (priv esc / rootkit installation)
pub(crate) const KERNEL_MODULE_COMMANDS: &[&str] = &["insmod", "modprobe"];

/// Process identity masking patterns (stealth -- hide real process name)
pub(crate) const PROCESS_MASKING_PATTERNS: &[&str] = &[
    "prctl(15",     // PR_SET_NAME = 15
    "prctl.15",
    "PR_SET_NAME",
];

// ─── Persistence patterns ───────────────────────────────────────────────────

/// Persistence-related binaries
pub(crate) const PERSISTENCE_BINARIES: &[&str] = &["crontab", "at", "atq", "atrm", "batch"];

/// Persistence-related write paths
pub(crate) const PERSISTENCE_WRITE_PATHS: &[&str] = &[
    "/etc/cron",          // covers cron.d, cron.daily, cron.hourly, etc.
    "/var/spool/cron",
    "/var/spool/at",
    "/etc/rc.local",
    "/etc/init.d/",
    "/etc/systemd/system/",
    "/usr/lib/systemd/system/",
    ".config/systemd/user/",
    "/etc/profile.d/",
    "/etc/ld.so.preload",
    "sitecustomize.py",
    "usercustomize.py",
    ".git/hooks/",
    "node_modules/.hooks/",
];

// ─── Reconnaissance patterns ────────────────────────────────────────────────

/// Recon commands
pub(crate) const RECON_COMMANDS: &[&str] = &["whoami", "id", "uname", "env", "printenv", "hostname", "ifconfig"];

/// Commands that look like recon but are normal system operations -- skip detection
pub(crate) const RECON_ALLOWLIST: &[&str] = &["ip neigh", "ip addr", "ip route", "ip link"];

// ─── Side-channel patterns ──────────────────────────────────────────────────

/// Side-channel attack tools
pub(crate) const SIDECHANNEL_TOOLS: &[&str] = &["mastik", "flush-reload", "prime-probe", "sgx-step", "cache-attack"];

// ─── Financial theft patterns ───────────────────────────────────────────────

/// Crypto wallet file paths -- access by agent is suspicious
pub(crate) const CRYPTO_WALLET_PATHS: &[&str] = &[
    ".ethereum/keystore",
    ".ethereum/geth/nodekey",
    ".config/solana/id.json",
    ".gnosis/keystores",
    ".brownie/accounts",
    ".foundry/keystores",
    "wallet.json",
    "keystore.json",
    ".env.local",
];

/// Command-line patterns indicating crypto key/seed access
pub(crate) const CRYPTO_KEY_PATTERNS: &[&str] = &[
    "private_key",
    "privatekey",
    "secret_key",
    "secretkey",
    "mnemonic",
    "seed_phrase",
    "seed phrase",
    "keystore",
    "PRIVATE_KEY=",
    "SECRET_KEY=",
    "MNEMONIC=",
    "eth_sendTransaction",
    "eth_signTransaction",
    "eth_sendRawTransaction",
    "solana transfer",
    "cast send",
    "cast wallet",
];

/// Crypto CLI tools -- usage by agent is suspicious
pub(crate) const CRYPTO_CLI_TOOLS: &[&str] = &[
    "cast",
    "forge",
    "solana-keygen",
    "solana",
    "ethkey",
    "geth account",
    "brownie",
];

// ─── MCP / external action patterns ────────────────────────────────────────

/// MCP server registration/config tampering indicators
pub(crate) const MCP_TAMPER_PATTERNS: &[&str] = &[
    "mcp.json",
    "mcp-servers",
    ".mcp/",
    "mcp_server",
    "modelcontextprotocol",
];

/// CLI tools that perform external destructive actions
pub(crate) const DESTRUCTIVE_EXTERNAL_TOOLS: &[&str] = &[
    "gh issue close",
    "gh pr close",
    "gh pr merge",
    "gh repo delete",
    "aws s3 rm",
    "aws ec2 terminate",
    "aws iam delete",
    "aws lambda delete",
    "gcloud compute instances delete",
    "gcloud projects delete",
    "az vm delete",
    "az group delete",
    "kubectl delete",
    "terraform destroy",
    "twilio",
    "sendgrid",
];

/// External messaging tools -- agent sending messages without confirmation
pub(crate) const EXTERNAL_MESSAGING_TOOLS: &[&str] = &[
    "gh issue create",
    "gh pr create",
    "gh pr comment",
    "tweet",
    "toot",
    "slack-cli",
];

// ─── Miscellaneous patterns ─────────────────────────────────────────────────

/// Scheduled task manipulation patterns
pub(crate) const SCHEDULED_TASK_BINARIES: &[&str] = &[
    "at",
    "atq",
    "atrm",
    "batch",
    "crontab",
];

/// Encoding/obfuscation tools (excluding common file readers like cat)
pub(crate) const ENCODING_TOOLS: &[&str] = &[
    "xxd",
    "od",
    "hexdump",
    "base64",
    "base32",
    "uuencode",
];

/// File extensions that are suspicious when created in temp directories
pub(crate) const SUSPICIOUS_TEMP_EXTENSIONS: &[&str] = &[
    ".elf",
    ".so",
    ".bin",
    ".exe",
    ".dll",
    ".dylib",
];

/// Build tools whose child processes should not trigger SEC_TAMPER for linker activity
pub(crate) const BUILD_TOOL_BASES: &[&str] = &[
    "cargo", "rustc", "cc", "cc1", "cc1plus", "gcc", "g++",
    "collect2", "ld", "make", "cmake", "ninja", "as",
];

// ─── Social engineering patterns ────────────────────────────────────────────

/// Social engineering patterns -- commands that trick agents into executing untrusted code.
///
/// Each entry is (pattern_substring, description, severity).
/// - Base64-piped installer chains and curl/wget pipe-to-shell are Critical (immediate RCE).
/// - Known paste services and password-protected archives are Warning (suspicious but may be benign).
pub(crate) const SOCIAL_ENGINEERING_PATTERNS: &[(&str, &str, Severity)] = &[
    // Base64-piped installer chains (Critical -- immediate code execution)
    ("base64 -d | sh", "base64 decode piped to sh", Severity::Critical),
    ("base64 --decode | bash", "base64 decode piped to bash", Severity::Critical),
    ("base64 -d | sudo", "base64 decode piped to sudo", Severity::Critical),
    ("base64 --decode | sh", "base64 decode piped to sh", Severity::Critical),
    ("base64 -d | bash", "base64 decode piped to bash", Severity::Critical),
    ("base64 --decode | sudo", "base64 decode piped to sudo", Severity::Critical),

    // curl/wget pipe-to-shell (Critical -- remote code execution)
    ("curl ", "curl piped to shell", Severity::Critical),   // matched only when combined with pipe-to-shell below
    ("wget ", "wget piped to shell", Severity::Critical),   // matched only when combined with pipe-to-shell below

    // Known paste services (Warning -- suspicious hosting)
    ("rentry.co", "paste service URL (rentry.co)", Severity::Warning),
    ("glot.io", "paste service URL (glot.io)", Severity::Warning),
    ("pastebin.com", "paste service URL (pastebin.com)", Severity::Warning),
    ("hastebin.com", "paste service URL (hastebin.com)", Severity::Warning),
    ("dpaste.org", "paste service URL (dpaste.org)", Severity::Warning),
    ("transfer.sh", "paste/file service URL (transfer.sh)", Severity::Warning),
    ("ix.io", "paste service URL (ix.io)", Severity::Warning),
    ("0x0.st", "paste/file service URL (0x0.st)", Severity::Warning),

    // Password-protected archive instructions (Warning -- hiding payload contents)
    ("unzip -P", "password-protected zip extraction", Severity::Warning),
    ("7z x -p", "password-protected 7z extraction", Severity::Warning),
    ("openssl enc -d", "openssl decryption of payload", Severity::Warning),

    // Deceptive prerequisite patterns (Warning -- installing from untrusted sources)
    ("pip install --index-url", "pip install from non-default index", Severity::Warning),
    ("pip install --extra-index-url", "pip install from extra index URL", Severity::Warning),
    ("npm install --registry", "npm install from non-default registry", Severity::Warning),
];

// ─── Plugin abuse patterns ───────────────────────────────────────────────

/// Binaries indicating plugin misbehavior when spawned from a Node.js context.
pub(crate) const PLUGIN_ABUSE_BINARIES: &[&str] = &[
    "nc", "ncat", "netcat", "socat",   // raw network listeners/proxies
    "nmap", "masscan",                  // network scanning
    "tcpdump", "tshark",               // packet capture
    "strace", "ltrace",                // process tracing
];

/// OpenClaw config files that plugins should never modify.
pub(crate) const PLUGIN_CONFIG_PATHS: &[&str] = &[
    "openclaw.json",
    "auth-profiles.json",
    "gateway.yaml",
    "device.json",
    "settings.json",
];

/// Plugin-specific persistence locations — writes here are suspicious.
pub(crate) const PLUGIN_PERSISTENCE_PATHS: &[&str] = &[
    "node_modules/.bin/",
    ".npmrc",
    "node_modules/.cache/",
    "node_modules/.hooks/",
    ".node_modules/.package-lock.json",
];

/// Document-specific social engineering patterns -- deceptive content in files
/// that wouldn't appear in command-stream detection.
pub(crate) const DOCUMENT_SOCIAL_ENGINEERING_PATTERNS: &[(&str, &str, Severity)] = &[
    // Paste service URLs in prose (not just commands)
    ("rentry.co", "paste service URL in document (rentry.co)", Severity::Warning),
    ("glot.io", "paste service URL in document (glot.io)", Severity::Warning),
    ("pastebin.com", "paste service URL in document (pastebin.com)", Severity::Warning),
    ("hastebin.com", "paste service URL in document (hastebin.com)", Severity::Warning),
    ("dpaste.org", "paste service URL in document (dpaste.org)", Severity::Warning),
    ("transfer.sh", "paste/file service URL in document (transfer.sh)", Severity::Warning),
    ("ix.io", "paste service URL in document (ix.io)", Severity::Warning),
    ("0x0.st", "paste/file service URL in document (0x0.st)", Severity::Warning),
    // Password-protected archives
    ("unzip -P", "password-protected zip extraction in document", Severity::Warning),
    ("7z x -p", "password-protected 7z extraction in document", Severity::Warning),
    ("openssl enc -d", "openssl decryption instruction in document", Severity::Warning),
    // Package registry tampering
    ("pip install --index-url", "pip non-default index in document", Severity::Warning),
    ("pip install --extra-index-url", "pip extra index URL in document", Severity::Warning),
    ("pip3 install --index-url", "pip3 non-default index in document", Severity::Warning),
    ("pip3 install --extra-index-url", "pip3 extra index URL in document", Severity::Warning),
    ("npm install --registry", "npm non-default registry in document", Severity::Warning),
    ("yarn add --registry", "yarn non-default registry in document", Severity::Warning),
];
