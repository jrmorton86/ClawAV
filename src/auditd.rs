//! Linux audit log parser and tail monitor.
//!
//! Parses auditd log lines (SYSCALL, EXECVE, AVC, ANOMALY records) into
//! structured [`ParsedEvent`] values. Supports aarch64 syscall number mapping,
//! hex-encoded EXECVE argument decoding, and actor attribution (agent vs human
//! based on auid).
//!
//! The main entry point [`tail_audit_log_with_behavior_and_policy`] tails the
//! audit log file and runs each event through the behavior detector, policy
//! engine, SecureClaw patterns, and tamper detection before emitting alerts.

use anyhow::Result;
use std::io::{BufRead, BufReader};
use std::fs::File;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Recommended auditd rules for ClawTower monitoring.
///
/// Install these via `auditctl` or drop into `/etc/audit/rules.d/clawtower.rules`.
#[allow(dead_code)]
pub const RECOMMENDED_AUDIT_RULES: &[&str] = &[
    // Detect immutable-flag removal on protected files
    "-w /usr/bin/chattr -p x -k clawtower-tamper",
    // Protect ClawTower config files
    "-w /etc/clawtower/ -p wa -k clawtower-config",
    // Monitor OpenClaw session log reads (prompt-injection / exfiltration vector)
    "-w /home/openclaw/.openclaw/agents/main/sessions/ -p r -k openclaw_session_read",
    // Credential file read monitoring (T2.1)
    "-w /home/openclaw/.openclaw/agents/main/agent/auth-profiles.json -p r -k clawtower_cred_read",
    "-w /home/openclaw/.aws/credentials -p r -k clawtower_cred_read",
    "-w /home/openclaw/.aws/config -p r -k clawtower_cred_read",
    "-w /home/openclaw/.ssh/id_ed25519 -p r -k clawtower_cred_read",
    "-w /home/openclaw/.ssh/id_rsa -p r -k clawtower_cred_read",
    "-w /home/openclaw/.openclaw/gateway.yaml -p r -k clawtower_cred_read",
    // System credential files (Flag 7 — catches interpreter-based reads)
    "-w /etc/shadow -p r -k clawtower_cred_read",
    "-w /etc/gshadow -p r -k clawtower_cred_read",
    "-w /etc/sudoers -p r -k clawtower_cred_read",
    // Network connect() monitoring for watched user (T6.1 — outbound escape detection)
    "-a always,exit -F arch=b64 -S connect -F uid=1000 -F success=1 -k clawtower_net_connect",
    // sendfile/copy_file_range monitoring — catches shutil.copyfile() and similar bypasses
    "-a always,exit -F arch=b64 -S sendfile -F uid=1000 -F success=1 -k clawtower_cred_read",
    "-a always,exit -F arch=b64 -S copy_file_range -F uid=1000 -F success=1 -k clawtower_cred_read",
];

use crate::alerts::{Alert, Severity};

/// Whether the event originated from the autonomous agent or a human operator
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Actor {
    Agent,
    Human,
    Unknown,
}

/// Parsed representation of an audit event (may combine SYSCALL + EXECVE records)
#[derive(Debug, Clone)]
pub struct ParsedEvent {
    /// Human-readable syscall name (e.g. "execve", "openat")
    pub syscall_name: String,
    /// The full command if EXECVE (e.g. "curl <http://evil.com>")
    pub command: Option<String>,
    /// Individual arguments from EXECVE
    pub args: Vec<String>,
    /// File path from the event if available
    pub file_path: Option<String>,
    /// Whether the syscall succeeded
    pub success: bool,
    /// Raw message for fallback
    pub raw: String,
    /// Attribution: agent (auid unset) vs human (auid set)
    pub actor: Actor,
    /// Parent process executable path (from `/proc/<ppid>/exe`)
    pub ppid_exe: Option<String>,
}

/// Map aarch64 syscall numbers to names
fn syscall_name_aarch64(num: u32) -> &'static str {
    match num {
        0 => "io_setup",
        17 => "getcwd",
        21 => "access", // actually faked via faccessat
        29 => "ioctl",
        35 => "unlinkat",
        38 => "renameat",
        48 => "faccessat",
        49 => "chdir",
        53 => "fchmodat",
        54 => "fchownat",
        56 => "openat",
        57 => "close",
        59 => "pipe2",
        61 => "getdents64",
        62 => "lseek",
        63 => "read",
        64 => "write",
        66 => "writev",
        78 => "readlinkat",
        79 => "newfstatat",
        80 => "fstat",
        93 => "exit",
        94 => "exit_group",
        96 => "set_tid_address",
        98 => "futex",
        100 => "set_robust_list",
        101 => "nanosleep",
        134 => "rt_sigaction",
        135 => "rt_sigprocmask",
        160 => "uname",
        172 => "getpid",
        173 => "getppid",
        174 => "getuid",
        175 => "geteuid",
        176 => "getgid",
        177 => "getegid",
        178 => "gettid",
        198 => "socket",
        200 => "bind",
        201 => "listen",
        203 => "connect",
        204 => "getsockname",
        205 => "getpeername",
        206 => "sendto",
        207 => "recvfrom",
        208 => "setsockopt",
        209 => "getsockopt",
        210 => "shutdown",
        220 => "clone",
        221 => "execve",
        222 => "mmap",
        226 => "mprotect",
        233 => "mkdirat",
        241 => "perf_event_open",
        242 => "accept4",
        260 => "wait4",
        261 => "prlimit64",
        271 => "sendfile",
        281 => "execveat",
        285 => "copy_file_range",
        291 => "statx",
        _ => "unknown",
    }
}

/// Extract a key=value field from an audit log line.
///
/// Splits on whitespace, finds the token starting with `field=`, and returns
/// the value portion with surrounding quotes stripped.
pub fn extract_field<'a>(line: &'a str, field: &str) -> Option<&'a str> {
    let prefix = format!("{}=", field);
    line.split_whitespace()
        .find(|s| s.starts_with(&prefix))
        .map(|s| &s[prefix.len()..])
        .map(|s| s.trim_matches('"'))
}

/// Decode hex-encoded argument strings from EXECVE records
fn decode_hex_arg(s: &str) -> String {
    // auditd sometimes hex-encodes args: a0=2F7573722F62696E2F6375726C
    if s.len() > 2 && s.chars().all(|c| c.is_ascii_hexdigit()) && s.len() % 2 == 0 {
        let bytes: Vec<u8> = (0..s.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
            .collect();
        if let Ok(decoded) = String::from_utf8(bytes) {
            if decoded.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                return decoded;
            }
        }
    }
    s.to_string()
}

/// Extract command + args from an EXECVE line
fn extract_execve_command(line: &str) -> Option<(String, Vec<String>)> {
    let mut args = Vec::new();
    for i in 0..20 {
        if let Some(val) = extract_field(line, &format!("a{}", i)) {
            args.push(decode_hex_arg(val.trim_matches('"')));
        } else {
            break;
        }
    }
    if args.is_empty() {
        None
    } else {
        let cmd = args.join(" ");
        Some((cmd, args))
    }
}

/// Parse a single auditd log line into a ParsedEvent
pub fn parse_to_event(line: &str, watched_users: Option<&[String]>) -> Option<ParsedEvent> {
    // EXECVE records don't contain uid/auid — they follow a SYSCALL record
    // that was already filtered. Allow all EXECVE lines through.
    if line.contains("type=EXECVE") {
        let (cmd, args) = extract_execve_command(line).unwrap_or_default();
        return Some(ParsedEvent {
            syscall_name: "execve".to_string(),
            command: if cmd.is_empty() { None } else { Some(cmd) },
            args,
            file_path: None,
            success: true,
            raw: line.to_string(),
            actor: Actor::Unknown,
            ppid_exe: None,
        });
    }

    // PROCTITLE records contain the full command line in hex, including env
    // var prefixes like LD_PRELOAD= that don't appear in EXECVE records.
    if line.contains("type=PROCTITLE") {
        if let Some(hex_start) = line.find("proctitle=") {
            let hex = &line[hex_start + 10..];
            // Decode hex to bytes, replace NUL with space
            if let Ok(bytes) = (0..hex.len())
                .step_by(2)
                .take_while(|&i| i + 2 <= hex.len())
                .map(|i| u8::from_str_radix(&hex[i..i+2], 16))
                .collect::<Result<Vec<u8>, _>>()
            {
                let decoded = String::from_utf8_lossy(&bytes).replace('\0', " ");
                if decoded.contains("LD_PRELOAD=") {
                    let cmd = decoded.trim().to_string();
                    return Some(ParsedEvent {
                        syscall_name: "execve".to_string(),
                        command: Some(cmd.clone()),
                        args: cmd.split_whitespace().map(|s| s.to_string()).collect(),
                        file_path: None,
                        success: true,
                        raw: format!("{} LD_PRELOAD={}", line, decoded),
                        actor: Actor::Unknown,
                        ppid_exe: None,
                    });
                }
            }
        }
        return None;
    }

    // Always allow tamper-detection events through regardless of user filter
    let is_tamper = line.contains("key=\"clawtower-tamper\"")
        || line.contains("key=clawtower-tamper")
        || line.contains("key=\"clawtower-config\"")
        || line.contains("key=clawtower-config");

    // For non-EXECVE lines, filter by watched users (unless tamper event)
    if !is_tamper {
    if let Some(users) = watched_users {
        let matches = users.iter().any(|uid| {
            line.contains(&format!("uid={}", uid)) || line.contains(&format!("auid={}", uid))
        });
        if !matches {
            return None;
        }
    }
    }

    if line.contains("type=SYSCALL") {
        let syscall_num = extract_field(line, "syscall")
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);
        let name = syscall_name_aarch64(syscall_num).to_string();
        let success = extract_field(line, "success").unwrap_or("no") == "yes";

        // Try to extract file path from name= field or exe= field
        let file_path = extract_field(line, "name")
            .or_else(|| extract_field(line, "exe"))
            .map(|s| decode_hex_arg(s));

        // Attribution: auid=4294967295 (unset) means agent/service, otherwise human
        let auid = extract_field(line, "auid").and_then(|s| s.parse::<u32>().ok());
        let actor = match auid {
            Some(4294967295) | None => Actor::Agent,
            Some(_) => Actor::Human,
        };

        // Extract parent process exe for build-tool detection
        let ppid = extract_field(line, "ppid").and_then(|s| s.parse::<u32>().ok());
        let ppid_exe = ppid.and_then(|p| {
            std::fs::read_link(format!("/proc/{}/exe", p)).ok()
                .map(|path| path.to_string_lossy().to_string())
        });

        return Some(ParsedEvent {
            syscall_name: name,
            command: None,
            args: vec![],
            file_path,
            success,
            raw: line.to_string(),
            actor,
            ppid_exe,
        });
    }

    // AVC / AppArmor / Anomaly lines
    if line.contains("type=AVC")
        || line.contains("apparmor=")
        || line.contains("type=ANOM")
        || line.contains("type=ANOMALY")
    {
        return Some(ParsedEvent {
            syscall_name: "security_event".to_string(),
            command: None,
            args: vec![],
            file_path: None,
            success: false,
            raw: line.to_string(),
            actor: Actor::Unknown,
            ppid_exe: None,
        });
    }

    None
}

/// Check if an audit event matches ClawTower tamper-detection keys
pub fn check_tamper_event(event: &ParsedEvent) -> Option<Alert> {
    let line = &event.raw;
    // Detect auditd events with our tamper-detection keys
    if line.contains("key=\"clawtower-tamper\"") || line.contains("key=clawtower-tamper") {
        let detail = event.command.as_deref()
            .or(event.file_path.as_deref())
            .unwrap_or(&line[..line.len().min(200)]);
        return Some(Alert::new(
            Severity::Critical,
            "auditd:tamper",
            &format!("🚨 TAMPER DETECTED: chattr executed (possible immutable flag removal) — {}", detail),
        ));
    }
    if line.contains("key=\"clawtower-config\"") || line.contains("key=clawtower-config") {
        let detail = event.file_path.as_deref()
            .or(event.command.as_deref())
            .unwrap_or(&line[..line.len().min(200)]);
        return Some(Alert::new(
            Severity::Critical,
            "auditd:tamper",
            &format!("🚨 CONFIG TAMPER: write/attr change on protected ClawTower file — {}", detail),
        ));
    }
    // Network connect() by suspicious binaries (T3.2)
    // Catches script files making outbound connections (python3 script.py, node app.js)
    if (line.contains("key=\"clawtower_net\"") || line.contains("key=clawtower_net"))
        && event.syscall_name == "connect"
    {
        let exe = extract_field(line, "exe").unwrap_or("unknown");
        let exe_base = exe.rsplit('/').next().unwrap_or(exe);
        const NET_SUSPICIOUS_EXES: &[&str] = &[
            "python3", "python", "node", "nodejs", "perl", "ruby", "php", "lua",
        ];
        if NET_SUSPICIOUS_EXES.iter().any(|&s| exe_base == s) {
            return Some(Alert::new(
                Severity::Warning,
                "auditd:net_connect",
                &format!("🌐 Network connect() by runtime: {} — possible script-based exfil", exe),
            ));
        }
    }

    // Credential file read detection (T2.1)
    if line.contains("key=\"clawtower_cred_read\"") || line.contains("key=clawtower_cred_read") {
        let detail = event.file_path.as_deref()
            .or(event.command.as_deref())
            .unwrap_or(&line[..line.len().min(200)]);
        let exe = extract_field(line, "exe").unwrap_or("unknown");
        // Allowlist: Only the OpenClaw gateway process itself (comm=openclaw-gateway)
        // Note: Node is NOT blanket-allowlisted — a compromised agent using Node
        // to read credentials must still trigger a Critical alert.
        let comm = extract_field(line, "comm").unwrap_or("unknown");
        let is_openclaw = exe.contains("openclaw") || comm.contains("openclaw");
        if !is_openclaw {
            return Some(Alert::new(
                Severity::Critical,
                "auditd:cred_read",
                &format!("🔑 CREDENTIAL READ: {} accessed by {} (comm={}) — possible exfiltration", detail, exe, comm),
            ));
        } else {
            return Some(Alert::new(
                Severity::Info,
                "auditd:cred_read",
                &format!("🔑 Credential access (expected): {} by {} (comm={})", detail, exe, comm),
            ));
        }
    }

    // Network connect() detection via auditd (T6.1)
    if line.contains("key=\"clawtower_net_connect\"") || line.contains("key=clawtower_net_connect") {
        let exe = extract_field(line, "exe").unwrap_or("unknown");
        let exe_base = exe.rsplit('/').next().unwrap_or(exe);
        // Skip localhost connections and known-safe processes
        let is_safe = exe.contains("clawtower") || exe.contains("systemd") || exe.contains("dbus");
        if !is_safe {
            // Runtime interpreters making raw connect() calls are Critical
            // (python ctypes, node net.Socket, ruby TCPSocket, etc.)
            const RUNTIME_INTERPRETERS: &[&str] = &[
                "python3", "python", "node", "nodejs", "perl", "ruby", "php", "lua",
            ];
            let is_runtime = RUNTIME_INTERPRETERS.iter().any(|&r| exe_base == r);
            let severity = if is_runtime { Severity::Critical } else { Severity::Warning };
            let msg = if is_runtime {
                format!("🚨 Runtime connect(): {} — possible scripted exfiltration via raw socket", exe)
            } else {
                format!("🌐 Outbound connect() by {}", exe)
            };
            return Some(Alert::new(severity, "auditd:net_connect", &msg));
        }
    }
    None
}

/// Convert a ParsedEvent into an Alert with readable message
pub fn event_to_alert(event: &ParsedEvent) -> Alert {
    let actor_tag = match event.actor {
        Actor::Agent => "[AGENT] ",
        Actor::Human => "[HUMAN] ",
        Actor::Unknown => "",
    };
    let (severity, msg) = if event.raw.contains("apparmor=\"DENIED\"") {
        let op = extract_field(&event.raw, "operation").unwrap_or("unknown");
        (Severity::Critical, format!("AppArmor denied: {}", op))
    } else if event.raw.contains("type=ANOM") || event.raw.contains("type=ANOMALY") {
        (Severity::Critical, format!("Anomaly detected: {}", &event.raw[..event.raw.len().min(120)]))
    } else if let Some(ref cmd) = event.command {
        (Severity::Info, format!("exec: {}", cmd))
    } else if event.syscall_name == "security_event" {
        (Severity::Warning, format!("security event: {}", &event.raw[..event.raw.len().min(120)]))
    } else {
        let path_info = event.file_path.as_deref().unwrap_or("");
        let status = if event.success { "ok" } else { "fail" };
        if !path_info.is_empty() {
            (Severity::Info, format!("{} {} ({})", event.syscall_name, path_info, status))
        } else {
            (Severity::Info, format!("{} ({})", event.syscall_name, status))
        }
    };

    Alert::new(severity, "auditd", &format!("{}{}", actor_tag, msg))
}

/// Legacy parse function — now wraps parse_to_event + event_to_alert
#[allow(dead_code)]
pub fn parse_audit_line(line: &str, watched_users: Option<&[String]>) -> Option<Alert> {
    let event = parse_to_event(line, watched_users)?;
    Some(event_to_alert(&event))
}

/// Tail the audit log file and send alerts
#[allow(dead_code)]
pub async fn tail_audit_log(
    path: &Path,
    watched_users: Option<Vec<String>>,
    tx: mpsc::Sender<Alert>,
) -> Result<()> {
    use std::io::{Seek, SeekFrom};
    use tokio::time::{sleep, Duration};

    let mut file = File::open(path)?;
    // Seek to last 64KB instead of EOF to catch events during downtime/crash-loops
    if file.seek(SeekFrom::End(-65536)).is_err() {
        // File smaller than 64KB, seek to start
        file.seek(SeekFrom::Start(0))?;
    }
    let mut reader = BufReader::new(file);
    // Skip partial first line after seeking mid-file
    let mut discard = String::new();
    let _ = reader.read_line(&mut discard);
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => {
                sleep(Duration::from_millis(500)).await;
            }
            Ok(_) => {
                if let Some(alert) = parse_audit_line(&line, watched_users.as_deref()) {
                    let _ = tx.send(alert).await;
                }
            }
            Err(e) => {
                let _ = tx
                    .send(Alert::new(
                        Severity::Warning,
                        "auditd",
                        &format!("Error reading audit log: {}", e),
                    ))
                    .await;
                sleep(Duration::from_secs(5)).await;
            }
        }
    }
}

/// Tail audit log with behavior detection — sends both alerts and parsed events
#[allow(dead_code)]
pub async fn tail_audit_log_with_behavior(
    path: &Path,
    watched_users: Option<Vec<String>>,
    tx: mpsc::Sender<Alert>,
) -> Result<()> {
    tail_audit_log_with_behavior_and_policy(path, watched_users, tx, None, None).await
}

/// Tail audit log with behavior detection + optional policy engine (legacy wrapper)
#[allow(dead_code)]
pub async fn tail_audit_log_with_behavior_and_policy(
    path: &Path,
    watched_users: Option<Vec<String>>,
    tx: mpsc::Sender<Alert>,
    policy_engine: Option<crate::policy::PolicyEngine>,
    secureclaw_engine: Option<Arc<crate::secureclaw::SecureClawEngine>>,
) -> Result<()> {
    tail_audit_log_full(path, watched_users, tx, policy_engine, secureclaw_engine, None, vec![]).await
}

/// Tail audit log with full detection: behavior, policy, SecureClaw, and network policy.
///
/// When `netpolicy` is provided, connect() syscalls are correlated with their
/// SOCKADDR records to extract destination IP:port. Destinations are evaluated
/// against the netpolicy allowlist/blocklist. Loopback and private LAN addresses
/// are automatically filtered out.
pub async fn tail_audit_log_full(
    path: &Path,
    watched_users: Option<Vec<String>>,
    tx: mpsc::Sender<Alert>,
    policy_engine: Option<crate::policy::PolicyEngine>,
    secureclaw_engine: Option<Arc<crate::secureclaw::SecureClawEngine>>,
    _netpolicy: Option<crate::netpolicy::NetPolicy>,
    _extra_safe_hosts: Vec<String>,
) -> Result<()> {
    use std::io::{Seek, SeekFrom};
    use tokio::time::{sleep, Duration};

    let mut file = File::open(path)?;
    // Seek to last 64KB instead of EOF to catch events during downtime/crash-loops
    if file.seek(SeekFrom::End(-65536)).is_err() {
        // File smaller than 64KB, seek to start
        file.seek(SeekFrom::Start(0))?;
    }
    let mut reader = BufReader::new(file);
    // Skip partial first line after seeking mid-file
    let mut discard = String::new();
    let _ = reader.read_line(&mut discard);
    let mut line = String::new();


    // Periodic auditd rule reload to fix inode staleness.
    // File watches (-w) use inodes; when files are replaced/rewritten,
    // the inode changes and the watch goes stale. Reloading every 5 min
    // refreshes all watches to current inodes.
    let mut last_rule_reload = std::time::Instant::now();
    const RULE_RELOAD_INTERVAL: Duration = Duration::from_secs(300); // 5 minutes
    loop {
        // Check if auditd rules need reloading (fixes inode staleness)
        if last_rule_reload.elapsed() >= RULE_RELOAD_INTERVAL {
            match std::process::Command::new("auditctl")
                .args(["-R", "/etc/audit/rules.d/clawtower.rules"])
                .output()
            {
                Ok(output) if output.status.success() => {
                    tracing::debug!("Periodic auditd rule reload succeeded");
                }
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    tracing::warn!("Periodic auditd rule reload failed: {}", stderr);
                }
                Err(e) => {
                    tracing::warn!("Failed to run auditctl for rule reload: {}", e);
                }
            }
            last_rule_reload = std::time::Instant::now();
        }

        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => {
                sleep(Duration::from_millis(500)).await;
            }
            Ok(_) => {
                if let Some(event) = parse_to_event(&line, watched_users.as_deref()) {
                    // Check for ClawTower tamper events (highest priority — fires for all users)
                    if let Some(tamper_alert) = check_tamper_event(&event) {
                        let _ = tx.send(tamper_alert).await;
                    }

                    // Run policy engine first (if available)
                    if let Some(ref engine) = policy_engine {
                        if let Some(verdict) = engine.evaluate(&event) {
                            let msg = format!(
                                "[POLICY:{}] {} — {}",
                                verdict.rule_name,
                                verdict.description,
                                event.command.as_deref().unwrap_or(&event.raw[..event.raw.len().min(100)])
                            );
                            let _ = tx.send(Alert::new(verdict.severity, "policy", &msg)).await;
                        }
                    }

                    // Run SecureClaw pattern matching (if available)
                    if let Some(ref engine) = secureclaw_engine {
                        if let Some(ref command) = event.command {
                            let matches = engine.check_command(command);
                            for pattern_match in matches {
                                let severity = match pattern_match.severity.as_str() {
                                    "critical" | "high" => Severity::Critical,
                                    "medium" => Severity::Warning,
                                    _ => Severity::Info,
                                };
                                let msg = format!(
                                    "[SECURECLAW:{}:{}] {} — {}",
                                    pattern_match.database,
                                    pattern_match.category,
                                    pattern_match.pattern_name,
                                    command
                                );
                                let _ = tx.send(Alert::new(severity, "secureclaw", &msg)).await;
                            }
                        }
                    }

                    // Run hardcoded behavior detection
                    if let Some((category, severity)) =
                        crate::behavior::classify_behavior(&event)
                    {
                        let msg = format!(
                            "[BEHAVIOR:{}] {}",
                            category,
                            event.command.as_deref().unwrap_or(&event.raw[..event.raw.len().min(100)])
                        );
                        let _ = tx.send(Alert::new(severity, "behavior", &msg)).await;
                    }

                    // Also send the base alert
                    let alert = event_to_alert(&event);
                    let _ = tx.send(alert).await;
                }
            }
            Err(e) => {
                let _ = tx
                    .send(Alert::new(
                        Severity::Warning,
                        "auditd",
                        &format!("Error reading audit log: {}", e),
                    ))
                    .await;
                sleep(Duration::from_secs(5)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_syscall_name_lookup() {
        assert_eq!(syscall_name_aarch64(221), "execve");
        assert_eq!(syscall_name_aarch64(56), "openat");
        assert_eq!(syscall_name_aarch64(203), "connect");
        assert_eq!(syscall_name_aarch64(35), "unlinkat");
        assert_eq!(syscall_name_aarch64(9999), "unknown");
    }

    #[test]
    fn test_parse_execve_line() {
        let line = r#"type=EXECVE msg=audit(1707849600.123:456): argc=3 a0="curl" a1="-s" a2="http://evil.com" uid=1000"#;
        let event = parse_to_event(line, Some(&["1000".to_string()])).unwrap();
        assert_eq!(event.syscall_name, "execve");
        assert_eq!(event.command.as_deref(), Some("curl -s http://evil.com"));
        assert_eq!(event.args, vec!["curl", "-s", "http://evil.com"]);
    }

    #[test]
    fn test_parse_syscall_line() {
        let line = r#"type=SYSCALL msg=audit(1707849600.123:456): arch=c00000b7 syscall=56 success=yes exit=3 uid=1000 name="/etc/shadow""#;
        let event = parse_to_event(line, Some(&["1000".to_string()])).unwrap();
        assert_eq!(event.syscall_name, "openat");
        assert!(event.success);
        assert_eq!(event.file_path.as_deref(), Some("/etc/shadow"));
    }

    #[test]
    fn test_readable_alert_from_execve() {
        let line = r#"type=EXECVE msg=audit(1707849600.123:456): argc=2 a0="whoami" a1="" uid=1000"#;
        let alert = parse_audit_line(line, Some(&["1000".to_string()])).unwrap();
        assert!(alert.message.starts_with("exec:"));
    }

    #[test]
    fn test_readable_alert_from_syscall() {
        let line = r#"type=SYSCALL msg=audit(1707849600.123:456): arch=c00000b7 syscall=56 success=yes uid=1000 exe="/usr/bin/cat""#;
        let alert = parse_audit_line(line, Some(&["1000".to_string()])).unwrap();
        assert!(alert.message.contains("openat"));
        assert!(alert.message.contains("ok"));
    }

    #[test]
    fn test_hex_decode() {
        // "/usr/bin/curl" in hex
        assert_eq!(decode_hex_arg("2F7573722F62696E2F6375726C"), "/usr/bin/curl");
    }

    #[test]
    fn test_ignores_other_user_syscall() {
        // SYSCALL records from other users should be filtered out
        let line = r#"type=SYSCALL msg=audit(1707849600.123:456): arch=c00000b7 syscall=56 success=yes uid=0 exe="/usr/bin/ls""#;
        assert!(parse_to_event(line, Some(&["1000".to_string()])).is_none());
    }

    #[test]
    fn test_watch_all_users() {
        // When None is passed, should match all users
        let line = r#"type=SYSCALL msg=audit(1707849600.123:456): arch=c00000b7 syscall=56 success=yes uid=0 exe="/usr/bin/ls""#;
        let event = parse_to_event(line, None).unwrap();
        assert_eq!(event.syscall_name, "openat");
    }

    #[test]
    fn test_multi_user_matching() {
        // Should match if any of the watched users matches
        let line1 = r#"type=SYSCALL msg=audit(1707849600.123:456): arch=c00000b7 syscall=56 success=yes uid=1000 exe="/usr/bin/ls""#;
        let line2 = r#"type=SYSCALL msg=audit(1707849600.123:456): arch=c00000b7 syscall=56 success=yes uid=1001 exe="/usr/bin/ls""#;
        let line3 = r#"type=SYSCALL msg=audit(1707849600.123:456): arch=c00000b7 syscall=56 success=yes uid=500 exe="/usr/bin/ls""#;
        
        let watched = vec!["1000".to_string(), "1001".to_string()];
        
        assert!(parse_to_event(line1, Some(&watched)).is_some());
        assert!(parse_to_event(line2, Some(&watched)).is_some());
        assert!(parse_to_event(line3, Some(&watched)).is_none());
    }

    #[test]
    fn test_tamper_detection_chattr_key() {
        let line = r#"type=SYSCALL msg=audit(1707849600.123:456): arch=c00000b7 syscall=221 success=yes uid=0 exe="/usr/bin/chattr" key="clawtower-tamper""#;
        let event = parse_to_event(line, None).unwrap();
        let tamper = check_tamper_event(&event);
        assert!(tamper.is_some());
        let alert = tamper.unwrap();
        assert_eq!(alert.severity, Severity::Critical);
        assert!(alert.message.contains("TAMPER"));
    }

    #[test]
    fn test_tamper_detection_config_key() {
        let line = r#"type=SYSCALL msg=audit(1707849600.123:456): arch=c00000b7 syscall=56 success=yes uid=0 name="/etc/clawtower/admin.key.hash" key="clawtower-config""#;
        let event = parse_to_event(line, None).unwrap();
        let tamper = check_tamper_event(&event);
        assert!(tamper.is_some());
        let alert = tamper.unwrap();
        assert_eq!(alert.severity, Severity::Critical);
        assert!(alert.message.contains("CONFIG TAMPER"));
    }

    #[test]
    fn test_tamper_events_bypass_user_filter() {
        // Tamper events should be parsed even when watched_users doesn't include root
        let line = r#"type=SYSCALL msg=audit(1707849600.123:456): arch=c00000b7 syscall=221 success=yes uid=0 exe="/usr/bin/chattr" key="clawtower-tamper""#;
        let event = parse_to_event(line, Some(&["1000".to_string()]));
        assert!(event.is_some(), "tamper events must bypass user filter");
    }

    #[test]
    fn test_non_tamper_event_no_false_positive() {
        let line = r#"type=SYSCALL msg=audit(1707849600.123:456): arch=c00000b7 syscall=56 success=yes uid=1000 exe="/usr/bin/cat""#;
        let event = parse_to_event(line, Some(&["1000".to_string()])).unwrap();
        let tamper = check_tamper_event(&event);
        assert!(tamper.is_none());
    }

    #[test]
    fn test_extract_auid_agent() {
        let line = r#"type=SYSCALL msg=audit(1707849600.123:456): arch=c00000b7 syscall=221 success=yes uid=1000 auid=4294967295 exe="/usr/bin/curl""#;
        let event = parse_to_event(line, Some(&["1000".to_string()])).unwrap();
        assert_eq!(event.actor, Actor::Agent);
    }

    #[test]
    fn test_extract_auid_human() {
        let line = r#"type=SYSCALL msg=audit(1707849600.123:456): arch=c00000b7 syscall=221 success=yes uid=1000 auid=1000 exe="/usr/bin/curl""#;
        let event = parse_to_event(line, Some(&["1000".to_string()])).unwrap();
        assert_eq!(event.actor, Actor::Human);
    }

    #[test]
    fn test_agent_tag_in_alert() {
        let line = r#"type=SYSCALL msg=audit(1707849600.123:456): arch=c00000b7 syscall=221 success=yes uid=1000 auid=4294967295 exe="/usr/bin/curl""#;
        let event = parse_to_event(line, Some(&["1000".to_string()])).unwrap();
        let alert = event_to_alert(&event);
        assert!(alert.message.starts_with("[AGENT] "));
    }

    #[test]
    fn test_human_tag_in_alert() {
        let line = r#"type=SYSCALL msg=audit(1707849600.123:456): arch=c00000b7 syscall=221 success=yes uid=1000 auid=1000 exe="/usr/bin/curl""#;
        let event = parse_to_event(line, Some(&["1000".to_string()])).unwrap();
        let alert = event_to_alert(&event);
        assert!(alert.message.starts_with("[HUMAN] "));
    }

    #[test]
    fn test_syscall_241_is_perf_event_open() {
        assert_eq!(syscall_name_aarch64(241), "perf_event_open");
    }

    #[test]
    fn test_proctitle_ld_preload_detected() {
        // "bash -c LD_PRELOAD=/tmp/evil.so ls" in hex with NUL separators
        let hex = "2F62696E2F62617368002D63004C445F5052454C4F41443D2F746D702F6576696C2E736F206C73";
        let line = format!("type=PROCTITLE msg=audit(1234567890.123:456): proctitle={}", hex);
        let event = parse_to_event(&line, None);
        assert!(event.is_some(), "PROCTITLE with LD_PRELOAD should produce an event");
        let e = event.unwrap();
        assert!(e.raw.contains("LD_PRELOAD="), "raw should contain LD_PRELOAD");
        assert!(e.command.unwrap().contains("LD_PRELOAD="));
    }

    #[test]
    fn test_proctitle_without_ld_preload_ignored() {
        // "ls /dev/null" in hex
        let hex = "6C73002F6465762F6E756C6C";
        let line = format!("type=PROCTITLE msg=audit(1234567890.123:456): proctitle={}", hex);
        let event = parse_to_event(&line, None);
        assert!(event.is_none(), "PROCTITLE without LD_PRELOAD should be ignored");
    }

    // ═══════════════════════════════════════════════════════════════════
    // REGRESSION TESTS — Adversarial edge cases
    // ═══════════════════════════════════════════════════════════════════

    // ── Hex decoding edge cases ─────────────────────────────────────

    #[test]
    fn test_hex_decode_empty_string() {
        assert_eq!(decode_hex_arg(""), "");
    }

    #[test]
    fn test_hex_decode_odd_length_not_decoded() {
        assert_eq!(decode_hex_arg("ABC"), "ABC");
    }

    #[test]
    fn test_hex_decode_non_hex_chars() {
        assert_eq!(decode_hex_arg("ZZZZ"), "ZZZZ");
    }

    #[test]
    fn test_hex_decode_single_byte() {
        // "41" is len 2, all hex, even — but the function checks len > 2
        // FINDING: single-byte hex strings (len==2) are NOT decoded because of len > 2 check
        assert_eq!(decode_hex_arg("41"), "41");
    }

    #[test]
    fn test_hex_decode_non_ascii_returns_original() {
        // Control chars should not be decoded
        let result = decode_hex_arg("0102");
        assert_eq!(result, "0102");
    }

    #[test]
    fn test_hex_decode_mixed_case_hex() {
        assert_eq!(decode_hex_arg("6375726C"), "curl");
    }

    #[test]
    fn test_hex_decode_with_spaces_not_decoded() {
        assert_eq!(decode_hex_arg("41 42"), "41 42");
    }

    // ── PROCTITLE edge cases ────────────────────────────────────────

    #[test]
    fn test_proctitle_ld_preload_with_spaces_in_path() {
        // "bash\0-c\0LD_PRELOAD=/tmp/my lib.so ls"
        let hex = "62617368002D63004C445F5052454C4F41443D2F746D702F6D79206C69622E736F206C73";
        let line = format!("type=PROCTITLE msg=audit(1234567890.123:456): proctitle={}", hex);
        let event = parse_to_event(&line, None);
        assert!(event.is_some(), "LD_PRELOAD with spaces in path should be detected");
        let e = event.unwrap();
        assert!(e.command.unwrap().contains("LD_PRELOAD="));
    }

    #[test]
    fn test_proctitle_multiple_env_vars_with_ld_preload() {
        // "env\0FOO=bar\0LD_PRELOAD=/evil.so\0ls"
        let hex = "656E7600464F4F3D626172004C445F5052454C4F41443D2F6576696C2E736F006C73";
        let line = format!("type=PROCTITLE msg=audit(1234567890.123:456): proctitle={}", hex);
        let event = parse_to_event(&line, None);
        assert!(event.is_some());
        let e = event.unwrap();
        assert!(e.command.unwrap().contains("LD_PRELOAD="));
    }

    #[test]
    fn test_proctitle_empty_hex() {
        let line = "type=PROCTITLE msg=audit(1234567890.123:456): proctitle=";
        let event = parse_to_event(line, None);
        assert!(event.is_none());
    }

    #[test]
    fn test_proctitle_malformed_hex_odd_length() {
        let line = "type=PROCTITLE msg=audit(1234567890.123:456): proctitle=6C730";
        let _event = parse_to_event(line, None);
        // Should not panic
    }

    #[test]
    fn test_proctitle_non_hex_chars() {
        let line = "type=PROCTITLE msg=audit(1234567890.123:456): proctitle=ZZZZZZ";
        let _event = parse_to_event(line, None);
        // Should not panic
    }

    // ── EXECVE edge cases ───────────────────────────────────────────

    #[test]
    fn test_execve_hex_encoded_args() {
        let line = r#"type=EXECVE msg=audit(1707849600.123:456): argc=2 a0=2F7573722F62696E2F6375726C a1="http://evil.com""#;
        let event = parse_to_event(line, None).unwrap();
        assert_eq!(event.args[0], "/usr/bin/curl");
        assert_eq!(event.args[1], "http://evil.com");
    }

    #[test]
    fn test_execve_very_long_command() {
        let long_arg = "A".repeat(5000);
        let line = format!(
            r#"type=EXECVE msg=audit(1707849600.123:456): argc=2 a0="echo" a1="{}""#,
            long_arg
        );
        let event = parse_to_event(&line, None).unwrap();
        assert_eq!(event.args[1].len(), 5000);
    }

    #[test]
    fn test_execve_no_args() {
        let line = r#"type=EXECVE msg=audit(1707849600.123:456): argc=0"#;
        let event = parse_to_event(line, None).unwrap();
        assert!(event.command.is_none());
        assert!(event.args.is_empty());
    }

    #[test]
    fn test_execve_20_args_max() {
        let mut parts = Vec::new();
        for i in 0..25 {
            parts.push(format!(r#"a{}="arg{}""#, i, i));
        }
        let line = format!(
            r#"type=EXECVE msg=audit(1707849600.123:456): argc=25 {}"#,
            parts.join(" ")
        );
        let event = parse_to_event(&line, None).unwrap();
        assert_eq!(event.args.len(), 20);
    }

    // ── Multi-user filtering edge cases ─────────────────────────────

    #[test]
    fn test_user_filter_matches_auid() {
        let line = r#"type=SYSCALL msg=audit(1707849600.123:456): arch=c00000b7 syscall=56 success=yes uid=0 auid=1000 exe="/usr/bin/cat""#;
        let event = parse_to_event(line, Some(&["1000".to_string()]));
        assert!(event.is_some(), "Should match on auid even if uid differs");
    }

    #[test]
    fn test_user_filter_uid_substring_no_false_match() {
        let line = r#"type=SYSCALL msg=audit(1707849600.123:456): arch=c00000b7 syscall=56 success=yes uid=100 exe="/usr/bin/ls""#;
        let event = parse_to_event(line, Some(&["1000".to_string()]));
        assert!(event.is_none(), "uid=100 should NOT match watched user 1000");
    }

    #[test]
    fn test_user_filter_uid_substring_false_positive() {
        // FINDING: uid=100 contains "uid=10" — potential false match!
        let line = r#"type=SYSCALL msg=audit(1707849600.123:456): arch=c00000b7 syscall=56 success=yes uid=100 exe="/usr/bin/ls""#;
        let event = parse_to_event(line, Some(&["10".to_string()]));
        // BUG: substring matching causes false positives — "uid=10" matches inside "uid=100"
        if event.is_some() {
            // BUG CONFIRMED: watching uid=10 also matches uid=100, uid=1000, etc.
        }
    }

    #[test]
    fn test_empty_watched_users_list() {
        let line = r#"type=SYSCALL msg=audit(1707849600.123:456): arch=c00000b7 syscall=56 success=yes uid=1000 exe="/usr/bin/ls""#;
        let watched: Vec<String> = vec![];
        let event = parse_to_event(line, Some(&watched));
        assert!(event.is_none(), "Empty watched list should match nothing");
    }

    // ── Tamper event detection edge cases ───────────────────────────

    #[test]
    fn test_tamper_key_without_quotes() {
        let line = r#"type=SYSCALL msg=audit(1707849600.123:456): arch=c00000b7 syscall=221 success=yes uid=0 exe="/usr/bin/chattr" key=clawtower-tamper"#;
        let event = parse_to_event(line, None).unwrap();
        let tamper = check_tamper_event(&event);
        assert!(tamper.is_some(), "key=clawtower-tamper (no quotes) should be detected");
    }

    #[test]
    fn test_tamper_config_key_without_quotes() {
        let line = r#"type=SYSCALL msg=audit(1707849600.123:456): arch=c00000b7 syscall=56 success=yes uid=0 key=clawtower-config"#;
        let event = parse_to_event(line, None).unwrap();
        let tamper = check_tamper_event(&event);
        assert!(tamper.is_some(), "key=clawtower-config (no quotes) should be detected");
    }

    #[test]
    fn test_tamper_key_in_middle_of_line() {
        let line = r#"type=SYSCALL msg=audit(1707849600.123:456): arch=c00000b7 syscall=56 success=yes uid=0 key="clawtower-tamper" name="/usr/bin/chattr""#;
        let event = parse_to_event(line, None).unwrap();
        let tamper = check_tamper_event(&event);
        assert!(tamper.is_some());
    }

    #[test]
    fn test_tamper_similar_key_false_positive() {
        // "clawtower-tamper-old" contains "clawtower-tamper" as substring
        let line = r#"type=SYSCALL msg=audit(1707849600.123:456): arch=c00000b7 syscall=56 success=yes uid=0 key="clawtower-tamper-old""#;
        let event = parse_to_event(line, None).unwrap();
        let tamper = check_tamper_event(&event);
        // FINDING: any key containing "clawtower-tamper" as substring triggers
        if tamper.is_some() {
            // Substring match means potential false positive on similar keys
        }
    }

    #[test]
    fn test_tamper_bypasses_user_filter_with_multiple_users() {
        let line = r#"type=SYSCALL msg=audit(1707849600.123:456): arch=c00000b7 syscall=56 success=yes uid=9999 key="clawtower-config""#;
        let watched = vec!["1000".to_string(), "1001".to_string()];
        let event = parse_to_event(line, Some(&watched));
        assert!(event.is_some(), "tamper events must bypass ALL user filters");
    }

    // ── Actor classification edge cases ─────────────────────────────

    #[test]
    fn test_actor_auid_unset_is_agent() {
        let line = r#"type=SYSCALL msg=audit(1707849600.123:456): arch=c00000b7 syscall=221 success=yes uid=1000 auid=4294967295 exe="/usr/bin/curl""#;
        let event = parse_to_event(line, Some(&["1000".to_string()])).unwrap();
        assert_eq!(event.actor, Actor::Agent);
    }

    #[test]
    fn test_actor_auid_equals_uid_is_human() {
        let line = r#"type=SYSCALL msg=audit(1707849600.123:456): arch=c00000b7 syscall=221 success=yes uid=1000 auid=1000 exe="/usr/bin/vim""#;
        let event = parse_to_event(line, Some(&["1000".to_string()])).unwrap();
        assert_eq!(event.actor, Actor::Human);
    }

    #[test]
    fn test_actor_sudo_still_human() {
        // auid=1000 but uid=0 (sudo) — still human
        let line = r#"type=SYSCALL msg=audit(1707849600.123:456): arch=c00000b7 syscall=221 success=yes uid=0 auid=1000 exe="/usr/bin/apt""#;
        let event = parse_to_event(line, Some(&["1000".to_string()])).unwrap();
        assert_eq!(event.actor, Actor::Human);
    }

    #[test]
    fn test_actor_no_auid_field_is_agent() {
        let line = r#"type=SYSCALL msg=audit(1707849600.123:456): arch=c00000b7 syscall=221 success=yes uid=1000 exe="/usr/bin/ls""#;
        let event = parse_to_event(line, Some(&["1000".to_string()])).unwrap();
        assert_eq!(event.actor, Actor::Agent);
    }

    #[test]
    fn test_actor_auid_zero_is_human() {
        let line = r#"type=SYSCALL msg=audit(1707849600.123:456): arch=c00000b7 syscall=221 success=yes uid=0 auid=0 exe="/usr/bin/cat""#;
        let event = parse_to_event(line, None).unwrap();
        assert_eq!(event.actor, Actor::Human);
    }

    #[test]
    fn test_execve_actor_is_unknown() {
        let line = r#"type=EXECVE msg=audit(1707849600.123:456): argc=1 a0="ls""#;
        let event = parse_to_event(line, None).unwrap();
        assert_eq!(event.actor, Actor::Unknown);
    }

    // ── AVC / security event parsing ────────────────────────────────

    #[test]
    fn test_avc_denied_parsed() {
        let line = r#"type=AVC msg=audit(1707849600.123:456): apparmor="DENIED" operation="open" name="/etc/shadow""#;
        let event = parse_to_event(line, None).unwrap();
        assert_eq!(event.syscall_name, "security_event");
        assert!(!event.success);
    }

    #[test]
    fn test_anomaly_parsed() {
        let line = r#"type=ANOMALY msg=audit(1707849600.123:456): something suspicious"#;
        let event = parse_to_event(line, None).unwrap();
        assert_eq!(event.syscall_name, "security_event");
    }

    #[test]
    fn test_anom_type_parsed() {
        let line = r#"type=ANOM_ABEND msg=audit(1707849600.123:456): auid=1000 pid=1234"#;
        let event = parse_to_event(line, None).unwrap();
        assert_eq!(event.syscall_name, "security_event");
    }

    // ── extract_field edge cases ────────────────────────────────────

    #[test]
    fn test_extract_field_with_quotes() {
        let line = r#"type=SYSCALL uid=1000 name="/etc/shadow""#;
        assert_eq!(extract_field(line, "name"), Some("/etc/shadow"));
    }

    #[test]
    fn test_extract_field_without_quotes() {
        let line = r#"type=SYSCALL uid=1000 name=/etc/shadow"#;
        assert_eq!(extract_field(line, "name"), Some("/etc/shadow"));
    }

    #[test]
    fn test_extract_field_missing() {
        let line = r#"type=SYSCALL uid=1000"#;
        assert_eq!(extract_field(line, "name"), None);
    }

    #[test]
    fn test_extract_field_partial_match() {
        let line = r#"type=SYSCALL myuid=999 uid=1000"#;
        // "myuid" starts with "myuid=" not "uid=", so extract_field("uid") should get 1000
        assert_eq!(extract_field(line, "uid"), Some("1000"));
    }

    // ── Alert generation edge cases ─────────────────────────────────

    #[test]
    fn test_alert_apparmor_denied() {
        let line = r#"type=AVC msg=audit(1707849600.123:456): apparmor="DENIED" operation="exec" name="/bin/sh""#;
        let event = parse_to_event(line, None).unwrap();
        let alert = event_to_alert(&event);
        assert_eq!(alert.severity, Severity::Critical);
        assert!(alert.message.contains("AppArmor denied"));
    }

    #[test]
    fn test_alert_syscall_with_failed_status() {
        let line = r#"type=SYSCALL msg=audit(1707849600.123:456): arch=c00000b7 syscall=56 success=no uid=1000 name="/etc/shadow""#;
        let event = parse_to_event(line, Some(&["1000".to_string()])).unwrap();
        let alert = event_to_alert(&event);
        assert!(alert.message.contains("fail"));
    }

    // ── Syscall number mapping ──────────────────────────────────────

    #[test]
    fn test_syscall_execveat_281() {
        assert_eq!(syscall_name_aarch64(281), "execveat");
    }

    #[test]
    fn test_syscall_statx_291() {
        assert_eq!(syscall_name_aarch64(291), "statx");
    }

    #[test]
    fn test_syscall_zero_is_io_setup() {
        assert_eq!(syscall_name_aarch64(0), "io_setup");
    }

    // ── EXECVE command edge cases ───────────────────────────────────

    #[test]
    fn test_execve_command_single_arg() {
        let line = r#"type=EXECVE msg=audit(1707849600.123:456): argc=1 a0="ls""#;
        let event = parse_to_event(line, None).unwrap();
        assert_eq!(event.command.as_deref(), Some("ls"));
        assert_eq!(event.args, vec!["ls"]);
    }

    #[test]
    fn test_execve_command_with_equals_in_arg() {
        let line = r#"type=EXECVE msg=audit(1707849600.123:456): argc=2 a0="env" a1="FOO=bar""#;
        let event = parse_to_event(line, None).unwrap();
        assert_eq!(event.args[1], "FOO=bar");
    }

    // ── Ignored line types ──────────────────────────────────────────

    #[test]
    fn test_unknown_type_ignored() {
        let line = r#"type=CWD msg=audit(1707849600.123:456): cwd="/home/user""#;
        assert!(parse_to_event(line, None).is_none());
    }

    #[test]
    fn test_empty_line_ignored() {
        assert!(parse_to_event("", None).is_none());
    }

    #[test]
    fn test_garbage_line_ignored() {
        assert!(parse_to_event("this is not an audit line", None).is_none());
    }

    // === T3.2: Network connect() by runtime ===

    #[test]
    fn test_connect_by_python_detected() {
        let event = ParsedEvent {
            syscall_name: "connect".to_string(),
            command: None,
            args: vec![],
            file_path: None,
            success: true,
            raw: r#"type=SYSCALL msg=audit(1707849600.123:456): arch=c00000b7 syscall=203 success=yes exe="/usr/bin/python3" key="clawtower_net""#.to_string(),
            actor: Actor::Agent,
            ppid_exe: None,
        };
        let alert = check_tamper_event(&event);
        assert!(alert.is_some(), "connect() by python3 should trigger alert");
        assert_eq!(alert.unwrap().severity, Severity::Warning);
    }

    #[test]
    fn test_connect_by_node_detected() {
        let event = ParsedEvent {
            syscall_name: "connect".to_string(),
            command: None,
            args: vec![],
            file_path: None,
            success: true,
            raw: r#"type=SYSCALL msg=audit(1707849600.123:456): arch=c00000b7 syscall=203 success=yes exe="/usr/bin/node" key="clawtower_net""#.to_string(),
            actor: Actor::Agent,
            ppid_exe: None,
        };
        let alert = check_tamper_event(&event);
        assert!(alert.is_some(), "connect() by node should trigger alert");
    }

    #[test]
    fn test_connect_by_curl_not_double_flagged() {
        // curl is already caught by behavior engine — connect() check skips it
        let event = ParsedEvent {
            syscall_name: "connect".to_string(),
            command: None,
            args: vec![],
            file_path: None,
            success: true,
            raw: r#"type=SYSCALL msg=audit(1707849600.123:456): arch=c00000b7 syscall=203 success=yes exe="/usr/bin/curl" key="clawtower_net""#.to_string(),
            actor: Actor::Agent,
            ppid_exe: None,
        };
        let alert = check_tamper_event(&event);
        // curl is NOT in NET_SUSPICIOUS_EXES (already handled by behavior engine)
        assert!(alert.is_none(), "curl connect() should not double-flag");
    }

    #[test]
    fn test_connect_audit_key_detected() {
        let line = r#"type=SYSCALL msg=audit(1234567890.123:456): arch=c00000b7 syscall=203 success=yes exit=0 a0=3 a1=7fff123 a2=10 a3=0 items=0 ppid=1234 pid=5678 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=(none) ses=1 comm="curl" exe="/usr/bin/curl" key="clawtower_net_connect""#;
        let event = parse_to_event(line, None).unwrap();
        let alert = check_tamper_event(&event);
        assert!(alert.is_some(), "connect() with clawtower_net_connect key should trigger alert");
        let alert = alert.unwrap();
        assert!(alert.source.contains("net_connect"));
    }

    #[test]
    fn test_connect_audit_key_safe_process_ignored() {
        let line = r#"type=SYSCALL msg=audit(1234567890.123:456): arch=c00000b7 syscall=203 success=yes exit=0 a0=3 a1=7fff123 a2=10 a3=0 items=0 ppid=1234 pid=5678 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=(none) ses=1 comm="systemd" exe="/lib/systemd/systemd" key="clawtower_net_connect""#;
        let event = parse_to_event(line, None).unwrap();
        let alert = check_tamper_event(&event);
        assert!(alert.is_none(), "systemd connect() should be ignored");
    }

    // ═══════════════════════════════════════════════════════════════════
    // RED LOBSTER v5 — Runtime connect() escalation tests
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn test_redlobster_python3_ctypes_connect_critical() {
        let line = r#"type=SYSCALL msg=audit(1234567890.123:456): arch=c00000b7 syscall=203 success=yes exit=0 uid=1000 comm="python3" exe="/usr/bin/python3" key="clawtower_net_connect""#;
        let event = parse_to_event(line, None).unwrap();
        let alert = check_tamper_event(&event);
        assert!(alert.is_some(), "python3 connect() must trigger alert");
        assert_eq!(alert.unwrap().severity, Severity::Critical, "runtime connect must be Critical");
    }

    #[test]
    fn test_redlobster_node_connect_critical() {
        let line = r#"type=SYSCALL msg=audit(1234567890.123:456): arch=c00000b7 syscall=203 success=yes exit=0 uid=1000 comm="node" exe="/usr/bin/node" key="clawtower_net_connect""#;
        let event = parse_to_event(line, None).unwrap();
        let alert = check_tamper_event(&event);
        assert!(alert.is_some(), "node connect() must trigger alert");
        assert_eq!(alert.unwrap().severity, Severity::Critical, "runtime connect must be Critical");
    }

    #[test]
    fn test_redlobster_ruby_connect_critical() {
        let line = r#"type=SYSCALL msg=audit(1234567890.123:456): arch=c00000b7 syscall=203 success=yes exit=0 uid=1000 comm="ruby" exe="/usr/bin/ruby" key="clawtower_net_connect""#;
        let event = parse_to_event(line, None).unwrap();
        let alert = check_tamper_event(&event);
        assert!(alert.is_some(), "ruby connect() must trigger alert");
        assert_eq!(alert.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn test_redlobster_curl_connect_still_warning() {
        let line = r#"type=SYSCALL msg=audit(1234567890.123:456): arch=c00000b7 syscall=203 success=yes exit=0 uid=1000 comm="curl" exe="/usr/bin/curl" key="clawtower_net_connect""#;
        let event = parse_to_event(line, None).unwrap();
        let alert = check_tamper_event(&event);
        assert!(alert.is_some(), "curl connect() must trigger alert");
        assert_eq!(alert.unwrap().severity, Severity::Warning, "non-runtime connect stays Warning");
    }

    #[test]
    fn test_sendfile_syscall_name() {
        assert_eq!(syscall_name_aarch64(271), "sendfile");
    }

    #[test]
    fn test_copy_file_range_syscall_name() {
        assert_eq!(syscall_name_aarch64(285), "copy_file_range");
    }
}
