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

/// Recommended auditd rules for ClawAV monitoring.
///
/// Install these via `auditctl` or drop into `/etc/audit/rules.d/clawav.rules`.
pub const RECOMMENDED_AUDIT_RULES: &[&str] = &[
    // Detect immutable-flag removal on protected files
    "-w /usr/bin/chattr -p x -k clawav-tamper",
    // Protect ClawAV config files
    "-w /etc/clawav/ -p wa -k clawav-config",
    // Monitor OpenClaw session log reads (prompt-injection / exfiltration vector)
    "-w /home/openclaw/.openclaw/agents/main/sessions/ -p r -k openclaw_session_read",
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
        281 => "execveat",
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

    // Always allow tamper-detection events through regardless of user filter
    let is_tamper = line.contains("key=\"clawav-tamper\"")
        || line.contains("key=clawav-tamper")
        || line.contains("key=\"clawav-config\"")
        || line.contains("key=clawav-config");

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

/// Check if an audit event matches ClawAV tamper-detection keys
pub fn check_tamper_event(event: &ParsedEvent) -> Option<Alert> {
    let line = &event.raw;
    // Detect auditd events with our tamper-detection keys
    if line.contains("key=\"clawav-tamper\"") || line.contains("key=clawav-tamper") {
        let detail = event.command.as_deref()
            .or(event.file_path.as_deref())
            .unwrap_or(&line[..line.len().min(200)]);
        return Some(Alert::new(
            Severity::Critical,
            "auditd:tamper",
            &format!("🚨 TAMPER DETECTED: chattr executed (possible immutable flag removal) — {}", detail),
        ));
    }
    if line.contains("key=\"clawav-config\"") || line.contains("key=clawav-config") {
        let detail = event.file_path.as_deref()
            .or(event.command.as_deref())
            .unwrap_or(&line[..line.len().min(200)]);
        return Some(Alert::new(
            Severity::Critical,
            "auditd:tamper",
            &format!("🚨 CONFIG TAMPER: write/attr change on protected ClawAV file — {}", detail),
        ));
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
    file.seek(SeekFrom::End(0))?;
    let mut reader = BufReader::new(file);
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

/// Tail audit log with behavior detection + optional policy engine
pub async fn tail_audit_log_with_behavior_and_policy(
    path: &Path,
    watched_users: Option<Vec<String>>,
    tx: mpsc::Sender<Alert>,
    policy_engine: Option<crate::policy::PolicyEngine>,
    secureclaw_engine: Option<Arc<crate::secureclaw::SecureClawEngine>>,
) -> Result<()> {
    use std::io::{Seek, SeekFrom};
    use tokio::time::{sleep, Duration};

    let mut file = File::open(path)?;
    file.seek(SeekFrom::End(0))?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => {
                sleep(Duration::from_millis(500)).await;
            }
            Ok(_) => {
                if let Some(event) = parse_to_event(&line, watched_users.as_deref()) {
                    // Check for ClawAV tamper events (highest priority — fires for all users)
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
        let line = r#"type=SYSCALL msg=audit(1707849600.123:456): arch=c00000b7 syscall=221 success=yes uid=0 exe="/usr/bin/chattr" key="clawav-tamper""#;
        let event = parse_to_event(line, None).unwrap();
        let tamper = check_tamper_event(&event);
        assert!(tamper.is_some());
        let alert = tamper.unwrap();
        assert_eq!(alert.severity, Severity::Critical);
        assert!(alert.message.contains("TAMPER"));
    }

    #[test]
    fn test_tamper_detection_config_key() {
        let line = r#"type=SYSCALL msg=audit(1707849600.123:456): arch=c00000b7 syscall=56 success=yes uid=0 name="/etc/clawav/admin.key.hash" key="clawav-config""#;
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
        let line = r#"type=SYSCALL msg=audit(1707849600.123:456): arch=c00000b7 syscall=221 success=yes uid=0 exe="/usr/bin/chattr" key="clawav-tamper""#;
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
}
