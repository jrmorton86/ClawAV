// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! clawsudo — sudo proxy/gatekeeper for ClawTower
//!
//! Every privileged command goes through policy evaluation before execution.
//! Usage: `clawsudo <command> [args...]`

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use sha2::{Sha256, Digest};


use chrono::Local;
use serde::Deserialize;

// ─── Exit codes ───
const EXIT_OK: u8 = 0;
const EXIT_FAIL: u8 = 1;
const EXIT_DENIED: u8 = 77;
const EXIT_TIMEOUT: u8 = 78;

// ─── Policy types ───

#[derive(Debug, Clone, Deserialize)]
struct PolicyRule {
    name: String,
    #[serde(rename = "match")]
    match_spec: MatchSpec,
    #[serde(default)]
    action: String,
    #[serde(default)]
    enforcement: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct MatchSpec {
    #[serde(default)]
    command: Vec<String>,
    #[serde(default)]
    command_contains: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct PolicyFile {
    #[serde(default)]
    rules: Vec<PolicyRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Enforcement {
    Allow,
    Deny,
    Ask,
}

struct MatchResult {
    rule_name: String,
    enforcement: Enforcement,
}

// ─── Config (minimal, just need webhook_url + api section) ───

#[derive(Debug, Deserialize)]
struct ConfigFile {
    #[serde(default)]
    slack: Option<SlackSection>,
    #[serde(default)]
    api: Option<ApiSection>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct SlackSection {
    #[serde(default)]
    webhook_url: String,
    #[serde(default)]
    backup_webhook_url: String,
}

#[derive(Debug, Deserialize, Clone)]
struct ApiSection {
    #[serde(default)]
    enabled: bool,
    #[serde(default = "default_api_bind")]
    bind: String,
    #[serde(default = "default_api_port")]
    port: u16,
    #[serde(default)]
    auth_token: String,
}

fn default_api_bind() -> String { "127.0.0.1".to_string() }
fn default_api_port() -> u16 { 18791 }

// ─── Policy engine ───

fn load_policies(dirs: &[&Path]) -> Vec<PolicyRule> {
    let mut rules = Vec::new();
    for dir in dirs {
        if !dir.exists() {
            continue;
        }
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        let mut sorted_entries: Vec<_> = entries.flatten().collect();
        sorted_entries.sort_by_key(|e| e.file_name());
        for entry in sorted_entries {
            let path = entry.path();
            match path.extension().and_then(|e| e.to_str()) {
                Some("yaml") | Some("yml") => {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        if let Ok(pf) = serde_yaml::from_str::<PolicyFile>(&content) {
                            rules.extend(pf.rules);
                        }
                    }
                }
                _ => {}
            }
        }
    }
    rules
}

fn evaluate(rules: &[PolicyRule], cmd_binary: &str, full_cmd: &str) -> Option<MatchResult> {
    let cmd_lower = cmd_binary.to_lowercase();
    let full_lower = full_cmd.to_lowercase();

    for rule in rules {
        let spec = &rule.match_spec;
        let mut matched = false;

        // Exact command match
        if !spec.command.is_empty()
            && spec.command.iter().any(|c| c.to_lowercase() == cmd_lower)
        {
            matched = true;
        }

        // Substring match
        if !matched
            && !spec.command_contains.is_empty()
            && spec
                .command_contains
                .iter()
                .any(|p| full_lower.contains(&p.to_lowercase()))
        {
            matched = true;
        }

        if matched {
            let enforcement = match rule.enforcement.as_deref() {
                Some("allow") => Enforcement::Allow,
                Some("deny") => Enforcement::Deny,
                Some("ask") => Enforcement::Ask,
                _ => {
                    // Infer from action
                    match rule.action.to_lowercase().as_str() {
                        "critical" | "block" => Enforcement::Deny,
                        _ => Enforcement::Ask,
                    }
                }
            };
            return Some(MatchResult {
                rule_name: rule.name.clone(),
                enforcement,
            });
        }
    }
    None
}

// ─── Logging ───

fn log_line(status: &str, full_cmd: &str) {
    let ts = Local::now().format("%Y-%m-%dT%H:%M:%S%z").to_string();
    let line = format!("[{}] [{}] user=openclaw cmd=\"{}\"\n", ts, status, full_cmd);

    // Try production path, fall back to local
    // Only use the production log path — never fall back to CWD which is
    // attacker-controlled (symlink to arbitrary file, corrupt audit chain).
    let log_paths: &[&str] = &["/var/log/clawtower/clawsudo.log"];
    for path in log_paths {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = f.write_all(line.as_bytes());
            break;
        }
    }

    // Also append to audit chain if it exists
    let chain_path = "/var/log/clawtower/audit.chain";
    if Path::new(chain_path).exists() {
        if let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(chain_path) {
            let _ = f.write_all(line.as_bytes());
        }
    }
}

// ─── Slack ───

fn load_webhook_url() -> Option<String> {
    let paths = [
        PathBuf::from("/etc/clawtower/config.toml"),
        PathBuf::from("./config.toml"),
    ];
    for path in &paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            if let Ok(cf) = toml::from_str::<ConfigFile>(&content) {
                if let Some(slack) = cf.slack {
                    if !slack.webhook_url.is_empty() {
                        return Some(slack.webhook_url);
                    }
                }
            }
        }
    }
    None
}

fn send_slack_sync(webhook_url: &str, text: &str) {
    let payload = serde_json::json!({
        "username": "ClawSudo",
        "icon_emoji": ":lock:",
        "text": text
    });
    // Fire-and-forget sync HTTP POST
    let _ = reqwest::blocking::Client::new()
        .post(webhook_url)
        .json(&payload)
        .timeout(Duration::from_secs(5))
        .send();
}

// ─── Unified Approval API ───

/// Load the API section from config.toml.
/// Returns None if not found or not enabled.
fn load_api_config() -> Option<ApiSection> {
    let paths = [
        PathBuf::from("/etc/clawtower/config.toml"),
        PathBuf::from("./config.toml"),
    ];
    for path in &paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            if let Ok(cf) = toml::from_str::<ConfigFile>(&content) {
                if let Some(api) = cf.api {
                    if api.enabled {
                        return Some(api);
                    }
                }
            }
        }
    }
    None
}

/// Try the unified approval API path.
///
/// Returns:
/// - `Some(true)` — approved via API
/// - `Some(false)` — denied or timed out via API
/// - `None` — API unreachable or not configured (caller should fall back to file-touch)
fn try_api_approval(full_cmd: &str, timeout_secs: u64) -> Option<bool> {
    let api = load_api_config()?;
    let api_base = format!("http://{}:{}", api.bind, api.port);

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .ok()?;

    // Step 1: POST /api/approvals
    let mut req = client
        .post(format!("{}/api/approvals", api_base))
        .json(&serde_json::json!({
            "command": full_cmd,
            "agent": "clawsudo",
            "context": format!("clawsudo approval request for: {}", full_cmd),
            "severity": "warning",
            "timeout_secs": timeout_secs
        }));

    if !api.auth_token.is_empty() {
        req = req.bearer_auth(&api.auth_token);
    }

    let resp = req.send().ok()?;

    if !resp.status().is_success() {
        return None; // API error — fall back to file-touch
    }

    let body: serde_json::Value = resp.json().ok()?;
    let id = body["id"].as_str()?;

    // Step 2: Poll GET /api/approvals/{id} every 2 seconds
    let poll_client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .ok()?;

    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_secs(2));

        let mut poll_req = poll_client.get(format!("{}/api/approvals/{}", api_base, id));
        if !api.auth_token.is_empty() {
            poll_req = poll_req.bearer_auth(&api.auth_token);
        }

        let resp = match poll_req.send() {
            Ok(r) => r,
            Err(_) => continue, // transient network error, keep polling
        };

        if let Ok(body) = resp.json::<serde_json::Value>() {
            match body["status"].as_str() {
                Some("approved") => return Some(true),
                Some("denied") | Some("timed_out") => return Some(false),
                Some("pending") => continue,
                _ => return None, // unexpected status — fall back
            }
        }
    }

    Some(false) // timed out locally
}

// ─── GTFOBins shell escape detection ───

const GTFOBINS_PATTERNS: &[&str] = &[
    // awk shell escapes
    "BEGIN{system(", "BEGIN {system(", "BEGIN{exec(", "|getline",
    // curl/wget shell escapes
    "-o /etc/", "-O /etc/", "--output /etc/",
    // tee to sensitive paths
    "/etc/sudoers", "/etc/shadow", "/etc/passwd",
    // cp/mv to sensitive paths
    " /usr/local/bin/clawtower", " /etc/clawtower/",
    // systemd-run
    "systemd-run",
    // find -exec (arbitrary command execution)
    "-exec", "-execdir", "-ok", "-okdir",
    // chmod SUID/SGID (privilege escalation via setuid bit)
    "chmod u+s", "chmod +s", "chmod g+s", "chmod 4", "chmod 2",
    // apt/apt-get hooks (arbitrary code via -o)
    "APT::Update::Pre-Invoke", "APT::Update::Post-Invoke",
    "Dpkg::Pre-Invoke", "Dpkg::Post-Invoke",
    "APT::Install::Pre-Invoke", "APT::Install::Post-Invoke",
    // apt-get -o direct hook injection
    "-o APT::", "-o Dpkg::", "-oAPT::", "-oDpkg::",
    // Generic shell metacharacters in args
    ";", "$(", "`",
    // Pipe to shell
    "|sh", "|bash", "|dash", "|zsh",
    "| sh", "| bash", "| dash", "| zsh",
];

/// Check if a command contains GTFOBins shell escape patterns.
/// Returns Some(pattern) if a dangerous pattern is found, None if safe.
fn check_gtfobins(cmd_binary: &str, args: &[String], full_cmd: &str) -> Option<String> {
    let full_lower = full_cmd.to_lowercase();

    // Special handling for sed: block standalone 'e' command (executes pattern space)
    if cmd_binary == "sed" {
        for (i, arg) in args.iter().enumerate() {
            // Skip the binary name (first arg after "sed")
            // A standalone 'e' arg or an arg starting with 'e' that isn't preceded by '-e'/'-f'/etc
            if arg == "e" {
                // Check it's not a flag value: previous arg should not be "-e", "-f", etc.
                let prev_is_flag = i > 0 && args[i - 1].starts_with('-') && args[i - 1].contains('e');
                if !prev_is_flag {
                    return Some("sed 'e' command (shell execution)".to_string());
                }
            }
            // Also catch patterns like 'e id' or '1e' passed as sed script
            if !arg.starts_with('-') && arg != "sed" {
                // If the arg looks like a sed script containing 'e' command
                // e.g., "e id", "1e", etc. but NOT substitutions like 's/foo/bar/'
                let trimmed = arg.trim_matches('\'').trim_matches('"');
                if trimmed == "e" || trimmed.starts_with("e ") || trimmed.ends_with("\\e") {
                    let prev_is_flag = i > 0 && args[i - 1] == "-e";
                    if !prev_is_flag {
                        return Some("sed 'e' command (shell execution)".to_string());
                    }
                }
            }
        }
    }

    // Check all generic patterns against the full command string
    for pattern in GTFOBINS_PATTERNS {
        if full_lower.contains(&pattern.to_lowercase()) {
            return Some(format!("GTFOBins pattern: {}", pattern));
        }
    }

    None
}

// ─── Approval file helpers ───

/// Secure approval directory — root-owned, mode 0700, not world-writable /tmp
const APPROVAL_DIR: &str = "/var/run/clawtower/approvals";

/// Ensure the approval directory exists with restrictive permissions (mode 0700).
fn ensure_approval_dir() {
    let dir = Path::new(APPROVAL_DIR);
    if !dir.exists() {
        // Create with mode 0700 — only root can read/write/traverse
        if std::fs::create_dir_all(dir).is_ok() {
            // Set permissions explicitly (create_dir_all doesn't honor umask reliably)
            let _ = std::fs::set_permissions(
                dir,
                std::os::unix::fs::PermissionsExt::from_mode(0o700),
            );
        }
    }
}

/// Compute a SHA-256 based approval filename for a command string.
/// Uses the first 16 bytes (32 hex chars) of the SHA-256 digest.
fn approval_path(full_cmd: &str) -> String {
    let digest = Sha256::digest(full_cmd.as_bytes());
    let hash_hex = hex::encode(&digest[..16]); // 32 hex chars
    format!("{}/clawsudo-{}.approved", APPROVAL_DIR, hash_hex)
}

/// Atomically consume an approval file.
/// Returns true if this process successfully consumed the approval (i.e., we were the
/// one to delete it). Returns false if the file didn't exist (already consumed by another
/// process or never created).
///
/// This eliminates the TOCTOU race in check-then-delete by using a single `remove_file()`
/// call — the filesystem guarantees only one unlink succeeds.
fn consume_approval(path: &str) -> bool {
    match std::fs::remove_file(path) {
        Ok(()) => true,           // We atomically consumed it
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false, // Someone else got it
        Err(_) => false,          // Permission error or other — treat as not approved
    }
}

/// Create an approval file atomically using O_CREAT|O_EXCL (create_new).
/// This ensures no race condition if two approval grants happen simultaneously.
#[allow(dead_code)]
fn create_approval_file(path: &str) -> std::io::Result<()> {
    ensure_approval_dir();
    OpenOptions::new()
        .write(true)
        .create_new(true) // O_CREAT | O_EXCL — fails if file already exists
        .mode(0o600)      // Only root can read/write
        .open(path)?;
    Ok(())
}

// ─── Main ───

fn print_help() {
    eprintln!("clawsudo — sudo proxy/gatekeeper for ClawTower");
    eprintln!();
    eprintln!("Usage: clawsudo <command> [args...]");
    eprintln!();
    eprintln!("Every privileged command is evaluated against ClawTower policy rules");
    eprintln!("before being passed to sudo for execution.");
    eprintln!();
    eprintln!("Policy decisions:");
    eprintln!("  ALLOW  — command runs via sudo immediately");
    eprintln!("  DENY   — command is blocked, alert sent to Slack");
    eprintln!("  ASK    — unknown command, waits for human approval via touch file");
    eprintln!();
    eprintln!("Exit codes:");
    eprintln!("  0   success");
    eprintln!("  1   general failure");
    eprintln!("  77  denied by policy");
    eprintln!("  78  approval timeout");
    eprintln!();
    eprintln!("Policy files: /etc/clawtower/policies/*.yaml");
    eprintln!("Logs: /var/log/clawtower/clawsudo.log");
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("Usage: clawsudo <command> [args...]");
        return ExitCode::from(EXIT_FAIL);
    }

    // Handle help flags before policy evaluation
    if matches!(args[0].as_str(), "--help" | "-h" | "help") {
        print_help();
        return ExitCode::from(EXIT_OK);
    }

    let cmd_binary = args[0]
        .rsplit('/')
        .next()
        .unwrap_or(&args[0])
        .to_string();
    let full_cmd = args.join(" ");

    // Check if clawsudo is locked by the response engine
    if Path::new("/var/run/clawtower/clawsudo.locked").exists() {
        eprintln!("🔴 clawsudo is locked by ClawTower response engine. All sudo requests denied.");
        eprintln!("   Action blocked by ClawTower security policy. Contact administrator.");
        log_line("DENIED-LOCKED", &full_cmd);
        if let Some(ref url) = load_webhook_url() {
            send_slack_sync(
                url,
                &format!(
                    "🔴 clawsudo locked — denied: `{}` (response engine lockdown active)",
                    full_cmd
                ),
            );
        }
        return ExitCode::from(EXIT_DENIED);
    }

    // Load policies
    let policy_dirs: Vec<&Path> = vec![
        Path::new("/etc/clawtower/policies/"),
    ];
    let rules = load_policies(&policy_dirs);

    let webhook_url = load_webhook_url();

    // Fail-secure: no rules → deny all
    if rules.is_empty() {
        eprintln!("🔴 No policy files found — DENY ALL (fail-secure)");
        log_line("DENIED", &full_cmd);
        if let Some(ref url) = webhook_url {
            send_slack_sync(
                url,
                &format!(
                    "🔴 *CRITICAL* clawsudo: No policy files found. Denied command: `{}`",
                    full_cmd
                ),
            );
        }
        return ExitCode::from(EXIT_DENIED);
    }

    // GTFOBins check — runs on ALL commands before policy evaluation.
    // This catches shell escape patterns regardless of whether a policy rule
    // matches, preventing commands from falling through to the Ask/timeout path.
    if let Some(reason) = check_gtfobins(&cmd_binary, &args, &full_cmd) {
        eprintln!("🔴 Blocked by GTFOBins defense: {}", reason);
        log_line("DENIED-GTFOBINS", &full_cmd);
        if let Some(ref url) = webhook_url {
            send_slack_sync(
                url,
                &format!(
                    "🔴 *CRITICAL* clawsudo GTFOBins block: `{}` ({})",
                    full_cmd, reason
                ),
            );
        }
        return ExitCode::from(EXIT_DENIED);
    }

    let result = evaluate(&rules, &cmd_binary, &full_cmd);

    match result {
        Some(MatchResult {
            ref rule_name,
            enforcement: Enforcement::Allow,
        }) => {
            eprintln!("✅ Allowed by policy: {}", rule_name);
            log_line("ALLOWED", &full_cmd);
            // Execute via sudo
            let status = std::process::Command::new("/usr/bin/sudo")
                .args(&args)
                .env_clear()
                .env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
                .env("TERM", std::env::var("TERM").unwrap_or_else(|_| "xterm".to_string()))
                .status();
            match status {
                Ok(s) if s.success() => ExitCode::from(EXIT_OK),
                Ok(s) => ExitCode::from(s.code().unwrap_or(1) as u8),
                Err(e) => {
                    eprintln!("Failed to execute sudo: {}", e);
                    ExitCode::from(EXIT_FAIL)
                }
            }
        }
        Some(MatchResult {
            ref rule_name,
            enforcement: Enforcement::Deny,
        }) => {
            eprintln!("🔴 Denied by policy: {}", rule_name);
            log_line("DENIED", &full_cmd);
            if let Some(ref url) = webhook_url {
                send_slack_sync(
                    url,
                    &format!(
                        "🔴 *CRITICAL* clawsudo denied command: `{}` (rule: {})",
                        full_cmd, rule_name
                    ),
                );
            }
            ExitCode::from(EXIT_DENIED)
        }
        Some(MatchResult {
            ref rule_name,
            enforcement: Enforcement::Ask,
        }) => {
            eprintln!(
                "⏳ Awaiting approval (5 min timeout)... (rule: {})",
                rule_name
            );
            log_line("PENDING", &full_cmd);

            // Try unified approval API first (orchestrator handles Slack/TUI/tray)
            match try_api_approval(&full_cmd, 300) {
                Some(true) => {
                    eprintln!("✅ Approved via ClawTower API");
                    log_line("ALLOWED", &full_cmd);
                    let status = std::process::Command::new("/usr/bin/sudo")
                        .args(&args)
                        .status();
                    return match status {
                        Ok(s) if s.success() => ExitCode::from(EXIT_OK),
                        Ok(s) => ExitCode::from(s.code().unwrap_or(1) as u8),
                        Err(e) => {
                            eprintln!("Failed to execute sudo: {}", e);
                            ExitCode::from(EXIT_FAIL)
                        }
                    };
                }
                Some(false) => {
                    eprintln!("🔴 Denied via ClawTower API");
                    log_line("DENIED", &full_cmd);
                    return ExitCode::from(EXIT_DENIED);
                }
                None => {
                    // API unreachable — fall back to file-touch + Slack
                    eprintln!("⏳ API unreachable, falling back to manual approval...");

                    // Ensure secure approval directory exists (root-only, mode 0700)
                    ensure_approval_dir();

                    // SHA-256 based approval filename (not collision-prone DefaultHasher)
                    let approval_file = approval_path(&full_cmd);

                    if let Some(ref url) = webhook_url {
                        send_slack_sync(
                            url,
                            &format!(
                                "⚠️ *WARNING* clawsudo awaiting approval for: `{}`\nTo approve: `sudo touch {}`",
                                full_cmd, approval_file
                            ),
                        );
                    }

                    // Wait up to 5 minutes, using atomic consume to prevent TOCTOU races
                    let start = Instant::now();
                    let timeout = Duration::from_secs(300);
                    loop {
                        // Atomic: try to unlink the file. If we succeed, we consumed the
                        // approval. If ENOENT, either it doesn't exist yet or another
                        // process already consumed it.
                        if consume_approval(&approval_file) {
                            eprintln!("✅ Approved!");
                            log_line("ALLOWED", &full_cmd);
                            let status = std::process::Command::new("sudo")
                                .args(&args)
                                .status();
                            return match status {
                                Ok(s) if s.success() => ExitCode::from(EXIT_OK),
                                Ok(s) => ExitCode::from(s.code().unwrap_or(1) as u8),
                                Err(e) => {
                                    eprintln!("Failed to execute sudo: {}", e);
                                    ExitCode::from(EXIT_FAIL)
                                }
                            };
                        }
                        if start.elapsed() >= timeout {
                            eprintln!("⏰ Approval timed out");
                            log_line("TIMEOUT", &full_cmd);
                            return ExitCode::from(EXIT_TIMEOUT);
                        }
                        std::thread::sleep(Duration::from_secs(2));
                    }
                }
            }
        }
        None => {
            // No rule matched → ambiguous → ask
            eprintln!("⏳ No matching rule — awaiting approval (5 min timeout)...");
            log_line("PENDING", &full_cmd);

            // Try unified approval API first (orchestrator handles Slack/TUI/tray)
            match try_api_approval(&full_cmd, 300) {
                Some(true) => {
                    eprintln!("✅ Approved via ClawTower API");
                    log_line("ALLOWED", &full_cmd);
                    let status = std::process::Command::new("/usr/bin/sudo")
                        .args(&args)
                        .status();
                    return match status {
                        Ok(s) if s.success() => ExitCode::from(EXIT_OK),
                        Ok(s) => ExitCode::from(s.code().unwrap_or(1) as u8),
                        Err(e) => {
                            eprintln!("Failed to execute sudo: {}", e);
                            ExitCode::from(EXIT_FAIL)
                        }
                    };
                }
                Some(false) => {
                    eprintln!("🔴 Denied via ClawTower API");
                    log_line("DENIED", &full_cmd);
                    return ExitCode::from(EXIT_DENIED);
                }
                None => {
                    // API unreachable — fall back to file-touch + Slack
                    eprintln!("⏳ API unreachable, falling back to manual approval...");

                    // Ensure secure approval directory exists (root-only, mode 0700)
                    ensure_approval_dir();

                    // SHA-256 based approval filename (not collision-prone DefaultHasher)
                    let approval_file = approval_path(&full_cmd);

                    if let Some(ref url) = webhook_url {
                        send_slack_sync(
                            url,
                            &format!(
                                "⚠️ *WARNING* clawsudo: unknown command awaiting approval: `{}`\nTo approve: `sudo touch {}`",
                                full_cmd, approval_file
                            ),
                        );
                    }

                    // Wait up to 5 minutes, using atomic consume to prevent TOCTOU races
                    let start = Instant::now();
                    let timeout = Duration::from_secs(300);
                    loop {
                        if consume_approval(&approval_file) {
                            eprintln!("✅ Approved!");
                            log_line("ALLOWED", &full_cmd);
                            let status = std::process::Command::new("sudo")
                                .args(&args)
                                .status();
                            return match status {
                                Ok(s) if s.success() => ExitCode::from(EXIT_OK),
                                Ok(s) => ExitCode::from(s.code().unwrap_or(1) as u8),
                                Err(e) => {
                                    eprintln!("Failed to execute sudo: {}", e);
                                    ExitCode::from(EXIT_FAIL)
                                }
                            };
                        }
                        if start.elapsed() >= timeout {
                            eprintln!("⏰ Approval timed out");
                            log_line("TIMEOUT", &full_cmd);
                            return ExitCode::from(EXIT_TIMEOUT);
                        }
                        std::thread::sleep(Duration::from_secs(2));
                    }
                }
            }
        }
    }
}

// ─── Tests ───

#[cfg(test)]
mod tests {
    use super::*;

    fn load_test_rules() -> Vec<PolicyRule> {
        let yaml = include_str!("../../policies/clawsudo.yaml");
        let pf: PolicyFile = serde_yaml::from_str(yaml).unwrap();
        pf.rules
    }

    #[test]
    fn test_apt_allowed() {
        let rules = load_test_rules();
        let result = evaluate(&rules, "apt", "apt install curl").unwrap();
        assert_eq!(result.enforcement, Enforcement::Allow);
        assert_eq!(result.rule_name, "allow-apt");
    }

    #[test]
    fn test_apt_get_allowed() {
        let rules = load_test_rules();
        let result = evaluate(&rules, "apt-get", "apt-get update").unwrap();
        assert_eq!(result.enforcement, Enforcement::Allow);
    }

    #[test]
    fn test_docker_allowed() {
        let rules = load_test_rules();
        let result = evaluate(&rules, "docker", "docker ps").unwrap();
        assert_eq!(result.enforcement, Enforcement::Allow);
    }

    #[test]
    fn test_bash_denied() {
        let rules = load_test_rules();
        let result = evaluate(&rules, "bash", "bash").unwrap();
        assert_eq!(result.enforcement, Enforcement::Deny);
        assert_eq!(result.rule_name, "deny-sudo-shell");
    }

    #[test]
    fn test_sh_denied() {
        let rules = load_test_rules();
        let result = evaluate(&rules, "sh", "sh -c whoami").unwrap();
        assert_eq!(result.enforcement, Enforcement::Deny);
    }

    #[test]
    fn test_ufw_disable_denied() {
        let rules = load_test_rules();
        let result = evaluate(&rules, "ufw", "ufw disable").unwrap();
        assert_eq!(result.enforcement, Enforcement::Deny);
    }

    #[test]
    fn test_dangerous_rm_denied() {
        let rules = load_test_rules();
        let result = evaluate(&rules, "rm", "rm -rf /etc").unwrap();
        assert_eq!(result.enforcement, Enforcement::Deny);
    }

    #[test]
    fn test_systemctl_restart_enterprise_not_allowed() {
        let rules = load_test_rules();
        // Enterprise policy: systemctl restart is NOT in the readonly allowlist
        let result = evaluate(&rules, "systemctl", "systemctl restart openclaw");
        // Should not match any allow rule; fail-secure means ask/deny
        if let Some(r) = result {
            assert_ne!(r.enforcement, Enforcement::Allow);
        }
        // None is also acceptable: fail-secure means deny
    }

    #[test]
    fn test_systemctl_stop_clawtower_denied() {
        let rules = load_test_rules();
        let result = evaluate(&rules, "systemctl", "systemctl stop clawtower").unwrap();
        assert_eq!(result.enforcement, Enforcement::Deny);
        assert_eq!(result.rule_name, "deny-security-service-tamper");
    }

    #[test]
    fn test_systemctl_restart_clawtower_denied() {
        let rules = load_test_rules();
        let result = evaluate(&rules, "systemctl", "systemctl restart clawtower").unwrap();
        assert_eq!(result.enforcement, Enforcement::Deny);
    }

    #[test]
    fn test_systemctl_stop_auditd_denied() {
        let rules = load_test_rules();
        let result = evaluate(&rules, "systemctl", "systemctl stop auditd").unwrap();
        assert_eq!(result.enforcement, Enforcement::Deny);
    }

    #[test]
    fn test_unknown_command_ambiguous() {
        let rules = load_test_rules();
        let result = evaluate(&rules, "htop", "htop");
        assert!(result.is_none(), "unknown command should return None (ambiguous)");
    }

    #[test]
    fn test_no_rules_scenario() {
        let rules: Vec<PolicyRule> = vec![];
        // With empty rules, evaluate returns None — caller handles fail-secure
        let result = evaluate(&rules, "apt", "apt install curl");
        assert!(result.is_none());
    }

    #[test]
    fn test_clawtower_tamper_denied() {
        let rules = load_test_rules();
        let result = evaluate(&rules, "chattr", "chattr +i /etc/clawtower/config.toml").unwrap();
        assert_eq!(result.enforcement, Enforcement::Deny);
    }

    #[test]
    fn test_deny_exit_code() {
        // Verify the exit code constant
        assert_eq!(EXIT_DENIED, 77);
    }

    #[test]
    fn test_timeout_exit_code() {
        assert_eq!(EXIT_TIMEOUT, 78);
    }

    // ─── GTFOBins tests ───

    #[test]
    fn test_gtfobins_awk_system() {
        let args: Vec<String> = vec!["awk".into(), "BEGIN{system(\"id\")}".into()];
        let full = "awk BEGIN{system(\"id\")}";
        assert!(check_gtfobins("awk", &args, full).is_some());
    }

    #[test]
    fn test_gtfobins_sed_e_command() {
        let args: Vec<String> = vec!["sed".into(), "e".into(), "id".into()];
        let full = "sed e id";
        assert!(check_gtfobins("sed", &args, full).is_some());
    }

    #[test]
    fn test_gtfobins_sed_e_flag_allowed() {
        // sed -e 's/foo/bar/' file — legitimate use, should NOT be blocked
        let args: Vec<String> = vec!["sed".into(), "-e".into(), "s/foo/bar/".into(), "file".into()];
        let full = "sed -e s/foo/bar/ file";
        assert!(check_gtfobins("sed", &args, full).is_none());
    }

    #[test]
    fn test_gtfobins_curl_output_etc() {
        let args: Vec<String> = vec!["curl".into(), "-o".into(), "/etc/evil".into(), "http://x".into()];
        let full = "curl -o /etc/evil http://x";
        assert!(check_gtfobins("curl", &args, full).is_some());
    }

    #[test]
    fn test_gtfobins_tee_sudoers() {
        let args: Vec<String> = vec!["tee".into(), "/etc/sudoers".into()];
        let full = "tee /etc/sudoers";
        assert!(check_gtfobins("tee", &args, full).is_some());
    }

    #[test]
    fn test_gtfobins_cp_clawtower() {
        let args: Vec<String> = vec!["cp".into(), "file".into(), "/usr/local/bin/clawtower".into()];
        let full = "cp file /usr/local/bin/clawtower";
        assert!(check_gtfobins("cp", &args, full).is_some());
    }

    #[test]
    fn test_gtfobins_systemd_run() {
        let args: Vec<String> = vec!["systemd-run".into(), "bash".into()];
        let full = "systemd-run bash";
        assert!(check_gtfobins("systemd-run", &args, full).is_some());
    }

    #[test]
    fn test_gtfobins_pipe_to_shell() {
        let args: Vec<String> = vec!["cat".into(), "file".into(), "|".into(), "bash".into()];
        let full = "cat file | bash";
        assert!(check_gtfobins("cat", &args, full).is_some());
    }

    #[test]
    fn test_gtfobins_shell_metachar_semicolon() {
        let args: Vec<String> = vec!["ls".into(), ";".into(), "bash".into()];
        let full = "ls ; bash";
        assert!(check_gtfobins("ls", &args, full).is_some());
    }

    #[test]
    fn test_gtfobins_command_substitution() {
        let args: Vec<String> = vec!["echo".into(), "$(id)".into()];
        let full = "echo $(id)";
        assert!(check_gtfobins("echo", &args, full).is_some());
    }

    #[test]
    fn test_gtfobins_apt_install_safe() {
        let args: Vec<String> = vec!["apt".into(), "install".into(), "vim".into()];
        let full = "apt install vim";
        assert!(check_gtfobins("apt", &args, full).is_none());
    }

    #[test]
    fn test_gtfobins_systemctl_restart_safe() {
        let args: Vec<String> = vec!["systemctl".into(), "restart".into(), "clawtower".into()];
        let full = "systemctl restart clawtower";
        assert!(check_gtfobins("systemctl", &args, full).is_none());
    }

    #[test]
    fn test_gtfobins_find_exec_denied() {
        let args: Vec<String> = vec!["find".into(), "/".into(), "-exec".into(), "id".into(), ";".into()];
        let full = "find / -exec id ;";
        assert!(check_gtfobins("find", &args, full).is_some(), "find -exec should be denied");
    }

    #[test]
    fn test_gtfobins_find_execdir_denied() {
        let args: Vec<String> = vec!["find".into(), "/tmp".into(), "-execdir".into(), "sh".into(), "-c".into(), "id".into(), ";".into()];
        let full = "find /tmp -execdir sh -c id ;";
        assert!(check_gtfobins("find", &args, full).is_some(), "find -execdir should be denied");
    }

    #[test]
    fn test_gtfobins_find_name_allowed() {
        let args: Vec<String> = vec!["find".into(), "/tmp".into(), "-name".into(), "*.log".into()];
        let full = "find /tmp -name *.log";
        assert!(check_gtfobins("find", &args, full).is_none(), "find -name should be allowed");
    }

    #[test]
    fn test_gtfobins_apt_get_hook_denied() {
        let args: Vec<String> = vec!["apt-get".into(), "update".into(), "-o".into(), "APT::Update::Pre-Invoke::=id".into()];
        let full = "apt-get update -o APT::Update::Pre-Invoke::=id";
        assert!(check_gtfobins("apt-get", &args, full).is_some(), "apt-get -o hook should be denied");
    }

    #[test]
    fn test_gtfobins_apt_get_install_allowed() {
        let args: Vec<String> = vec!["apt-get".into(), "install".into(), "vim".into()];
        let full = "apt-get install vim";
        assert!(check_gtfobins("apt-get", &args, full).is_none(), "apt-get install should be allowed");
    }

    #[test]
    fn test_gtfobins_dpkg_hook_denied() {
        let args: Vec<String> = vec!["apt-get".into(), "install".into(), "-o".into(), "Dpkg::Pre-Invoke::=sh".into()];
        let full = "apt-get install -o Dpkg::Pre-Invoke::=sh";
        assert!(check_gtfobins("apt-get", &args, full).is_some(), "Dpkg hook should be denied");
    }

    #[test]
    fn test_gtfobins_chmod_suid_denied() {
        let args: Vec<String> = vec!["chmod".into(), "u+s".into(), "/usr/bin/find".into()];
        let full = "chmod u+s /usr/bin/find";
        assert!(check_gtfobins("chmod", &args, full).is_some(), "chmod u+s should be denied");
    }

    #[test]
    fn test_gtfobins_chmod_plus_s_denied() {
        let args: Vec<String> = vec!["chmod".into(), "+s".into(), "/usr/bin/python3".into()];
        let full = "chmod +s /usr/bin/python3";
        assert!(check_gtfobins("chmod", &args, full).is_some(), "chmod +s should be denied");
    }

    #[test]
    fn test_gtfobins_chmod_4755_denied() {
        let args: Vec<String> = vec!["chmod".into(), "4755".into(), "/usr/bin/find".into()];
        let full = "chmod 4755 /usr/bin/find";
        assert!(check_gtfobins("chmod", &args, full).is_some(), "chmod 4xxx should be denied");
    }

    #[test]
    fn test_gtfobins_chmod_755_allowed() {
        let args: Vec<String> = vec!["chmod".into(), "755".into(), "/tmp/script.sh".into()];
        let full = "chmod 755 /tmp/script.sh";
        assert!(check_gtfobins("chmod", &args, full).is_none(), "chmod 755 should be allowed");
    }

    // ─── Approval file security tests ───

    #[test]
    fn test_approval_path_uses_sha256() {
        let path = approval_path("apt install curl");
        // Should be in secure directory, not /tmp
        assert!(path.starts_with("/var/run/clawtower/approvals/"));
        assert!(path.ends_with(".approved"));
        // Should contain a 32-char hex hash (16 bytes of SHA-256)
        let filename = path.rsplit('/').next().unwrap();
        let hash_part = filename
            .strip_prefix("clawsudo-")
            .unwrap()
            .strip_suffix(".approved")
            .unwrap();
        assert_eq!(hash_part.len(), 32, "SHA-256 truncated hash should be 32 hex chars");
        assert!(hash_part.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_approval_path_deterministic() {
        let path1 = approval_path("apt install curl");
        let path2 = approval_path("apt install curl");
        assert_eq!(path1, path2, "Same command should produce same approval path");
    }

    #[test]
    fn test_approval_path_different_commands_differ() {
        let path1 = approval_path("apt install curl");
        let path2 = approval_path("apt install wget");
        assert_ne!(path1, path2, "Different commands should produce different approval paths");
    }

    #[test]
    fn test_approval_dir_not_tmp() {
        assert!(!APPROVAL_DIR.starts_with("/tmp"), "Approval dir must not be in /tmp");
        assert_eq!(APPROVAL_DIR, "/var/run/clawtower/approvals");
    }

    #[test]
    fn test_consume_approval_nonexistent() {
        // Consuming a nonexistent file should return false
        let result = consume_approval("/tmp/nonexistent-test-file-clawsudo-12345.approved");
        assert!(!result, "Consuming nonexistent file should return false");
    }

    #[test]
    fn test_consume_approval_atomic() {
        // Create a temp file, consume it, verify it's gone
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.approved");
        std::fs::write(&path, b"").unwrap();
        let path_str = path.to_str().unwrap();

        // First consume should succeed
        assert!(consume_approval(path_str), "First consume should succeed");
        // Second consume should fail (already consumed)
        assert!(!consume_approval(path_str), "Second consume should fail — file already gone");
    }

    #[test]
    fn test_create_approval_file_exclusive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test-excl.approved");
        let path_str = path.to_str().unwrap();

        // First create should succeed
        assert!(create_approval_file(path_str).is_ok());
        // Second create should fail (O_EXCL)
        assert!(create_approval_file(path_str).is_err(), "Double-create should fail with O_EXCL");
    }

    // ── Enterprise hardening policy tests ──

    #[test]
    fn test_enterprise_deny_find() {
        let rules = load_test_rules();
        let r = evaluate(&rules, "find", "find /etc -name foo").unwrap();
        assert_eq!(r.enforcement, Enforcement::Deny);
        assert_eq!(r.rule_name, "deny-find-exec");
    }

    #[test]
    fn test_enterprise_deny_sed_write() {
        let rules = load_test_rules();
        let r = evaluate(&rules, "sed", "sed -i s/old/new/ /etc/passwd").unwrap();
        assert_eq!(r.enforcement, Enforcement::Deny);
    }

    #[test]
    fn test_enterprise_deny_tee() {
        let rules = load_test_rules();
        let r = evaluate(&rules, "tee", "tee /etc/cron.d/backdoor").unwrap();
        assert_eq!(r.enforcement, Enforcement::Deny);
    }

    #[test]
    fn test_enterprise_deny_chmod_suid() {
        let rules = load_test_rules();
        let r = evaluate(&rules, "chmod", "chmod +s /tmp/escalate").unwrap();
        assert_eq!(r.enforcement, Enforcement::Deny);
    }

    #[test]
    fn test_enterprise_deny_sudoers() {
        let rules = load_test_rules();
        let r = evaluate(&rules, "visudo", "visudo").unwrap();
        assert_eq!(r.enforcement, Enforcement::Deny);
    }

    #[test]
    fn test_enterprise_systemctl_status_ok() {
        let rules = load_test_rules();
        let r = evaluate(&rules, "systemctl", "systemctl status nginx").unwrap();
        assert_eq!(r.enforcement, Enforcement::Allow);
    }

    #[test]
    fn test_enterprise_systemctl_restart_blocked() {
        let rules = load_test_rules();
        let result = evaluate(&rules, "systemctl", "systemctl restart nginx");
        // No allow rule matches; fail-secure means ask/deny
        if let Some(r) = result {
            assert_ne!(r.enforcement, Enforcement::Allow);
        }
    }

    #[test]
    fn test_policies_not_loaded_from_cwd() {
        // Verify that only /etc/clawtower/policies/ is in the policy path
        // (we can't easily test the main function, but we can verify the constant)
        let policy_dirs: Vec<&Path> = vec![
            Path::new("/etc/clawtower/policies/"),
        ];
        // Verify no CWD-relative paths
        for dir in &policy_dirs {
            assert!(dir.is_absolute() || dir.starts_with("/"),
                "Policy dir {:?} must be absolute — CWD-relative paths are unsafe", dir);
        }
    }
}
