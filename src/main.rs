// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! ClawTower — Tamper-proof security watchdog for AI agents.
//!
//! This is the main entry point. It handles CLI argument parsing, privilege escalation
//! via `sudo`, and orchestrates the async runtime that spawns all monitoring subsystems:
//!
//! - **auditd**: Tails the Linux audit log for syscall-level events
//! - **behavior**: Classifies audit events against known attack patterns
//! - **policy**: Evaluates events against user-defined YAML policy rules
//! - **barnacle**: Matches commands against vendor threat pattern databases
//! - **network/journald**: Monitors iptables/firewall log entries
//! - **falco/samhain**: Integrates with external security tools
//! - **sentinel**: Real-time file integrity monitoring with quarantine/restore
//! - **cognitive**: Monitors AI identity files (SOUL.md, AGENTS.md, etc.)
//! - **scanner**: Periodic security posture scans (30+ checks)
//! - **firewall**: Detects UFW rule changes and disablement
//! - **logtamper**: Detects audit log truncation/replacement
//! - **proxy**: API key vault proxy with DLP scanning
//! - **aggregator**: Deduplicates and rate-limits alerts before delivery
//! - **api**: HTTP API for external integrations
//! - **slack**: Forwards high-severity alerts to Slack
//! - **tui**: Terminal dashboard with config editor
//! - **admin**: Unix socket for authenticated admin commands
//! - **audit_chain**: Hash-chained tamper-evident alert log
//! - **update**: Self-update from GitHub releases with Ed25519 verification
//!
//! The architecture is a channel pipeline:
//! Sources → raw_tx → Aggregator → alert_tx → TUI/headless + slack_tx → Slack

mod admin;
mod agent_profile;
mod alerts;
mod aggregator;
mod apparmor;
mod capabilities;
mod capability;
mod correlator;
mod detect;
mod export;
mod memory_sentinel;
mod process_cage;
mod api;
mod audit_chain;
mod auth_hooks;
mod auditd;
mod behavior;
mod cloud;
mod cognitive;
mod compliance;
mod config;
mod config_merge;
mod sentinel;
mod falco;
mod firewall;
mod identity;
mod journald;
mod logtamper;
mod netpolicy;
mod network;
mod openclaw_config;
mod policy;
mod proxy;
mod runtime;
mod safe_cmd;
mod safe_io;
mod safe_match;
mod safe_tail;
mod samhain;
mod scanner;
mod sources;
mod forensics;
mod seccomp;
mod barnacle;
mod slack;
mod tui;
mod response;
mod update;

#[cfg(test)]
mod integration_tests;
#[cfg(test)]
mod adversarial_tests;
#[cfg(test)]
mod benchmarks;

use anyhow::Result;
use config::Config;
use alerts::{Alert, Severity};
use aggregator::AggregatorConfig;
use response::{ResponseRequest, SharedPendingActions};
use slack::SlackNotifier;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::mpsc;

fn print_help() {
    eprintln!(r#"🛡️  ClawTower — Tamper-proof security watchdog for AI agents

USAGE:
    clawtower [COMMAND] [OPTIONS]

COMMANDS:
    run                  Start the watchdog with TUI dashboard (default)
    run --headless       Start in headless mode (no TUI, log to stderr)
    install [--force]    Bootstrap /etc/clawtower with default config + directories
    status               Show service status and recent alerts
    configure            Interactive configuration wizard
    update               Self-update to latest GitHub release
    scan                 Run a one-shot security scan and exit
    compliance-report    Generate a compliance report (SOC2/NIST/CIS)
    verify-key           Verify admin key from stdin (or --key flag)
    verify-audit [PATH]  Verify audit chain integrity
    setup                Install ClawTower as a system service
    setup --source       Build from source + install
    setup --auto         Install + start service automatically
    harden               Apply tamper-proof "swallowed key" hardening
    generate-key         Generate admin key (called by harden, idempotent)
    setup-apparmor       Install AppArmor profiles (or pam_cap fallback)
    uninstall            Reverse hardening + remove ClawTower (requires admin key)
    profile list         List available deployment profiles
    update-ioc           Update IOC bundles with signature verification
    sync                 Update Barnacle pattern databases
    logs                 Tail the service logs (journalctl)
    help                 Show this help message
    version              Show version info

EXAMPLES:
    clawtower                           Start TUI dashboard
    clawtower run --headless            Run as background daemon
    clawtower run --profile=production  Run with production profile
    clawtower configure                 Set up Slack, watched users, etc.
    clawtower scan                      Quick security scan
    sudo clawtower update               Self-update to latest release
    clawtower update --check            Check for updates without installing
    clawtower setup --source --auto     Full unattended install from source
    clawtower status                    Check if service is running

CONFIG:
    Default config path: /etc/clawtower/config.toml
    Override with:       clawtower run /path/to/config.toml
"#);
}

fn print_version() {
    eprintln!("ClawTower v{}", env!("CARGO_PKG_VERSION"));
    eprintln!("Tamper-proof security watchdog for AI agents");
    eprintln!("https://github.com/ClawTower/ClawTower");
}

/// Find the scripts directory relative to the binary or fallback locations
fn find_scripts_dir() -> Option<PathBuf> {
    // Check relative to binary location
    if let Ok(exe) = std::env::current_exe() {
        // Binary at /usr/local/bin/clawtower → scripts at source dir
        // Binary at target/release/clawtower → scripts at ../../scripts
        let parent = exe.parent()?;
        let candidate = parent.join("../../scripts");
        if candidate.join("configure.sh").exists() {
            return candidate.canonicalize().ok();
        }
    }
    // Check common locations
    let candidates = [
        PathBuf::from("/home/openclaw/.openclaw/workspace/projects/ClawTower/scripts"),
        PathBuf::from("/home/openclaw/.openclaw/workspace/openclawtower/scripts"),
        PathBuf::from("./scripts"),
        PathBuf::from("/opt/clawtower/scripts"),
    ];
    for c in &candidates {
        if c.join("configure.sh").exists() || c.join("uninstall.sh").exists() {
            return Some(c.clone());
        }
    }
    None
}

fn download_script(name: &str) -> Result<PathBuf> {
    let version = env!("CARGO_PKG_VERSION");
    let tag = format!("v{}", version);
    let url = format!(
        "https://raw.githubusercontent.com/ClawTower/ClawTower/{}/scripts/{}",
        tag, name
    );
    eprintln!("Downloading {} from GitHub ({})...", name, tag);
    let output = std::process::Command::new("curl")
        .args(["-sSL", "-f", "-o", &format!("/tmp/clawtower-{}", name), &url])
        .status()?;
    if !output.success() {
        // Fall back to main branch
        let url_main = format!(
            "https://raw.githubusercontent.com/ClawTower/ClawTower/main/scripts/{}",
            name
        );
        let output2 = std::process::Command::new("curl")
            .args(["-sSL", "-f", "-o", &format!("/tmp/clawtower-{}", name), &url_main])
            .status()?;
        if !output2.success() {
            anyhow::bail!("Failed to download script '{}' from GitHub", name);
        }
    }
    let path = PathBuf::from(format!("/tmp/clawtower-{}", name));
    Ok(path)
}

fn run_script(name: &str, extra_args: &[String]) -> Result<()> {
    let script = if let Some(scripts_dir) = find_scripts_dir() {
        let s = scripts_dir.join(name);
        if s.exists() { s } else { download_script(name)? }
    } else {
        download_script(name)?
    };
    if !script.exists() {
        anyhow::bail!("Script not found: {}", script.display());
    }
    let mut cmd = std::process::Command::new("bash");
    cmd.arg(&script);
    for arg in extra_args {
        cmd.arg(arg);
    }
    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("{} exited with code {}", name, status.code().unwrap_or(-1));
    }
    Ok(())
}

/// Strip the immutable flag (chattr +i) from a file or directory.
/// Three-level fallback:
///   1. Direct ioctl (bypasses AppArmor on /usr/bin/chattr)
///   2. External chattr command (works when AppArmor profiles aren't loaded)
///   3. systemd-run chattr (runs in PID 1's scope, bypasses dropped bounding set)
fn strip_immutable_flag(path: &str) {
    use std::os::unix::io::AsRawFd;

    if !Path::new(path).exists() {
        return;
    }

    // Try direct ioctl first
    if let Ok(file) = std::fs::File::open(path) {
        let fd = file.as_raw_fd();
        let mut flags: libc::c_long = 0;
        let ret = unsafe { libc::ioctl(fd, 0x80086601_u64, &mut flags as *mut libc::c_long) };
        if ret == 0 && (flags & 0x10) != 0 {
            flags &= !0x10;
            let ret = unsafe { libc::ioctl(fd, 0x40086602_u64, &flags as *const libc::c_long) };
            if ret == 0 {
                eprintln!("  chattr -i {} (ioctl)", path);
                return;
            }
        } else if ret == 0 {
            // File exists but doesn't have immutable flag — nothing to do
            return;
        }
        drop(file);
    }

    // Fallback: external chattr command
    if let Ok(o) = std::process::Command::new("chattr").args(["-i", path]).output() {
        if o.status.success() {
            eprintln!("  chattr -i {} (cmd)", path);
            return;
        }
    }

    // Final fallback: systemd-run runs in PID 1's scope, which has the full
    // capability bounding set (not affected by pam_cap session restrictions).
    if let Ok(o) = std::process::Command::new("systemd-run")
        .args(["--wait", "--collect", "--quiet", "chattr", "-i", path])
        .output()
    {
        if o.status.success() {
            eprintln!("  chattr -i {} (systemd-run)", path);
            return;
        }
        let stderr = String::from_utf8_lossy(&o.stderr);
        eprintln!("  chattr -i {}: all methods failed ({})", path, stderr.trim());
    }
}

/// Pre-harden cleanup: remove immutable flags and AppArmor profiles that
/// would otherwise block install.sh from modifying protected files.
fn pre_harden_cleanup() {
    eprintln!("[PRE-HARDEN] Stripping immutable flags...");

    // Capability check for diagnostics
    let cap_status = std::process::Command::new("cat")
        .arg("/proc/self/status")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();
    for line in cap_status.lines() {
        if line.starts_with("Cap") {
            eprintln!("  {}", line);
        }
    }

    // Directories first (must be writable before files inside can be created)
    let all_paths = [
        "/etc/clawtower",
        "/etc/clawtower/config.d",
        "/var/log/clawtower",
        "/usr/local/bin/clawtower",
        "/usr/local/bin/clawsudo",
        "/etc/clawtower/config.toml",
        "/etc/clawtower/admin.key.hash",
        "/etc/clawtower/preload-policy.json",
        "/etc/systemd/system/clawtower.service",
        "/etc/sudoers.d/010_openclaw",
        "/usr/local/lib/clawtower/libclawtower.so",
    ];
    for path in &all_paths {
        strip_immutable_flag(path);
    }
    // Unload AppArmor protection profiles (may fail if profiles can't parse — that's OK)
    let _ = std::process::Command::new("apparmor_parser")
        .args(["-R", "/etc/apparmor.d/etc.clawtower.protect"])
        .output();

    // Clean up stale pam_cap entry that drops CAP_LINUX_IMMUTABLE from all sessions.
    // Use systemd-run so sed can write even if the current session lacks capabilities.
    let pam_auth = "/etc/pam.d/common-auth";
    if let Ok(contents) = std::fs::read_to_string(pam_auth) {
        if contents.contains("pam_cap") {
            let cleaned: String = contents.lines()
                .filter(|line| !line.contains("pam_cap"))
                .collect::<Vec<_>>()
                .join("\n");
            if std::fs::write(pam_auth, format!("{}\n", cleaned)).is_ok() {
                eprintln!("[PRE-HARDEN] Removed stale pam_cap from {}", pam_auth);
            }
        }
    }
}

/// Bootstrap /etc/clawtower with default config and directory structure.
/// With --force, overwrites existing config and policies.
fn run_install(force: bool) -> Result<()> {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let conf_dir = Path::new("/etc/clawtower");
    let dirs = [
        conf_dir.to_path_buf(),
        conf_dir.join("policies"),
        conf_dir.join("barnacle"),
        conf_dir.join("sentinel-shadow"),
        conf_dir.join("quarantine"),
        PathBuf::from("/var/log/clawtower"),
        PathBuf::from("/var/run/clawtower"),
    ];

    eprintln!("🛡️  ClawTower Install{}", if force { " (--force)" } else { "" });
    eprintln!("====================\n");

    if force {
        // Remove immutable flags so we can overwrite
        let _ = std::process::Command::new("chattr")
            .args(["-i", "-R", conf_dir.to_str().unwrap_or_default()])
            .status();
    }

    // Create directories
    for dir in &dirs {
        if !dir.exists() {
            fs::create_dir_all(dir)?;
            eprintln!("  Created {}", dir.display());
        }
    }

    // Restrict sensitive dirs
    for dir_name in &["sentinel-shadow", "quarantine"] {
        let dir = conf_dir.join(dir_name);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }

    // Write default config (embedded at compile time from repo root)
    let config_path = conf_dir.join("config.toml");
    if force || !config_path.exists() {
        fs::write(&config_path, include_str!("../config.toml"))?;
        eprintln!("  Wrote default config to {}", config_path.display());
    } else {
        eprintln!("  Config already exists: {} (use --force to overwrite)", config_path.display());
    }

    // Write default policy
    let default_policy = conf_dir.join("policies/default.yaml");
    if force || !default_policy.exists() {
        // Check if we can find a default.yaml in the source tree
        if let Some(scripts_dir) = find_scripts_dir() {
            let source_policy = scripts_dir.parent()
                .map(|p| p.join("policies/default.yaml"));
            if let Some(ref sp) = source_policy {
                if sp.exists() {
                    fs::copy(sp, &default_policy)?;
                    eprintln!("  Copied default policy to {}", default_policy.display());
                }
            }
        }
    }

    eprintln!("\n✅ ClawTower installed. Next steps:");
    eprintln!("  1. Edit /etc/clawtower/config.toml (set watched_user, Slack webhook, etc.)");
    eprintln!("  2. Run: clawtower configure    (interactive wizard)");
    eprintln!("  3. Run: clawtower              (start the dashboard)");
    eprintln!("  4. Run: clawtower harden       (generates admin key + applies hardening)");

    Ok(())
}

/// Check privileges and re-exec via sudo BEFORE tokio starts.
/// This ensures the password prompt isn't clobbered by async tasks.
fn ensure_root() {
    let args: Vec<String> = std::env::args().collect();
    let subcommand = args.get(1).map(|s| s.as_str()).unwrap_or("run");

    // Skip for help/version which don't need privileges
    if unsafe { libc::getuid() } != 0
        && !matches!(subcommand, "help" | "--help" | "-h" | "version" | "--version" | "-V")
    {
        eprintln!("🛡️  ClawTower requires root privileges. Escalating via sudo...\n");
        let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("clawtower"));
        let status = std::process::Command::new("sudo")
            .arg("--")
            .arg(&exe)
            .args(&args[1..])
            .status();
        match status {
            Ok(s) => std::process::exit(s.code().unwrap_or(1)),
            Err(e) => {
                eprintln!("Failed to escalate privileges: {}", e);
                std::process::exit(1);
            }
        }
    }
}

fn main() -> Result<()> {
    // Auth FIRST, before any async runtime
    ensure_root();

    // Now start tokio and run the app
    tokio::runtime::Runtime::new()?.block_on(async_main())
}

async fn async_main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let subcommand = args.get(1).map(|s| s.as_str()).unwrap_or("run");
    let rest_args: Vec<String> = args.iter().skip(2).cloned().collect();

    match subcommand {
        "help" | "--help" | "-h" => {
            print_help();
            return Ok(());
        }
        "version" | "--version" | "-V" => {
            print_version();
            return Ok(());
        }
        "verify-key" => {
            // Read key from --key flag or stdin
            let key = if let Some(pos) = rest_args.iter().position(|a| a == "--key") {
                rest_args.get(pos + 1).cloned().unwrap_or_default()
            } else {
                // Read from stdin
                let mut key = String::new();
                std::io::Read::read_to_string(&mut std::io::stdin(), &mut key)
                    .unwrap_or_default();
                key.trim().to_string()
            };
            if key.is_empty() {
                eprintln!("No key provided");
                std::process::exit(1);
            }
            let hash_path = std::path::Path::new("/etc/clawtower/admin.key.hash");
            let hash = match std::fs::read_to_string(hash_path) {
                Ok(h) => h.trim().to_string(),
                Err(e) => {
                    eprintln!("Cannot read {}: {}", hash_path.display(), e);
                    std::process::exit(1);
                }
            };
            if admin::verify_key(&key, &hash) {
                std::process::exit(0);
            } else {
                std::process::exit(1);
            }
        }
        "verify-audit" => {
            let path = args.get(2).map(|s| s.as_str());
            return audit_chain::run_verify_audit(path);
        }
        "update" => {
            return update::run_update(&rest_args);
        }
        "install" => {
            let force = rest_args.iter().any(|a| a == "--force" || a == "-f");
            return run_install(force);
        }
        "configure" => {
            // Remove immutable flag so configure.sh can edit config (direct ioctl
            // bypasses AppArmor deny on /usr/bin/chattr)
            strip_immutable_flag("/etc/clawtower/config.toml");
            let result = run_script("configure.sh", &rest_args);
            // Re-lock config after configure — use chattr here since AppArmor
            // only blocks the deny direction, or fall back silently
            let _ = std::process::Command::new("chattr").args(["+i", "/etc/clawtower/config.toml"]).status();
            return result;
        }
        "setup" => {
            return run_script("setup.sh", &rest_args);
        }
        "harden" => {
            // Pre-cleanup: strip immutable flags and unload AppArmor profiles.
            // On a previously hardened system, AppArmor deny rules block even
            // root's /usr/bin/cp and /usr/bin/chattr from touching protected
            // paths. The clawtower binary itself is unconfined, so we do the
            // ioctl-based flag removal here before install.sh runs.
            pre_harden_cleanup();
            return run_script("install.sh", &rest_args);
        }
        "generate-key" => {
            let hash_path = std::path::Path::new("/etc/clawtower/admin.key.hash");
            match admin::generate_and_show_admin_key(hash_path) {
                Ok(_) => return Ok(()),
                Err(e) => {
                    eprintln!("Failed to generate admin key: {}", e);
                    std::process::exit(1);
                }
            }
        }
        "setup-apparmor" => {
            let quiet = rest_args.iter().any(|a| a == "--quiet" || a == "-q");
            let result = apparmor::setup(quiet);
            if !result.any_protection() {
                eprintln!("No AppArmor or pam_cap protection could be applied.");
                std::process::exit(1);
            }
            return Ok(());
        }
        "uninstall" => {
            // Same pre-cleanup as harden — strip immutable flags so uninstall.sh
            // can remove protected files even with AppArmor profiles active.
            pre_harden_cleanup();
            return run_script("uninstall.sh", &rest_args);
        }
        "update-ioc" => {
            return barnacle::run_update_ioc(&rest_args);
        }
        "sync" => {
            return run_script("sync-barnacle.sh", &rest_args);
        }
        "logs" => {
            let status = std::process::Command::new("journalctl")
                .args(["-u", "clawtower", "-f", "--no-pager"])
                .status()?;
            std::process::exit(status.code().unwrap_or(1));
        }
        "status" => {
            // Show service status
            let _ = std::process::Command::new("systemctl")
                .args(["status", "clawtower", "--no-pager"])
                .status();
            eprintln!();
            // Show recent alerts from API if available
            let api_result = std::process::Command::new("curl")
                .args(["-s", "http://localhost:18791/api/security"])
                .output();
            if let Ok(output) = api_result {
                let body = String::from_utf8_lossy(&output.stdout);
                if !body.is_empty() && body.contains("critical") {
                    eprintln!("Alert Summary (from API):");
                    eprintln!("{}", body);
                }
            }
            return Ok(());
        }
        "scan" => {
            // Run one-shot scan and print results
            let results = scanner::SecurityScanner::run_all_scans();
            eprintln!("🛡️  ClawTower Security Scan");
            eprintln!("========================");
            for r in &results {
                let icon = match r.status {
                    scanner::ScanStatus::Pass => "✅",
                    scanner::ScanStatus::Warn => "⚠️ ",
                    scanner::ScanStatus::Fail => "❌",
                };
                eprintln!("{} [{}] {}: {}", icon, r.status, r.category, r.details);
            }
            let pass_count = results.iter().filter(|r| r.status == scanner::ScanStatus::Pass).count();
            let total = results.len();
            eprintln!();
            eprintln!("Score: {}/{} checks passed", pass_count, total);
            return Ok(());
        }
        "profile" => {
            let sub = rest_args.first().map(|s| s.as_str()).unwrap_or("list");
            match sub {
                "list" => {
                    eprintln!("Available profiles:");
                    let dirs = [
                        PathBuf::from("/etc/clawtower/profiles"),
                        PathBuf::from("profiles"),
                    ];
                    let mut found = false;
                    for dir in &dirs {
                        if let Ok(entries) = std::fs::read_dir(dir) {
                            for entry in entries.flatten() {
                                let path = entry.path();
                                if path.extension().and_then(|e| e.to_str()) == Some("toml") {
                                    let name = path.file_stem()
                                        .and_then(|s| s.to_str())
                                        .unwrap_or("?");
                                    // Read first comment line as description
                                    let desc = std::fs::read_to_string(&path).ok()
                                        .and_then(|c| c.lines()
                                            .find(|l| l.starts_with("# ClawTower Profile:"))
                                            .map(|l| l.trim_start_matches("# ClawTower Profile:").trim().to_string()))
                                        .unwrap_or_default();
                                    eprintln!("  {:<25} {}", name, desc);
                                    found = true;
                                }
                            }
                        }
                    }
                    if !found {
                        eprintln!("  (no profiles found in /etc/clawtower/profiles/ or ./profiles/)");
                    }
                    eprintln!();
                    eprintln!("Usage: clawtower run --profile=<name>");
                }
                _ => {
                    eprintln!("Unknown profile subcommand: {}", sub);
                    eprintln!("Usage: clawtower profile list");
                }
            }
            return Ok(());
        }
        "compliance-report" => {
            let framework = rest_args.iter()
                .find_map(|a| a.strip_prefix("--framework="))
                .unwrap_or("soc2");
            let period = rest_args.iter()
                .find_map(|a| a.strip_prefix("--period="))
                .and_then(|p| p.trim_end_matches('d').parse::<u32>().ok())
                .unwrap_or(30);
            let output_format = rest_args.iter()
                .find_map(|a| a.strip_prefix("--format="))
                .unwrap_or("text");
            let output_path = rest_args.iter()
                .find_map(|a| a.strip_prefix("--output="));

            // Generate report (empty data = baseline report showing all controls)
            let report = compliance::generate_report(framework, period, &[], &[]);

            let output = match output_format {
                "json" => compliance::report_to_json(&report),
                _ => compliance::report_to_text(&report),
            };

            if let Some(path) = output_path {
                std::fs::write(path, &output)?;
                eprintln!("Report written to {}", path);
            } else {
                println!("{}", output);
            }
            return Ok(());
        }
        _ => {
            // Fall through to normal watchdog startup
        }
    }

    // ── Normal watchdog startup ──────────────────────────────────────────────
    // Parse remaining args for run mode
    let run_args: Vec<&String> = if subcommand == "run" {
        rest_args.iter().collect()
    } else {
        // Called as `clawtower /path/to/config.toml` or `clawtower --headless`
        args.iter().skip(1).collect()
    };

    let config_path = run_args.iter()
        .find(|a| !a.starts_with("--"))
        .map(|s| PathBuf::from(s.as_str()))
        .unwrap_or_else(|| PathBuf::from("/etc/clawtower/config.toml"));

    let headless = run_args.iter().any(|a| a.as_str() == "--headless")
        || unsafe { libc::isatty(0) == 0 };

    // Parse --profile=<name> flag
    let profile_name: Option<String> = run_args.iter().find_map(|a| {
        a.strip_prefix("--profile=").map(|s| s.to_string())
    });

    // If running in TUI mode, stop the background service to avoid port/socket conflicts
    if !headless {
        let service_was_running = std::process::Command::new("systemctl")
            .args(["is-active", "--quiet", "clawtower"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if service_was_running {
            eprintln!("Stopping clawtower service for TUI mode...");
            let _ = std::process::Command::new("sudo")
                .args(["systemctl", "stop", "clawtower"])
                .status();
            // Brief pause for sockets to release
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        // Re-start on exit via drop guard
        if service_was_running {
            // We'll restart in the cleanup section after TUI exits
            std::env::set_var("CLAWTOWER_RESTART_SERVICE", "1");
        }
    }

    let config_d = config_path.parent()
        .unwrap_or(Path::new("/etc/clawtower"))
        .join("config.d");

    // Resolve profile path: look in /etc/clawtower/profiles/ then ./profiles/
    let profile_path: Option<PathBuf> = profile_name.as_ref().map(|name| {
        let system_path = PathBuf::from(format!("/etc/clawtower/profiles/{}.toml", name));
        if system_path.exists() {
            system_path
        } else {
            PathBuf::from(format!("profiles/{}.toml", name))
        }
    });

    let config = Config::load_with_profile_and_overrides(
        &config_path,
        profile_path.as_deref(),
        &config_d,
    )?;
    if let Some(ref name) = profile_name {
        eprintln!("Config loaded with profile '{}' (overlays from {})", name, config_d.display());
    } else {
        eprintln!("Config loaded (with overlays from {})", config_d.display());
    }
    let notifier = SlackNotifier::new(&config.slack);
    let min_slack_level = Severity::from_str(&config.slack.min_slack_level);

    // Three-stage channel pipeline:
    // Sources → raw_tx/raw_rx → Aggregator → alert_tx/alert_rx → TUI
    //                                      → slack_tx/slack_rx → Slack
    let (raw_tx, raw_rx) = mpsc::channel::<Alert>(1000);
    let (alert_tx, alert_rx) = mpsc::channel::<Alert>(1000);
    let (slack_tx, mut slack_rx) = mpsc::channel::<Alert>(100);

    // Load policy engine
    let policy_engine = if config.policy.enabled {
        let policy_dir = std::path::Path::new(&config.policy.dir);
        let system_dir = std::path::Path::new("/etc/clawtower/policies");
        match policy::PolicyEngine::load_dirs(&[policy_dir, system_dir]) {
            Ok(engine) => {
                eprintln!("Policy engine loaded: {} rules", engine.rule_count());
                Some(engine)
            }
            Err(e) => {
                eprintln!("Policy engine load error: {} (continuing without)", e);
                None
            }
        }
    } else {
        None
    };

    // Load Barnacle engine
    let barnacle_engine = if config.barnacle.enabled {
        match barnacle::BarnacleEngine::load(&config.barnacle.vendor_dir) {
            Ok(engine) => {
                eprintln!("Barnacle loaded: {} injection, {} command, {} privacy, {} supply-chain patterns",
                    engine.injection_patterns.len(),
                    engine.dangerous_commands.len(),
                    engine.privacy_rules.len(),
                    engine.supply_chain_iocs.len());
                Some(Arc::new(engine))
            }
            Err(e) => {
                eprintln!("Barnacle load error: {} (continuing without)", e);
                None
            }
        }
    } else {
        None
    };

    // Spawn auditd tail with behavior detection + network policy
    if config.auditd.enabled {
        let tx = raw_tx.clone();
        let path = PathBuf::from(&config.auditd.log_path);
        let watched = config.general.effective_watched_users();
        let pe = policy_engine.clone();
        let se = barnacle_engine.clone();
        let np = if config.netpolicy.enabled {
            eprintln!("Network policy enabled (mode: {}, {} allowed hosts, {} blocked hosts)",
                config.netpolicy.mode,
                config.netpolicy.allowed_hosts.len(),
                config.netpolicy.blocked_hosts.len());
            Some(netpolicy::NetPolicy::from_config(&config.netpolicy))
        } else {
            None
        };
        // Check read access before spawning
        let extra_safe = config.behavior.safe_hosts.clone();
        let behavior_shadow_mode = config.behavior.detector_shadow_mode;
        if std::fs::metadata(&path).is_ok() {
            tokio::spawn(async move {
                if let Err(e) = auditd::tail_audit_log_full(&path, watched, tx, pe, se, np, extra_safe, behavior_shadow_mode).await {
                    eprintln!("auditd monitor error: {}", e);
                }
            });
        } else {
            eprintln!("auditd monitor: skipping (no read access to {} — run as root for full monitoring)", path.display());
        }
    }

    // Spawn network monitor (auto-detect journald vs file)
    if config.network.enabled {
        let tx = raw_tx.clone();
        let source = config.network.source.clone();
        let path = PathBuf::from(&config.network.log_path);
        let prefix = config.network.log_prefix.clone();

        tokio::spawn(async move {
            let use_journald = match source.as_str() {
                "journald" => true,
                "file" => false,
                _ => {
                    // Auto-detect: prefer journald, fall back to file
                    if journald::journald_available() {
                        true
                    } else {
                        path.exists()
                    }
                }
            };

            if use_journald {
                if let Err(e) = journald::tail_journald_network(&prefix, tx).await {
                    eprintln!("journald network monitor error: {}", e);
                }
            } else if let Err(e) = network::tail_network_log(&path, &prefix, tx).await {
                eprintln!("file network monitor error: {}", e);
            }
        });
    }

    // Spawn Falco log tail
    if config.falco.enabled {
        let tx = raw_tx.clone();
        let path = PathBuf::from(&config.falco.log_path);
        tokio::spawn(async move {
            if let Err(e) = falco::tail_falco_log(&path, tx).await {
                eprintln!("Falco monitor error: {}", e);
            }
        });
    }

    // Spawn Samhain log tail
    if config.samhain.enabled {
        let tx = raw_tx.clone();
        let path = PathBuf::from(&config.samhain.log_path);
        tokio::spawn(async move {
            if let Err(e) = samhain::tail_samhain_log(&path, tx).await {
                eprintln!("Samhain monitor error: {}", e);
            }
        });
    }

    // Spawn SSH login monitor
    if config.ssh.enabled {
        let tx = raw_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = journald::tail_journald_ssh(tx).await {
                eprintln!("SSH monitor error: {}", e);
            }
        });
    }

    // Spawn proxy server if enabled
    if config.proxy.enabled {
        let proxy_config = config.proxy.clone();
        let proxy_tx = raw_tx.clone();
        tokio::spawn(async move {
            let server = proxy::ProxyServer::new(proxy_config, proxy_tx);
            if let Err(e) = server.start().await {
                eprintln!("Proxy server error: {}", e);
            }
        });
    }

    // Send Slack startup message before moving notifier
    if let Err(e) = notifier.send_startup_message().await {
        eprintln!("Slack startup message failed: {}", e);
    }

    // Spawn periodic heartbeat if enabled
    let heartbeat_interval = config.slack.heartbeat_interval;
    if heartbeat_interval > 0 {
        let heartbeat_notifier = SlackNotifier::new(&config.slack);
        let start = std::time::Instant::now();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(heartbeat_interval));
            interval.tick().await; // skip first
            loop {
                interval.tick().await;
                let _ = heartbeat_notifier.send_heartbeat(start.elapsed().as_secs(), 0).await;
            }
        });
    }

    // Spawn Slack forwarder
    tokio::spawn(async move {
        while let Some(alert) = slack_rx.recv().await {
            if let Err(e) = notifier.send_alert(&alert).await {
                eprintln!("Slack send error: {}", e);
            }
        }
    });

    // Create shared alert store for API
    let alert_store = api::new_shared_store(1000);

    // Spawn aggregator (sits between raw sources and TUI/Slack)
    // Use tightened config if incident mode is active (config flag or runtime lockfile)
    let agg_config = if config.incident_mode.enabled
        || Path::new("/var/run/clawtower/incident-mode.active").exists()
    {
        eprintln!("INCIDENT MODE ACTIVE — tightened aggregation ({}s dedup, {} rate limit)",
            config.incident_mode.dedup_window_secs, config.incident_mode.rate_limit_per_source);
        AggregatorConfig {
            dedup_window: std::time::Duration::from_secs(config.incident_mode.dedup_window_secs),
            scan_dedup_window: std::time::Duration::from_secs(config.incident_mode.scan_dedup_window_secs),
            rate_limit_per_source: config.incident_mode.rate_limit_per_source,
            rate_limit_window: std::time::Duration::from_secs(60),
        }
    } else {
        AggregatorConfig::default()
    };
    let min_slack = min_slack_level;
    let agg_store = alert_store.clone();
    tokio::spawn(async move {
        aggregator::run_aggregator(raw_rx, alert_tx, slack_tx, agg_config, min_slack, agg_store).await;
    });

    // Create shared pending actions store (unconditionally, needed by API and TUI)
    let pending_store: SharedPendingActions = response::new_shared_pending();

    // Spawn response engine if enabled
    let response_tx: Option<mpsc::Sender<ResponseRequest>> = if config.response.enabled {
        let (resp_tx, resp_rx) = mpsc::channel::<ResponseRequest>(100);
        let resp_slack_tx = raw_tx.clone();
        let resp_config = config.response.clone();
        let playbook_dir = std::path::Path::new(&resp_config.playbook_dir);
        let playbooks = response::load_playbooks(playbook_dir);
        eprintln!("Response engine enabled: {} playbooks loaded, {}s timeout",
            playbooks.len(), resp_config.timeout_secs);

        let resp_pending = pending_store.clone();
        tokio::spawn(async move {
            response::run_response_engine(
                resp_rx,
                resp_slack_tx,
                resp_pending,
                resp_config,
                playbooks,
            ).await;
        });
        Some(resp_tx)
    } else {
        None
    };

    // Create shared scan results store (shared between scanner and API)
    let scan_store = scanner::new_shared_scan_results();

    // Spawn API server if enabled (after pending_store and response_tx are ready)
    if config.api.enabled {
        let audit_chain_path = if unsafe { libc::getuid() } == 0 {
            PathBuf::from("/var/log/clawtower/audit.chain")
        } else {
            PathBuf::from(format!("/tmp/clawtower-{}/audit.chain", unsafe { libc::getuid() }))
        };
        let ctx = std::sync::Arc::new(api::ApiContext {
            store: alert_store.clone(),
            start_time: std::time::Instant::now(),
            auth_token: config.api.auth_token.clone(),
            pending_store: pending_store.clone(),
            response_tx: response_tx.clone().map(std::sync::Arc::new),
            scan_results: Some(scan_store.clone()),
            audit_chain_path: Some(audit_chain_path),
            policy_dir: Some(PathBuf::from(&config.policy.dir)),
            barnacle_dir: Some(PathBuf::from(&config.barnacle.vendor_dir)),
            active_profile: profile_name.clone(),
        });
        let bind = config.api.bind.clone();
        let port = config.api.port;
        tokio::spawn(async move {
            if let Err(e) = api::run_api_server_with_context(&bind, port, ctx).await {
                eprintln!("API server error: {}", e);
            }
        });
    }

    // Tee aggregated alerts to response engine (warnings+ get forwarded)
    let alert_rx = if let Some(ref resp_tx) = response_tx {
        let (tee_tx, tee_rx) = mpsc::channel::<Alert>(1000);
        let resp_tx = resp_tx.clone();
        tokio::spawn(async move {
            let mut rx = alert_rx;
            while let Some(alert) = rx.recv().await {
                if alert.severity >= Severity::Warning {
                    let _ = resp_tx.send(ResponseRequest::EvaluateAlert(alert.clone())).await;
                }
                let _ = tee_tx.send(alert).await;
            }
        });
        tee_rx
    } else {
        alert_rx
    };

    // Spawn firewall state monitor
    {
        let tx = raw_tx.clone();
        tokio::spawn(async move {
            firewall::monitor_firewall(tx).await;
        });
    }

    // Spawn audit log tampering monitor
    if config.auditd.enabled {
        let log_path = PathBuf::from(&config.auditd.log_path);
        if std::fs::metadata(&log_path).is_ok() {
            let tx = raw_tx.clone();
            tokio::spawn(async move {
                crate::logtamper::monitor_log_integrity(log_path, tx, 30).await;
            });
        }
    }

    // Initialize admin key and spawn admin socket
    let admin_key_hash_path = PathBuf::from("/etc/clawtower/admin.key.hash");
    if let Err(e) = admin::init_admin_key(&admin_key_hash_path) {
        eprintln!("Admin key init: {} (non-fatal, admin socket will still start)", e);
    }
    // Use /var/run/clawtower/ if accessible, otherwise fall back to /tmp/
    let socket_dir = PathBuf::from("/var/run/clawtower");
    let socket_path = if socket_dir.exists() && std::fs::metadata(&socket_dir).map(|m| {
        use std::os::unix::fs::MetadataExt;
        m.uid() == unsafe { libc::getuid() } || unsafe { libc::getuid() } == 0
    }).unwrap_or(false) {
        socket_dir.join("admin.sock")
    } else {
        let fallback = PathBuf::from(format!("/tmp/clawtower-{}/admin.sock", unsafe { libc::getuid() }));
        if let Some(parent) = fallback.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        eprintln!("Admin socket: using fallback {}", fallback.display());
        fallback
    };
    let admin_socket = admin::AdminSocket::new(
        socket_path,
        admin_key_hash_path,
        raw_tx.clone(),
    );
    tokio::spawn(async move {
        if let Err(e) = admin_socket.run().await {
            eprintln!("Admin socket error: {}", e);
        }
    });

    // Spawn periodic security scanner (uses hoisted scan_store shared with API)
    {
        let tx = raw_tx.clone();
        let scan_store = scan_store.clone();
        let interval = config.scans.interval;
        let oc_cfg = config.openclaw.clone();
        tokio::spawn(async move {
            scanner::run_periodic_scans(interval, tx, scan_store, oc_cfg, config.scans.dedup_interval_secs).await;
        });
    }

    // Spawn fast-cycle persistence scanner (default 300s)
    {
        let tx = raw_tx.clone();
        let persist_interval = config.scans.persistence_interval;
        tokio::spawn(async move {
            scanner::run_persistence_scans(persist_interval, tx).await;
        });
    }

    // Spawn real-time file sentinel
    if config.sentinel.enabled {
        let sentinel_config = config.sentinel.clone();
        let sentinel_tx = raw_tx.clone();
        let barnacle_engine = crate::barnacle::BarnacleEngine::load(
            std::path::Path::new("/etc/clawtower/barnacle")
        ).ok().map(std::sync::Arc::new);
        
        tokio::spawn(async move {
            eprintln!("[sentinel] Starting sentinel with {} watch paths", sentinel_config.watch_paths.len());
            match crate::sentinel::Sentinel::new(sentinel_config, sentinel_tx, barnacle_engine) {
                Ok(sentinel) => {
                    eprintln!("[sentinel] Initialized OK, entering run loop");
                    if let Err(e) = sentinel.run().await {
                        eprintln!("[sentinel] Sentinel error: {}", e);
                    }
                }
                Err(e) => eprintln!("[sentinel] Failed to start sentinel: {}", e),
            }
        });
    }

    // Spawn auto-updater (checks for new GitHub releases)
    if config.auto_update.enabled {
        let update_tx = raw_tx.clone();
        let update_interval = config.auto_update.interval;
        let update_mode = config.auto_update.mode.clone();
        tokio::spawn(async move {
            crate::update::run_auto_updater(update_tx, update_interval, update_mode).await;
        });
    }

    // Send startup alert (through aggregator)
    let startup = Alert::new(Severity::Info, "system", "ClawTower watchdog started");
    let _ = raw_tx.send(startup).await;

    if headless {
        // Headless mode: just drain alerts and log them
        let mut alert_rx = alert_rx;
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        eprintln!("ClawTower running in headless mode (Ctrl+C or SIGTERM to stop)");
        loop {
            tokio::select! {
                Some(alert) = alert_rx.recv() => {
                    eprintln!("[{}] [{}] {}", alert.severity, alert.source, alert.message);
                }
                _ = tokio::signal::ctrl_c() => {
                    eprintln!("Shutting down (SIGINT)...");
                    break;
                }
                _ = sigterm.recv() => {
                    eprintln!("Shutting down (SIGTERM)...");
                    break;
                }
            }
        }
    } else {
        // Run TUI (blocks until quit, also handles SIGTERM)
        // Spawn a SIGTERM watcher that will cleanly exit the TUI
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("failed to register SIGTERM handler");
            sigterm.recv().await;
            eprintln!("Shutting down (SIGTERM)...");
            let _ = shutdown_tx.send(());
        });

        tokio::select! {
            result = tui::run_tui(alert_rx, Some(config_path.clone()), pending_store.clone(), response_tx.clone()) => { result?; }
            _ = &mut shutdown_rx => { /* SIGTERM received, exit cleanly */ }
        }
    }

    // Restart the background service if we stopped it for TUI mode
    if std::env::var("CLAWTOWER_RESTART_SERVICE").is_ok() {
        eprintln!("Restarting clawtower service...");
        let _ = std::process::Command::new("sudo")
            .args(["systemctl", "start", "clawtower"])
            .status();
    }

    Ok(())
}
