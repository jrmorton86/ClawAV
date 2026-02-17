//! ClawTower — Tamper-proof security watchdog for AI agents.
//!
//! This is the main entry point. It handles CLI argument parsing, privilege escalation
//! via `sudo`, and orchestrates the async runtime that spawns all monitoring subsystems:
//!
//! - **auditd**: Tails the Linux audit log for syscall-level events
//! - **behavior**: Classifies audit events against known attack patterns
//! - **policy**: Evaluates events against user-defined YAML policy rules
//! - **secureclaw**: Matches commands against vendor threat pattern databases
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
mod alerts;
mod aggregator;
mod api;
mod audit_chain;
mod auditd;
mod behavior;
mod cognitive;
mod config;
mod config_merge;
mod sentinel;
mod falco;
mod firewall;
mod journald;
mod logtamper;
mod netpolicy;
mod network;
mod openclaw_config;
mod policy;
mod proxy;
mod samhain;
mod scanner;
mod secureclaw;
mod slack;
mod tui;
mod update;

use anyhow::Result;
use config::Config;
use alerts::{Alert, Severity};
use aggregator::AggregatorConfig;
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
    status               Show service status and recent alerts
    configure            Interactive configuration wizard
    update               Self-update to latest GitHub release
    scan                 Run a one-shot security scan and exit
    verify-key           Verify admin key from stdin (or --key flag)
    verify-audit [PATH]  Verify audit chain integrity
    setup                Install ClawTower as a system service
    setup --source       Build from source + install
    setup --auto         Install + start service automatically
    harden               Apply tamper-proof "swallowed key" hardening
    uninstall            Reverse hardening + remove ClawTower (requires admin key)
    sync                 Update SecureClaw pattern databases
    logs                 Tail the service logs (journalctl)
    help                 Show this help message
    version              Show version info

EXAMPLES:
    clawtower                           Start TUI dashboard
    clawtower run --headless            Run as background daemon
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
    eprintln!("https://github.com/coltz108/ClawTower");
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
            return Some(candidate.canonicalize().ok()?);
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
        "https://raw.githubusercontent.com/coltz108/ClawTower/{}/scripts/{}",
        tag, name
    );
    eprintln!("Downloading {} from GitHub ({})...", name, tag);
    let output = std::process::Command::new("curl")
        .args(["-sSL", "-f", "-o", &format!("/tmp/clawtower-{}", name), &url])
        .status()?;
    if !output.success() {
        // Fall back to main branch
        let url_main = format!(
            "https://raw.githubusercontent.com/coltz108/ClawTower/main/scripts/{}",
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
        "configure" => {
            return run_script("configure.sh", &rest_args);
        }
        "setup" => {
            return run_script("setup.sh", &rest_args);
        }
        "harden" => {
            return run_script("install.sh", &rest_args);
        }
        "uninstall" => {
            return run_script("uninstall.sh", &rest_args);
        }
        "sync" => {
            return run_script("sync-secureclaw.sh", &rest_args);
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
            eprintln!("");
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
            eprintln!("");
            eprintln!("Score: {}/{} checks passed", pass_count, total);
            return Ok(());
        }
        "run" | "tui" | _ => {
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

    let headless = run_args.iter().any(|a| a.as_str() == "--headless");

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
    let config = Config::load_with_overrides(&config_path, &config_d)?;
    eprintln!("Config loaded (with overlays from {})", config_d.display());
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

    // Load SecureClaw engine
    let secureclaw_engine = if config.secureclaw.enabled {
        match secureclaw::SecureClawEngine::load(&config.secureclaw.vendor_dir) {
            Ok(engine) => {
                eprintln!("SecureClaw loaded: {} injection, {} command, {} privacy, {} supply-chain patterns",
                    engine.injection_patterns.len(),
                    engine.dangerous_commands.len(),
                    engine.privacy_rules.len(),
                    engine.supply_chain_iocs.len());
                Some(Arc::new(engine))
            }
            Err(e) => {
                eprintln!("SecureClaw load error: {} (continuing without)", e);
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
        let se = secureclaw_engine.clone();
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
        if std::fs::metadata(&path).is_ok() {
            tokio::spawn(async move {
                if let Err(e) = auditd::tail_audit_log_full(&path, watched, tx, pe, se, np, extra_safe).await {
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
            } else {
                if let Err(e) = network::tail_network_log(&path, &prefix, tx).await {
                    eprintln!("file network monitor error: {}", e);
                }
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

    // Spawn API server if enabled
    if config.api.enabled {
        let store = alert_store.clone();
        let bind = config.api.bind.clone();
        let port = config.api.port;
        let auth_token = config.api.auth_token.clone();
        tokio::spawn(async move {
            if let Err(e) = api::run_api_server(&bind, port, store, auth_token).await {
                eprintln!("API server error: {}", e);
            }
        });
    }

    // Spawn aggregator (sits between raw sources and TUI/Slack)
    let agg_config = AggregatorConfig::default();
    let min_slack = min_slack_level;
    let agg_store = alert_store.clone();
    tokio::spawn(async move {
        aggregator::run_aggregator(raw_rx, alert_tx, slack_tx, agg_config, min_slack, agg_store).await;
    });

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

    // Spawn periodic security scanner
    {
        let tx = raw_tx.clone();
        let scan_store = scanner::new_shared_scan_results();
        let interval = config.scans.interval;
        let oc_cfg = config.openclaw.clone();
        tokio::spawn(async move {
            scanner::run_periodic_scans(interval, tx, scan_store, oc_cfg).await;
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
        let secureclaw_engine = crate::secureclaw::SecureClawEngine::load(
            std::path::Path::new("/etc/clawtower/secureclaw")
        ).ok().map(std::sync::Arc::new);
        
        tokio::spawn(async move {
            match crate::sentinel::Sentinel::new(sentinel_config, sentinel_tx, secureclaw_engine) {
                Ok(sentinel) => {
                    if let Err(e) = sentinel.run().await {
                        eprintln!("Sentinel error: {}", e);
                    }
                }
                Err(e) => eprintln!("Failed to start sentinel: {}", e),
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
        eprintln!("ClawTower running in headless mode (Ctrl+C to stop)");
        loop {
            tokio::select! {
                Some(alert) = alert_rx.recv() => {
                    eprintln!("[{}] [{}] {}", alert.severity, alert.source, alert.message);
                }
                _ = tokio::signal::ctrl_c() => {
                    eprintln!("Shutting down...");
                    break;
                }
            }
        }
    } else {
        // Run TUI (blocks until quit)
        tui::run_tui(alert_rx, Some(config_path.clone())).await?;
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
