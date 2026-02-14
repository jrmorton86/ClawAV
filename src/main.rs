mod admin;
mod alerts;
mod aggregator;
mod api;
mod audit_chain;
mod auditd;
mod behavior;
mod config;
mod falco;
mod firewall;
mod journald;
mod network;
mod policy;
mod proxy;
mod samhain;
mod scanner;
mod secureclaw;
mod slack;
mod tui;

use anyhow::Result;
use config::Config;
use alerts::{Alert, Severity};
use aggregator::AggregatorConfig;
use slack::SlackNotifier;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<()> {
    // Check for verify-audit subcommand
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 2 && args[1] == "verify-audit" {
        let path = args.get(2).map(|s| s.as_str());
        return audit_chain::run_verify_audit(path);
    }

    let config_path = args
        .get(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/openclawav/config.toml"));

    let config = Config::load(&config_path)?;
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
        let system_dir = std::path::Path::new("/etc/openclawav/policies");
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

    // Spawn auditd tail with behavior detection
    if config.auditd.enabled {
        let tx = raw_tx.clone();
        let path = PathBuf::from(&config.auditd.log_path);
        let watched = config.general.effective_watched_users();
        let pe = policy_engine.clone();
        let se = secureclaw_engine.clone();
        tokio::spawn(async move {
            if let Err(e) = auditd::tail_audit_log_with_behavior_and_policy(&path, watched, tx, pe, se).await {
                eprintln!("auditd monitor error: {}", e);
            }
        });
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
        tokio::spawn(async move {
            if let Err(e) = api::run_api_server(&bind, port, store).await {
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

    // Initialize admin key and spawn admin socket
    let admin_key_hash_path = PathBuf::from("/etc/openclawav/admin.key.hash");
    if let Err(e) = admin::init_admin_key(&admin_key_hash_path) {
        eprintln!("Admin key init: {} (non-fatal, admin socket will still start)", e);
    }
    let admin_socket = admin::AdminSocket::new(
        PathBuf::from("/var/run/openclawav/admin.sock"),
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
        tokio::spawn(async move {
            scanner::run_periodic_scans(interval, tx, scan_store).await;
        });
    }

    // Send startup alert (through aggregator)
    let startup = Alert::new(Severity::Info, "system", "OpenClawAV watchdog started");
    let _ = raw_tx.send(startup).await;

    // Check for --headless flag
    let headless = std::env::args().any(|a| a == "--headless");

    if headless {
        // Headless mode: just drain alerts and log them
        let mut alert_rx = alert_rx;
        eprintln!("OpenClawAV running in headless mode (Ctrl+C to stop)");
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
        tui::run_tui(alert_rx).await?;
    }

    Ok(())
}
