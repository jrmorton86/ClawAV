// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Runtime orchestration — spawns all monitoring subsystems and the frontend.
//!
//! [`run_watchdog`] is the single entry point for the long-lived watchdog runtime.
//! It takes ownership of [`AppState`] and [`AlertReceivers`], spawns all configured
//! monitoring tasks, then blocks on either TUI or headless alert drain until shutdown.

use anyhow::Result;
use std::path::{Path, PathBuf};
use tokio::sync::{mpsc, watch};

use super::aggregator::AggregatorConfig;
use super::alerts::{Alert, Severity};
use super::app_state::{AlertReceivers, AppState};
use super::response::ResponseRequest;
use super::{admin, aggregator, response, update};
use crate::interface::slack::SlackNotifier;
use crate::interface::api;
use crate::{netpolicy, proxy, scanner, sentinel, tui};
use crate::detect::barnacle;
use crate::sources::{auditd, falco, firewall, journald, logtamper, memory_sentinel, network, samhain};

/// Run the watchdog runtime. Spawns all monitoring sources, the aggregator,
/// Slack forwarder, API server, and frontend (TUI or headless). Blocks until
/// the user quits or a signal is received.
pub async fn run_watchdog(state: AppState, receivers: AlertReceivers) -> Result<()> {
    let AlertReceivers { raw_rx, alert_rx, mut slack_rx } = receivers;

    // ── Monitoring sources ──────────────────────────────────────────────────

    // Auditd tail with behavior detection + network policy
    if state.config.auditd.enabled {
        let tx = state.raw_tx.clone();
        let path = PathBuf::from(&state.config.auditd.log_path);
        let watched = state.config.general.effective_watched_users();
        let pe = state.policy_engine.clone();
        let se = state.barnacle_engine.clone();
        let np = if state.config.netpolicy.enabled {
            eprintln!("Network policy enabled (mode: {}, {} allowed hosts, {} blocked hosts)",
                state.config.netpolicy.mode,
                state.config.netpolicy.allowed_hosts.len(),
                state.config.netpolicy.blocked_hosts.len());
            Some(netpolicy::NetPolicy::from_config(&state.config.netpolicy))
        } else {
            None
        };
        let extra_safe = state.config.behavior.safe_hosts.clone();
        let behavior_shadow_mode = state.config.behavior.detector_shadow_mode;
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

    // Network monitor (auto-detect journald vs file)
    if state.config.network.enabled {
        let tx = state.raw_tx.clone();
        let source = state.config.network.source.clone();
        let path = PathBuf::from(&state.config.network.log_path);
        let prefix = state.config.network.log_prefix.clone();

        tokio::spawn(async move {
            let use_journald = match source.as_str() {
                "journald" => true,
                "file" => false,
                _ => {
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

    // Watch channels for live log path switching (TUI config editor → tailer)
    let (falco_path_tx, falco_path_rx) = watch::channel(PathBuf::from(&state.config.falco.log_path));
    let (samhain_path_tx, samhain_path_rx) = watch::channel(PathBuf::from(&state.config.samhain.log_path));

    // Falco log tail (dynamic: restarts on path change from TUI)
    if state.config.falco.enabled {
        let tx = state.raw_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = falco::tail_falco_log_dynamic(tx, falco_path_rx).await {
                eprintln!("Falco monitor error: {}", e);
            }
        });
    }

    // Samhain log tail (dynamic: restarts on path change from TUI)
    if state.config.samhain.enabled {
        let tx = state.raw_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = samhain::tail_samhain_log_dynamic(tx, samhain_path_rx).await {
                eprintln!("Samhain monitor error: {}", e);
            }
        });
    }

    // SSH login monitor
    if state.config.ssh.enabled {
        let tx = state.raw_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = journald::tail_journald_ssh(tx).await {
                eprintln!("SSH monitor error: {}", e);
            }
        });
    }

    // Shared dynamic mappings for auth-profile virtualization (used by both proxy and guard)
    let dynamic_mappings = std::sync::Arc::new(std::sync::Mutex::new(Vec::<proxy::KeyMapping>::new()));

    // Proxy server
    if state.config.proxy.enabled {
        let proxy_config = state.config.proxy.clone();
        let firewall_config = state.config.prompt_firewall.clone();
        let proxy_tx = state.raw_tx.clone();
        let proxy_dyn = dynamic_mappings.clone();
        let (_proxy_reload_tx, proxy_reload_rx) = tokio::sync::watch::channel(());
        // _proxy_reload_tx is kept alive by the spawned scope — the reload channel
        // will be wired up to the remediation module in a future task.
        tokio::spawn(async move {
            let _reload_tx = _proxy_reload_tx; // move into task to keep sender alive
            let server = proxy::ProxyServer::new_with_reload(
                proxy_config, firewall_config, proxy_tx, proxy_dyn, proxy_reload_rx,
            );
            if let Err(e) = server.start().await {
                eprintln!("Proxy server error: {}", e);
            }
        });

        // Auth-profile virtual credential guard
        let auth_path = std::path::PathBuf::from(&state.config.proxy.auth_profile_path);
        let guard_mappings = dynamic_mappings.clone();
        let guard_tx = state.raw_tx.clone();
        tokio::spawn(async move {
            proxy::auth_profiles::start_auth_profile_guard(auth_path, guard_mappings, guard_tx).await;
        });
    }

    // Firewall state monitor
    {
        let tx = state.raw_tx.clone();
        tokio::spawn(async move {
            firewall::monitor_firewall(tx).await;
        });
    }

    // Audit log tampering monitor
    if state.config.auditd.enabled {
        let log_path = PathBuf::from(&state.config.auditd.log_path);
        if std::fs::metadata(&log_path).is_ok() {
            let tx = state.raw_tx.clone();
            tokio::spawn(async move {
                logtamper::monitor_log_integrity(log_path, tx, 30).await;
            });
        }
    }

    // Periodic security scanner
    {
        let tx = state.raw_tx.clone();
        let scan_store = state.scan_results.clone();
        let interval = state.config.scans.interval;
        let oc_cfg = state.config.openclaw.clone();
        let dedup = state.config.scans.dedup_interval_secs;
        tokio::spawn(async move {
            scanner::run_periodic_scans(interval, tx, scan_store, oc_cfg, dedup).await;
        });
    }

    // Fast-cycle persistence scanner (default 300s)
    {
        let tx = state.raw_tx.clone();
        let persist_interval = state.config.scans.persistence_interval;
        tokio::spawn(async move {
            scanner::run_persistence_scans(persist_interval, tx).await;
        });
    }

    // Real-time file sentinel
    if state.config.sentinel.enabled {
        let sentinel_config = state.config.sentinel.clone();
        let sentinel_tx = state.raw_tx.clone();
        let barnacle_for_sentinel = barnacle::BarnacleEngine::load(
            std::path::Path::new("/etc/clawtower/barnacle")
        ).ok().map(std::sync::Arc::new);

        tokio::spawn(async move {
            match sentinel::Sentinel::new(sentinel_config, sentinel_tx, barnacle_for_sentinel) {
                Ok(s) => {
                    if let Err(e) = s.run().await {
                        eprintln!("[sentinel] run() error: {}", e);
                    }
                }
                Err(e) => {
                    eprintln!("[sentinel] init error: {}", e);
                }
            }
        });
    }

    // Auto-updater (checks for new GitHub releases)
    if state.config.auto_update.enabled {
        let update_tx = state.raw_tx.clone();
        let update_interval = state.config.auto_update.interval;
        let update_mode = state.config.auto_update.mode.clone();
        tokio::spawn(async move {
            update::run_auto_updater(update_tx, update_interval, update_mode).await;
        });
    }

    // Memory sentinel
    if state.config.memory_sentinel.enabled {
        let mem_config = state.config.memory_sentinel.clone();
        let mem_tx = state.raw_tx.clone();
        eprintln!("Memory sentinel enabled (target_pid: {:?}, interval: {}ms)",
            mem_config.target_pid, mem_config.scan_interval_ms);
        tokio::spawn(async move {
            memory_sentinel::run_memory_sentinel(mem_config, mem_tx).await;
        });
    }

    // ── Admin socket ────────────────────────────────────────────────────────

    let admin_key_hash_path = PathBuf::from("/etc/clawtower/admin.key.hash");
    if let Err(e) = admin::init_admin_key(&admin_key_hash_path) {
        eprintln!("Admin key init: {} (non-fatal, admin socket will still start)", e);
    }
    let socket_dir = PathBuf::from("/var/run/clawtower");
    // RuntimeDirectory is cleaned up when systemd stops the service,
    // so re-create it if we're running as root (TUI mode after service stop).
    if !socket_dir.exists() && unsafe { libc::getuid() } == 0 {
        let _ = std::fs::create_dir_all(&socket_dir);
    }
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
        state.raw_tx.clone(),
    );
    tokio::spawn(async move {
        if let Err(e) = admin_socket.run().await {
            eprintln!("Admin socket error: {}", e);
        }
    });

    // ── Slack ───────────────────────────────────────────────────────────────

    // Send startup message before moving notifier into forwarder
    if let Err(e) = state.notifier.send_startup_message().await {
        eprintln!("Slack startup message failed: {}", e);
    }

    // Periodic heartbeat
    let heartbeat_interval = state.config.slack.heartbeat_interval;
    if heartbeat_interval > 0 {
        let heartbeat_notifier = SlackNotifier::new(&state.config.slack);
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

    // Slack forwarder (consumes notifier)
    let notifier = state.notifier;
    tokio::spawn(async move {
        while let Some(alert) = slack_rx.recv().await {
            if let Err(e) = notifier.send_alert(&alert).await {
                eprintln!("Slack send error: {}", e);
            }
        }
    });

    // ── Aggregator ──────────────────────────────────────────────────────────

    let agg_config = if state.config.incident_mode.enabled
        || Path::new("/var/run/clawtower/incident-mode.active").exists()
    {
        eprintln!("INCIDENT MODE ACTIVE — tightened aggregation ({}s dedup, {} rate limit)",
            state.config.incident_mode.dedup_window_secs, state.config.incident_mode.rate_limit_per_source);
        AggregatorConfig {
            dedup_window: std::time::Duration::from_secs(state.config.incident_mode.dedup_window_secs),
            scan_dedup_window: std::time::Duration::from_secs(state.config.incident_mode.scan_dedup_window_secs),
            rate_limit_per_source: state.config.incident_mode.rate_limit_per_source,
            rate_limit_window: std::time::Duration::from_secs(60),
            critical_dedup_window: std::time::Duration::from_secs(5),
        }
    } else {
        AggregatorConfig::default()
    };
    let min_slack = state.min_slack_level;
    let agg_store = state.alert_store.clone();
    let agg_alert_tx = state.alert_tx.clone();
    let agg_slack_tx = state.slack_tx.clone();
    tokio::spawn(async move {
        aggregator::run_aggregator(raw_rx, agg_alert_tx, agg_slack_tx, agg_config, min_slack, agg_store).await;
    });

    // ── Response engine ─────────────────────────────────────────────────────

    let response_tx: Option<mpsc::Sender<ResponseRequest>> = if state.config.response.enabled {
        let (resp_tx, resp_rx) = mpsc::channel::<ResponseRequest>(100);
        let resp_slack_tx = state.raw_tx.clone();
        let resp_config = state.config.response.clone();
        let playbook_dir = std::path::Path::new(&resp_config.playbook_dir);
        let playbooks = response::load_playbooks(playbook_dir);
        eprintln!("Response engine enabled: {} playbooks loaded, {}s timeout",
            playbooks.len(), resp_config.timeout_secs);

        let resp_pending = state.pending_actions.clone();
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

    // ── API server ──────────────────────────────────────────────────────────

    if state.config.api.enabled {
        if let Err(e) = state.config.api.validate() {
            eprintln!("FATAL: {}", e);
            std::process::exit(1);
        }
        let audit_chain_path = if unsafe { libc::getuid() } == 0 {
            PathBuf::from("/var/log/clawtower/audit.chain")
        } else {
            PathBuf::from(format!("/tmp/clawtower-{}/audit.chain", unsafe { libc::getuid() }))
        };
        let ctx = std::sync::Arc::new(api::ApiContext {
            store: state.alert_store.clone(),
            start_time: std::time::Instant::now(),
            auth_token: state.config.api.auth_token.clone(),
            cors_origin: state.config.api.cors_origin.clone(),
            pending_store: state.pending_actions.clone(),
            response_tx: response_tx.clone().map(std::sync::Arc::new),
            scan_results: Some(state.scan_results.clone()),
            audit_chain_path: Some(audit_chain_path),
            policy_dir: Some(PathBuf::from(&state.config.policy.dir)),
            barnacle_dir: Some(PathBuf::from(&state.config.barnacle.vendor_dir)),
            active_profile: state.profile_name.clone(),
        });
        let bind = state.config.api.bind.clone();
        let port = state.config.api.port;
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

    // ── Frontend (TUI or headless) ──────────────────────────────────────────

    // Send startup alert (through aggregator)
    let startup = Alert::new(Severity::Info, "system", "ClawTower watchdog started");
    let _ = state.raw_tx.send(startup).await;

    if state.headless {
        run_headless(alert_rx).await?;
    } else {
        run_tui_frontend(
            alert_rx,
            state.config_path.clone(),
            state.pending_actions.clone(),
            state.scan_results.clone(),
            response_tx,
            falco_path_tx,
            samhain_path_tx,
        ).await?;
    }

    restart_service_if_needed();
    Ok(())
}

/// Headless mode: drain alerts to stderr until SIGTERM or SIGINT.
async fn run_headless(mut alert_rx: mpsc::Receiver<Alert>) -> Result<()> {
    let mut sigterm = tokio::signal::unix::signal(
        tokio::signal::unix::SignalKind::terminate(),
    )?;
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
    Ok(())
}

/// TUI mode: run the dashboard, with SIGTERM causing clean exit.
async fn run_tui_frontend(
    alert_rx: mpsc::Receiver<Alert>,
    config_path: PathBuf,
    pending_actions: super::response::SharedPendingActions,
    scan_results: crate::scanner::SharedScanResults,
    response_tx: Option<mpsc::Sender<ResponseRequest>>,
    falco_path_tx: watch::Sender<PathBuf>,
    samhain_path_tx: watch::Sender<PathBuf>,
) -> Result<()> {
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let mut sigterm = tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::terminate(),
        ).expect("failed to register SIGTERM handler");
        sigterm.recv().await;
        eprintln!("Shutting down (SIGTERM)...");
        let _ = shutdown_tx.send(());
    });

    tokio::select! {
        result = tui::run_tui(
            alert_rx,
            Some(config_path),
            pending_actions,
            response_tx,
            Some(scan_results),
            Some(falco_path_tx),
            Some(samhain_path_tx),
        ) => { result?; }
        _ = &mut shutdown_rx => { /* SIGTERM received, exit cleanly */ }
    }
    Ok(())
}

/// Restart the clawtower systemd service if we stopped it for TUI mode.
fn restart_service_if_needed() {
    if std::env::var("CLAWTOWER_RESTART_SERVICE").is_ok() {
        eprintln!("Restarting clawtower service...");
        let _ = std::process::Command::new("sudo")
            .args(["systemctl", "start", "clawtower"])
            .status();
    }
}
