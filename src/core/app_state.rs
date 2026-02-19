// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Centralized application state for the ClawTower watchdog runtime.
//!
//! [`AppState`] bundles the shared resources (config, alert stores, detection engines,
//! channel senders) that are threaded through the spawn blocks in the orchestrator.
//! This eliminates scattered `.clone()` calls and makes the dependency graph explicit.

use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;

use super::alerts::{Alert, Severity};
use super::response::{self, SharedPendingActions};
use crate::interface::api;
use crate::config::Config;
use crate::detect::barnacle;
use crate::policy::rules as policy;
use crate::scanner;
use crate::interface::slack::SlackNotifier;

/// Channel receivers consumed by the aggregator, TUI, and Slack forwarder.
/// These are separated from AppState because each receiver can only be consumed once.
pub struct AlertReceivers {
    pub raw_rx: mpsc::Receiver<Alert>,
    pub alert_rx: mpsc::Receiver<Alert>,
    pub slack_rx: mpsc::Receiver<Alert>,
}

/// Centralized application state shared across all spawned tasks.
pub struct AppState {
    pub config: Config,
    pub config_path: PathBuf,
    pub profile_name: Option<String>,
    pub headless: bool,

    // Channel senders (cloned into spawned tasks)
    pub raw_tx: mpsc::Sender<Alert>,
    pub alert_tx: mpsc::Sender<Alert>,
    pub slack_tx: mpsc::Sender<Alert>,

    // Shared stores
    pub alert_store: api::SharedAlertStore,
    pub scan_results: scanner::SharedScanResults,
    pub pending_actions: SharedPendingActions,

    // Detection engines
    pub policy_engine: Option<policy::PolicyEngine>,
    pub barnacle_engine: Option<Arc<barnacle::BarnacleEngine>>,

    // Slack
    pub notifier: SlackNotifier,
    pub min_slack_level: Severity,
}

impl AppState {
    /// Build all shared state from config. Returns the state and the channel
    /// receivers that must be consumed by the aggregator and frontend.
    pub fn build(
        config: Config,
        config_path: PathBuf,
        profile_name: Option<String>,
        headless: bool,
    ) -> (Self, AlertReceivers) {
        // Three-stage channel pipeline:
        // Sources → raw_tx/raw_rx → Aggregator → alert_tx/alert_rx → TUI
        //                                      → slack_tx/slack_rx → Slack
        let (raw_tx, raw_rx) = mpsc::channel::<Alert>(1000);
        let (alert_tx, alert_rx) = mpsc::channel::<Alert>(1000);
        let (slack_tx, slack_rx) = mpsc::channel::<Alert>(100);

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
            match barnacle::BarnacleEngine::load_verified(
                &config.barnacle.vendor_dir,
                Some(std::path::Path::new(&config.barnacle.ioc_pubkey_path)),
            ) {
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

        // Shared stores
        let alert_store = api::new_shared_store(1000);
        let scan_results = scanner::new_shared_scan_results();
        let pending_actions = response::new_shared_pending();

        // Slack
        let notifier = SlackNotifier::new(&config.slack);
        let min_slack_level = Severity::from_str(&config.slack.min_slack_level);

        let state = Self {
            config,
            config_path,
            profile_name,
            headless,
            raw_tx,
            alert_tx,
            slack_tx,
            alert_store,
            scan_results,
            pending_actions,
            policy_engine,
            barnacle_engine,
            notifier,
            min_slack_level,
        };

        let receivers = AlertReceivers {
            raw_rx,
            alert_rx,
            slack_rx,
        };

        (state, receivers)
    }
}
