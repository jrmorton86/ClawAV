// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Alert aggregator: deduplication and per-source rate limiting.
//!
//! Sits between raw alert sources and consumers (TUI, Slack, API).
//! Uses fuzzy dedup (digits replaced with "#") so alerts differing only in
//! PIDs or counts share the same shape. Critical alerts bypass most filtering.
//! Also handles JSONL logging, audit chain appending, and log rotation.

use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

use super::alerts::Alert;

/// Configuration for the alert aggregator
pub struct AggregatorConfig {
    /// Window for deduplication — alerts with identical shape
    /// within this window are suppressed
    pub dedup_window: Duration,
    /// Longer dedup window for scan-prefixed sources
    pub scan_dedup_window: Duration,
    /// Maximum alerts per source per minute
    pub rate_limit_per_source: u32,
    /// Rate limit window
    pub rate_limit_window: Duration,
    /// Dedup window for Critical alerts (same-source only).
    /// Cross-source Criticals always pass through (H9 defense preserved).
    /// Set to zero to disable (old behavior: no Critical dedup at all).
    pub critical_dedup_window: Duration,
}

impl Default for AggregatorConfig {
    fn default() -> Self {
        Self {
            dedup_window: Duration::from_secs(30),
            scan_dedup_window: Duration::from_secs(3600),
            rate_limit_per_source: 20,
            rate_limit_window: Duration::from_secs(60),
            critical_dedup_window: Duration::from_secs(5),
        }
    }
}

/// Tracks recent alerts for deduplication
struct DeduplicationEntry {
    last_seen: Instant,
    #[allow(dead_code)]
    suppressed_count: u32,
}

/// Tracks per-source rate limiting
struct RateLimitEntry {
    timestamps: Vec<Instant>,
}

/// Central alert aggregator that sits between sources and consumers.
/// Provides deduplication and per-source rate limiting.
pub struct Aggregator {
    config: AggregatorConfig,
    /// Key: "source:message_hash" -> last seen time
    dedup_map: HashMap<String, DeduplicationEntry>,
    /// Key: source name -> rate limit state
    rate_limits: HashMap<String, RateLimitEntry>,
}

impl Aggregator {
    /// Create a new aggregator with the given configuration.
    pub fn new(config: AggregatorConfig) -> Self {
        Self {
            config,
            dedup_map: HashMap::new(),
            rate_limits: HashMap::new(),
        }
    }

    /// Generate a fuzzy dedup key from an alert.
    /// Replaces ASCII digits with '#' so alerts differing only in
    /// numbers (PIDs, counts, timestamps) share the same shape.
    fn dedup_key(alert: &Alert) -> String {
        let shape: String = alert.message.chars().map(|c| {
            if c.is_ascii_digit() { '#' } else { c }
        }).collect();
        format!("{}:{}", alert.source, shape)
    }

    /// Check if a Critical alert is a same-source duplicate within the
    /// critical dedup window. Cross-source Criticals always pass through
    /// to preserve H9 defense (attacker can't suppress cross-engine detections).
    fn dedup_critical(&mut self, alert: &Alert) -> bool {
        if self.config.critical_dedup_window.is_zero() {
            return false; // disabled — old behavior
        }
        let key = Self::dedup_key(alert);
        let now = Instant::now();

        if let Some(entry) = self.dedup_map.get_mut(&key) {
            if now.duration_since(entry.last_seen) < self.config.critical_dedup_window {
                entry.suppressed_count += 1;
                entry.last_seen = now;
                return true; // same source + same shape within window → suppress
            }
            entry.last_seen = now;
            entry.suppressed_count = 0;
            false
        } else {
            self.dedup_map.insert(key, DeduplicationEntry {
                last_seen: now,
                suppressed_count: 0,
            });
            false
        }
    }

    /// Check if an alert is a duplicate within the dedup window
    fn is_duplicate(&mut self, alert: &Alert) -> bool {
        let key = Self::dedup_key(alert);
        let now = Instant::now();

        let window = if alert.source.starts_with("scan:") {
            self.config.scan_dedup_window
        } else {
            self.config.dedup_window
        };

        if let Some(entry) = self.dedup_map.get_mut(&key) {
            if now.duration_since(entry.last_seen) < window {
                entry.suppressed_count += 1;
                entry.last_seen = now;
                return true;
            }
            // Window expired — allow through and reset
            entry.last_seen = now;
            entry.suppressed_count = 0;
            false
        } else {
            self.dedup_map.insert(key, DeduplicationEntry {
                last_seen: now,
                suppressed_count: 0,
            });
            false
        }
    }

    /// Check if the source has exceeded its rate limit
    fn is_rate_limited(&mut self, source: &str) -> bool {
        let now = Instant::now();
        let entry = self.rate_limits
            .entry(source.to_string())
            .or_insert_with(|| RateLimitEntry { timestamps: Vec::new() });

        // Remove timestamps outside the rate limit window
        entry.timestamps.retain(|t| now.duration_since(*t) < self.config.rate_limit_window);

        if entry.timestamps.len() >= self.config.rate_limit_per_source as usize {
            true
        } else {
            entry.timestamps.push(now);
            false
        }
    }

    /// Periodically clean up old entries to prevent unbounded memory growth
    fn cleanup(&mut self) {
        let now = Instant::now();
        let dedup_window = self.config.dedup_window
            .max(self.config.scan_dedup_window)
            .max(self.config.critical_dedup_window);
        let rate_window = self.config.rate_limit_window;

        self.dedup_map.retain(|_, entry| {
            now.duration_since(entry.last_seen) < dedup_window * 3
        });

        self.rate_limits.retain(|_, entry| {
            entry.timestamps.retain(|t| now.duration_since(*t) < rate_window);
            !entry.timestamps.is_empty()
        });
    }

    /// Process an alert through dedup and rate limiting.
    /// Returns Some(alert) if it should be forwarded, None if suppressed.
    pub fn process(&mut self, alert: Alert) -> Option<Alert> {
        // Critical alerts use a short same-source dedup window instead of
        // full bypass. Cross-source Criticals always pass through, preserving
        // H9 defense (attacker can't suppress cross-engine detections).
        if alert.severity == super::alerts::Severity::Critical {
            if self.dedup_critical(&alert) {
                return None;
            }
            return Some(alert);
        }

        if self.is_duplicate(&alert) {
            return None;
        }

        if self.is_rate_limited(&alert.source) {
            return None;
        }

        Some(alert)
    }
}

/// Spawn the aggregator as a task that reads from `input_rx`,
/// filters through dedup/rate-limiting, and forwards to `output_tx`.
/// Also forwards qualifying alerts to `slack_tx`.
pub async fn run_aggregator(
    mut input_rx: mpsc::Receiver<Alert>,
    output_tx: mpsc::Sender<Alert>,
    slack_tx: mpsc::Sender<Alert>,
    config: AggregatorConfig,
    min_slack_severity: super::alerts::Severity,
    api_store: crate::interface::api::SharedAlertStore,
    hmac_secret: Option<String>,
) {
    let mut aggregator = Aggregator::new(config);
    let mut cleanup_counter: u32 = 0;

    // Initialize JSONL alert log path
    let alerts_log_path = if unsafe { libc::getuid() } == 0 {
        "/var/log/clawtower/alerts.jsonl".to_string()
    } else {
        format!("/tmp/clawtower-{}/alerts.jsonl", unsafe { libc::getuid() })
    };
    let _ = std::fs::create_dir_all(std::path::Path::new(&alerts_log_path).parent().unwrap_or(std::path::Path::new("/tmp")));

    // Initialize audit chain
    let chain_path = if unsafe { libc::getuid() } == 0 {
        "/var/log/clawtower/audit.chain".to_string()
    } else {
        format!("/tmp/clawtower-{}/audit.chain", unsafe { libc::getuid() })
    };
    let mut audit_chain = match super::audit_chain::AuditChain::new_with_hmac(&chain_path, hmac_secret) {
        Ok(chain) => Some(chain),
        Err(e) => {
            eprintln!("Warning: Failed to initialize audit chain: {}. Continuing without it.", e);
            None
        }
    };

    while let Some(alert) = input_rx.recv().await {
        if let Some(alert) = aggregator.process(alert) {
            // Append to audit chain
            if let Some(ref mut chain) = audit_chain {
                if let Err(e) = chain.append(&alert) {
                    eprintln!("Audit chain append error: {}", e);
                }
            }

            // Persist to JSONL log
            {
                use std::io::Write;
                if let Ok(mut file) = std::fs::OpenOptions::new()
                    .create(true).append(true)
                    .open(&alerts_log_path)
                {
                    if let Ok(json) = serde_json::to_string(&alert) {
                        let _ = writeln!(file, "{}", json);
                    }
                }
            }

            // Forward to API alert store
            {
                let mut store = api_store.lock().await;
                store.push(alert.clone());
            }

            // Forward to Slack if severity meets threshold
            if alert.severity >= min_slack_severity {
                let _ = slack_tx.send(alert.clone()).await;
            }

            // Forward to TUI/consumers
            let _ = output_tx.send(alert).await;
        }

        // Periodic cleanup every 100 alerts
        cleanup_counter += 1;
        if cleanup_counter >= 100 {
            aggregator.cleanup();
            // Rotate JSONL log if over 10MB
            if let Ok(meta) = std::fs::metadata(&alerts_log_path) {
                if meta.len() > 10_000_000 {
                    let rotated = format!("{}.1", alerts_log_path);
                    let _ = std::fs::rename(&alerts_log_path, &rotated);
                }
            }
            cleanup_counter = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::alerts::{Alert, Severity};

    fn make_alert(source: &str, msg: &str, sev: Severity) -> Alert {
        Alert::new(sev, source, msg)
    }

    #[test]
    fn test_dedup_suppresses_identical() {
        let mut agg = Aggregator::new(AggregatorConfig::default());
        let a1 = make_alert("auditd", "exec: bash", Severity::Info);
        let a2 = make_alert("auditd", "exec: bash", Severity::Info);

        assert!(agg.process(a1).is_some());
        assert!(agg.process(a2).is_none()); // duplicate
    }

    #[test]
    fn test_different_messages_not_deduped() {
        let mut agg = Aggregator::new(AggregatorConfig::default());
        let a1 = make_alert("auditd", "exec: bash", Severity::Info);
        let a2 = make_alert("auditd", "exec: curl", Severity::Info);

        assert!(agg.process(a1).is_some());
        assert!(agg.process(a2).is_some());
    }

    #[test]
    fn test_critical_always_passes() {
        let mut agg = Aggregator::new(AggregatorConfig {
            rate_limit_per_source: 1,
            ..Default::default()
        });
        // Use up the rate limit
        let a1 = make_alert("falco", "something", Severity::Info);
        assert!(agg.process(a1).is_some());

        // Critical should still pass even though rate limited
        let a2 = make_alert("falco", "privilege escalation!", Severity::Critical);
        assert!(agg.process(a2).is_some());
    }

    #[test]
    fn test_fuzzy_dedup_strips_numbers() {
        let mut agg = Aggregator::new(AggregatorConfig::default());
        let a1 = make_alert("scan:cron", "Found 3 suspicious crontab entries for uid 1000", Severity::Warning);
        let a2 = make_alert("scan:cron", "Found 4 suspicious crontab entries for uid 1000", Severity::Warning);

        assert!(agg.process(a1).is_some());
        assert!(agg.process(a2).is_none()); // fuzzy match — same shape
    }

    #[test]
    fn test_fuzzy_dedup_different_shapes_pass() {
        let mut agg = Aggregator::new(AggregatorConfig::default());
        let a1 = make_alert("auditd", "exec: curl http://api.example.com", Severity::Info);
        let a2 = make_alert("auditd", "exec: wget http://evil.com", Severity::Info);

        assert!(agg.process(a1).is_some());
        assert!(agg.process(a2).is_some()); // different commands, different shape
    }

    #[test]
    fn test_alert_serializes_to_json() {
        let alert = Alert::new(Severity::Warning, "test", "hello world");
        let json = serde_json::to_string(&alert).unwrap();
        assert!(json.contains("hello world"));
        assert!(json.contains("test"));
    }

    // --- NEW REGRESSION TESTS ---

    #[test]
    fn test_dedup_after_window_expires() {
        let mut agg = Aggregator::new(AggregatorConfig {
            dedup_window: Duration::from_millis(10),
            ..Default::default()
        });
        let a1 = make_alert("auditd", "exec: bash", Severity::Info);
        assert!(agg.process(a1).is_some());

        std::thread::sleep(Duration::from_millis(20));

        let a2 = make_alert("auditd", "exec: bash", Severity::Info);
        assert!(agg.process(a2).is_some(), "Same alert after window should pass");
    }

    #[test]
    fn test_different_sources_not_deduped() {
        let mut agg = Aggregator::new(AggregatorConfig::default());
        let a1 = make_alert("auditd", "exec: bash", Severity::Info);
        let a2 = make_alert("network", "exec: bash", Severity::Info);
        assert!(agg.process(a1).is_some());
        assert!(agg.process(a2).is_some(), "Same message from different source should pass");
    }

    #[test]
    fn test_critical_same_source_deduped_within_window() {
        let mut agg = Aggregator::new(AggregatorConfig::default());
        let a1 = make_alert("falco", "privilege escalation!", Severity::Critical);
        let a2 = make_alert("falco", "privilege escalation!", Severity::Critical);
        assert!(agg.process(a1).is_some());
        // Same source + same shape within 5s window → suppressed
        assert!(agg.process(a2).is_none(), "Same-source Critical should be deduped within window");
    }

    #[test]
    fn test_critical_cross_source_never_deduped() {
        // H9 defense: Criticals from different sources always pass through
        let mut agg = Aggregator::new(AggregatorConfig::default());
        let a1 = make_alert("behavior", "CREDENTIAL READ: /etc/shadow", Severity::Critical);
        let a2 = make_alert("policy", "CREDENTIAL READ: /etc/shadow", Severity::Critical);
        assert!(agg.process(a1).is_some());
        assert!(agg.process(a2).is_some(), "Cross-source Critical must never be deduped (H9)");
    }

    #[test]
    fn test_critical_dedup_after_window_expires() {
        let mut agg = Aggregator::new(AggregatorConfig {
            critical_dedup_window: Duration::from_millis(10),
            ..Default::default()
        });
        let a1 = make_alert("falco", "privilege escalation!", Severity::Critical);
        assert!(agg.process(a1).is_some());

        std::thread::sleep(Duration::from_millis(20));

        let a2 = make_alert("falco", "privilege escalation!", Severity::Critical);
        assert!(agg.process(a2).is_some(), "Critical after window expires should pass");
    }

    #[test]
    fn test_critical_dedup_zero_window_disables() {
        let mut agg = Aggregator::new(AggregatorConfig {
            critical_dedup_window: Duration::ZERO,
            ..Default::default()
        });
        let a1 = make_alert("falco", "privilege escalation!", Severity::Critical);
        let a2 = make_alert("falco", "privilege escalation!", Severity::Critical);
        assert!(agg.process(a1).is_some());
        // Zero window = disabled = old behavior (no dedup)
        assert!(agg.process(a2).is_some(), "Zero critical_dedup_window should disable dedup");
    }

    #[test]
    fn test_critical_alerts_different_pids_deduped_same_source() {
        let mut agg = Aggregator::new(AggregatorConfig::default());
        let a1 = make_alert("behavior", "CREDENTIAL READ: /etc/shadow accessed by /usr/bin/python3 pid=1234", Severity::Critical);
        let a2 = make_alert("behavior", "CREDENTIAL READ: /etc/shadow accessed by /usr/bin/python3 pid=5678", Severity::Critical);
        assert!(agg.process(a1).is_some());
        // Same source, same shape (PIDs fuzzy-matched) → suppressed within window
        assert!(agg.process(a2).is_none(), "Same-source Critical with fuzzy-matching PIDs should be deduped");
    }

    #[test]
    fn test_scan_source_uses_longer_dedup() {
        let mut agg = Aggregator::new(AggregatorConfig {
            dedup_window: Duration::from_millis(10),
            scan_dedup_window: Duration::from_secs(3600),
            ..Default::default()
        });
        let a1 = make_alert("scan:cron", "found suspicious entry", Severity::Warning);
        assert!(agg.process(a1).is_some());

        std::thread::sleep(Duration::from_millis(20));
        // Normal dedup would have expired, but scan uses longer window
        let a2 = make_alert("scan:cron", "found suspicious entry", Severity::Warning);
        assert!(agg.process(a2).is_none(), "scan: source should use longer dedup window");
    }

    #[test]
    fn test_cleanup_removes_old_entries() {
        let mut agg = Aggregator::new(AggregatorConfig {
            dedup_window: Duration::from_millis(1),
            scan_dedup_window: Duration::from_millis(1),
            rate_limit_window: Duration::from_millis(1),
            ..Default::default()
        });
        for i in 0..10 {
            agg.process(make_alert("test", &format!("msg {}", i), Severity::Info));
        }
        std::thread::sleep(Duration::from_millis(10));
        agg.cleanup();
        assert!(agg.dedup_map.is_empty() || agg.dedup_map.len() < 10);
    }

    #[test]
    fn test_dedup_key_shape() {
        let a1 = make_alert("test", "pid 12345 did thing", Severity::Info);
        let a2 = make_alert("test", "pid 99999 did thing", Severity::Info);
        assert_eq!(Aggregator::dedup_key(&a1), Aggregator::dedup_key(&a2),
            "Alerts differing only in digits should share dedup key");
    }

    #[test]
    fn test_dedup_key_different_text() {
        let a1 = make_alert("test", "opened file", Severity::Info);
        let a2 = make_alert("test", "closed file", Severity::Info);
        assert_ne!(Aggregator::dedup_key(&a1), Aggregator::dedup_key(&a2));
    }

    #[test]
    fn test_rate_limiting() {
        let mut agg = Aggregator::new(AggregatorConfig {
            rate_limit_per_source: 2,
            dedup_window: Duration::from_millis(1), // basically disabled
            ..Default::default()
        });

        // Need different messages (with different shapes) to avoid dedup
        let a1 = make_alert("network", "conn from alpha", Severity::Info);
        let a2 = make_alert("network", "conn from bravo", Severity::Info);
        let a3 = make_alert("network", "conn from charlie", Severity::Info);

        assert!(agg.process(a1).is_some());
        assert!(agg.process(a2).is_some());
        // Sleep briefly to let dedup window expire
        std::thread::sleep(Duration::from_millis(5));
        assert!(agg.process(a3).is_none()); // rate limited
    }
}
