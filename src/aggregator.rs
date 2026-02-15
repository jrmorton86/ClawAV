//! Alert aggregator: deduplication and per-source rate limiting.
//!
//! Sits between raw alert sources and consumers (TUI, Slack, API).
//! Uses fuzzy dedup (digits replaced with "#") so alerts differing only in
//! PIDs or counts share the same shape. Critical alerts bypass most filtering.
//! Also handles JSONL logging, audit chain appending, and log rotation.

use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

use crate::alerts::Alert;

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
}

impl Default for AggregatorConfig {
    fn default() -> Self {
        Self {
            dedup_window: Duration::from_secs(30),
            scan_dedup_window: Duration::from_secs(3600),
            rate_limit_per_source: 20,
            rate_limit_window: Duration::from_secs(60),
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
        let dedup_window = self.config.dedup_window.max(self.config.scan_dedup_window);
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
        // Always allow Critical alerts through (never suppress)
        if alert.severity == crate::alerts::Severity::Critical {
            // Still track for dedup but don't suppress
            let key = Self::dedup_key(&alert);
            let now = Instant::now();
            if let Some(entry) = self.dedup_map.get(&key) {
                if now.duration_since(entry.last_seen) < Duration::from_secs(5) {
                    // Only dedup criticals within 5 seconds (very tight window)
                    return None;
                }
            }
            self.dedup_map.insert(key, DeduplicationEntry {
                last_seen: now,
                suppressed_count: 0,
            });
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
    min_slack_severity: crate::alerts::Severity,
    api_store: crate::api::SharedAlertStore,
) {
    let mut aggregator = Aggregator::new(config);
    let mut cleanup_counter: u32 = 0;

    // Initialize JSONL alert log path
    let alerts_log_path = if unsafe { libc::getuid() } == 0 {
        "/var/log/clawav/alerts.jsonl".to_string()
    } else {
        format!("/tmp/clawav-{}/alerts.jsonl", unsafe { libc::getuid() })
    };
    let _ = std::fs::create_dir_all(std::path::Path::new(&alerts_log_path).parent().unwrap_or(std::path::Path::new("/tmp")));

    // Initialize audit chain
    let chain_path = if unsafe { libc::getuid() } == 0 {
        "/var/log/clawav/audit.chain".to_string()
    } else {
        format!("/tmp/clawav-{}/audit.chain", unsafe { libc::getuid() })
    };
    let mut audit_chain = match crate::audit_chain::AuditChain::new(&chain_path) {
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
    use crate::alerts::{Alert, Severity};

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
