// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Session log audit source.
//!
//! Monitors the OpenClaw sessions directory for anomalies:
//! - Rapid session log growth (potential data dumping)
//! - Unusually high session count
//! - Session log deletion (tampering indicator)

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

use crate::core::alerts::{Alert, Severity};

/// Maximum expected session log size before alerting (10 MB).
const MAX_SESSION_LOG_SIZE: u64 = 10 * 1024 * 1024;
/// Maximum expected active sessions before alerting.
const MAX_ACTIVE_SESSIONS: usize = 50;
/// Poll interval for session directory checks.
const POLL_INTERVAL_SECS: u64 = 60;

/// Track file sizes for growth detection.
struct FileTracker {
    sizes: HashMap<PathBuf, u64>,
}

impl FileTracker {
    fn new() -> Self {
        Self { sizes: HashMap::new() }
    }

    /// Scan a directory and return alerts for anomalies.
    fn check_directory(&mut self, sessions_dir: &Path) -> Vec<Alert> {
        let mut alerts = Vec::new();

        if !sessions_dir.exists() {
            return alerts;
        }

        let entries = match std::fs::read_dir(sessions_dir) {
            Ok(e) => e,
            Err(_) => return alerts,
        };

        let mut current_files: HashMap<PathBuf, u64> = HashMap::new();
        let mut session_count = 0;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                session_count += 1;
                if let Ok(meta) = std::fs::metadata(&path) {
                    let size = meta.len();
                    current_files.insert(path.clone(), size);

                    // Check for oversized session logs
                    if size > MAX_SESSION_LOG_SIZE {
                        alerts.push(Alert::new(
                            Severity::Warning,
                            "session_log",
                            &format!("Session log {} exceeds {}MB ({:.1}MB) — possible data dumping",
                                path.display(), MAX_SESSION_LOG_SIZE / (1024 * 1024),
                                size as f64 / (1024.0 * 1024.0)),
                        ));
                    }
                }
            }
        }

        // Check for unusually high session count
        if session_count > MAX_ACTIVE_SESSIONS {
            alerts.push(Alert::new(
                Severity::Warning,
                "session_log",
                &format!("Unusually high session count: {} (threshold: {})",
                    session_count, MAX_ACTIVE_SESSIONS),
            ));
        }

        // Check for deleted files (present in tracker but gone now)
        let deleted: Vec<PathBuf> = self.sizes.keys()
            .filter(|p| !current_files.contains_key(*p))
            .cloned()
            .collect();

        for deleted_path in deleted {
            alerts.push(Alert::new(
                Severity::Critical,
                "session_log",
                &format!("Session log deleted (tampering): {}", deleted_path.display()),
            ));
            self.sizes.remove(&deleted_path);
        }

        // Update tracker
        self.sizes = current_files;

        alerts
    }
}

/// Tail session logs directory, emitting alerts for anomalies.
pub async fn tail_session_logs(state_dir: String, tx: mpsc::Sender<Alert>) {
    let sessions_dir = Path::new(&state_dir).join("agents/main/sessions");
    let mut tracker = FileTracker::new();

    loop {
        let alerts = tracker.check_directory(&sessions_dir);
        for alert in alerts {
            if tx.send(alert).await.is_err() {
                return; // Channel closed
            }
        }
        sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;
    }
}

/// Check a sessions directory for anomalies (testable helper).
///
/// Returns a list of issues found. This is the pure-logic counterpart
/// of `tail_session_logs` for use in tests.
pub fn check_sessions_directory(sessions_dir: &Path, previous_files: &HashMap<PathBuf, u64>) -> (Vec<String>, HashMap<PathBuf, u64>) {
    let mut issues = Vec::new();
    let mut current_files: HashMap<PathBuf, u64> = HashMap::new();

    if !sessions_dir.exists() {
        return (issues, current_files);
    }

    let entries = match std::fs::read_dir(sessions_dir) {
        Ok(e) => e,
        Err(_) => return (issues, current_files),
    };

    let mut session_count = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            session_count += 1;
            if let Ok(meta) = std::fs::metadata(&path) {
                current_files.insert(path.clone(), meta.len());

                if meta.len() > MAX_SESSION_LOG_SIZE {
                    issues.push(format!("oversized: {}", path.display()));
                }
            }
        }
    }

    if session_count > MAX_ACTIVE_SESSIONS {
        issues.push(format!("high_count: {}", session_count));
    }

    // Check for deletions
    for prev_path in previous_files.keys() {
        if !current_files.contains_key(prev_path) {
            issues.push(format!("deleted: {}", prev_path.display()));
        }
    }

    (issues, current_files)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_directory() {
        let dir = tempfile::tempdir().unwrap();
        let (issues, files) = check_sessions_directory(dir.path(), &HashMap::new());
        assert!(issues.is_empty());
        assert!(files.is_empty());
    }

    #[test]
    fn test_nonexistent_directory() {
        let (issues, files) = check_sessions_directory(
            Path::new("/nonexistent/sessions/12345"), &HashMap::new());
        assert!(issues.is_empty());
        assert!(files.is_empty());
    }

    #[test]
    fn test_normal_session_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("session1.jsonl"), "small data").unwrap();
        std::fs::write(dir.path().join("session2.jsonl"), "small data").unwrap();
        let (issues, files) = check_sessions_directory(dir.path(), &HashMap::new());
        assert!(issues.is_empty());
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn test_deleted_file_detected() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("session1.jsonl");
        std::fs::write(&file_path, "data").unwrap();

        // First scan
        let (_, files) = check_sessions_directory(dir.path(), &HashMap::new());
        assert_eq!(files.len(), 1);

        // Delete the file
        std::fs::remove_file(&file_path).unwrap();

        // Second scan with previous state
        let (issues, _) = check_sessions_directory(dir.path(), &files);
        assert!(issues.iter().any(|i| i.starts_with("deleted:")));
    }

    #[test]
    fn test_file_tracker_deletion() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("session.jsonl");
        std::fs::write(&file_path, "data").unwrap();

        let mut tracker = FileTracker::new();
        let alerts = tracker.check_directory(dir.path());
        assert!(alerts.is_empty());

        std::fs::remove_file(&file_path).unwrap();
        let alerts = tracker.check_directory(dir.path());
        assert!(alerts.iter().any(|a| a.message.contains("deleted")));
    }
}
