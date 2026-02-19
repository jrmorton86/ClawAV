// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Audit log tampering detection.
//!
//! Monitors the audit log file for four indicators of evidence destruction:
//! - **Missing**: file no longer exists
//! - **Replaced**: inode changed (file was recreated), distinguishing log rotation
//! - **Truncated**: file size decreased
//! - **Content modified**: SHA-256 hash of content changed (catches same-size overwrites)
//!
//! Also provides a scanner function to check log file permissions.

use std::path::{Path, PathBuf};
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

use crate::core::alerts::{Alert, Severity};

/// Monitor audit log file for tampering indicators
pub async fn monitor_log_integrity(
    log_path: PathBuf,
    tx: mpsc::Sender<Alert>,
    interval_secs: u64,
) {
    let mut last_size: Option<u64> = None;
    let mut last_inode: Option<u64> = None;
    let mut last_hash: Option<String> = None;

    loop {
        if let Some(alert) = check_log_file(&log_path, &mut last_size, &mut last_inode, &mut last_hash) {
            let _ = tx.send(alert).await;
        }
        sleep(Duration::from_secs(interval_secs)).await;
    }
}

fn check_log_file(
    path: &Path,
    last_size: &mut Option<u64>,
    last_inode: &mut Option<u64>,
    last_hash: &mut Option<String>,
) -> Option<Alert> {
    use std::os::unix::fs::MetadataExt;

    // Use symlink_metadata (lstat) to avoid following symlinks.
    // An attacker replacing the audit log with a symlink would fool stat().
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(m) => {
            if m.file_type().is_symlink() {
                return Some(Alert::new(
                    Severity::Critical,
                    "logtamper",
                    &format!("Audit log {} is a SYMLINK — possible evidence redirection attack", path.display()),
                ));
            }
            m
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return Some(Alert::new(
                Severity::Warning,
                "logtamper",
                &format!("Cannot read audit log {} — permission denied (run as root for full monitoring)", path.display()),
            ));
        }
        Err(_) => {
            return Some(Alert::new(
                Severity::Critical,
                "logtamper",
                &format!("Audit log MISSING: {} — possible evidence destruction", path.display()),
            ));
        }
    };

    let current_size = metadata.len();
    let current_inode = metadata.ino();

    // Check for inode change (file was replaced/recreated)
    if let Some(prev_inode) = *last_inode {
        if current_inode != prev_inode {
            *last_inode = Some(current_inode);
            // Check if this is log rotation (rotated file exists)
            if crate::sentinel::is_log_rotation(&path.to_string_lossy()) {
                *last_size = Some(current_size);
                return Some(Alert::new(
                    Severity::Info,
                    "logtamper/rotation",
                    &format!("Log rotated: {} — inode {} → {} (rotation detected)",
                        path.display(), prev_inode, current_inode),
                ));
            }
            *last_size = Some(current_size);
            return Some(Alert::new(
                Severity::Critical,
                "logtamper",
                &format!(
                    "Audit log REPLACED: {} — inode changed from {} to {} — possible tampering",
                    path.display(), prev_inode, current_inode
                ),
            ));
        }
    }

    // Check for size decrease (file was truncated)
    if let Some(prev_size) = *last_size {
        if current_size < prev_size {
            *last_size = Some(current_size);
            return Some(Alert::new(
                Severity::Critical,
                "logtamper",
                &format!(
                    "Audit log TRUNCATED: {} — size decreased from {} to {} bytes — possible evidence destruction",
                    path.display(), prev_size, current_size
                ),
            ));
        }
    }

    // Content integrity check (SHA-256 of first 64KB + last 64KB)
    // Only alert on hash change when size is unchanged — a same-size overwrite attack.
    // When the file grows (normal log append), just update the hash silently.
    if let Ok(content) = std::fs::read(path) {
        let hash = {
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            // Hash first 64KB and last 64KB (efficient for large files)
            let chunk_size = 65536;
            if content.len() <= chunk_size * 2 {
                hasher.update(&content);
            } else {
                hasher.update(&content[..chunk_size]);
                hasher.update(&content[content.len() - chunk_size..]);
            }
            format!("{:x}", hasher.finalize())
        };

        if let Some(ref prev_hash) = *last_hash {
            let size_unchanged = last_size.map_or(false, |s| s == current_size);
            if hash != *prev_hash && size_unchanged {
                *last_hash = Some(hash);
                *last_size = Some(current_size);
                *last_inode = Some(current_inode);
                return Some(Alert::new(
                    Severity::Critical,
                    "logtamper",
                    &format!("Audit log CONTENT MODIFIED: {} — hash changed without size change", path.display()),
                ));
            }
        }
        *last_hash = Some(hash);
    }

    // Update tracking state
    *last_size = Some(current_size);
    *last_inode = Some(current_inode);

    None
}

/// Scanner integration: check audit log health
pub fn scan_audit_log_health(log_path: &Path) -> crate::scanner::ScanResult {
    use crate::scanner::{ScanResult, ScanStatus};

    match std::fs::metadata(log_path) {
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return ScanResult::new("audit_log", ScanStatus::Warn, 
                "Cannot access audit log — permission denied (run as root)");
        }
        Err(_) => {
            return ScanResult::new("audit_log", ScanStatus::Fail, "Audit log file does not exist");
        }
        Ok(_) => {} // exists and accessible, continue checks
    }

    match std::fs::metadata(log_path) {
        Ok(metadata) => {
            use std::os::unix::fs::MetadataExt;
            let size = metadata.len();
            let mode = metadata.mode();

            // Check permissions (should be 600 or 640)
            let world_readable = mode & 0o004 != 0;
            let world_writable = mode & 0o002 != 0;

            if world_writable {
                ScanResult::new("audit_log", ScanStatus::Fail, 
                    &format!("Audit log is world-writable (mode {:o}) — anyone can tamper", mode & 0o777))
            } else if world_readable {
                ScanResult::new("audit_log", ScanStatus::Warn, 
                    &format!("Audit log is world-readable (mode {:o})", mode & 0o777))
            } else if size == 0 {
                ScanResult::new("audit_log", ScanStatus::Warn, "Audit log is empty (0 bytes)")
            } else {
                ScanResult::new("audit_log", ScanStatus::Pass, 
                    &format!("Audit log healthy: {} bytes, mode {:o}", size, mode & 0o777))
            }
        }
        Err(e) => ScanResult::new("audit_log", ScanStatus::Fail, &format!("Cannot stat audit log: {}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_missing_log_triggers_critical() {
        let mut last_size = Some(1000);
        let mut last_inode = Some(12345);
        let mut last_hash = None;
        let alert = check_log_file(Path::new("/nonexistent/audit.log"), &mut last_size, &mut last_inode, &mut last_hash);
        assert!(alert.is_some());
        let alert = alert.unwrap();
        assert_eq!(alert.severity, Severity::Critical);
        assert!(alert.message.contains("MISSING"));
    }

    #[test]
    fn test_first_check_no_alert() {
        // Use /dev/null as a file that exists
        let mut last_size = None;
        let mut last_inode = None;
        let mut last_hash = None;
        let alert = check_log_file(Path::new("/dev/null"), &mut last_size, &mut last_inode, &mut last_hash);
        assert!(alert.is_none());
        assert!(last_size.is_some());
        assert!(last_inode.is_some());
    }

    #[test]
    fn test_size_decrease_triggers_truncation_alert() {
        let mut last_size = Some(10000);
        let mut last_inode = None;
        let mut last_hash = None;
        // /dev/null has size 0, so this simulates truncation
        let alert = check_log_file(Path::new("/dev/null"), &mut last_size, &mut last_inode, &mut last_hash);
        // First call sets inode, but since last_inode was None, no inode change alert
        // Size check: 0 < 10000 = truncation
        assert!(alert.is_some());
        let alert = alert.unwrap();
        assert_eq!(alert.severity, Severity::Critical);
        assert!(alert.message.contains("TRUNCATED"));
    }

    #[test]
    fn test_scan_audit_log_missing() {
        let result = scan_audit_log_health(Path::new("/nonexistent/audit.log"));
        assert_eq!(result.status, crate::scanner::ScanStatus::Fail);
    }

    // --- NEW REGRESSION TESTS ---

    #[test]
    fn test_normal_growth_no_alert() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        std::fs::write(&path, "initial content").unwrap();

        let mut last_size = None;
        let mut last_inode = None;
        let mut last_hash = None;

        // First check: baseline
        let alert = check_log_file(&path, &mut last_size, &mut last_inode, &mut last_hash);
        assert!(alert.is_none());

        // Grow the file
        std::fs::write(&path, "initial content\nmore data here\neven more").unwrap();

        let alert = check_log_file(&path, &mut last_size, &mut last_inode, &mut last_hash);
        assert!(alert.is_none(), "Growing file should not alert");
    }

    #[test]
    fn test_size_decrease_with_real_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        std::fs::write(&path, "lots of audit data here that is quite long").unwrap();

        let mut last_size = None;
        let mut last_inode = None;
        let mut last_hash = None;

        // Baseline
        check_log_file(&path, &mut last_size, &mut last_inode, &mut last_hash);

        // Truncate
        std::fs::write(&path, "short").unwrap();

        let alert = check_log_file(&path, &mut last_size, &mut last_inode, &mut last_hash);
        assert!(alert.is_some());
        let alert = alert.unwrap();
        assert_eq!(alert.severity, Severity::Critical);
        assert!(alert.message.contains("TRUNCATED"));
    }

    #[test]
    fn test_same_size_no_alert() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        std::fs::write(&path, "exact").unwrap();

        let mut last_size = None;
        let mut last_inode = None;
        let mut last_hash = None;

        check_log_file(&path, &mut last_size, &mut last_inode, &mut last_hash);
        // Same content = same size = same hash
        let alert = check_log_file(&path, &mut last_size, &mut last_inode, &mut last_hash);
        assert!(alert.is_none(), "Same size should not alert");
    }

    #[test]
    fn test_file_deleted_after_baseline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        std::fs::write(&path, "content").unwrap();

        let mut last_size = None;
        let mut last_inode = None;
        let mut last_hash = None;

        check_log_file(&path, &mut last_size, &mut last_inode, &mut last_hash);
        std::fs::remove_file(&path).unwrap();

        let alert = check_log_file(&path, &mut last_size, &mut last_inode, &mut last_hash);
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn test_scan_audit_log_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        std::fs::write(&path, "").unwrap();
        // Set mode 600 so it doesn't hit world-readable check first
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let result = scan_audit_log_health(&path);
        assert_eq!(result.status, crate::scanner::ScanStatus::Warn);
        assert!(result.details.contains("empty"));
    }

    #[test]
    fn test_scan_audit_log_exists() {
        // /etc/passwd exists on all Linux systems
        let result = scan_audit_log_health(Path::new("/etc/passwd"));
        // Should pass or warn depending on permissions, but not fail
        assert_ne!(result.status, crate::scanner::ScanStatus::Fail);
    }

    #[test]
    fn test_content_overwrite_same_size_detected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        std::fs::write(&path, "original content here!").unwrap();

        let mut last_size = None;
        let mut last_inode = None;
        let mut last_hash = None;

        // Baseline
        let alert = check_log_file(&path, &mut last_size, &mut last_inode, &mut last_hash);
        assert!(alert.is_none());

        // Overwrite with same length but different content
        std::fs::write(&path, "tampered content here!").unwrap(); // same length
        let alert = check_log_file(&path, &mut last_size, &mut last_inode, &mut last_hash);
        assert!(alert.is_some(), "Same-size content overwrite must be detected");
        assert!(alert.unwrap().message.contains("CONTENT MODIFIED"));
    }
}