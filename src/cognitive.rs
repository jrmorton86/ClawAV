// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Cognitive file integrity monitoring for AI agent identity files.
//!
//! Maintains SHA-256 baselines of critical workspace files (SOUL.md, AGENTS.md,
//! IDENTITY.md, TOOLS.md, etc.) and checks for unauthorized modifications.
//!
//! Files are classified as either:
//! - **Protected**: modifications trigger Critical alerts (identity tampering)
//! - **Watched**: modifications are logged as Info with diffs, then auto-rebaselined
//!
//! Shadow copies in `/etc/clawtower/cognitive-shadow/` enable unified diff generation
//! for watched file changes.

use anyhow::Result;
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::safe_io::{atomic_write, mkdir_safe, open_nofollow, read_nofollow};
use crate::scanner::{ScanResult, ScanStatus};

/// Protected cognitive files — changes are CRIT (tampering)
const PROTECTED_FILES: &[&str] = &[
    "SOUL.md",
    "IDENTITY.md", 
    "TOOLS.md",
    "AGENTS.md",
    "USER.md",
    "HEARTBEAT.md",
];

/// Watched cognitive files — changes are INFO with diff, auto-rebaselined
const WATCHED_FILES: &[&str] = &[
    "MEMORY.md",
];

/// SHA-256 baseline store for cognitive identity files.
///
/// Tracks the expected hash of each protected and watched file. Baselines
/// can be saved to/loaded from a file for persistence across restarts.
pub struct CognitiveBaseline {
    baselines: HashMap<PathBuf, String>,
    workspace_dir: PathBuf,
}

impl CognitiveBaseline {
    /// Create baselines from current state of files
    pub fn from_workspace(workspace_dir: &Path) -> Self {
        let mut baselines = HashMap::new();
        for filename in PROTECTED_FILES.iter().chain(WATCHED_FILES.iter()) {
            let path = workspace_dir.join(filename);
            if path.exists() {
                if let Ok(hash) = compute_sha256(&path) {
                    baselines.insert(path, hash);
                }
            }
        }
        Self {
            baselines,
            workspace_dir: workspace_dir.to_path_buf(),
        }
    }

    /// Load baselines from a saved file
    pub fn load(baseline_path: &Path, workspace_dir: &Path) -> Result<Self> {
        let content = read_nofollow(baseline_path, None)?;
        let mut baselines = HashMap::new();
        for line in content.lines() {
            let parts: Vec<&str> = line.splitn(2, " ").collect();
            if parts.len() == 2 {
                baselines.insert(PathBuf::from(parts[1]), parts[0].to_string());
            }
        }
        Ok(Self {
            baselines,
            workspace_dir: workspace_dir.to_path_buf(),
        })
    }

    /// Save baselines to a file
    pub fn save(&self, baseline_path: &Path) -> Result<()> {
        let mut content = String::new();
        let mut sorted: Vec<_> = self.baselines.iter().collect();
        sorted.sort_by_key(|(p, _)| (*p).clone());
        for (path, hash) in sorted {
            content.push_str(&format!("{} {}\n", hash, path.display()));
        }
        if let Some(parent) = baseline_path.parent() {
            mkdir_safe(parent, 0o700)?;
        }
        atomic_write(baseline_path, content.as_bytes(), 0o600)?;
        Ok(())
    }

    /// Check all cognitive files against baselines
    pub fn check(&self) -> Vec<CognitiveAlert> {
        let mut alerts = Vec::new();
        let all_files: Vec<&str> = PROTECTED_FILES.iter().chain(WATCHED_FILES.iter()).copied().collect();

        // Check for modified or deleted files
        for (path, expected_hash) in &self.baselines {
            // Skip files no longer in our lists (stale baseline entries)
            let filename = path.file_name().unwrap_or_default().to_string_lossy();
            if !all_files.iter().any(|&f| f == filename.as_ref()) {
                continue;
            }

            let is_watched = WATCHED_FILES.iter().any(|&f| f == filename.as_ref());

            match std::fs::metadata(path) {
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    // Can't access file — skip, don't report as deleted
                    continue;
                }
                Err(_) => {
                    // File actually missing
                    alerts.push(CognitiveAlert {
                        file: path.clone(),
                        kind: CognitiveAlertKind::Deleted,
                        watched: is_watched,
                    });
                    continue;
                }
                Ok(_) => {}
            }
            if let Ok(current_hash) = compute_sha256(path) {
                if &current_hash != expected_hash {
                    let diff = if is_watched {
                        generate_diff(path, &self.workspace_dir)
                    } else {
                        None
                    };
                    alerts.push(CognitiveAlert {
                        file: path.clone(),
                        kind: CognitiveAlertKind::Modified { diff },
                        watched: is_watched,
                    });
                }
            }
        }

        // Check for new files that weren't in baseline
        for filename in &all_files {
            let path = self.workspace_dir.join(filename);
            if path.exists() && !self.baselines.contains_key(&path) {
                let is_watched = WATCHED_FILES.contains(filename);
                alerts.push(CognitiveAlert {
                    file: path,
                    kind: CognitiveAlertKind::NewFile,
                    watched: is_watched,
                });
            }
        }

        alerts
    }

    /// Update baseline for a single file
    pub fn update_file(&mut self, path: &Path) {
        if path.exists() {
            if let Ok(hash) = compute_sha256(path) {
                self.baselines.insert(path.to_path_buf(), hash);
            }
        }
    }

    /// Update baselines to current state
    #[allow(dead_code)]
    pub fn rebaseline(&mut self) {
        self.baselines.clear();
        for filename in PROTECTED_FILES.iter().chain(WATCHED_FILES.iter()) {
            let path = self.workspace_dir.join(filename);
            if path.exists() {
                if let Ok(hash) = compute_sha256(&path) {
                    self.baselines.insert(path, hash);
                }
            }
        }
    }
}

/// Alert from the cognitive integrity checker.
#[derive(Debug, Clone)]
pub struct CognitiveAlert {
    pub file: PathBuf,
    pub kind: CognitiveAlertKind,
    /// If true, this is a watched (mutable) file — report as info, not critical
    pub watched: bool,
}

/// What kind of change was detected on a cognitive file.
#[derive(Debug, Clone)]
pub enum CognitiveAlertKind {
    Modified { diff: Option<String> },
    Deleted,
    NewFile,
}

impl std::fmt::Display for CognitiveAlert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let filename = self.file.file_name().unwrap_or_default().to_string_lossy();
        match &self.kind {
            CognitiveAlertKind::Modified { diff: Some(d) } => {
                write!(f, "{} updated:\n{}", filename, d)
            }
            CognitiveAlertKind::Modified { diff: None } => {
                write!(f, "{} has been modified", filename)
            }
            CognitiveAlertKind::Deleted => write!(f, "{} has been deleted", filename),
            CognitiveAlertKind::NewFile => write!(f, "{} is new (no baseline)", filename),
        }
    }
}

fn compute_sha256(path: &Path) -> Result<String> {
    let mut file = open_nofollow(path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    let hash = Sha256::digest(&data);
    Ok(hex::encode(hash))
}

/// Shadow directory for storing previous versions of watched files
const SHADOW_DIR: &str = "/etc/clawtower/cognitive-shadow";

/// Generate a unified diff between the shadow (previous) and current version
fn generate_diff(current_path: &Path, _workspace_dir: &Path) -> Option<String> {
    let filename = current_path.file_name()?.to_string_lossy();
    let shadow_path = PathBuf::from(SHADOW_DIR).join(filename.as_ref());

    let current = read_nofollow(current_path, None).ok()?;

    if !shadow_path.exists() {
        // No previous version — show summary
        let lines: Vec<&str> = current.lines().collect();
        return Some(format!("(new file, {} lines)", lines.len()));
    }

    let previous = read_nofollow(&shadow_path, None).ok()?;
    if previous == current {
        return None;
    }

    // Simple line-based diff
    let old_lines: Vec<&str> = previous.lines().collect();
    let new_lines: Vec<&str> = current.lines().collect();

    let mut diff_lines = Vec::new();
    let mut added = 0;
    let mut removed = 0;

    // Find removed lines (in old but not in new)
    for line in &old_lines {
        if !new_lines.contains(line) {
            removed += 1;
            if diff_lines.len() < 15 {
                diff_lines.push(format!("- {}", line));
            }
        }
    }

    // Find added lines (in new but not in old)
    for line in &new_lines {
        if !old_lines.contains(line) {
            added += 1;
            if diff_lines.len() < 15 {
                diff_lines.push(format!("+ {}", line));
            }
        }
    }

    let total_changes = added + removed;
    if total_changes == 0 {
        return None;
    }

    let mut result = format!("+{} -{} lines", added, removed);
    if !diff_lines.is_empty() {
        result.push('\n');
        result.push_str(&diff_lines.join("\n"));
        if total_changes > 15 {
            result.push_str(&format!("\n... and {} more changes", total_changes - diff_lines.len()));
        }
    }

    Some(result)
}

/// Save current version to shadow directory for future diffs
fn save_shadow(path: &Path) {
    if let Some(filename) = path.file_name() {
        let shadow_dir = Path::new(SHADOW_DIR);
        let _ = mkdir_safe(shadow_dir, 0o700);
        let shadow_path = shadow_dir.join(filename);
        if let Ok(content) = read_nofollow(path, None) {
            let _ = atomic_write(&shadow_path, content.as_bytes(), 0o600);
        }
    }
}

/// Scanner integration: check cognitive file integrity against baselines.
///
/// Creates baselines on first run, then checks for modifications, deletions,
/// and new files. Protected file changes are CRIT; watched file changes are WARN
/// with auto-rebaseline.
pub fn scan_cognitive_integrity(workspace_dir: &Path, baseline_path: &Path, _barnacle: Option<&crate::barnacle::BarnacleEngine>) -> Vec<ScanResult> {
    // If no baseline exists yet, create one and save shadows
    if !baseline_path.exists() {
        let baseline = CognitiveBaseline::from_workspace(workspace_dir);
        if baseline.baselines.is_empty() {
            return vec![ScanResult::new("cognitive", ScanStatus::Warn, "No cognitive files found in workspace")];
        }
        // Save shadows for watched files
        for filename in WATCHED_FILES {
            let path = workspace_dir.join(filename);
            if path.exists() {
                save_shadow(&path);
            }
        }
        match baseline.save(baseline_path) {
            Ok(_) => return vec![ScanResult::new("cognitive", ScanStatus::Pass, 
                &format!("Created baselines for {} cognitive files", baseline.baselines.len()))],
            Err(e) => return vec![ScanResult::new("cognitive", ScanStatus::Warn, 
                &format!("Cannot save baselines: {}", e))],
        }
    }

    // Load and check
    match CognitiveBaseline::load(baseline_path, workspace_dir) {
        Ok(mut baseline) => {
            let alerts = baseline.check();
            if alerts.is_empty() {
                return vec![ScanResult::new("cognitive", ScanStatus::Pass, "All cognitive files intact")];
            }

            let mut results = Vec::new();
            let mut has_protected_alerts = false;
            let mut protected_details = Vec::new();

            for alert in &alerts {
                if alert.watched {
                    // Watched files (MEMORY.md) are mutable working documents — they legitimately
                    // contain command references, IPs, paths, etc. as technical documentation.
                    // Do NOT run Barnacle content scanning on them (too many false positives).
                    // Barnacle scanning is reserved for protected identity files only.
                    
                    // Clean change — report diff, rebaseline
                    results.push(ScanResult::new("cognitive", ScanStatus::Warn,
                        &format!("📝 {}", alert)));
                    baseline.update_file(&alert.file);
                    save_shadow(&alert.file);
                } else {
                    // Protected file changed — CRIT
                    has_protected_alerts = true;
                    protected_details.push(alert.to_string());
                }
            }

            if has_protected_alerts {
                results.push(ScanResult::new("cognitive", ScanStatus::Fail,
                    &format!("TAMPERING DETECTED: {}", protected_details.join("; "))));
            }

            // Save updated baselines for watched files
            let _ = baseline.save(baseline_path);

            results
        }
        Err(e) => vec![ScanResult::new("cognitive", ScanStatus::Warn, 
            &format!("Cannot load baselines: {}", e))],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_baseline_creation() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("SOUL.md"), "I am an agent").unwrap();
        fs::write(dir.path().join("IDENTITY.md"), "Name: Claw").unwrap();

        let baseline = CognitiveBaseline::from_workspace(dir.path());
        assert_eq!(baseline.baselines.len(), 2);
    }

    #[test]
    fn test_baseline_includes_watched() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("SOUL.md"), "I am an agent").unwrap();
        fs::write(dir.path().join("MEMORY.md"), "memories").unwrap();

        let baseline = CognitiveBaseline::from_workspace(dir.path());
        assert_eq!(baseline.baselines.len(), 2);
    }

    #[test]
    fn test_detect_modification() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("SOUL.md"), "I am an agent").unwrap();

        let baseline = CognitiveBaseline::from_workspace(dir.path());

        // Modify the file
        fs::write(dir.path().join("SOUL.md"), "I am now evil").unwrap();

        let alerts = baseline.check();
        assert_eq!(alerts.len(), 1);
        assert!(matches!(alerts[0].kind, CognitiveAlertKind::Modified { .. }));
        assert!(!alerts[0].watched);
    }

    #[test]
    fn test_watched_file_modification() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("MEMORY.md"), "old memories").unwrap();

        let baseline = CognitiveBaseline::from_workspace(dir.path());

        fs::write(dir.path().join("MEMORY.md"), "new memories").unwrap();

        let alerts = baseline.check();
        assert_eq!(alerts.len(), 1);
        assert!(matches!(alerts[0].kind, CognitiveAlertKind::Modified { .. }));
        assert!(alerts[0].watched);
    }

    #[test]
    fn test_detect_deletion() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("SOUL.md"), "I am an agent").unwrap();

        let baseline = CognitiveBaseline::from_workspace(dir.path());

        // Delete the file
        fs::remove_file(dir.path().join("SOUL.md")).unwrap();

        let alerts = baseline.check();
        assert_eq!(alerts.len(), 1);
        assert!(matches!(alerts[0].kind, CognitiveAlertKind::Deleted));
    }

    #[test]
    fn test_detect_new_file() {
        let dir = TempDir::new().unwrap();
        let baseline = CognitiveBaseline::from_workspace(dir.path());

        // Create a new cognitive file
        fs::write(dir.path().join("SOUL.md"), "surprise").unwrap();

        let alerts = baseline.check();
        assert_eq!(alerts.len(), 1);
        assert!(matches!(alerts[0].kind, CognitiveAlertKind::NewFile));
    }

    #[test]
    fn test_no_changes_passes() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("SOUL.md"), "I am an agent").unwrap();
        fs::write(dir.path().join("TOOLS.md"), "my tools").unwrap();

        let baseline = CognitiveBaseline::from_workspace(dir.path());
        let alerts = baseline.check();
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_save_and_load() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("SOUL.md"), "I am an agent").unwrap();

        let baseline = CognitiveBaseline::from_workspace(dir.path());
        let baseline_path = dir.path().join("baselines.sha256");
        baseline.save(&baseline_path).unwrap();

        let loaded = CognitiveBaseline::load(&baseline_path, dir.path()).unwrap();
        assert_eq!(loaded.baselines.len(), 1);

        let alerts = loaded.check();
        assert!(alerts.is_empty());
    }

    // --- NEW REGRESSION TESTS ---

    #[test]
    fn test_all_protected_files_classified() {
        // Ensure every PROTECTED_FILE is actually checked
        for filename in PROTECTED_FILES {
            assert!(!filename.is_empty());
            assert!(filename.ends_with(".md"), "Protected files should be markdown: {}", filename);
        }
    }

    #[test]
    fn test_all_watched_files_classified() {
        for filename in WATCHED_FILES {
            assert!(!filename.is_empty());
        }
        assert!(WATCHED_FILES.contains(&"MEMORY.md"), "MEMORY.md must be watched");
    }

    #[test]
    fn test_protected_and_watched_no_overlap() {
        for f in PROTECTED_FILES {
            assert!(!WATCHED_FILES.contains(f),
                "{} is in both PROTECTED and WATCHED — must be one or the other", f);
        }
    }

    #[test]
    fn test_update_file_rebaselines_single() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("SOUL.md"), "original").unwrap();

        let mut baseline = CognitiveBaseline::from_workspace(dir.path());
        fs::write(dir.path().join("SOUL.md"), "modified").unwrap();

        assert_eq!(baseline.check().len(), 1);
        baseline.update_file(&dir.path().join("SOUL.md"));
        assert!(baseline.check().is_empty(), "After update_file, no alerts");
    }

    #[test]
    fn test_multiple_files_modified() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("SOUL.md"), "soul").unwrap();
        fs::write(dir.path().join("TOOLS.md"), "tools").unwrap();
        fs::write(dir.path().join("MEMORY.md"), "memory").unwrap();

        let baseline = CognitiveBaseline::from_workspace(dir.path());

        fs::write(dir.path().join("SOUL.md"), "evil soul").unwrap();
        fs::write(dir.path().join("TOOLS.md"), "evil tools").unwrap();
        fs::write(dir.path().join("MEMORY.md"), "new memory").unwrap();

        let alerts = baseline.check();
        assert_eq!(alerts.len(), 3);

        let protected_count = alerts.iter().filter(|a| !a.watched).count();
        let watched_count = alerts.iter().filter(|a| a.watched).count();
        assert_eq!(protected_count, 2, "SOUL.md and TOOLS.md are protected");
        assert_eq!(watched_count, 1, "MEMORY.md is watched");
    }

    #[test]
    fn test_baseline_save_format() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("SOUL.md"), "test content").unwrap();

        let baseline = CognitiveBaseline::from_workspace(dir.path());
        let bp = dir.path().join("baselines.sha256");
        baseline.save(&bp).unwrap();

        let content = fs::read_to_string(&bp).unwrap();
        // Format: "hash path\n"
        for line in content.lines() {
            let parts: Vec<&str> = line.splitn(2, ' ').collect();
            assert_eq!(parts.len(), 2, "Baseline line should be 'hash path'");
            assert_eq!(parts[0].len(), 64, "SHA-256 hash should be 64 hex chars");
        }
    }

    #[test]
    fn test_cognitive_alert_display() {
        let alert = CognitiveAlert {
            file: PathBuf::from("/test/SOUL.md"),
            kind: CognitiveAlertKind::Deleted,
            watched: false,
        };
        let s = format!("{}", alert);
        assert!(s.contains("SOUL.md"));
        assert!(s.contains("deleted"));
    }

    #[test]
    fn test_compute_sha256_deterministic() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.txt");
        fs::write(&path, "hello world").unwrap();

        let h1 = compute_sha256(&path).unwrap();
        let h2 = compute_sha256(&path).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn test_empty_workspace_no_baselines() {
        let dir = TempDir::new().unwrap();
        let baseline = CognitiveBaseline::from_workspace(dir.path());
        assert!(baseline.baselines.is_empty());
        assert!(baseline.check().is_empty());
    }

    #[test]
    fn test_rebaseline() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("SOUL.md"), "original").unwrap();

        let mut baseline = CognitiveBaseline::from_workspace(dir.path());
        fs::write(dir.path().join("SOUL.md"), "modified").unwrap();

        // Before rebaseline: detects change
        assert_eq!(baseline.check().len(), 1);

        // After rebaseline: clean
        baseline.rebaseline();
        assert!(baseline.check().is_empty());
    }
}
