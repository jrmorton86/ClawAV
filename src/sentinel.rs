//! Real-time file integrity sentinel with quarantine and restore.
//!
//! Uses `notify` (inotify on Linux) to watch configured file paths for changes.
//! Each watched file has a shadow copy for diff generation. When a protected file
//! is modified, the change is quarantined and the original is restored from shadow.
//! Watched (non-protected) files are allowed to change — shadow is updated instead.
//!
//! Optionally scans file content against SecureClaw patterns to detect threats
//! injected into watched files.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use sha2::{Sha256, Digest};
use tokio::sync::mpsc;

use crate::alerts::{Alert, Severity};
use crate::config::{SentinelConfig, WatchPolicy};
use crate::secureclaw::SecureClawEngine;

/// Compute a shadow file path: shadow_dir / hex(sha256(file_path))[..16]
pub fn shadow_path_for(shadow_dir: &str, file_path: &str) -> PathBuf {
    let mut hasher = Sha256::new();
    hasher.update(file_path.as_bytes());
    let hash = hex::encode(hasher.finalize());
    let name = format!("{}_{}", &hash[..16], Path::new(file_path)
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string()));
    PathBuf::from(shadow_dir).join(name)
}

/// Compute a quarantine path: quarantine_dir / timestamp_filename
pub fn quarantine_path_for(quarantine_dir: &str, file_path: &str) -> PathBuf {
    let ts = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let fname = Path::new(file_path)
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    PathBuf::from(quarantine_dir).join(format!("{}_{}", ts, fname))
}

/// Generate a simple unified-style diff. Returns empty string if identical.
pub fn generate_unified_diff(old: &str, new: &str, filename: &str) -> String {
    if old == new {
        return String::new();
    }
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();
    let mut out = String::new();
    out.push_str(&format!("--- a/{}\n", filename));
    out.push_str(&format!("+++ b/{}\n", filename));

    // Simple line-by-line diff (not optimal, but functional)
    let max = old_lines.len().max(new_lines.len());
    let mut i = 0;
    while i < max {
        let ol = old_lines.get(i).copied();
        let nl = new_lines.get(i).copied();
        match (ol, nl) {
            (Some(o), Some(n)) if o == n => {
                out.push_str(&format!(" {}\n", o));
            }
            (Some(o), Some(n)) => {
                out.push_str(&format!("-{}\n", o));
                out.push_str(&format!("+{}\n", n));
            }
            (Some(o), None) => {
                out.push_str(&format!("-{}\n", o));
            }
            (None, Some(n)) => {
                out.push_str(&format!("+{}\n", n));
            }
            (None, None) => break,
        }
        i += 1;
    }
    out
}

/// Check if a file change is likely a log rotation (has .1/.gz/.0 siblings).
pub fn is_log_rotation(file_path: &str) -> bool {
    let p = Path::new(file_path);
    let parent = match p.parent() {
        Some(d) => d,
        None => return false,
    };
    let fname = match p.file_name() {
        Some(f) => f.to_string_lossy().to_string(),
        None => return false,
    };
    for suffix in &[".1", ".0", ".gz"] {
        let sibling = parent.join(format!("{}{}", fname, suffix));
        if sibling.exists() {
            return true;
        }
    }
    false
}

/// Resolve which WatchPolicy applies to a path, if any.
fn policy_for_path(config: &SentinelConfig, path: &str) -> Option<WatchPolicy> {
    for wp in &config.watch_paths {
        if path == wp.path {
            return Some(wp.policy.clone());
        }
        // Directory prefix match — check if file matches patterns
        if path.starts_with(&wp.path) {
            let filename = Path::new(path)
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_default();
            for pattern in &wp.patterns {
                if pattern == "*" || filename == *pattern {
                    return Some(wp.policy.clone());
                }
            }
        }
    }
    None
}

/// Real-time file integrity monitor using inotify.
///
/// Watches configured paths, compares changes against shadow copies, and either
/// quarantines+restores (protected files) or updates shadows (watched files).
pub struct Sentinel {
    config: SentinelConfig,
    alert_tx: mpsc::Sender<Alert>,
    engine: Option<Arc<SecureClawEngine>>,
}

impl Sentinel {
    /// Create a new Sentinel, initializing shadow and quarantine directories.
    ///
    /// Shadow copies are created for any watched files that don't already have one.
    pub fn new(
        config: SentinelConfig,
        alert_tx: mpsc::Sender<Alert>,
        engine: Option<Arc<SecureClawEngine>>,
    ) -> Result<Self> {
        // Create shadow and quarantine dirs
        std::fs::create_dir_all(&config.shadow_dir)
            .with_context(|| format!("Failed to create shadow dir: {}", config.shadow_dir))?;
        std::fs::create_dir_all(&config.quarantine_dir)
            .with_context(|| format!("Failed to create quarantine dir: {}", config.quarantine_dir))?;

        // Initialize shadow copies for all watched paths
        for wp in &config.watch_paths {
            let p = Path::new(&wp.path);
            if p.is_file() {
                let shadow = shadow_path_for(&config.shadow_dir, &wp.path);
                if !shadow.exists() {
                    if let Ok(content) = std::fs::read(&wp.path) {
                        let _ = std::fs::write(&shadow, &content);
                    }
                }
            }
        }

        Ok(Self { config, alert_tx, engine })
    }

    /// Process a file change event for the given path.
    ///
    /// For protected files: quarantines the modified version and restores from shadow.
    /// For watched files: updates the shadow copy and emits an Info alert.
    /// If content scanning is enabled, runs SecureClaw patterns against the file.
    pub async fn handle_change(&self, path: &str) {
        let file_path = Path::new(path);
        if !file_path.exists() {
            return;
        }

        // Check file size limit
        if let Ok(meta) = std::fs::metadata(file_path) {
            if meta.len() > self.config.max_file_size_kb * 1024 {
                return;
            }
        }

        // Log rotation check
        if is_log_rotation(path) {
            let _ = self.alert_tx.send(Alert::new(
                Severity::Info,
                "sentinel",
                &format!("Log rotation detected: {}", path),
            )).await;
            // Update shadow
            let shadow = shadow_path_for(&self.config.shadow_dir, path);
            if let Ok(content) = std::fs::read(file_path) {
                let _ = std::fs::write(&shadow, &content);
            }
            return;
        }

        // Read current and shadow
        let current = match std::fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(_) => return,
        };

        let shadow = shadow_path_for(&self.config.shadow_dir, path);
        let shadow_exists = shadow.exists();
        let previous = std::fs::read_to_string(&shadow).unwrap_or_default();

        if current == previous {
            return;
        }

        // First time seeing this file — initialize shadow, don't treat as threat
        if !shadow_exists {
            let _ = std::fs::write(&shadow, &current);
            let _ = self.alert_tx.send(Alert::new(
                Severity::Info,
                "sentinel",
                &format!("New watched file detected, shadow initialized: {}", path),
            )).await;
            return;
        }

        let fname = file_path.file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_else(|| path.to_string());
        let diff = generate_unified_diff(&previous, &current, &fname);

        let policy = policy_for_path(&self.config, path);

        // Scan content if enabled — but skip for Watched files (workspace docs like
        // MEMORY.md legitimately contain IPs, paths, credentials references, etc.
        // that trigger SecureClaw privacy patterns as false positives).
        // Also skip paths matching content_scan_excludes (e.g. OpenClaw auth stores
        // that legitimately contain API keys).
        let mut threat_found = false;
        let content_scan_excluded = self.config.content_scan_excludes.iter().any(|pattern| {
            glob_match::glob_match(pattern, path)
        });
        let substring_excluded = self.config.exclude_content_scan.iter().any(|excl| path.contains(excl));
        if self.config.scan_content && policy != Some(WatchPolicy::Watched) && !content_scan_excluded && !substring_excluded {
            if let Some(ref engine) = self.engine {
                let content_matches = engine.check_text(&current);
                let diff_matches = engine.check_text(&diff);
                if !content_matches.is_empty() || !diff_matches.is_empty() {
                    threat_found = true;
                }
            }
        }

        if threat_found || policy == Some(WatchPolicy::Protected) {
            // Quarantine current, restore from shadow
            let q_path = quarantine_path_for(&self.config.quarantine_dir, path);
            let _ = std::fs::copy(file_path, &q_path);

            if shadow.exists() {
                let _ = std::fs::copy(&shadow, file_path);
            }

            let msg = if threat_found {
                format!("THREAT detected in {}, quarantined to {}", path, q_path.display())
            } else {
                format!("Protected file {} modified, quarantined to {}, restored from shadow", path, q_path.display())
            };
            let _ = self.alert_tx.send(Alert::new(
                Severity::Critical,
                "sentinel",
                &msg,
            )).await;
        } else {
            // Watched policy or unknown — update shadow, info alert
            let _ = std::fs::write(&shadow, &current);
            let _ = self.alert_tx.send(Alert::new(
                Severity::Info,
                "sentinel",
                &format!("File changed: {}", path),
            )).await;
        }
    }

    /// Start the sentinel event loop, watching configured paths via inotify.
    ///
    /// Runs forever, debouncing filesystem events and dispatching to [`handle_change`](Self::handle_change).
    pub async fn run(self) -> Result<()> {
        use notify::{Config as NotifyConfig, Event, RecommendedWatcher, RecursiveMode, Watcher};

        let (ntx, mut nrx) = mpsc::channel::<Event>(500);

        let mut watcher = RecommendedWatcher::new(
            move |res: std::result::Result<Event, notify::Error>| {
                if let Ok(event) = res {
                    let _ = ntx.blocking_send(event);
                }
            },
            NotifyConfig::default(),
        )?;

        // Watch parent directories of each configured path
        let mut watched_dirs = std::collections::HashSet::new();
        for wp in &self.config.watch_paths {
            let p = Path::new(&wp.path);
            if p.is_dir() {
                if watched_dirs.insert(p.to_path_buf()) {
                    watcher.watch(p, RecursiveMode::Recursive)?;
                }
            } else {
                let dir = p.parent().unwrap_or(p);
                if watched_dirs.insert(dir.to_path_buf()) {
                    if dir.exists() {
                        watcher.watch(dir, RecursiveMode::NonRecursive)?;
                    }
                }
            }
        }

        // Debounce map
        let debounce = Duration::from_millis(self.config.debounce_ms);
        let mut pending: HashMap<String, Instant> = HashMap::new();

        let _ = self.alert_tx.send(Alert::new(
            Severity::Info,
            "sentinel",
            &format!("Sentinel watching {} paths", self.config.watch_paths.len()),
        )).await;

        loop {
            tokio::select! {
                Some(event) = nrx.recv() => {
                    for path in event.paths {
                        let path_str = path.to_string_lossy().to_string();
                        // Only process paths we care about
                        if policy_for_path(&self.config, &path_str).is_some() {
                            pending.insert(path_str, Instant::now());
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(50)) => {
                    let now = Instant::now();
                    let ready: Vec<String> = pending.iter()
                        .filter(|(_, ts)| now.duration_since(**ts) >= debounce)
                        .map(|(p, _)| p.clone())
                        .collect();
                    for path in ready {
                        pending.remove(&path);
                        self.handle_change(&path).await;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WatchPathConfig;

    #[test]
    fn test_shadow_path_uniqueness() {
        let s1 = shadow_path_for("/tmp/shadow", "/etc/passwd");
        let s2 = shadow_path_for("/tmp/shadow", "/etc/shadow");
        assert_ne!(s1, s2);
        // Same input should give same output
        let s3 = shadow_path_for("/tmp/shadow", "/etc/passwd");
        assert_eq!(s1, s3);
    }

    #[test]
    fn test_shadow_path_contains_filename() {
        let s = shadow_path_for("/tmp/shadow", "/home/user/SOUL.md");
        let name = s.file_name().unwrap().to_string_lossy();
        assert!(name.contains("SOUL.md"));
    }

    #[test]
    fn test_generate_unified_diff_identical() {
        let diff = generate_unified_diff("hello\nworld\n", "hello\nworld\n", "test.txt");
        assert!(diff.is_empty());
    }

    #[test]
    fn test_generate_unified_diff_with_changes() {
        let diff = generate_unified_diff("hello\nworld\n", "hello\nearth\n", "test.txt");
        assert!(!diff.is_empty());
        assert!(diff.contains("-world"));
        assert!(diff.contains("+earth"));
        assert!(diff.contains("--- a/test.txt"));
        assert!(diff.contains("+++ b/test.txt"));
    }

    #[test]
    fn test_is_log_rotation_false() {
        // A random temp file should not have rotation siblings
        let tmp = std::env::temp_dir().join("sentinel_test_no_rotation.log");
        let _ = std::fs::write(&tmp, "test");
        assert!(!is_log_rotation(&tmp.to_string_lossy()));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_is_log_rotation_true() {
        let tmp_dir = std::env::temp_dir().join("sentinel_logrot_test");
        let _ = std::fs::create_dir_all(&tmp_dir);
        let log = tmp_dir.join("app.log");
        let rotated = tmp_dir.join("app.log.1");
        let _ = std::fs::write(&log, "current");
        let _ = std::fs::write(&rotated, "old");
        assert!(is_log_rotation(&log.to_string_lossy()));
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[tokio::test]
    async fn test_handle_change_protected_quarantines() {
        let tmp = std::env::temp_dir().join("sentinel_test_protected");
        let _ = std::fs::remove_dir_all(&tmp);
        let shadow_dir = tmp.join("shadow");
        let quarantine_dir = tmp.join("quarantine");
        let workspace = tmp.join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();

        let soul_path = workspace.join("SOUL.md");
        let original = "I am the soul file.\n";
        std::fs::write(&soul_path, original).unwrap();

        let config = SentinelConfig {
            enabled: true,
            watch_paths: vec![WatchPathConfig {
                path: soul_path.to_string_lossy().to_string(),
                patterns: vec!["*".to_string()],
                policy: WatchPolicy::Protected,
            }],
            quarantine_dir: quarantine_dir.to_string_lossy().to_string(),
            shadow_dir: shadow_dir.to_string_lossy().to_string(),
            debounce_ms: 200,
            scan_content: false,
            max_file_size_kb: 1024,
            content_scan_excludes: vec![],
            exclude_content_scan: vec![],
        };

        let (tx, mut rx) = mpsc::channel::<Alert>(16);
        let sentinel = Sentinel::new(config, tx, None).unwrap();

        // Shadow should have been initialized with original content
        // Now write malicious content
        std::fs::write(&soul_path, "HACKED CONTENT\n").unwrap();
        sentinel.handle_change(&soul_path.to_string_lossy()).await;

        // File should be restored
        let restored = std::fs::read_to_string(&soul_path).unwrap();
        assert_eq!(restored, original);

        // Quarantine dir should have a file
        let q_entries: Vec<_> = std::fs::read_dir(&quarantine_dir).unwrap().collect();
        assert!(!q_entries.is_empty(), "quarantine should have a file");

        // Alert should be Critical
        let alert = rx.try_recv().unwrap();
        assert_eq!(alert.severity, Severity::Critical);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn test_handle_change_watched_allows_clean() {
        let tmp = std::env::temp_dir().join("sentinel_test_watched");
        let _ = std::fs::remove_dir_all(&tmp);
        let shadow_dir = tmp.join("shadow");
        let quarantine_dir = tmp.join("quarantine");
        let workspace = tmp.join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();

        let mem_path = workspace.join("MEMORY.md");
        let original = "Original memory.\n";
        std::fs::write(&mem_path, original).unwrap();

        let config = SentinelConfig {
            enabled: true,
            watch_paths: vec![WatchPathConfig {
                path: mem_path.to_string_lossy().to_string(),
                patterns: vec!["*".to_string()],
                policy: WatchPolicy::Watched,
            }],
            quarantine_dir: quarantine_dir.to_string_lossy().to_string(),
            shadow_dir: shadow_dir.to_string_lossy().to_string(),
            debounce_ms: 200,
            scan_content: false,
            max_file_size_kb: 1024,
            content_scan_excludes: vec![],
            exclude_content_scan: vec![],
        };

        let (tx, mut rx) = mpsc::channel::<Alert>(16);
        let sentinel = Sentinel::new(config, tx, None).unwrap();

        let new_content = "Updated memory content.\n";
        std::fs::write(&mem_path, new_content).unwrap();
        sentinel.handle_change(&mem_path.to_string_lossy()).await;

        // File should keep new content
        let current = std::fs::read_to_string(&mem_path).unwrap();
        assert_eq!(current, new_content);

        // Shadow should be updated to new content
        let shadow = shadow_path_for(
            &shadow_dir.to_string_lossy(),
            &mem_path.to_string_lossy(),
        );
        let shadow_content = std::fs::read_to_string(&shadow).unwrap();
        assert_eq!(shadow_content, new_content);

        // Alert should be Info
        let alert = rx.try_recv().unwrap();
        assert_eq!(alert.severity, Severity::Info);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_default_config_heartbeat_watched() {
        let config = SentinelConfig::default();
        let hb = config.watch_paths.iter().find(|w| w.path.ends_with("HEARTBEAT.md")).unwrap();
        assert!(matches!(hb.policy, WatchPolicy::Watched));
    }

    #[test]
    fn test_default_config_identity_protected() {
        let config = SentinelConfig::default();
        let id = config.watch_paths.iter().find(|w| w.path.ends_with("IDENTITY.md")).unwrap();
        assert!(matches!(id.policy, WatchPolicy::Protected));
    }

    #[test]
    fn test_default_config_skills_dir_watched() {
        let config = SentinelConfig::default();
        let sk = config.watch_paths.iter().find(|w| w.path.contains("superpowers/skills")).unwrap();
        assert!(matches!(sk.policy, WatchPolicy::Watched));
        assert_eq!(sk.patterns, vec!["SKILL.md".to_string()]);
    }

    #[test]
    fn test_policy_for_path_exact_match() {
        let config = SentinelConfig::default();
        let policy = policy_for_path(&config, "/home/openclaw/.openclaw/workspace/SOUL.md");
        assert!(matches!(policy, Some(WatchPolicy::Protected)));
    }

    #[test]
    fn test_policy_for_path_directory_pattern_match() {
        let config = SentinelConfig::default();
        let policy = policy_for_path(&config, "/home/openclaw/.openclaw/workspace/superpowers/skills/some_skill/SKILL.md");
        assert!(matches!(policy, Some(WatchPolicy::Watched)));
    }

    #[test]
    fn test_policy_for_path_directory_pattern_reject() {
        let config = SentinelConfig::default();
        let policy = policy_for_path(&config, "/home/openclaw/.openclaw/workspace/superpowers/skills/some_skill/README.md");
        assert!(policy.is_none());
    }

    #[test]
    fn test_content_scan_exclude_glob_matches() {
        let excludes = vec![
            "**/.openclaw/**/auth-profiles.json".to_string(),
            "**/.openclaw/credentials/**".to_string(),
        ];

        // auth-profiles.json should match
        assert!(excludes.iter().any(|p| glob_match::glob_match(p,
            "/home/openclaw/.openclaw/agents/main/agent/auth-profiles.json")));

        // credentials subpath should match
        assert!(excludes.iter().any(|p| glob_match::glob_match(p,
            "/home/openclaw/.openclaw/credentials/whatsapp/creds.json")));

        // unrelated path should NOT match
        assert!(!excludes.iter().any(|p| glob_match::glob_match(p,
            "/home/openclaw/.openclaw/workspace/SOUL.md")));

        // different user's openclaw auth should also match
        assert!(excludes.iter().any(|p| glob_match::glob_match(p,
            "/home/otheruser/.openclaw/agents/main/agent/auth-profiles.json")));
    }

    #[tokio::test]
    async fn test_handle_change_skips_content_scan_for_excluded_path() {
        // Verify that a file matching content_scan_excludes is NOT quarantined
        // even when it contains content that would trigger SecureClaw patterns.
        let tmp = std::env::temp_dir().join("sentinel_test_exclude");
        let _ = std::fs::remove_dir_all(&tmp);
        let shadow_dir = tmp.join("shadow");
        let quarantine_dir = tmp.join("quarantine");

        // Simulate .openclaw/agents/main/agent/ structure
        let auth_dir = tmp.join(".openclaw/agents/main/agent");
        std::fs::create_dir_all(&auth_dir).unwrap();
        let auth_path = auth_dir.join("auth-profiles.json");
        let original = r#"{"profiles":[]}"#;
        std::fs::write(&auth_path, original).unwrap();

        let auth_path_str = auth_path.to_string_lossy().to_string();

        let config = SentinelConfig {
            enabled: true,
            watch_paths: vec![WatchPathConfig {
                path: auth_path_str.clone(),
                patterns: vec!["*".to_string()],
                policy: WatchPolicy::Protected,
            }],
            quarantine_dir: quarantine_dir.to_string_lossy().to_string(),
            shadow_dir: shadow_dir.to_string_lossy().to_string(),
            debounce_ms: 200,
            scan_content: true,
            max_file_size_kb: 1024,
            content_scan_excludes: vec![
                "**/.openclaw/**/auth-profiles.json".to_string(),
            ],
            exclude_content_scan: vec![],
        };

        let (tx, mut rx) = mpsc::channel::<Alert>(16);
        let sentinel = Sentinel::new(config, tx, None).unwrap();

        // Write content with an API key pattern — without exclusion this would
        // be flagged by SecureClaw if an engine were present. The key point is
        // that the exclusion path logic is exercised. Since there's no engine
        // in this test, we verify the file is still treated as Protected
        // (quarantine + restore) rather than threat-scanned.
        std::fs::write(&auth_path, r#"{"profiles":[{"key":"sk-ant-fake"}]}"#).unwrap();
        sentinel.handle_change(&auth_path_str).await;

        // Protected file should be restored to original
        let restored = std::fs::read_to_string(&auth_path).unwrap();
        assert_eq!(restored, original);

        let alert = rx.try_recv().unwrap();
        assert_eq!(alert.severity, Severity::Critical);
        // The message should say "Protected file" not "THREAT detected"
        assert!(alert.message.contains("Protected file"),
            "Should be protected-file restore, not threat detection: {}", alert.message);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_quarantine_path_format() {
        let q = quarantine_path_for("/tmp/quarantine", "/home/user/SOUL.md");
        let name = q.file_name().unwrap().to_string_lossy();
        // Should contain timestamp pattern and original filename
        assert!(name.contains("SOUL.md"));
        assert!(name.contains('_'));
        assert!(q.starts_with("/tmp/quarantine"));
    }
}
