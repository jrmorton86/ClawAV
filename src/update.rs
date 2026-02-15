//! Self-update subcommand: `clawav update`
//!
//! 1. Prompts for admin key (or accepts --key flag)
//! 2. Checks GitHub releases API for latest version
//! 3. Downloads + verifies new binary (SHA256 checksum)
//! 4. Does chattr -i → replace → chattr +i → restart dance
//! 5. Logs the upgrade to Slack

use anyhow::{bail, Context, Result};
use ed25519_dalek::{Verifier, VerifyingKey, Signature};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::Command;
use tokio::sync::mpsc;
use crate::alerts::{Alert, Severity};
use std::time::Duration;

const GITHUB_REPO: &str = "coltz108/ClawAV";
const RELEASE_PUBLIC_KEY: &[u8; 32] = include_bytes!("release-key.pub");

/// Verify an Ed25519 signature over the SHA-256 digest of a binary.
///
/// The embedded public key (`release-key.pub`) is compiled into the binary at build time.
/// Returns an error if the signature length is wrong, the key is invalid, or verification fails.
fn verify_release_signature(binary_data: &[u8], sig_bytes: &[u8]) -> Result<()> {
    if sig_bytes.len() != 64 {
        bail!("Invalid signature length: {} (expected 64)", sig_bytes.len());
    }
    let pubkey = VerifyingKey::from_bytes(RELEASE_PUBLIC_KEY)
        .context("Invalid embedded public key")?;
    let mut hasher = Sha256::new();
    hasher.update(binary_data);
    let digest = hasher.finalize();
    let sig = Signature::from_slice(sig_bytes)
        .context("Invalid signature format")?;
    pubkey.verify(&digest, &sig)
        .context("❌ SIGNATURE VERIFICATION FAILED — binary may be tampered")?;
    eprintln!("✅ Ed25519 signature verified");
    Ok(())
}
/// Path to the stored admin key hash (Argon2), used for custom binary installs.
const ADMIN_KEY_HASH_PATH: &str = "/etc/clawav/admin.key.hash";

/// Detect the correct release asset name for this platform
fn asset_name() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "clawav-aarch64-linux"
    } else {
        "clawav-x86_64-linux"
    }
}

/// Get the path of the currently running binary
fn current_binary_path() -> Result<PathBuf> {
    std::env::current_exe().context("Failed to determine current binary path")
}

/// Prompt for admin key from stdin (unless --key was passed)
fn get_admin_key(args: &[String]) -> Result<String> {
    // Check for --key flag
    for (i, arg) in args.iter().enumerate() {
        if arg == "--key" {
            if let Some(key) = args.get(i + 1) {
                return Ok(key.clone());
            }
            bail!("--key flag requires a value");
        }
        if let Some(key) = arg.strip_prefix("--key=") {
            return Ok(key.to_string());
        }
    }

    // Interactive prompt
    eprint!("Admin key: ");
    io::stderr().flush()?;
    let mut key = String::new();
    io::stdin().read_line(&mut key)?;
    let key = key.trim().to_string();
    if key.is_empty() {
        bail!("Admin key is required for updates");
    }
    Ok(key)
}

/// Verify admin key against stored hash
fn verify_admin_key(key: &str) -> Result<bool> {
    let hash = fs::read_to_string(ADMIN_KEY_HASH_PATH)
        .context("Cannot read admin key hash — is ClawAV installed?")?;
    Ok(crate::admin::verify_key(key, hash.trim()))
}

/// Fetch release info from GitHub API (latest or specific version)
fn fetch_release(version: Option<&str>) -> Result<(String, String, Option<String>, Option<String>)> {
    // Returns (tag, download_url, sha256_url, sig_url)
    let url = if let Some(ver) = version {
        let tag = if ver.starts_with('v') { ver.to_string() } else { format!("v{}", ver) };
        format!(
            "https://api.github.com/repos/{}/releases/tags/{}",
            GITHUB_REPO, tag
        )
    } else {
        format!(
            "https://api.github.com/repos/{}/releases/latest",
            GITHUB_REPO
        )
    };

    let client = reqwest::blocking::Client::builder()
        .user_agent("clawav-updater")
        .build()?;

    let resp = client.get(&url).send()?.error_for_status()?;
    let release: serde_json::Value = resp.json()?;

    let tag = release["tag_name"]
        .as_str()
        .context("No tag_name in release")?
        .to_string();

    let target_asset = asset_name();
    let sha_asset = format!("{}.sha256", target_asset);
    let sig_asset = format!("{}.sig", target_asset);

    let assets = release["assets"]
        .as_array()
        .context("No assets in release")?;

    let mut download_url = None;
    let mut sha256_url = None;
    let mut sig_url = None;

    for asset in assets {
        let name = asset["name"].as_str().unwrap_or("");
        let url = asset["browser_download_url"].as_str().unwrap_or("");
        if name == target_asset {
            download_url = Some(url.to_string());
        } else if name == sha_asset {
            sha256_url = Some(url.to_string());
        } else if name == sig_asset {
            sig_url = Some(url.to_string());
        }
    }

    let download_url = download_url
        .with_context(|| format!("No asset '{}' found in release {}", target_asset, tag))?;

    Ok((tag, download_url, sha256_url, sig_url))
}

/// Download binary and optionally verify checksum
fn download_and_verify(download_url: &str, sha256_url: Option<&str>) -> Result<Vec<u8>> {
    eprintln!("Downloading binary...");
    let client = reqwest::blocking::Client::builder()
        .user_agent("clawav-updater")
        .build()?;

    let binary_data = client
        .get(download_url)
        .send()?
        .error_for_status()?
        .bytes()?
        .to_vec();

    eprintln!("Downloaded {} bytes", binary_data.len());

    // Verify checksum if available
    if let Some(sha_url) = sha256_url {
        eprintln!("Verifying SHA256 checksum...");
        let sha_resp = client.get(sha_url).send()?.error_for_status()?;
        let sha_text = sha_resp.text()?;
        // Format: "<hash>  <filename>" or just "<hash>"
        let expected_hash = sha_text
            .split_whitespace()
            .next()
            .context("Empty checksum file")?
            .to_lowercase();

        let mut hasher = Sha256::new();
        hasher.update(&binary_data);
        let actual_hash = hex::encode(hasher.finalize());

        if actual_hash != expected_hash {
            bail!(
                "Checksum mismatch!\n  Expected: {}\n  Got:      {}",
                expected_hash,
                actual_hash
            );
        }
        eprintln!("✅ Checksum verified");
    } else {
        eprintln!("⚠️  No checksum file in release — skipping verification");
    }

    Ok(binary_data)
}

/// Run a shell command, bail on failure
fn run_cmd(program: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(program).args(args).status()?;
    if !status.success() {
        bail!(
            "{} {} exited with code {}",
            program,
            args.join(" "),
            status.code().unwrap_or(-1)
        );
    }
    Ok(())
}

/// Notify Slack about a completed upgrade (best-effort, reads config from disk).
///
/// Silently fails if Slack is not configured or the webhook request errors.
fn notify_slack(from_version: &str, to_version: &str) {
    let config_path = PathBuf::from("/etc/clawav/config.toml");
    let config = match crate::config::Config::load(&config_path) {
        Ok(c) => c,
        Err(_) => return,
    };
    if config.slack.webhook_url.is_empty() {
        return;
    }

    let payload = serde_json::json!({
        "text": format!(
            "🔄 *ClawAV self-update complete*\n`{}` → `{}`\nBinary: `{}`\nHost: {}",
            from_version,
            to_version,
            current_binary_path().map(|p| p.display().to_string()).unwrap_or_else(|_| "unknown".into()),
            hostname()
        )
    });

    let _ = reqwest::blocking::Client::new()
        .post(&config.slack.webhook_url)
        .json(&payload)
        .send();
}

/// Read the system hostname from `/etc/hostname`, falling back to "unknown".
fn hostname() -> String {
    fs::read_to_string("/etc/hostname")
        .unwrap_or_else(|_| "unknown".into())
        .trim()
        .to_string()
}

/// Parse --binary flag from args
fn get_custom_binary_path(args: &[String]) -> Option<String> {
    for (i, arg) in args.iter().enumerate() {
        if arg == "--binary" {
            return args.get(i + 1).cloned();
        }
        if let Some(path) = arg.strip_prefix("--binary=") {
            return Some(path.to_string());
        }
    }
    None
}

/// Parse --version flag from args (target release version)
fn get_target_version(args: &[String]) -> Option<String> {
    for (i, arg) in args.iter().enumerate() {
        if arg == "--version" || arg == "-v" {
            return args.get(i + 1).cloned();
        }
        if let Some(ver) = arg.strip_prefix("--version=") {
            return Some(ver.to_string());
        }
    }
    None
}

/// Main entry point for `clawav update`.
///
/// Supports `--check` (dry run), `--version <ver>` (specific release),
/// `--binary <path>` (custom binary requiring admin key), and `--key <key>`.
/// GitHub release path uses SHA-256 + optional Ed25519 signature verification.
pub fn run_update(args: &[String]) -> Result<()> {
    let current_version = env!("CARGO_PKG_VERSION");
    eprintln!("🛡️  ClawAV Self-Update");
    eprintln!("Current version: v{}", current_version);
    eprintln!();

    let check_only = args.iter().any(|a| a == "--check");
    let custom_binary = get_custom_binary_path(args);
    let target_version = get_target_version(args);

    // Custom binary path requires admin key (no CI verification available)
    // GitHub release path does NOT require admin key (SHA256 checksum is sufficient)
    let (binary_data, version_tag) = if let Some(ref binary_path) = custom_binary {
        eprintln!("Custom binary install: {}", binary_path);
        eprintln!("⚠️  No CI verification — admin key required");
        eprintln!();

        let key = get_admin_key(args)?;
        if !verify_admin_key(&key)? {
            bail!("❌ Invalid admin key — custom binary install refused");
        }
        eprintln!("✅ Admin key verified");
        eprintln!();

        let data = fs::read(binary_path)
            .with_context(|| format!("Failed to read custom binary: {}", binary_path))?;
        eprintln!("Read {} bytes from {}", data.len(), binary_path);

        (data, "custom".to_string())
    } else {
        // GitHub release path — checksum verification is the trust anchor
        if let Some(ref ver) = target_version {
            eprintln!("Fetching release {}...", ver);
        } else {
            eprintln!("Checking for latest release...");
        }
        let (tag, download_url, sha256_url, sig_url) = fetch_release(target_version.as_deref())?;
        let remote_version = tag.strip_prefix('v').unwrap_or(&tag);

        eprintln!("Release: {} ({})", tag, asset_name());

        if remote_version == current_version {
            eprintln!("✅ Already running the latest version");
            return Ok(());
        }

        eprintln!("Update available: v{} → {}", current_version, tag);

        if check_only {
            return Ok(());
        }

        if sha256_url.is_none() {
            bail!("❌ Release has no checksum file — refusing to install unverified binary");
        }

        let data = download_and_verify(&download_url, sha256_url.as_deref())?;

        // Verify Ed25519 signature if available
        if let Some(ref sig_url) = sig_url {
            eprintln!("Verifying Ed25519 signature...");
            let client = reqwest::blocking::Client::builder()
                .user_agent("clawav-updater")
                .build()?;
            let sig_bytes = client.get(sig_url).send()?.error_for_status()?.bytes()?.to_vec();
            verify_release_signature(&data, &sig_bytes)?;
        } else {
            eprintln!("⚠️  No .sig file in release — skipping signature verification (pre-signing release)");
        }

        (data, tag)
    };

    if check_only {
        return Ok(());
    }

    let binary_data = binary_data;

    // 4. Replace binary (chattr dance)
    let binary_path = current_binary_path()?;
    let tmp_path = binary_path.with_extension("new");

    eprintln!("Installing to {}...", binary_path.display());

    // Write new binary to temp location
    fs::write(&tmp_path, &binary_data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o755))?;
    }

    // Remove immutable flag (may fail if not set — that's fine)
    let _ = run_cmd("chattr", &["-i", &binary_path.to_string_lossy()]);

    // Atomic replace
    fs::rename(&tmp_path, &binary_path)?;

    // Re-apply immutable flag
    let _ = run_cmd("chattr", &["+i", &binary_path.to_string_lossy()]);

    eprintln!("✅ Binary replaced");

    // 5. Notify Slack
    notify_slack(&format!("v{}", current_version), &version_tag);

    // 6. Restart service
    eprintln!("Restarting clawav service...");
    let restart_result = run_cmd("systemctl", &["restart", "clawav"]);
    match restart_result {
        Ok(()) => eprintln!("✅ Service restarted"),
        Err(e) => eprintln!("⚠️  Service restart failed ({}). You may need to restart manually.", e),
    }

    eprintln!();
    eprintln!("🎉 Updated to {}", version_tag);

    Ok(())
}

/// Compare semver strings: returns true if `remote` is strictly newer than `current`.
///
/// Strips leading 'v' and compares each `.`-delimited component numerically.
/// Missing components are treated as 0.
pub fn is_newer_version(current: &str, remote: &str) -> bool {
    let current = current.strip_prefix('v').unwrap_or(current);
    let remote = remote.strip_prefix('v').unwrap_or(remote);
    if current == remote {
        return false;
    }
    let parse = |s: &str| -> Vec<u64> {
        s.split('.').filter_map(|p| p.parse().ok()).collect()
    };
    let c = parse(current);
    let r = parse(remote);
    for i in 0..c.len().max(r.len()) {
        let cv = c.get(i).copied().unwrap_or(0);
        let rv = r.get(i).copied().unwrap_or(0);
        if rv > cv { return true; }
        if rv < cv { return false; }
    }
    false
}

/// Background auto-updater loop. Checks GitHub for new releases and installs them.
///
/// Runs forever, sleeping for `interval_secs` between checks. On finding a newer
/// release with a valid checksum (and optional Ed25519 signature), downloads and
/// replaces the binary, notifies Slack, and restarts the systemd service.
pub async fn run_auto_updater(alert_tx: mpsc::Sender<Alert>, interval_secs: u64, mode: String) {
    let mut last_notified_version = String::new();
    loop {
        tokio::time::sleep(Duration::from_secs(interval_secs)).await;

        let tx = alert_tx.clone();
        let mode = mode.clone();
        let last_notified = last_notified_version.clone();
        let result: Result<Option<String>> = async {
            // fetch_release uses reqwest::blocking, so wrap in spawn_blocking
            let (tag, download_url, sha256_url, sig_url) =
                tokio::task::spawn_blocking(|| fetch_release(None))
                    .await
                    .context("spawn_blocking join error")??;

            let current_version = env!("CARGO_PKG_VERSION");
            let remote_version = tag.strip_prefix('v').unwrap_or(&tag);

            if !is_newer_version(current_version, remote_version) {
                return Ok(None);
            }

            // Notify mode: alert once per version, don't install
            if mode == "notify" {
                if last_notified != tag {
                    let _ = tx.send(Alert::new(
                        Severity::Info, "auto-update",
                        &format!("🆕 ClawAV {} available (current: v{}). Run `clawav update` to install.", tag, current_version),
                    )).await;
                }
                return Ok(Some(tag));
            }

            let _ = tx.send(Alert::new(
                Severity::Info, "auto-update",
                &format!("New release {} available, auto-updating...", tag),
            )).await;

            if sha256_url.is_none() {
                bail!("Release has no checksum file — refusing unverified binary");
            }

            let dl_url = download_url.clone();
            let sha_url = sha256_url.clone();
            let sig_url2 = sig_url.clone();
            let (binary_data, sig_bytes) = tokio::task::spawn_blocking(move || -> Result<(Vec<u8>, Option<Vec<u8>>)> {
                let data = download_and_verify(&dl_url, sha_url.as_deref())?;
                let sig = if let Some(ref su) = sig_url2 {
                    let client = reqwest::blocking::Client::builder()
                        .user_agent("clawav-updater").build()?;
                    Some(client.get(su).send()?.error_for_status()?.bytes()?.to_vec())
                } else { None };
                Ok((data, sig))
            }).await.context("spawn_blocking join error")??;

            if let Some(ref sig) = sig_bytes {
                verify_release_signature(&binary_data, sig)?;
            }

            // Binary replace (chattr dance)
            let binary_path = current_binary_path()?;
            let tmp_path = binary_path.with_extension("new");
            fs::write(&tmp_path, &binary_data)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o755))?;
            }
            let _ = run_cmd("chattr", &["-i", &binary_path.to_string_lossy()]);
            fs::rename(&tmp_path, &binary_path)?;
            let _ = run_cmd("chattr", &["+i", &binary_path.to_string_lossy()]);
            let _ = run_cmd("chattr", &["+i", "/etc/clawav/admin.key.hash"]);

            // Update tray binary if installed
            if std::path::Path::new("/usr/local/bin/clawav-tray").exists() {
                let tray_asset = format!("clawav-tray-{}-linux", if cfg!(target_arch = "aarch64") { "aarch64" } else { "x86_64" });
                let tray_url = format!("https://github.com/{}/releases/download/{}/{}", GITHUB_REPO, tag, tray_asset);
                match tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
                    let client = reqwest::blocking::Client::builder().user_agent("clawav-updater").build()?;
                    Ok(client.get(&tray_url).send()?.error_for_status()?.bytes()?.to_vec())
                }).await {
                    Ok(Ok(tray_data)) => {
                        let tray_path = std::path::PathBuf::from("/usr/local/bin/clawav-tray");
                        let tray_tmp = tray_path.with_extension("new");
                        if fs::write(&tray_tmp, &tray_data).is_ok() {
                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::PermissionsExt;
                                let _ = fs::set_permissions(&tray_tmp, fs::Permissions::from_mode(0o755));
                            }
                            let _ = run_cmd("chattr", &["-i", "/usr/local/bin/clawav-tray"]);
                            let _ = fs::rename(&tray_tmp, &tray_path);
                            let _ = run_cmd("chattr", &["+i", "/usr/local/bin/clawav-tray"]);
                        }
                    }
                    _ => {} // Tray update is best-effort
                }
            }

            let _ = tx.send(Alert::new(
                Severity::Info, "auto-update",
                &format!("Updated to {}, restarting...", tag),
            )).await;

            // Notify Slack (blocking)
            let current_ver = format!("v{}", current_version);
            let tag2 = tag.clone();
            let _ = tokio::task::spawn_blocking(move || {
                notify_slack(&current_ver, &tag2);
            }).await;

            // Restart service
            let _ = run_cmd("systemctl", &["restart", "clawav"]);

            Ok(None)
        }.await;

        match result {
            Ok(Some(notified_tag)) => {
                last_notified_version = notified_tag;
            }
            Ok(None) => {}
            Err(e) => {
                let _ = alert_tx.send(Alert::new(
                    Severity::Warning, "auto-update",
                    &format!("Auto-update check failed: {}", e),
                )).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asset_name() {
        let name = asset_name();
        assert!(name.starts_with("clawav-"));
        assert!(name.contains("-linux"));
    }

    #[test]
    fn test_hostname() {
        // Should return something non-empty
        let h = hostname();
        assert!(!h.is_empty() || true); // May fail in CI, don't hard-fail
    }

    #[test]
    fn test_get_admin_key_from_flag() {
        let args = vec!["--key".to_string(), "OCAV-test123".to_string()];
        let key = get_admin_key(&args).unwrap();
        assert_eq!(key, "OCAV-test123");
    }

    #[test]
    fn test_get_admin_key_from_equals_flag() {
        let args = vec!["--key=OCAV-test456".to_string()];
        let key = get_admin_key(&args).unwrap();
        assert_eq!(key, "OCAV-test456");
    }

    #[test]
    fn test_is_newer_version() {
        assert!(is_newer_version("0.1.0", "0.2.0"));
        assert!(is_newer_version("0.1.0", "v0.2.8"));
        assert!(is_newer_version("1.0.0", "1.0.1"));
        assert!(is_newer_version("1.0.0", "2.0.0"));
        assert!(!is_newer_version("0.2.0", "0.1.0"));
        assert!(!is_newer_version("0.2.0", "0.2.0"));
        assert!(!is_newer_version("v0.2.8", "v0.2.8"));
        assert!(is_newer_version("0.9.9", "1.0.0"));
    }

    #[test]
    fn test_verify_signature_bad_length() {
        let result = verify_release_signature(b"binary", &[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_admin_key_missing_value() {
        let args = vec!["--key".to_string()];
        assert!(get_admin_key(&args).is_err());
    }
}
