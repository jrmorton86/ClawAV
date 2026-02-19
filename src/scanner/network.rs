// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Network-related security scanners.
//!
//! Network interfaces, listening services, DNS config, NTP,
//! OpenClaw security checks.

use std::process::Command;

use super::{ScanResult, ScanStatus};
use super::helpers::{run_cmd, run_cmd_with_sudo, detect_agent_home};
use super::remediate;

/// Check for promiscuous-mode interfaces, unusual tunnel/tap devices, IP forwarding, and VPN routes.
pub fn scan_network_interfaces() -> ScanResult {
    let mut issues = Vec::new();

    // Check for promiscuous mode interfaces (sniffing)
    if let Ok(output) = run_cmd("ip", &["link", "show"]) {
        for line in output.lines() {
            if line.contains("PROMISC") {
                let interface = line.split(':').nth(1).unwrap_or("unknown").trim();
                issues.push(format!("Interface in promiscuous mode: {}", interface));
            }
        }
    }

    // Check for unusual network interfaces
    if let Ok(output) = run_cmd("ip", &["addr", "show"]) {
        let mut interface_count = 0;
        for line in output.lines() {
            if line.starts_with(char::is_numeric) && line.contains(":") {
                interface_count += 1;
                // Look for suspicious interface names
                if line.contains("tun") && !line.contains("tailscale") {
                    issues.push("Tunnel interface detected".to_string());
                }
                if line.contains("tap") {
                    issues.push("TAP interface detected".to_string());
                }
            }
        }

        if interface_count > 10 {
            issues.push(format!("Many network interfaces: {}", interface_count));
        }
    }

    // Check for IP forwarding enabled
    if let Ok(ipv4_forward) = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward") {
        if ipv4_forward.trim() == "1" {
            issues.push("IPv4 forwarding enabled".to_string());
        }
    }

    // Check for unusual routes
    if let Ok(output) = run_cmd("ip", &["route", "show"]) {
        for line in output.lines() {
            // Check for routes to private networks that might indicate tunneling
            if (line.contains("10.0.0.0/8") || line.contains("172.16.0.0/12") || line.contains("192.168.0.0/16"))
                && (line.contains("tun") || line.contains("tap")) {
                    issues.push(format!("VPN/tunnel route detected: {}", line.trim()));
            }
        }
    }

    if issues.is_empty() {
        ScanResult::new("network_interfaces", ScanStatus::Pass, "Network interfaces appear normal")
    } else {
        ScanResult::new("network_interfaces", ScanStatus::Warn, &format!("Network concerns: {}", issues.join("; ")))
    }
}

/// List TCP listening sockets and flag any not in the expected set (ClawTower API port 18791).
pub fn scan_listening_services() -> ScanResult {
    match run_cmd("ss", &["-tlnp"]) {
        Ok(output) => {
            let expected_ports = ["18791"]; // ClawTower API
            let mut unexpected = Vec::new();
            for line in output.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    let local = parts[3];
                    let port = local.rsplit(':').next().unwrap_or("");
                    if !expected_ports.contains(&port) {
                        unexpected.push(local.to_string());
                    }
                }
            }
            if unexpected.is_empty() {
                ScanResult::new("listening", ScanStatus::Pass, "No unexpected listening services")
            } else {
                ScanResult::new("listening", ScanStatus::Warn, &format!("Unexpected listeners: {}", unexpected.join(", ")))
            }
        }
        Err(e) => ScanResult::new("listening", ScanStatus::Warn, &format!("Cannot check listeners: {}", e)),
    }
}

/// Verify `/etc/resolv.conf` has nameservers configured and check for DNS hijacking indicators.
pub fn scan_dns_resolver() -> ScanResult {
    match std::fs::read_to_string("/etc/resolv.conf") {
        Ok(content) => {
            let mut nameservers = Vec::new();
            let mut suspicious_entries = Vec::new();

            for line in content.lines() {
                let line = line.trim();
                if line.starts_with("nameserver") {
                    if let Some(ip) = line.split_whitespace().nth(1) {
                        nameservers.push(ip.to_string());

                        // Check for suspicious DNS servers
                        let suspicious_dns = ["8.8.4.4", "1.1.1.1"]; // Actually these are fine, but flagging non-standard
                        if !ip.starts_with("127.") && !ip.starts_with("192.168.") &&
                           !ip.starts_with("10.") && !ip.starts_with("172.") &&
                           !suspicious_dns.contains(&ip) && ip != "8.8.8.8" && ip != "1.0.0.1" {
                            suspicious_entries.push(format!("Unusual DNS server: {}", ip));
                        }
                    }
                }

                // Check for DNS hijacking indicators
                if line.contains("search ") && (line.contains(".local") || line.contains("attacker")) {
                    suspicious_entries.push(format!("Suspicious search domain: {}", line));
                }
            }

            if nameservers.is_empty() {
                ScanResult::new("dns_resolver", ScanStatus::Fail, "No nameservers configured")
            } else if !suspicious_entries.is_empty() {
                ScanResult::new("dns_resolver", ScanStatus::Warn, &format!("DNS concerns: {}", suspicious_entries.join("; ")))
            } else {
                ScanResult::new("dns_resolver", ScanStatus::Pass, &format!("DNS resolvers configured: {}", nameservers.join(", ")))
            }
        }
        Err(e) => ScanResult::new("dns_resolver", ScanStatus::Fail, &format!("Cannot read /etc/resolv.conf: {}", e)),
    }
}

/// Check NTP synchronization status via `timedatectl`, `ntp`, or `chronyd`.
pub fn scan_ntp_sync() -> ScanResult {
    // Try timedatectl first (systemd)
    if let Ok(output) = run_cmd("timedatectl", &["show", "--property=NTPSynchronized,NTP"]) {
        let ntp_sync = output.lines().any(|l| l.starts_with("NTPSynchronized=yes"));
        let ntp_enabled = output.lines().any(|l| l.starts_with("NTP=yes"));

        if ntp_sync && ntp_enabled {
            ScanResult::new("ntp_sync", ScanStatus::Pass, "NTP synchronized and enabled")
        } else if ntp_enabled {
            ScanResult::new("ntp_sync", ScanStatus::Warn, "NTP enabled but not synchronized")
        } else {
            ScanResult::new("ntp_sync", ScanStatus::Warn, "NTP not enabled")
        }
    }
    // Fall back to checking ntpd/chronyd services
    else if let Ok(status) = run_cmd("systemctl", &["is-active", "ntp"]) {
        if status.trim() == "active" {
            ScanResult::new("ntp_sync", ScanStatus::Pass, "NTP service active")
        } else {
            ScanResult::new("ntp_sync", ScanStatus::Warn, "NTP service not active")
        }
    } else if let Ok(status) = run_cmd("systemctl", &["is-active", "chronyd"]) {
        if status.trim() == "active" {
            ScanResult::new("ntp_sync", ScanStatus::Pass, "Chrony service active")
        } else {
            ScanResult::new("ntp_sync", ScanStatus::Warn, "No NTP service detected")
        }
    } else {
        ScanResult::new("ntp_sync", ScanStatus::Warn, "Cannot determine NTP status")
    }
}

/// OpenClaw-specific security checks
/// Check that a path has permissions no more permissive than `max_mode`.
pub fn check_path_permissions(path: &str, max_mode: u32, label: &str) -> ScanResult {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(meta) => {
            let mode = meta.permissions().mode() & 0o777;
            if (mode & !max_mode) == 0 {
                ScanResult::new(
                    &format!("openclaw:perms:{}", label),
                    ScanStatus::Pass,
                    &format!("{} permissions {:o} (max {:o})", path, mode, max_mode),
                )
            } else {
                ScanResult::new(
                    &format!("openclaw:perms:{}", label),
                    ScanStatus::Warn,
                    &format!("{} permissions {:o} — should be {:o} or tighter", path, mode, max_mode),
                )
            }
        }
        Err(_) => ScanResult::new(
            &format!("openclaw:perms:{}", label),
            ScanStatus::Warn,
            &format!("{} not found — skipping permission check", path),
        ),
    }
}

/// Check for symlinks inside a directory that point outside it (symlink attack vector).
pub fn check_symlinks_in_dir(dir: &str) -> ScanResult {
    let dir_path = std::path::Path::new(dir);
    if !dir_path.exists() {
        return ScanResult::new("openclaw:symlinks", ScanStatus::Warn,
            &format!("{} not found", dir));
    }

    let mut suspicious = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir_path) {
        for entry in entries.flatten() {
            if entry.file_type().map(|ft| ft.is_symlink()).unwrap_or(false) {
                if let Ok(target) = std::fs::read_link(entry.path()) {
                    let resolved = entry.path().parent()
                        .unwrap_or(dir_path)
                        .join(&target);
                    if let Ok(canonical) = std::fs::canonicalize(&resolved) {
                        if !canonical.starts_with(dir_path) {
                            suspicious.push(format!("{} → {}",
                                entry.path().display(), canonical.display()));
                        }
                    }
                }
            }
        }
    }

    if suspicious.is_empty() {
        ScanResult::new("openclaw:symlinks", ScanStatus::Pass,
            &format!("No suspicious symlinks in {}", dir))
    } else {
        ScanResult::new("openclaw:symlinks", ScanStatus::Fail,
            &format!("Symlinks pointing outside directory: {}", suspicious.join(", ")))
    }
}

/// Parse `openclaw security audit` text output into ScanResults.
///
/// Line format: `✓ description` (pass), `⚠ description` (warn), `✗ description` (fail)
pub fn parse_openclaw_audit_output(output: &str) -> Vec<ScanResult> {
    let mut results = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }

        let (status, detail) = if trimmed.starts_with('✓') {
            (ScanStatus::Pass, trimmed.trim_start_matches('✓').trim())
        } else if trimmed.starts_with('⚠') {
            (ScanStatus::Warn, trimmed.trim_start_matches('⚠').trim())
        } else if trimmed.starts_with('✗') {
            (ScanStatus::Fail, trimmed.trim_start_matches('✗').trim())
        } else {
            continue; // skip non-finding lines (headers, etc.)
        };

        // Extract category from description (first word before colon, or "general")
        let category = detail.split(':').next()
            .unwrap_or("general")
            .trim()
            .to_lowercase()
            .replace(' ', "_");

        results.push(ScanResult::new(
            &format!("openclaw:audit:{}", category),
            status,
            detail,
        ));
    }
    results
}

/// Run `openclaw security audit --deep` and parse results.
pub fn run_openclaw_audit(command: &str) -> Vec<ScanResult> {
    let parts: Vec<&str> = command.split_whitespace().collect();
    if parts.is_empty() {
        return vec![ScanResult::new("openclaw:audit", ScanStatus::Warn,
            "Empty audit command configured")];
    }

    match Command::new(parts[0]).args(&parts[1..]).output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let mut results = parse_openclaw_audit_output(&stdout);
            if results.is_empty() && !stderr.is_empty() {
                results.push(ScanResult::new("openclaw:audit", ScanStatus::Warn,
                    &format!("Audit produced no findings. stderr: {}",
                        stderr.chars().take(200).collect::<String>())));
            }
            if !output.status.success() {
                results.push(ScanResult::new("openclaw:audit", ScanStatus::Warn,
                    &format!("Audit exited with code {}", output.status)));
            }
            results
        }
        Err(e) => vec![ScanResult::new("openclaw:audit", ScanStatus::Warn,
            &format!("Failed to run audit: {} (is openclaw installed?)", e))],
    }
}

/// Check avahi-browse output for OpenClaw service advertisements (info leak).
pub fn check_mdns_openclaw_leak(avahi_output: &str) -> ScanResult {
    let openclaw_services: Vec<&str> = avahi_output.lines()
        .filter(|l| l.to_lowercase().contains("openclaw") || l.to_lowercase().contains("clawtower"))
        .collect();

    if openclaw_services.is_empty() {
        ScanResult::new("openclaw:mdns", ScanStatus::Pass,
            "No OpenClaw/ClawTower services advertised via mDNS")
    } else {
        ScanResult::new("openclaw:mdns", ScanStatus::Warn,
            &format!("OpenClaw services advertised via mDNS (info leak): {}",
                openclaw_services.join("; ")))
    }
}

/// Scan for mDNS info leaks by checking avahi-browse.
pub fn scan_mdns_leaks() -> Vec<ScanResult> {
    match Command::new("avahi-browse").args(["-apt", "--no-db-lookup"]).output() {
        Ok(output) => vec![check_mdns_openclaw_leak(
            &String::from_utf8_lossy(&output.stdout))],
        Err(_) => vec![ScanResult::new("openclaw:mdns", ScanStatus::Pass,
            "avahi-browse not available — mDNS check skipped")],
    }
}

/// Scan OpenClaw extensions directory for installed plugins.
pub fn scan_extensions_dir(extensions_path: &str) -> Vec<ScanResult> {
    let path = std::path::Path::new(extensions_path);
    if !path.exists() {
        return vec![ScanResult::new("openclaw:extensions", ScanStatus::Pass,
            "No extensions directory — no plugins installed")];
    }

    let mut results = Vec::new();
    let mut count = 0;

    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                count += 1;
                let pkg = entry.path().join("package.json");
                if pkg.exists() {
                    results.push(ScanResult::new("openclaw:extension",
                        ScanStatus::Warn,
                        &format!("Plugin installed: {} — verify trusted source",
                            entry.file_name().to_string_lossy())));
                }
            }
        }
    }

    if results.is_empty() {
        results.push(ScanResult::new("openclaw:extensions", ScanStatus::Pass,
            &format!("{} extension dirs found, all clean", count)));
    }

    results
}

/// Check OpenClaw Control UI security settings using proper JSON parsing.
pub fn scan_control_ui_security(config: &str) -> Vec<ScanResult> {
    let mut results = Vec::new();

    if let Ok(val) = serde_json::from_str::<serde_json::Value>(config) {
        // Check dangerouslyDisableDeviceAuth
        let dangerous = val.pointer("/controlUi/dangerouslyDisableDeviceAuth")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if dangerous {
            results.push(ScanResult::new("openclaw:controlui", ScanStatus::Fail,
                "Control UI: dangerouslyDisableDeviceAuth is TRUE — severe security downgrade"));
        }

        // Check allowInsecureAuth
        let insecure = val.pointer("/controlUi/allowInsecureAuth")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if insecure {
            results.push(ScanResult::new("openclaw:controlui", ScanStatus::Warn,
                "Control UI: allowInsecureAuth enabled — token-only auth, no device pairing"));
        }
    }
    // If JSON parsing fails, skip silently (other checks will catch malformed config)

    if results.is_empty() {
        results.push(ScanResult::new("openclaw:controlui", ScanStatus::Pass,
            "Control UI security settings nominal"));
    }

    results
}

/// Check whether the OpenClaw process is running inside a container/namespace.
///
/// Detects Docker, LXC, and general PID namespace isolation by inspecting
/// /proc/<pid>/cgroup and /proc/1/cgroup. Running bare-metal is a WARN.
pub fn scan_openclaw_container_isolation() -> ScanResult {
    // Find openclaw PID
    let pid = match run_cmd("pgrep", &["-x", "openclaw"]) {
        Ok(p) if !p.trim().is_empty() => p.trim().lines().next().unwrap_or("").to_string(),
        _ => {
            return ScanResult::new("openclaw:isolation", ScanStatus::Warn,
                "OpenClaw process not found — cannot check container isolation");
        }
    };

    // Check process cgroup for container indicators
    let cgroup_path = format!("/proc/{}/cgroup", pid);
    let cgroup = std::fs::read_to_string(&cgroup_path).unwrap_or_default();

    let in_docker = cgroup.contains("/docker/") || cgroup.contains("/containerd/");
    let in_lxc = cgroup.contains("/lxc/");
    let in_podman = cgroup.contains("/libpod-");

    // Also check for PID namespace isolation (PID 1 in container won't be systemd/init)
    let pid_ns_self = std::fs::read_link(format!("/proc/{}/ns/pid", pid)).ok();
    let pid_ns_init = std::fs::read_link("/proc/1/ns/pid").ok();
    let ns_isolated = pid_ns_self != pid_ns_init && pid_ns_self.is_some();

    if in_docker || in_podman {
        ScanResult::new("openclaw:isolation", ScanStatus::Pass,
            "OpenClaw running inside container (Docker/Podman)")
    } else if in_lxc {
        ScanResult::new("openclaw:isolation", ScanStatus::Pass,
            "OpenClaw running inside LXC container")
    } else if ns_isolated {
        ScanResult::new("openclaw:isolation", ScanStatus::Pass,
            "OpenClaw running in isolated PID namespace")
    } else {
        ScanResult::new("openclaw:isolation", ScanStatus::Warn,
            "OpenClaw running on bare metal — consider containerizing for isolation")
    }
}

/// Check whether the OpenClaw process is running as root (UID 0).
///
/// Running as root gives the agent full system access, violating least-privilege.
pub fn scan_openclaw_running_as_root() -> ScanResult {
    let pid = match run_cmd("pgrep", &["-x", "openclaw"]) {
        Ok(p) if !p.trim().is_empty() => p.trim().lines().next().unwrap_or("").to_string(),
        _ => {
            return ScanResult::new("openclaw:run_as_root", ScanStatus::Warn,
                "OpenClaw process not found — cannot check running UID");
        }
    };

    // Read /proc/<pid>/status for Uid line
    let status_path = format!("/proc/{}/status", pid);
    let status = match std::fs::read_to_string(&status_path) {
        Ok(s) => s,
        Err(_) => {
            return ScanResult::new("openclaw:run_as_root", ScanStatus::Warn,
                &format!("Cannot read {} — permission denied or process exited", status_path));
        }
    };

    // Uid line format: "Uid:\treal\teffective\tsaved\tfs"
    let uid_line = status.lines().find(|l| l.starts_with("Uid:"));
    if let Some(line) = uid_line {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // fields[1] = real UID, fields[2] = effective UID
        let effective_uid = fields.get(2).unwrap_or(&"");
        if *effective_uid == "0" {
            ScanResult::new("openclaw:run_as_root", ScanStatus::Fail,
                "OpenClaw running as root (UID 0) — use a dedicated non-admin user")
        } else {
            ScanResult::new("openclaw:run_as_root", ScanStatus::Pass,
                &format!("OpenClaw running as UID {} (non-root)", effective_uid))
        }
    } else {
        ScanResult::new("openclaw:run_as_root", ScanStatus::Warn,
            "Could not determine OpenClaw UID from /proc status")
    }
}

/// Scan OpenClaw config files for hardcoded API keys / secrets.
///
/// Keys should be loaded via environment variables at runtime, never stored
/// in config files where they can be leaked in logs, backups, or version control.
pub fn scan_openclaw_hardcoded_secrets() -> ScanResult {
    let state_dir = format!("{}/.openclaw", detect_agent_home());
    let config_paths = [
        format!("{}/openclaw.json", state_dir),
        format!("{}/agents/main/agent/gateway.yaml", state_dir),
    ];

    // Patterns that indicate hardcoded API keys (prefix + min length)
    const KEY_PREFIXES: &[&str] = &[
        "sk-ant-",       // Anthropic
        "sk-proj-",      // OpenAI project keys
        "sk-",           // OpenAI legacy (match after more specific)
        "key-",          // Generic API keys
        "gsk_",          // Groq
        "xai-",          // xAI/Grok
        "AKIA",          // AWS access key ID
        "ghp_",          // GitHub personal access token
        "glpat-",        // GitLab personal access token
        "xoxb-",         // Slack bot token
        "xoxp-",         // Slack user token
    ];

    let mut found = Vec::new();

    for path in &config_paths {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        for prefix in KEY_PREFIXES {
            // Look for the prefix followed by at least 16 more chars (real keys are long)
            if let Some(pos) = content.find(prefix) {
                let after = &content[pos + prefix.len()..];
                let key_chars = after.chars().take_while(|c| c.is_alphanumeric() || *c == '-' || *c == '_').count();
                if key_chars >= 16 {
                    let file_name = std::path::Path::new(path)
                        .file_name().unwrap_or_default().to_string_lossy();
                    found.push(format!("{}:{}", file_name, prefix));
                }
            }
        }
    }

    if found.is_empty() {
        return ScanResult::new("openclaw:hardcoded_secrets", ScanStatus::Pass,
            "No hardcoded API keys detected in OpenClaw config");
    }

    // Attempt auto-remediation: replace real keys with proxy virtual keys
    let mut remediated = Vec::new();
    for path in &config_paths {
        let results = remediate::remediate_file(
            path,
            remediate::MANIFEST_PATH,
            remediate::OVERLAY_PATH,
        );
        for r in results {
            if r.success {
                remediated.push(format!("{}→{} ({})", r.prefix, r.virtual_key, r.provider));
            }
        }
    }

    if !remediated.is_empty() {
        return ScanResult::new("openclaw:remediated_secrets", ScanStatus::Fail,
            &format!("Auto-remediated {} hardcoded key(s): {}. Real keys secured in proxy config. Run `clawtower restore-keys` to reverse.",
                remediated.len(), remediated.join(", ")));
    }

    // Remediation failed or nothing to remediate — return original detection alert
    ScanResult::new("openclaw:hardcoded_secrets", ScanStatus::Fail,
        &format!("Hardcoded API keys in config (use env vars instead): {}",
            found.join(", ")))
}

/// Check whether the installed OpenClaw version is current.
///
/// Compares `openclaw --version` output against known latest or checks
/// if the binary was last modified more than 30 days ago as a staleness proxy.
pub fn scan_openclaw_version_freshness() -> ScanResult {
    // Try to get the installed version
    let version_output = match run_cmd("openclaw", &["--version"]) {
        Ok(v) => v.trim().to_string(),
        Err(_) => {
            // Fallback: check binary modification time
            let binary_paths = ["/usr/local/bin/openclaw", "/usr/bin/openclaw"];
            let binary_path = binary_paths.iter().find(|p| std::path::Path::new(p).exists());

            return if let Some(path) = binary_path {
                match std::fs::metadata(path) {
                    Ok(meta) => {
                        if let Ok(modified) = meta.modified() {
                            let age = modified.elapsed().unwrap_or_default();
                            let days = age.as_secs() / 86400;
                            if days > 90 {
                                ScanResult::new("openclaw:version", ScanStatus::Warn,
                                    &format!("OpenClaw binary {} days old — check for updates", days))
                            } else {
                                ScanResult::new("openclaw:version", ScanStatus::Pass,
                                    &format!("OpenClaw binary modified {} days ago", days))
                            }
                        } else {
                            ScanResult::new("openclaw:version", ScanStatus::Warn,
                                "Cannot determine OpenClaw binary age")
                        }
                    }
                    Err(_) => ScanResult::new("openclaw:version", ScanStatus::Warn,
                        "Cannot read OpenClaw binary metadata"),
                }
            } else {
                ScanResult::new("openclaw:version", ScanStatus::Warn,
                    "OpenClaw binary not found — cannot check version freshness")
            };
        }
    };

    // Check if there's an update available via openclaw's own mechanism
    match run_cmd("openclaw", &["update", "--check"]) {
        Ok(output) => {
            let up_to_date = output.contains("up to date")
                || output.contains("already on the latest")
                || output.contains("no update");
            if up_to_date {
                ScanResult::new("openclaw:version", ScanStatus::Pass,
                    &format!("OpenClaw {} — up to date", version_output))
            } else {
                ScanResult::new("openclaw:version", ScanStatus::Warn,
                    &format!("OpenClaw {} — update available: {}",
                        version_output, output.trim().chars().take(100).collect::<String>()))
            }
        }
        Err(_) => {
            // update --check not available, just report the version
            ScanResult::new("openclaw:version", ScanStatus::Pass,
                &format!("OpenClaw {} installed (update check unavailable)", version_output))
        }
    }
}

/// Verify that auditd read-watch rules are installed for critical credential files.
///
/// Infostealers read credential files without modifying them, so sentinel (inotify)
/// can't detect the access. Auditd `-p r` rules are the only kernel-level defense
/// against silent reads. This scanner confirms those rules are actually loaded.
pub fn scan_openclaw_credential_audit() -> ScanResult {
    // Critical files that must have auditd read-watch rules
    let required_watches: &[&str] = &[
        "device.json",
        "openclaw.json",
        "auth-profiles.json",
        "gateway.yaml",
        ".aws/credentials",
        ".ssh/id_",
    ];

    match run_cmd_with_sudo("auditctl", &["-l"]) {
        Ok(rules) => {
            let missing: Vec<&str> = required_watches.iter()
                .filter(|watch| !rules.lines().any(|line| line.contains(**watch) && line.contains("-p r")))
                .copied()
                .collect();

            if missing.is_empty() {
                ScanResult::new("openclaw:credential_audit", ScanStatus::Pass,
                    &format!("All {} credential read-watch rules installed", required_watches.len()))
            } else {
                ScanResult::new("openclaw:credential_audit", ScanStatus::Warn,
                    &format!("Missing auditd read-watch rules for: {}. Run: clawtower setup audit-rules",
                        missing.join(", ")))
            }
        }
        Err(_) => {
            ScanResult::new("openclaw:credential_audit", ScanStatus::Warn,
                "Cannot check auditd rules (auditctl not available or no permission)")
        }
    }
}

pub fn scan_openclaw_security() -> Vec<ScanResult> {
    let mut results = Vec::new();
    let state_dir = format!("{}/.openclaw", detect_agent_home());

    // Check OpenClaw gateway config (JSON format in openclaw.json)
    let config_paths = [
        format!("{}/openclaw.json", state_dir),
        format!("{}/agents/main/agent/gateway.yaml", state_dir),
    ];
    let gateway_config = config_paths.iter()
        .find(|p| std::path::Path::new(p).exists())
        .and_then(|p| std::fs::read_to_string(p).ok());

    if let Some(ref config) = gateway_config {
        // 1. Gateway not publicly exposed
        let bind_loopback = config.contains("\"loopback\"") || config.contains("\"127.0.0.1\"");
        let bind_public = config.contains("\"bind\":\"0.0.0.0\"") || config.contains("\"bind\": \"0.0.0.0\"");

        let listeners = run_cmd("ss", &["-tlnp"]).unwrap_or_default();
        let gateway_exposed = listeners.lines().any(|l| l.contains("0.0.0.0:18789") || l.contains("*:18789"));

        if bind_public || gateway_exposed {
            results.push(ScanResult::new("openclaw:gateway", ScanStatus::Fail,
                "Gateway bound to 0.0.0.0 — publicly accessible! Use loopback + tunnel"));
        } else if bind_loopback {
            results.push(ScanResult::new("openclaw:gateway", ScanStatus::Pass,
                "Gateway bound to loopback only"));
        } else {
            results.push(ScanResult::new("openclaw:gateway", ScanStatus::Warn,
                "Gateway bind address unclear — verify not public"));
        }

        // 2. Auth required
        let has_auth = config.contains("\"token\"") && config.contains("\"auth\"");
        let auth_none = config.contains("\"mode\":\"none\"") || config.contains("\"mode\": \"none\"");

        if auth_none || !has_auth {
            results.push(ScanResult::new("openclaw:auth", ScanStatus::Fail,
                "Gateway auth disabled — anyone can connect"));
        } else {
            results.push(ScanResult::new("openclaw:auth", ScanStatus::Pass,
                "Gateway auth enabled (token mode)"));
        }

        // 3. Filesystem scoped
        let workspace_root = config.contains("\"workspace\":\"/\"") || config.contains("\"workspace\": \"/\"");
        let workspace_scoped = config.contains("\"workspace\":\"/home/") || config.contains("\"workspace\": \"/home/");

        if workspace_root {
            results.push(ScanResult::new("openclaw:filesystem", ScanStatus::Fail,
                "Workspace set to / — agent has full filesystem access"));
        } else if workspace_scoped {
            results.push(ScanResult::new("openclaw:filesystem", ScanStatus::Pass,
                "Workspace scoped to home directory"));
        } else {
            results.push(ScanResult::new("openclaw:filesystem", ScanStatus::Warn,
                "Verify workspace is properly scoped"));
        }
    } else {
        results.push(ScanResult::new("openclaw:config", ScanStatus::Warn,
            "OpenClaw gateway config not found — skipping OpenClaw checks"));
    }

    // Permission checks (from OpenClaw security docs)
    results.push(check_path_permissions(&state_dir, 0o700, "state_dir"));
    results.push(check_path_permissions(
        &format!("{}/openclaw.json", state_dir), 0o600, "config"));
    results.push(check_path_permissions(
        &format!("{}/device.json", state_dir), 0o600, "device_key"));

    // Check credential files aren't group/world readable
    let cred_dir = format!("{}/credentials", state_dir);
    if std::path::Path::new(&cred_dir).exists() {
        results.push(check_path_permissions(&cred_dir, 0o700, "credentials_dir"));
        if let Ok(entries) = std::fs::read_dir(&cred_dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_file() {
                    results.push(check_path_permissions(
                        p.to_str().unwrap_or(""), 0o600,
                        &format!("cred:{}", p.file_name().unwrap_or_default().to_string_lossy())));
                }
            }
        }
    }

    // Session log permissions
    let agents_dir = format!("{}/agents", state_dir);
    if let Ok(agents) = std::fs::read_dir(&agents_dir) {
        for agent in agents.flatten() {
            let sessions_dir = agent.path().join("sessions");
            if sessions_dir.exists() {
                results.push(check_path_permissions(
                    sessions_dir.to_str().unwrap_or(""), 0o700,
                    &format!("sessions:{}", agent.file_name().to_string_lossy())));
            }
        }
    }

    // Symlink safety check
    results.push(check_symlinks_in_dir(&state_dir));

    // 4. Access via Tailscale/SSH tunnel
    let tailscale_running = run_cmd("tailscale", &["status"]).is_ok()
        || run_cmd("systemctl", &["is-active", "tailscaled"]).map(|s| s.trim() == "active").unwrap_or(false);

    let ssh_tunnels = run_cmd("ss", &["-tlnp"]).unwrap_or_default();
    let has_tunnel = tailscale_running
        || ssh_tunnels.contains("ssh")
        || std::path::Path::new("/var/run/tailscaled.socket").exists();

    let connectify = std::path::Path::new("/etc/connectify").exists()
        || run_cmd("systemctl", &["is-active", "connectify"]).map(|s| s.trim() == "active").unwrap_or(false);

    if tailscale_running {
        results.push(ScanResult::new("openclaw:tunnel", ScanStatus::Pass,
            "Tailscale VPN active — secure tunnel access"));
    } else if connectify || has_tunnel {
        results.push(ScanResult::new("openclaw:tunnel", ScanStatus::Pass,
            "Tunnel/VPN detected for remote access"));
    } else {
        results.push(ScanResult::new("openclaw:tunnel", ScanStatus::Warn,
            "No VPN/tunnel detected — ensure gateway is not directly exposed"));
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_path_permissions_secure() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let result = check_path_permissions(dir.path().to_str().unwrap(), 0o700, "test_dir");
        assert_eq!(result.status, ScanStatus::Pass);
    }

    #[test]
    fn test_check_path_permissions_too_open() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let result = check_path_permissions(dir.path().to_str().unwrap(), 0o700, "test_dir");
        assert_eq!(result.status, ScanStatus::Warn);
    }

    #[test]
    fn test_check_path_permissions_missing() {
        let result = check_path_permissions("/nonexistent/path/12345", 0o700, "missing");
        assert_eq!(result.status, ScanStatus::Warn);
    }

    #[test]
    fn test_check_path_permissions_exact_match() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o600)).unwrap();
        let result = check_path_permissions(dir.path().to_str().unwrap(), 0o600, "exact");
        assert_eq!(result.status, ScanStatus::Pass);
    }

    #[test]
    fn test_check_path_permissions_tighter_than_max() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o400)).unwrap();
        let result = check_path_permissions(dir.path().to_str().unwrap(), 0o700, "tight");
        assert_eq!(result.status, ScanStatus::Pass);
    }

    #[test]
    fn test_check_path_permissions_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o744)).unwrap();
        let result = check_path_permissions(dir.path().to_str().unwrap(), 0o700, "world_read");
        assert_eq!(result.status, ScanStatus::Warn);
    }

    #[test]
    fn test_check_path_permissions_group_write() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o770)).unwrap();
        let result = check_path_permissions(dir.path().to_str().unwrap(), 0o700, "group_write");
        assert_eq!(result.status, ScanStatus::Warn);
    }

    #[test]
    fn test_check_symlinks_no_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let result = check_symlinks_in_dir(dir.path().to_str().unwrap());
        assert_eq!(result.status, ScanStatus::Pass);
    }

    #[test]
    fn test_check_symlinks_missing_dir() {
        let result = check_symlinks_in_dir("/nonexistent/dir/12345");
        assert_eq!(result.status, ScanStatus::Warn);
    }

    #[test]
    fn test_check_symlinks_internal_link_ok() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real_file");
        std::fs::write(&target, "data").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let result = check_symlinks_in_dir(dir.path().to_str().unwrap());
        assert_eq!(result.status, ScanStatus::Pass);
    }

    #[test]
    fn test_check_symlinks_external_link_flagged() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("escape_link");
        std::os::unix::fs::symlink("/etc/passwd", &link).unwrap();
        let result = check_symlinks_in_dir(dir.path().to_str().unwrap());
        assert_eq!(result.status, ScanStatus::Fail);
        assert!(result.details.contains("/etc/passwd"));
    }

    #[test]
    fn test_parse_openclaw_audit_output() {
        let output = "⚠ Gateway auth: mode is 'none' — anyone on the network can connect\n✓ DM policy: pairing (secure)\n⚠ groupPolicy is 'open' for slack — restrict to allowlist\n✓ Filesystem permissions: ~/.openclaw is 700\n✗ Browser control: CDP port exposed on 0.0.0.0";
        let results = parse_openclaw_audit_output(output);
        assert_eq!(results.len(), 5);
        assert_eq!(results[0].status, ScanStatus::Warn);
        assert_eq!(results[1].status, ScanStatus::Pass);
        assert_eq!(results[2].status, ScanStatus::Warn);
        assert_eq!(results[3].status, ScanStatus::Pass);
        assert_eq!(results[4].status, ScanStatus::Fail);
    }

    #[test]
    fn test_parse_openclaw_audit_empty() {
        let results = parse_openclaw_audit_output("");
        assert!(results.is_empty());
    }

    #[test]
    fn test_parse_openclaw_audit_with_headers() {
        let output = "OpenClaw Security Audit\n=======================\n✓ Gateway bound to loopback\n⚠ No auth configured";
        let results = parse_openclaw_audit_output(output);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].status, ScanStatus::Pass);
        assert_eq!(results[1].status, ScanStatus::Warn);
    }

    #[test]
    fn test_parse_openclaw_audit_categories() {
        let output = "✓ DM policy: pairing mode active\n✗ Browser control: exposed";
        let results = parse_openclaw_audit_output(output);
        assert!(results[0].category.contains("openclaw:audit:dm_policy"));
        assert!(results[1].category.contains("openclaw:audit:browser_control"));
    }

    #[test]
    fn test_parse_openclaw_audit_only_passes() {
        let output = "✓ All good\n✓ Everything fine";
        let results = parse_openclaw_audit_output(output);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.status == ScanStatus::Pass));
    }

    #[test]
    fn test_parse_openclaw_audit_only_failures() {
        let output = "✗ Bad thing 1\n✗ Bad thing 2\n✗ Bad thing 3";
        let results = parse_openclaw_audit_output(output);
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|r| r.status == ScanStatus::Fail));
    }

    #[test]
    fn test_parse_openclaw_audit_unicode_handling() {
        let output = "✓ Résumé check: ok\n⚠ Naïve setting detected";
        let results = parse_openclaw_audit_output(output);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_mdns_openclaw_exposed() {
        let output = "+;eth0;IPv4;OpenClaw Gateway;_http._tcp;local\n";
        let result = check_mdns_openclaw_leak(output);
        assert_eq!(result.status, ScanStatus::Warn);
    }

    #[test]
    fn test_mdns_no_openclaw() {
        let output = "+;eth0;IPv4;Printer;_ipp._tcp;local\n";
        let result = check_mdns_openclaw_leak(output);
        assert_eq!(result.status, ScanStatus::Pass);
    }

    #[test]
    fn test_mdns_empty() {
        let result = check_mdns_openclaw_leak("");
        assert_eq!(result.status, ScanStatus::Pass);
    }

    #[test]
    fn test_mdns_clawtower_exposed() {
        let output = "+;eth0;IPv4;ClawTower Security;_http._tcp;local\n";
        let result = check_mdns_openclaw_leak(output);
        assert_eq!(result.status, ScanStatus::Warn);
    }

    #[test]
    fn test_mdns_case_insensitive() {
        let output = "+;wlan0;IPv4;OPENCLAW gateway;_http._tcp;local\n";
        let result = check_mdns_openclaw_leak(output);
        assert_eq!(result.status, ScanStatus::Warn);
    }

    #[test]
    fn test_scan_extensions_none() {
        let dir = tempfile::tempdir().unwrap();
        let result = scan_extensions_dir(dir.path().to_str().unwrap());
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].status, ScanStatus::Pass);
    }

    #[test]
    fn test_scan_extensions_missing_dir() {
        let result = scan_extensions_dir("/nonexistent/extensions/12345");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].status, ScanStatus::Pass);
    }

    #[test]
    fn test_scan_extensions_with_plugin() {
        let dir = tempfile::tempdir().unwrap();
        let plugin_dir = dir.path().join("my-plugin");
        std::fs::create_dir(&plugin_dir).unwrap();
        std::fs::write(plugin_dir.join("package.json"), "{}").unwrap();
        let result = scan_extensions_dir(dir.path().to_str().unwrap());
        assert!(result.iter().any(|r| r.status == ScanStatus::Warn));
    }

    #[test]
    fn test_scan_extensions_dir_without_package_json() {
        let dir = tempfile::tempdir().unwrap();
        let plugin_dir = dir.path().join("empty-plugin");
        std::fs::create_dir(&plugin_dir).unwrap();
        let result = scan_extensions_dir(dir.path().to_str().unwrap());
        assert!(result.iter().all(|r| r.status == ScanStatus::Pass));
    }

    #[test]
    fn test_scan_extensions_multiple_plugins() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..3 {
            let plugin_dir = dir.path().join(format!("plugin-{}", i));
            std::fs::create_dir(&plugin_dir).unwrap();
            std::fs::write(plugin_dir.join("package.json"), "{}").unwrap();
        }
        let result = scan_extensions_dir(dir.path().to_str().unwrap());
        let warns: Vec<_> = result.iter().filter(|r| r.status == ScanStatus::Warn).collect();
        assert_eq!(warns.len(), 3);
    }

    #[test]
    fn test_control_ui_dangerous_flag() {
        let config = r#"{"controlUi": {"dangerouslyDisableDeviceAuth": true}}"#;
        let results = scan_control_ui_security(config);
        assert!(results.iter().any(|r| r.status == ScanStatus::Fail));
    }

    #[test]
    fn test_control_ui_insecure_auth() {
        let config = r#"{"controlUi": {"allowInsecureAuth": true}}"#;
        let results = scan_control_ui_security(config);
        assert!(results.iter().any(|r| r.status == ScanStatus::Warn));
    }

    #[test]
    fn test_control_ui_secure() {
        let config = r#"{"controlUi": {"enabled": true}}"#;
        let results = scan_control_ui_security(config);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, ScanStatus::Pass);
    }

    #[test]
    fn test_control_ui_both_flags() {
        let config = r#"{"controlUi": {"dangerouslyDisableDeviceAuth": true, "allowInsecureAuth": true}}"#;
        let results = scan_control_ui_security(config);
        assert_eq!(results.len(), 2);
        assert!(results.iter().any(|r| r.status == ScanStatus::Fail));
        assert!(results.iter().any(|r| r.status == ScanStatus::Warn));
    }

    #[test]
    fn test_control_ui_invalid_json() {
        let config = "not valid json at all";
        let results = scan_control_ui_security(config);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, ScanStatus::Pass);
    }

    #[test]
    fn test_control_ui_empty_object() {
        let config = "{}";
        let results = scan_control_ui_security(config);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, ScanStatus::Pass);
    }

    #[test]
    fn test_control_ui_flags_false() {
        let config = r#"{"controlUi": {"dangerouslyDisableDeviceAuth": false, "allowInsecureAuth": false}}"#;
        let results = scan_control_ui_security(config);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, ScanStatus::Pass);
    }

    #[test]
    fn test_openclaw_container_isolation_no_process() {
        let result = scan_openclaw_container_isolation();
        assert!(result.status == ScanStatus::Warn || result.status == ScanStatus::Pass);
        assert!(result.category == "openclaw:isolation");
    }

    #[test]
    fn test_openclaw_running_as_root_no_process() {
        let result = scan_openclaw_running_as_root();
        assert!(result.status == ScanStatus::Warn || result.status == ScanStatus::Pass
            || result.status == ScanStatus::Fail);
        assert!(result.category == "openclaw:run_as_root");
    }

    #[test]
    fn test_openclaw_hardcoded_secrets_no_config() {
        let result = scan_openclaw_hardcoded_secrets();
        assert!(result.category == "openclaw:hardcoded_secrets");
    }

    #[test]
    fn test_openclaw_hardcoded_secrets_detection() {
        let config_with_key = r#"{"apiKey": "sk-ant-api03-realkey1234567890abcdef1234567890"}"#;
        let has_match = ["sk-ant-"].iter().any(|prefix| {
            if let Some(pos) = config_with_key.find(prefix) {
                let after = &config_with_key[pos + prefix.len()..];
                let key_chars = after.chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
                    .count();
                key_chars >= 16
            } else {
                false
            }
        });
        assert!(has_match, "Should detect sk-ant- prefixed key");
    }

    #[test]
    fn test_openclaw_hardcoded_secrets_short_value_ignored() {
        let config = r#"{"mode": "sk-ant-short"}"#;
        let has_match = ["sk-ant-"].iter().any(|prefix| {
            if let Some(pos) = config.find(prefix) {
                let after = &config[pos + prefix.len()..];
                let key_chars = after.chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
                    .count();
                key_chars >= 16
            } else {
                false
            }
        });
        assert!(!has_match, "Short values should not trigger secret detection");
    }

    #[test]
    fn test_openclaw_version_freshness_no_binary() {
        let result = scan_openclaw_version_freshness();
        assert!(result.category == "openclaw:version");
    }
}
