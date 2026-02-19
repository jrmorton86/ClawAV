// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Response Engine — automated threat containment with human approval.
//!
//! Evaluates alerts against playbooks, creates pending actions, and waits for
//! human approval via Slack, TUI, or API. Auto-denies on timeout (default 2 min).
//!
//! Two modes:
//! - **Gate**: action is held mid-flight (clawsudo, proxy). Agent blocks until resolved.
//! - **Reactive**: threat detected after the fact. Containment proposed.
//!
//! Critical alerts always require human approval. Warning behavior is configurable.

use super::alerts::{Alert, Severity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex, oneshot};

// ── Config types (moved from config.rs) ──────────────────────────────────────

/// Configuration for the response engine — automated threat containment with human approval.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResponseConfig {
    /// Enable the response engine.
    #[serde(default)]
    pub enabled: bool,

    /// Default timeout for human approval in seconds (default: 120 = 2 minutes).
    #[serde(default = "default_response_timeout")]
    pub timeout_secs: u64,

    /// What to do with Warning-level alerts. Options: "gate", "alert_only", "auto_deny".
    /// Critical alerts always use "gate" regardless of this setting.
    #[serde(default = "default_warning_mode")]
    pub warning_mode: String,

    /// Directory containing response playbook YAML files.
    #[serde(default = "default_playbook_dir")]
    pub playbook_dir: String,

    /// Message returned to agent when an action is denied.
    #[serde(default = "default_deny_message")]
    pub deny_message: String,
}

fn default_response_timeout() -> u64 { 120 }
fn default_warning_mode() -> String { "gate".to_string() }
fn default_playbook_dir() -> String { "/etc/clawtower/playbooks".to_string() }
fn default_deny_message() -> String {
    "Action blocked by ClawTower security policy. Contact administrator.".to_string()
}

impl Default for ResponseConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            timeout_secs: default_response_timeout(),
            warning_mode: default_warning_mode(),
            playbook_dir: default_playbook_dir(),
            deny_message: default_deny_message(),
        }
    }
}

/// Incident mode configuration - deterministic containment on toggle.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IncidentModeConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_incident_dedup")]
    pub dedup_window_secs: u64,
    #[serde(default = "default_incident_scan_dedup")]
    pub scan_dedup_window_secs: u64,
    #[serde(default = "default_incident_rate_limit")]
    pub rate_limit_per_source: u32,
    #[serde(default)]
    pub lock_clawsudo: bool,
}

fn default_incident_dedup() -> u64 { 2 }
fn default_incident_scan_dedup() -> u64 { 60 }
fn default_incident_rate_limit() -> u32 { 200 }

impl Default for IncidentModeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            dedup_window_secs: default_incident_dedup(),
            scan_dedup_window_secs: default_incident_scan_dedup(),
            rate_limit_per_source: default_incident_rate_limit(),
            lock_clawsudo: false,
        }
    }
}

// ── Core Types ───────────────────────────────────────────────────────────────

/// A pending action awaiting human approval.
#[derive(Clone, Serialize)]
pub struct PendingAction {
    /// Unique identifier (UUID v4).
    pub id: String,
    /// Which module detected the threat.
    pub threat_source: String,
    /// Human-readable description of the threat.
    pub threat_message: String,
    /// Alert severity.
    pub severity: Severity,
    /// Gate (action held) or Reactive (post-detection containment).
    pub mode: ResponseMode,
    /// Proposed containment actions.
    pub actions: Vec<ContainmentAction>,
    /// Which playbook matched, if any.
    pub playbook: Option<String>,
    /// When the pending action was created (serialized as elapsed secs for JSON).
    #[serde(skip)]
    pub created_at: Instant,
    /// How long to wait for approval.
    #[serde(skip)]
    pub timeout: Duration,
    /// Current status.
    pub status: PendingStatus,
}

/// Whether the response engine intercepted the action or is reacting after detection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ResponseMode {
    /// Action is held at a control point. Agent is blocked.
    Gate,
    /// Threat detected post-fact. Containment proposed.
    Reactive,
}

/// A containment action the response engine can execute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContainmentAction {
    KillProcess { pid: u32 },
    SuspendProcess { pid: u32 },
    DropNetwork { uid: u32 },
    RevokeApiKeys,
    FreezeFilesystem { paths: Vec<String> },
    LockClawsudo,
}

impl std::fmt::Display for ContainmentAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContainmentAction::KillProcess { pid } => write!(f, "kill_process(pid={})", pid),
            ContainmentAction::SuspendProcess { pid } => write!(f, "suspend_process(pid={})", pid),
            ContainmentAction::DropNetwork { uid } => write!(f, "drop_network(uid={})", uid),
            ContainmentAction::RevokeApiKeys => write!(f, "revoke_api_keys"),
            ContainmentAction::FreezeFilesystem { paths } => write!(f, "freeze_filesystem({} paths)", paths.len()),
            ContainmentAction::LockClawsudo => write!(f, "lock_clawsudo"),
        }
    }
}

/// Current status of a pending action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PendingStatus {
    AwaitingApproval,
    Approved {
        by: String,
        message: Option<String>,
        surface: String,
    },
    Denied {
        by: String,
        message: Option<String>,
        surface: String,
    },
    Expired,
}

// ── Playbooks ────────────────────────────────────────────────────────────────

/// A response playbook — a preconfigured bundle of containment actions.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct Playbook {
    /// Human-readable name.
    pub name: String,
    /// Description of what this playbook does.
    pub description: String,
    /// Containment actions to propose (as string tags).
    pub actions: Vec<String>,
    /// Alert source/message patterns that trigger this playbook.
    pub trigger_on: Vec<String>,
}

/// Top-level playbook file structure.
#[derive(Debug, Deserialize)]
struct PlaybookFile {
    playbooks: HashMap<String, Playbook>,
}

/// Load playbooks from a directory of YAML files.
pub fn load_playbooks(dir: &Path) -> Vec<(String, Playbook)> {
    let mut result = Vec::new();
    if !dir.exists() {
        return result;
    }
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "yaml" || e == "yml").unwrap_or(false) {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    match serde_yaml::from_str::<PlaybookFile>(&content) {
                        Ok(file) => {
                            for (name, playbook) in file.playbooks {
                                result.push((name, playbook));
                            }
                        }
                        Err(e) => {
                            eprintln!("Warning: failed to parse playbook {}: {}", path.display(), e);
                        }
                    }
                }
            }
        }
    }
    result
}

// ── Gate Request (for clawsudo/proxy integration) ────────────────────────────

/// A gate request from clawsudo or the proxy, waiting for approval.
#[allow(dead_code)]
pub struct GateRequest {
    /// The pending action ID this gate is associated with.
    pub action_id: String,
    /// Channel to send the decision back to the blocked caller.
    pub reply_tx: oneshot::Sender<GateDecision>,
}

/// The decision for a gated request.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum GateDecision {
    Approved,
    Denied { reason: String },
}

// ── Response Engine ──────────────────────────────────────────────────────────

/// Shared state for pending actions, accessible from TUI, API, and Slack handlers.
pub type SharedPendingActions = Arc<Mutex<Vec<PendingAction>>>;

/// Create a new shared pending actions store.
pub fn new_shared_pending() -> SharedPendingActions {
    Arc::new(Mutex::new(Vec::new()))
}

/// Message sent to the response engine to request approval.
pub enum ResponseRequest {
    /// Evaluate an alert and create a pending action if it matches a playbook.
    EvaluateAlert(Alert),
    /// A gate request from clawsudo/proxy — block until approved or denied.
    #[allow(dead_code)]
    GateAction {
        alert: Alert,
        actions: Vec<ContainmentAction>,
        reply_tx: oneshot::Sender<GateDecision>,
    },
    /// Resolve a pending action (approve or deny from any surface).
    Resolve {
        id: String,
        approved: bool,
        by: String,
        message: Option<String>,
        surface: String,
    },
}

/// Run the response engine as a long-lived tokio task.
///
/// Receives requests via `request_rx`, manages pending actions, sends notifications
/// via `slack_tx` and `tui_tx`, auto-expires after timeout.
pub async fn run_response_engine(
    mut request_rx: mpsc::Receiver<ResponseRequest>,
    slack_tx: mpsc::Sender<Alert>,
    pending_store: SharedPendingActions,
    config: ResponseConfig,
    playbooks: Vec<(String, Playbook)>,
    orchestrator: Option<Arc<crate::approval::ApprovalOrchestrator>>,
) {
    // Map from pending action ID → gate reply channel (if gated)
    let mut gate_channels: HashMap<String, oneshot::Sender<GateDecision>> = HashMap::new();

    let timeout = Duration::from_secs(config.timeout_secs);
    let deny_message = config.deny_message.clone();

    loop {
        // Check for expired pending actions every 500ms
        let request = tokio::time::timeout(Duration::from_millis(500), request_rx.recv()).await;

        // Expire old pending actions
        {
            let mut pending = pending_store.lock().await;
            let now = Instant::now();
            for action in pending.iter_mut() {
                if matches!(action.status, PendingStatus::AwaitingApproval)
                    && now.duration_since(action.created_at) >= action.timeout
                {
                    action.status = PendingStatus::Expired;

                    // Notify gate channel if this was a gated request
                    if let Some(reply_tx) = gate_channels.remove(&action.id) {
                        let _ = reply_tx.send(GateDecision::Denied {
                            reason: format!("{} (approval timed out)", deny_message),
                        });
                    }

                    // Send expiry alert
                    let expiry_alert = Alert::new(
                        Severity::Warning,
                        "response",
                        &format!(
                            "Pending action expired (no human response in {}s): {} — {}",
                            config.timeout_secs, action.threat_source, action.threat_message
                        ),
                    );
                    let _ = slack_tx.send(expiry_alert).await;
                }
            }

            // Garbage collect resolved/expired actions older than 10 minutes
            pending.retain(|a| {
                matches!(a.status, PendingStatus::AwaitingApproval)
                    || now.duration_since(a.created_at) < Duration::from_secs(600)
            });
        }

        // Process incoming request
        let request = match request {
            Ok(Some(r)) => r,
            Ok(None) => break, // channel closed
            Err(_) => continue, // timeout, loop back to expire check
        };

        match request {
            ResponseRequest::EvaluateAlert(alert) => {
                // Skip if not critical or warning
                if alert.severity < Severity::Warning {
                    continue;
                }

                // Check warning mode
                if alert.severity == Severity::Warning && config.warning_mode == "alert_only" {
                    continue;
                }

                // Match against playbooks
                let matched = find_matching_playbook(&alert, &playbooks);

                if let Some((name, playbook)) = matched {
                    let actions = parse_containment_actions(&playbook.actions, &alert);
                    let id = uuid::Uuid::new_v4().to_string();

                    let pending_action = PendingAction {
                        id: id.clone(),
                        threat_source: alert.source.clone(),
                        threat_message: alert.message.clone(),
                        severity: alert.severity.clone(),
                        mode: ResponseMode::Reactive,
                        actions: actions.clone(),
                        playbook: Some(name.clone()),
                        created_at: Instant::now(),
                        timeout,
                        status: PendingStatus::AwaitingApproval,
                    };

                    // Store
                    {
                        let mut pending = pending_store.lock().await;
                        pending.push(pending_action);
                    }

                    // Also submit to unified approval orchestrator if available
                    if let Some(ref orch) = orchestrator {
                        let approval_req = crate::approval::ApprovalRequest::new(
                            crate::approval::ApprovalSource::ResponseEngine {
                                threat_id: id.clone(),
                                playbook: Some(name.clone()),
                            },
                            format!("{}: {}", alert.source, alert.message),
                            "response-engine".to_string(),
                            alert.severity.clone(),
                            alert.message.clone(),
                            timeout,
                        );
                        if let Err(e) = orch.submit(approval_req).await {
                            eprintln!("Failed to submit to approval orchestrator: {}", e);
                        }
                    }

                    // Send Slack notification
                    let actions_str: Vec<String> = actions.iter().map(|a| a.to_string()).collect();
                    let notif = Alert::new(
                        Severity::Critical,
                        "response",
                        &format!(
                            "🚨 PENDING APPROVAL ({}s timeout) [{}]: {} — {} | Proposed: {} | Reply APPROVE-{} or DENY-{}",
                            config.timeout_secs, name, alert.source, alert.message,
                            actions_str.join(", "), id, id
                        ),
                    );
                    let _ = slack_tx.send(notif).await;
                }
            }

            ResponseRequest::GateAction { alert, actions, reply_tx } => {
                let id = uuid::Uuid::new_v4().to_string();

                let actions_str: Vec<String> = actions.iter().map(|a| a.to_string()).collect();
                let pending_action = PendingAction {
                    id: id.clone(),
                    threat_source: alert.source.clone(),
                    threat_message: alert.message.clone(),
                    severity: alert.severity.clone(),
                    mode: ResponseMode::Gate,
                    actions: actions.clone(),
                    playbook: None,
                    created_at: Instant::now(),
                    timeout,
                    status: PendingStatus::AwaitingApproval,
                };

                // Store pending action and gate channel
                {
                    let mut pending = pending_store.lock().await;
                    pending.push(pending_action);
                }
                gate_channels.insert(id.clone(), reply_tx);

                // Also submit to unified approval orchestrator if available
                if let Some(ref orch) = orchestrator {
                    let approval_req = crate::approval::ApprovalRequest::new(
                        crate::approval::ApprovalSource::ResponseEngine {
                            threat_id: id.clone(),
                            playbook: None,
                        },
                        format!("{}: {}", alert.source, alert.message),
                        "response-engine".to_string(),
                        alert.severity.clone(),
                        alert.message.clone(),
                        timeout,
                    );
                    if let Err(e) = orch.submit(approval_req).await {
                        eprintln!("Failed to submit to approval orchestrator: {}", e);
                    }
                }

                // Slack notification
                let notif = Alert::new(
                    Severity::Critical,
                    "response",
                    &format!(
                        "🔒 GATED ACTION ({}s timeout): {} — {} | Actions: {} | Reply APPROVE-{} or DENY-{}",
                        config.timeout_secs, alert.source, alert.message,
                        actions_str.join(", "), id, id
                    ),
                );
                let _ = slack_tx.send(notif).await;
            }

            ResponseRequest::Resolve { id, approved, by, message, surface } => {
                let mut pending = pending_store.lock().await;
                if let Some(action) = pending.iter_mut().find(|a| a.id == id) {
                    if !matches!(action.status, PendingStatus::AwaitingApproval) {
                        continue; // already resolved
                    }

                    if approved {
                        action.status = PendingStatus::Approved {
                            by: by.clone(),
                            message: message.clone(),
                            surface: surface.clone(),
                        };

                        // Execute containment actions
                        for containment in &action.actions {
                            execute_containment(containment).await;
                        }

                        // Release gate if present
                        if let Some(reply_tx) = gate_channels.remove(&id) {
                            let _ = reply_tx.send(GateDecision::Approved);
                        }
                    } else {
                        action.status = PendingStatus::Denied {
                            by: by.clone(),
                            message: message.clone(),
                            surface: surface.clone(),
                        };

                        // Deny gate if present
                        if let Some(reply_tx) = gate_channels.remove(&id) {
                            let _ = reply_tx.send(GateDecision::Denied {
                                reason: format!(
                                    "{} Denied by {} via {}.{}",
                                    deny_message,
                                    by,
                                    surface,
                                    message.as_deref().map(|m| format!(" Reason: {}", m)).unwrap_or_default()
                                ),
                            });
                        }
                    }

                    // Audit log alert
                    let decision = if approved { "APPROVED" } else { "DENIED" };
                    let audit_alert = Alert::new(
                        Severity::Warning,
                        "response",
                        &format!(
                            "Action {} {} by {} via {}. Source: {} — {}{}",
                            id, decision, by, surface,
                            action.threat_source, action.threat_message,
                            message.as_deref().map(|m| format!(". Note: {}", m)).unwrap_or_default()
                        ),
                    );
                    drop(pending); // release lock before sending
                    let _ = slack_tx.send(audit_alert).await;
                }
            }
        }
    }
}

// ── Playbook Matching ────────────────────────────────────────────────────────

fn find_matching_playbook<'a>(
    alert: &Alert,
    playbooks: &'a [(String, Playbook)],
) -> Option<(&'a String, &'a Playbook)> {
    let alert_text = format!("{} {}", alert.source, alert.message).to_lowercase();
    for (name, playbook) in playbooks {
        for trigger in &playbook.trigger_on {
            if alert_text.contains(&trigger.to_lowercase()) {
                return Some((name, playbook));
            }
        }
    }
    None
}

/// Parse string action tags into ContainmentAction enums.
/// Some actions need context from the alert (e.g., PID, UID).
fn parse_containment_actions(action_tags: &[String], alert: &Alert) -> Vec<ContainmentAction> {
    let mut result = Vec::new();
    for tag in action_tags {
        match tag.as_str() {
            "kill_process" => {
                if let Some(pid) = extract_pid(&alert.message) {
                    result.push(ContainmentAction::KillProcess { pid });
                }
            }
            "suspend_process" => {
                if let Some(pid) = extract_pid(&alert.message) {
                    result.push(ContainmentAction::SuspendProcess { pid });
                }
            }
            "drop_network" => {
                if let Some(uid) = extract_uid(&alert.message) {
                    result.push(ContainmentAction::DropNetwork { uid });
                }
            }
            "revoke_api_keys" => {
                result.push(ContainmentAction::RevokeApiKeys);
            }
            "freeze_filesystem" => {
                let paths = extract_paths(&alert.message);
                if !paths.is_empty() {
                    result.push(ContainmentAction::FreezeFilesystem { paths });
                }
            }
            "lock_clawsudo" => {
                result.push(ContainmentAction::LockClawsudo);
            }
            _ => {
                eprintln!("Warning: unknown containment action tag: {}", tag);
            }
        }
    }
    result
}

/// Extract a PID from an alert message (looks for pid=NNNN or PID NNNN patterns).
/// Returns None if no PID found or if PID is 0 (which would signal the entire process group).
fn extract_pid(message: &str) -> Option<u32> {
    // Try pid=NNNN
    if let Some(idx) = message.find("pid=") {
        let rest = &message[idx + 4..];
        let num: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(pid) = num.parse::<u32>() {
            if pid > 0 {
                return Some(pid);
            }
            eprintln!("Warning: refusing to act on PID 0 (would target entire process group)");
            return None;
        }
    }
    // Try PID NNNN
    if let Some(idx) = message.to_uppercase().find("PID ") {
        let rest = &message[idx + 4..];
        let num: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(pid) = num.parse::<u32>() {
            if pid > 0 {
                return Some(pid);
            }
            eprintln!("Warning: refusing to act on PID 0 (would target entire process group)");
            return None;
        }
    }
    None
}

/// Extract a UID from an alert message (looks for uid=NNNN patterns).
fn extract_uid(message: &str) -> Option<u32> {
    if let Some(idx) = message.find("uid=") {
        let rest = &message[idx + 4..];
        let num: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(uid) = num.parse() {
            return Some(uid);
        }
    }
    None
}

/// Validate that a path contains only safe characters: alphanumeric, `/`, `_`, `.`, `-`.
/// Rejects paths that could be used for command injection or argument injection.
fn is_safe_path(path: &str) -> bool {
    !path.is_empty()
        && path.starts_with('/')
        && path.len() > 1
        && path.chars().all(|c| c.is_alphanumeric() || "/_.-".contains(c))
        // Reject path traversal patterns
        && !path.contains("..")
}

/// Extract file paths from an alert message (looks for /absolute/paths).
/// Only returns paths that pass validation (alphanumeric + `/_.-`).
fn extract_paths(message: &str) -> Vec<String> {
    let mut paths = Vec::new();
    for word in message.split_whitespace() {
        let clean = word.trim_matches(|c: char| !c.is_alphanumeric() && c != '/' && c != '.' && c != '-' && c != '_');
        if is_safe_path(clean) {
            paths.push(clean.to_string());
        } else if clean.starts_with('/') && clean.len() > 1 {
            eprintln!(
                "Warning: skipping path with unsafe characters extracted from alert: {:?}",
                clean
            );
        }
    }
    paths
}

// ── Containment Execution ────────────────────────────────────────────────────

/// Execute a single containment action. Logs success/failure.
async fn execute_containment(action: &ContainmentAction) {
    let result = match action {
        ContainmentAction::KillProcess { pid } => {
            let r = unsafe { libc::kill(*pid as i32, libc::SIGKILL) };
            if r == 0 { Ok(()) } else { Err(format!("kill failed: errno {}", std::io::Error::last_os_error())) }
        }
        ContainmentAction::SuspendProcess { pid } => {
            let r = unsafe { libc::kill(*pid as i32, libc::SIGSTOP) };
            if r == 0 { Ok(()) } else { Err(format!("SIGSTOP failed: errno {}", std::io::Error::last_os_error())) }
        }
        ContainmentAction::DropNetwork { uid } => {
            let output = std::process::Command::new("iptables")
                .args(["-A", "OUTPUT", "-m", "owner", "--uid-owner", &uid.to_string(), "-j", "DROP"])
                .output();
            match output {
                Ok(o) if o.status.success() => Ok(()),
                Ok(o) => Err(String::from_utf8_lossy(&o.stderr).to_string()),
                Err(e) => Err(e.to_string()),
            }
        }
        ContainmentAction::RevokeApiKeys => {
            // Write a lockfile that the proxy checks
            match std::fs::write("/var/run/clawtower/proxy.locked", "revoked by response engine") {
                Ok(_) => Ok(()),
                Err(e) => Err(e.to_string()),
            }
        }
        ContainmentAction::FreezeFilesystem { paths } => {
            let mut errors = Vec::new();
            for path in paths {
                // Defense-in-depth: re-validate path at execution time
                if !is_safe_path(path) {
                    errors.push(format!("{}: rejected — path contains unsafe characters", path));
                    eprintln!("Warning: refusing to execute chattr on unsafe path: {:?}", path);
                    continue;
                }
                let output = std::process::Command::new("chattr")
                    .arg("+i")
                    .arg("--")
                    .arg(path)
                    .output();
                if let Err(e) = output {
                    errors.push(format!("{}: {}", path, e));
                } else if let Ok(o) = output {
                    if !o.status.success() {
                        errors.push(format!("{}: {}", path, String::from_utf8_lossy(&o.stderr)));
                    }
                }
            }
            if errors.is_empty() { Ok(()) } else { Err(errors.join("; ")) }
        }
        ContainmentAction::LockClawsudo => {
            // Write a lockfile that clawsudo checks
            match std::fs::write("/var/run/clawtower/clawsudo.locked", "locked by response engine") {
                Ok(_) => Ok(()),
                Err(e) => Err(e.to_string()),
            }
        }
    };

    match result {
        Ok(()) => eprintln!("✅ Containment executed: {}", action),
        Err(e) => eprintln!("❌ Containment failed: {} — {}", action, e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_pid() {
        assert_eq!(extract_pid("process pid=12345 did something"), Some(12345));
        assert_eq!(extract_pid("PID 42 exited"), Some(42));
        assert_eq!(extract_pid("no pid here"), None);
    }

    #[test]
    fn test_extract_pid_rejects_zero() {
        // PID 0 would signal the entire process group — must be rejected
        assert_eq!(extract_pid("pid=0 something"), None);
        assert_eq!(extract_pid("PID 0 something"), None);
    }

    #[test]
    fn test_extract_uid() {
        assert_eq!(extract_uid("user uid=1000 accessed file"), Some(1000));
        assert_eq!(extract_uid("no uid"), None);
    }

    #[test]
    fn test_extract_paths() {
        let paths = extract_paths("modified /etc/passwd and /home/user/.ssh/authorized_keys");
        assert_eq!(paths, vec!["/etc/passwd", "/home/user/.ssh/authorized_keys"]);
    }

    #[test]
    fn test_extract_paths_rejects_injection() {
        // Shell metacharacters must be rejected
        let paths = extract_paths("modified /etc/passwd;rm -rf / and /tmp/safe_file");
        // The injected path should be filtered out; /tmp/safe_file should pass
        assert_eq!(paths, vec!["/tmp/safe_file"]);
    }

    #[test]
    fn test_extract_paths_rejects_backticks() {
        let paths = extract_paths("file at /tmp/`whoami`/test");
        assert!(paths.is_empty());
    }

    #[test]
    fn test_extract_paths_rejects_dollar_subshell() {
        let paths = extract_paths("file at /tmp/$(id)/test");
        assert!(paths.is_empty());
    }

    #[test]
    fn test_extract_paths_rejects_traversal() {
        let paths = extract_paths("file at /etc/../../../etc/shadow");
        assert!(paths.is_empty());
    }

    #[test]
    fn test_extract_paths_rejects_spaces_and_special() {
        // Paths with spaces, pipes, redirects, etc.
        let paths = extract_paths("modified /tmp/good_file and /tmp/bad|file");
        assert_eq!(paths, vec!["/tmp/good_file"]);
    }

    #[test]
    fn test_is_safe_path() {
        assert!(is_safe_path("/etc/passwd"));
        assert!(is_safe_path("/home/user/.ssh/authorized_keys"));
        assert!(is_safe_path("/var/log/auth.log"));
        assert!(is_safe_path("/tmp/test-file_v2.txt"));

        // Rejections
        assert!(!is_safe_path(""));
        assert!(!is_safe_path("/"));
        assert!(!is_safe_path("relative/path"));
        assert!(!is_safe_path("/etc/passwd;rm -rf /"));
        assert!(!is_safe_path("/tmp/$(whoami)"));
        assert!(!is_safe_path("/tmp/`id`"));
        assert!(!is_safe_path("/tmp/file with spaces"));
        assert!(!is_safe_path("/etc/../shadow"));
        assert!(!is_safe_path("/tmp/file|pipe"));
        assert!(!is_safe_path("/tmp/file>redirect"));
        assert!(!is_safe_path("/tmp/file&background"));
    }

    #[test]
    fn test_playbook_matching() {
        let playbooks = vec![
            ("exfil".to_string(), Playbook {
                name: "exfiltration".to_string(),
                description: "test".to_string(),
                actions: vec!["suspend_process".to_string()],
                trigger_on: vec!["dns_exfil".to_string(), "data_staging".to_string()],
            }),
        ];
        let alert = Alert::new(Severity::Critical, "network", "DNS exfil detected: dns_exfil pattern");
        let matched = find_matching_playbook(&alert, &playbooks);
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().0, "exfil");

        let benign = Alert::new(Severity::Info, "system", "startup complete");
        assert!(find_matching_playbook(&benign, &playbooks).is_none());
    }
}
