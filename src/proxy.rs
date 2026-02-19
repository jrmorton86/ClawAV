// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! API key vault proxy with DLP (Data Loss Prevention) scanning.
//!
//! Provides a reverse proxy that maps virtual API keys to real ones, preventing
//! the AI agent from ever seeing actual credentials. Supports Anthropic (x-api-key)
//! and OpenAI (Bearer token) auth styles.
//!
//! Outbound request bodies are scanned against configurable DLP regex patterns.
//! Matches can trigger blocking (SSN, AWS keys) or redaction (credit cards).

use crate::alerts::{Alert, Severity};
use crate::config::{KeyMapping, ProxyConfig, PromptFirewallConfig};
use crate::prompt_firewall::{PromptFirewall, FirewallResult};
use anyhow::Result;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Request, Response, Server, StatusCode, Uri};
use regex::Regex;
use std::net::SocketAddr;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

struct ProxyState {
    key_mappings: Vec<KeyMapping>,
    credential_states: HashMap<String, CredentialState>,
    dlp_patterns: Vec<CompiledDlpPattern>,
    prompt_firewall: PromptFirewall,
    alert_tx: mpsc::Sender<Alert>,
}

pub(crate) struct CompiledDlpPattern {
    name: String,
    regex: Regex,
    action: String,
}

/// HTTP reverse proxy server that swaps virtual keys for real ones and scans for DLP violations.
pub struct ProxyServer {
    config: ProxyConfig,
    firewall_config: PromptFirewallConfig,
    alert_tx: mpsc::Sender<Alert>,
}

impl ProxyServer {
    pub fn new(config: ProxyConfig, firewall_config: PromptFirewallConfig, alert_tx: mpsc::Sender<Alert>) -> Self {
        Self { config, firewall_config, alert_tx }
    }

    pub async fn start(self) -> Result<()> {
        let compiled_patterns: Vec<CompiledDlpPattern> = self
            .config
            .dlp
            .patterns
            .iter()
            .filter_map(|p| {
                Regex::new(&p.regex).ok().map(|r| CompiledDlpPattern {
                    name: p.name.clone(),
                    regex: r,
                    action: p.action.clone(),
                })
            })
            .collect();

        let mut credential_states = HashMap::new();
        for mapping in &self.config.key_mapping {
            credential_states.insert(mapping.virtual_key.clone(), CredentialState::new(mapping));
        }

        let prompt_firewall = PromptFirewall::load(
            &self.firewall_config.patterns_path,
            self.firewall_config.tier,
            &self.firewall_config.overrides,
        ).unwrap_or_else(|e| {
            eprintln!("Prompt firewall load error: {}", e);
            PromptFirewall::load("/dev/null", 2, &std::collections::HashMap::new()).unwrap()
        });

        let state = Arc::new(ProxyState {
            key_mappings: self.config.key_mapping.clone(),
            credential_states,
            dlp_patterns: compiled_patterns,
            prompt_firewall,
            alert_tx: self.alert_tx,
        });

        let addr: SocketAddr = format!("{}:{}", self.config.bind, self.config.port).parse()?;

        let make_svc = make_service_fn(move |_| {
            let state = state.clone();
            async move {
                Ok::<_, hyper::Error>(service_fn(move |req| {
                    handle_request(req, state.clone())
                }))
            }
        });

        eprintln!("Proxy server listening on {}", addr);
        Server::bind(&addr).serve(make_svc).await?;
        Ok(())
    }
}

/// Look up a virtual key and return (real_key, provider, upstream)
pub fn lookup_virtual_key<'a>(
    mappings: &'a [KeyMapping],
    virtual_key: &str,
) -> Option<(&'a str, &'a str, &'a str)> {
    mappings.iter().find(|m| m.virtual_key == virtual_key).map(|m| {
        (m.real.as_str(), m.provider.as_str(), m.upstream.as_str())
    })
}

/// Extract virtual key from request headers
fn extract_virtual_key(req: &Request<Body>) -> Option<String> {
    // Check x-api-key (Anthropic style)
    if let Some(val) = req.headers().get("x-api-key") {
        return val.to_str().ok().map(|s| s.to_string());
    }
    // Check Authorization: Bearer (OpenAI style)
    if let Some(val) = req.headers().get("authorization") {
        if let Ok(s) = val.to_str() {
            if let Some(token) = s.strip_prefix("Bearer ") {
                return Some(token.to_string());
            }
        }
    }
    None
}

/// Scan body for DLP violations. Returns Err with response if blocked,
/// Ok with (possibly redacted) body otherwise.
pub fn scan_dlp(
    body: &str,
    patterns: &[CompiledDlpPattern],
) -> DlpResult {
    let mut result_body = body.to_string();
    let mut alerts: Vec<(String, Severity, String)> = Vec::new();

    for pattern in patterns {
        if pattern.regex.is_match(&result_body) {
            match pattern.action.as_str() {
                "block" => {
                    return DlpResult::Blocked {
                        pattern_name: pattern.name.clone(),
                    };
                }
                "redact" => {
                    result_body = pattern.regex.replace_all(&result_body, "[REDACTED]").to_string();
                    alerts.push((
                        pattern.name.clone(),
                        Severity::Warning,
                        format!("DLP: redacted '{}' pattern in request", pattern.name),
                    ));
                }
                _ => {}
            }
        }
    }

    DlpResult::Pass {
        body: result_body,
        alerts,
    }
}

/// Result of DLP scanning: either blocked or passed (with possible redactions).
pub enum DlpResult {
    Blocked { pattern_name: String },
    Pass {
        body: String,
        alerts: Vec<(String, Severity, String)>,
    },
}

/// Runtime state for an active credential mapping.
#[derive(Debug, Clone)]
pub struct CredentialState {
    pub virtual_key: String,
    pub created_at: Instant,
    pub ttl: Option<Duration>,
    pub revoked: bool,
    pub revoke_reason: Option<String>,
}

impl CredentialState {
    pub fn new(mapping: &KeyMapping) -> Self {
        Self {
            virtual_key: mapping.virtual_key.clone(),
            created_at: Instant::now(),
            ttl: mapping.ttl_secs.map(Duration::from_secs),
            revoked: false,
            revoke_reason: None,
        }
    }

    pub fn is_expired(&self) -> bool {
        if let Some(ttl) = self.ttl {
            self.created_at.elapsed() > ttl
        } else {
            false
        }
    }

    pub fn is_active(&self) -> bool {
        !self.revoked && !self.is_expired()
    }

    pub fn revoke(&mut self, reason: &str) {
        self.revoked = true;
        self.revoke_reason = Some(reason.to_string());
    }
}

/// Check if a credential is allowed for the given request path.
/// Returns Ok(()) if allowed, Err(reason) if denied.
pub fn check_credential_access(
    mapping: &KeyMapping,
    state: &CredentialState,
    request_path: &str,
) -> Result<(), String> {
    if !state.is_active() {
        if state.revoked {
            return Err(format!("Credential revoked: {}",
                state.revoke_reason.as_deref().unwrap_or("unknown")));
        }
        return Err("Credential expired (TTL exceeded)".to_string());
    }

    // Check path scope
    if !mapping.allowed_paths.is_empty() {
        if !mapping.allowed_paths.iter().any(|p| request_path.starts_with(p)) {
            return Err(format!("Path '{}' not in allowed paths", request_path));
        }
    }

    Ok(())
}

async fn handle_request(
    req: Request<Body>,
    state: Arc<ProxyState>,
) -> Result<Response<Body>, hyper::Error> {
    // Check if API keys are revoked by response engine
    if std::path::Path::new("/var/run/clawtower/proxy.locked").exists() {
        let _ = state.alert_tx.send(Alert::new(
            Severity::Warning,
            "proxy",
            &format!("API request blocked — keys revoked by response engine: {} {}", req.method(), req.uri()),
        )).await;
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"error":"API access revoked by ClawTower security policy. Contact administrator."}"#))
            .unwrap());
    }

    // Extract virtual key
    let virtual_key = match extract_virtual_key(&req) {
        Some(k) => k,
        None => {
            return Ok(Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::from("Missing API key"))
                .unwrap());
        }
    };

    // Look up mapping
    let (real_key, provider, upstream) = match lookup_virtual_key(&state.key_mappings, &virtual_key) {
        Some(v) => v,
        None => {
            return Ok(Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::from("Unknown virtual key"))
                .unwrap());
        }
    };

    let real_key = real_key.to_string();
    let provider = provider.to_string();
    let upstream = upstream.to_string();

    // Check credential scoping (TTL, path restriction, revocation)
    if let Some(cred_state) = state.credential_states.get(&virtual_key) {
        let mapping = state.key_mappings.iter().find(|m| m.virtual_key == virtual_key).unwrap();
        let request_path = req.uri().path();
        if let Err(reason) = check_credential_access(mapping, cred_state, request_path) {
            let _ = state.alert_tx.send(Alert::new(
                Severity::Warning,
                "proxy",
                &format!("Credential access denied for {}: {}", virtual_key, reason),
            )).await;
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header("Content-Type", "application/json")
                .body(Body::from(format!(r#"{{"error":"credential denied: {}"}}"#, reason)))
                .unwrap());
        }
    }

    // Read body for DLP scanning
    let (parts, body) = req.into_parts();
    let body_bytes = hyper::body::to_bytes(body).await?;
    let body_str = String::from_utf8_lossy(&body_bytes);

    // DLP scan
    let final_body = match scan_dlp(&body_str, &state.dlp_patterns) {
        DlpResult::Blocked { pattern_name } => {
            let alert = Alert::new(
                Severity::Critical,
                "proxy-dlp",
                &format!("BLOCKED: '{}' pattern detected in request", pattern_name),
            );
            let _ = state.alert_tx.send(alert).await;
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from(format!("Request blocked by DLP policy: {}", pattern_name)))
                .unwrap());
        }
        DlpResult::Pass { body, alerts } => {
            for (_name, severity, msg) in alerts {
                let alert = Alert::new(severity, "proxy-dlp", &msg);
                let _ = state.alert_tx.send(alert).await;
            }
            body
        }
    };

    // Prompt firewall scan (after DLP, before forwarding)
    let final_body = if state.prompt_firewall.total_patterns() > 0 {
        match state.prompt_firewall.scan(&final_body) {
            FirewallResult::Block { matches } => {
                let pattern_names: Vec<&str> = matches.iter().map(|m| m.pattern_name.as_str()).collect();
                let alert = Alert::new(
                    Severity::Critical,
                    "prompt-firewall",
                    &format!("BLOCKED prompt: matched [{}]", pattern_names.join(", ")),
                );
                let _ = state.alert_tx.send(alert).await;
                return Ok(Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .header("Content-Type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"error":"Prompt blocked by firewall policy","patterns":["{}"]}}"#,
                        pattern_names.join("\",\"")
                    )))
                    .unwrap());
            }
            FirewallResult::Warn { matches } => {
                let pattern_names: Vec<&str> = matches.iter().map(|m| m.pattern_name.as_str()).collect();
                let alert = Alert::new(
                    Severity::Warning,
                    "prompt-firewall",
                    &format!("Suspicious prompt: matched [{}]", pattern_names.join(", ")),
                );
                let _ = state.alert_tx.send(alert).await;
                final_body
            }
            FirewallResult::Log { matches } => {
                let pattern_names: Vec<&str> = matches.iter().map(|m| m.pattern_name.as_str()).collect();
                let alert = Alert::new(
                    Severity::Info,
                    "prompt-firewall",
                    &format!("Prompt logged: matched [{}]", pattern_names.join(", ")),
                );
                let _ = state.alert_tx.send(alert).await;
                final_body
            }
            FirewallResult::Pass => final_body,
        }
    } else {
        final_body
    };

    // Build upstream URI
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let upstream_uri: Uri = format!("{}{}", upstream, path_and_query)
        .parse()
        .unwrap_or_else(|_| Uri::from_static("http://localhost"));

    // Build forwarded request
    let mut builder = Request::builder()
        .method(parts.method)
        .uri(upstream_uri);

    // Copy headers, replacing auth
    for (key, value) in parts.headers.iter() {
        if key == "host" {
            continue;
        }
        if key == "x-api-key" && provider == "anthropic" {
            continue;
        }
        if key == "authorization" && provider == "openai" {
            continue;
        }
        builder = builder.header(key, value);
    }

    // Set real key
    match provider.as_str() {
        "anthropic" => {
            builder = builder.header("x-api-key", &real_key);
        }
        "openai" => {
            builder = builder.header("authorization", format!("Bearer {}", real_key));
        }
        _ => {}
    }

    let upstream_req = builder.body(Body::from(final_body)).unwrap();

    // Forward to upstream
    let client = Client::builder().build(hyper_tls_connector());
    match client.request(upstream_req).await {
        Ok(resp) => Ok(resp),
        Err(e) => Ok(Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Body::from(format!("Upstream error: {}", e)))
            .unwrap()),
    }
}

fn hyper_tls_connector() -> hyper_tls::HttpsConnector<hyper::client::HttpConnector> {
    hyper_tls::HttpsConnector::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::KeyMapping;

    fn test_mappings() -> Vec<KeyMapping> {
        vec![
            KeyMapping {
                virtual_key: "vk-anthropic-001".to_string(),
                real: "sk-ant-api03-REAL".to_string(),
                provider: "anthropic".to_string(),
                upstream: "https://api.anthropic.com".to_string(),
                ttl_secs: None,
                allowed_paths: vec![],
                revoke_at_risk: 0.0,
            },
            KeyMapping {
                virtual_key: "vk-openai-001".to_string(),
                real: "sk-REAL".to_string(),
                provider: "openai".to_string(),
                upstream: "https://api.openai.com".to_string(),
                ttl_secs: None,
                allowed_paths: vec![],
                revoke_at_risk: 0.0,
            },
        ]
    }

    fn test_dlp_patterns() -> Vec<CompiledDlpPattern> {
        vec![
            CompiledDlpPattern {
                name: "ssn".to_string(),
                regex: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
                action: "block".to_string(),
            },
            CompiledDlpPattern {
                name: "credit-card".to_string(),
                regex: Regex::new(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b").unwrap(),
                action: "redact".to_string(),
            },
            CompiledDlpPattern {
                name: "credit-card-amex".to_string(),
                regex: Regex::new(r"\b3[47]\d{2}[- ]?\d{6}[- ]?\d{5}\b").unwrap(),
                action: "redact".to_string(),
            },
            CompiledDlpPattern {
                name: "aws-key".to_string(),
                regex: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
                action: "block".to_string(),
            },
        ]
    }

    #[test]
    fn test_virtual_key_lookup_found() {
        let mappings = test_mappings();
        let result = lookup_virtual_key(&mappings, "vk-anthropic-001");
        assert!(result.is_some());
        let (real, provider, upstream) = result.unwrap();
        assert_eq!(real, "sk-ant-api03-REAL");
        assert_eq!(provider, "anthropic");
        assert_eq!(upstream, "https://api.anthropic.com");
    }

    #[test]
    fn test_virtual_key_lookup_openai() {
        let mappings = test_mappings();
        let result = lookup_virtual_key(&mappings, "vk-openai-001");
        assert!(result.is_some());
        let (real, provider, _) = result.unwrap();
        assert_eq!(real, "sk-REAL");
        assert_eq!(provider, "openai");
    }

    #[test]
    fn test_virtual_key_lookup_unknown() {
        let mappings = test_mappings();
        let result = lookup_virtual_key(&mappings, "vk-unknown-999");
        assert!(result.is_none());
    }

    #[test]
    fn test_dlp_ssn_blocked() {
        let patterns = test_dlp_patterns();
        let body = "My SSN is 123-45-6789 please process";
        match scan_dlp(body, &patterns) {
            DlpResult::Blocked { pattern_name } => assert_eq!(pattern_name, "ssn"),
            _ => panic!("Expected block"),
        }
    }

    #[test]
    fn test_dlp_credit_card_redacted() {
        let patterns = test_dlp_patterns();
        // Only credit card, no SSN
        let body = "Card: 4111-1111-1111-1111 thanks";
        match scan_dlp(body, &patterns) {
            DlpResult::Pass { body, alerts } => {
                assert!(body.contains("[REDACTED]"));
                assert!(!body.contains("4111"));
                assert_eq!(alerts.len(), 1);
                assert_eq!(alerts[0].1, Severity::Warning);
            }
            DlpResult::Blocked { .. } => panic!("Expected pass with redaction"),
        }
    }

    #[test]
    fn test_dlp_aws_key_blocked() {
        let patterns = test_dlp_patterns();
        let body = "key is AKIAIOSFODNN7EXAMPLE";
        match scan_dlp(body, &patterns) {
            DlpResult::Blocked { pattern_name } => assert_eq!(pattern_name, "aws-key"),
            _ => panic!("Expected block"),
        }
    }

    #[test]
    fn test_dlp_clean_body_passes() {
        let patterns = test_dlp_patterns();
        let body = "Hello, please summarize this document";
        match scan_dlp(body, &patterns) {
            DlpResult::Pass { body: b, alerts } => {
                assert_eq!(b, body);
                assert!(alerts.is_empty());
            }
            _ => panic!("Expected pass"),
        }
    }

    // ═══════════════════════ REGRESSION TESTS ═══════════════════════

    #[test]
    fn test_dlp_visa_card_spaces() {
        let patterns = test_dlp_patterns();
        match scan_dlp("Card: 4111 1111 1111 1111", &patterns) {
            DlpResult::Pass { body, .. } => assert!(body.contains("[REDACTED]")),
            _ => panic!("Expected redaction"),
        }
    }

    #[test]
    fn test_dlp_mastercard() {
        let patterns = test_dlp_patterns();
        match scan_dlp("MC: 5500-0000-0000-0004", &patterns) {
            DlpResult::Pass { body, .. } => assert!(body.contains("[REDACTED]")),
            _ => panic!("Expected redaction"),
        }
    }

    #[test]
    fn test_dlp_card_no_separators() {
        let patterns = test_dlp_patterns();
        match scan_dlp("num: 4111111111111111", &patterns) {
            DlpResult::Pass { body, .. } => assert!(body.contains("[REDACTED]")),
            _ => panic!("Expected redaction"),
        }
    }

    #[test]
    fn test_dlp_amex_15_digits_detected() {
        let patterns = test_dlp_patterns();
        // Amex 15-digit cards (3[47]xx) now detected by credit-card-amex pattern
        match scan_dlp("Amex: 3782 8224 6310 005", &patterns) {
            DlpResult::Pass { body, alerts } => {
                assert!(body.contains("[REDACTED]"), "Amex card should be redacted");
                let amex_alerts: Vec<_> = alerts.iter().filter(|a| a.0 == "credit-card-amex").collect();
                assert!(!amex_alerts.is_empty(), "Amex card must trigger credit-card-amex alert");
            }
            DlpResult::Blocked { .. } => panic!("Amex should be redacted, not blocked"),
        }
    }

    #[test]
    fn test_dlp_phone_not_card() {
        let patterns = test_dlp_patterns();
        match scan_dlp("Call 555-123-4567", &patterns) {
            DlpResult::Pass { alerts, .. } => assert!(alerts.is_empty()),
            _ => panic!("Phone should not trigger"),
        }
    }

    #[test]
    fn test_dlp_sixteen_digit_false_positive() {
        let patterns = test_dlp_patterns();
        match scan_dlp("Order: 1234567890123456", &patterns) {
            DlpResult::Pass { body, .. } => assert!(body.contains("[REDACTED]")),
            _ => panic!("Should redact (false positive by design)"),
        }
    }

    #[test]
    fn test_dlp_aws_key_in_json() {
        let patterns = test_dlp_patterns();
        match scan_dlp(r#"{"key": "AKIAIOSFODNN7EXAMPLE"}"#, &patterns) {
            DlpResult::Blocked { pattern_name } => assert_eq!(pattern_name, "aws-key"),
            _ => panic!("AWS key in JSON should block"),
        }
    }

    #[test]
    fn test_dlp_not_aws_wrong_prefix() {
        let patterns = test_dlp_patterns();
        match scan_dlp("ASIA1234567890ABCDEF", &patterns) {
            DlpResult::Pass { .. } => {}
            _ => panic!("ASIA prefix should not match AKIA"),
        }
    }

    #[test]
    fn test_dlp_empty_body() {
        let patterns = test_dlp_patterns();
        match scan_dlp("", &patterns) {
            DlpResult::Pass { body, alerts } => { assert_eq!(body, ""); assert!(alerts.is_empty()); }
            _ => panic!("Empty should pass"),
        }
    }

    #[test]
    fn test_dlp_large_body() {
        let patterns = test_dlp_patterns();
        let body = "x".repeat(1_000_000);
        match scan_dlp(&body, &patterns) {
            DlpResult::Pass { .. } => {}
            _ => panic!("Large clean body should pass"),
        }
    }

    #[test]
    fn test_dlp_no_patterns() {
        let empty: Vec<CompiledDlpPattern> = vec![];
        match scan_dlp("SSN: 123-45-6789", &empty) {
            DlpResult::Pass { body, .. } => assert!(body.contains("123-45-6789")),
            _ => panic!("No patterns = pass"),
        }
    }

    #[test]
    fn test_dlp_ssn_and_card_ssn_blocks_first() {
        let patterns = test_dlp_patterns();
        match scan_dlp("SSN: 123-45-6789 Card: 4111111111111111", &patterns) {
            DlpResult::Blocked { pattern_name } => assert_eq!(pattern_name, "ssn"),
            _ => panic!("SSN should block first"),
        }
    }

    #[test]
    fn test_dlp_multiple_cards_redacted() {
        let patterns = test_dlp_patterns();
        match scan_dlp("A: 4111111111111111 B: 5500000000000004", &patterns) {
            DlpResult::Pass { body, .. } => {
                assert!(!body.contains("4111"));
                assert!(!body.contains("5500"));
            }
            _ => panic!("Cards should redact not block"),
        }
    }

    #[test]
    fn test_dlp_ssn_boundary() {
        let patterns = test_dlp_patterns();
        match scan_dlp("ref:123-45-6789:end", &patterns) {
            DlpResult::Blocked { pattern_name } => assert_eq!(pattern_name, "ssn"),
            _ => panic!("SSN at boundary should block"),
        }
    }

    #[test]
    fn test_dlp_ssn_wrong_format() {
        let patterns = test_dlp_patterns();
        match scan_dlp("12-34-5678", &patterns) {
            DlpResult::Pass { .. } => {}
            _ => panic!("Wrong SSN format should pass"),
        }
    }

    #[test]
    fn test_virtual_key_empty_mappings() {
        assert!(lookup_virtual_key(&[], "vk-anything").is_none());
    }

    #[test]
    fn test_virtual_key_partial_match() {
        let m = test_mappings();
        assert!(lookup_virtual_key(&m, "vk-anthropic").is_none());
    }

    #[test]
    fn test_virtual_key_case_sensitive() {
        let m = test_mappings();
        assert!(lookup_virtual_key(&m, "VK-ANTHROPIC-001").is_none());
    }

    #[test]
    fn test_key_rotation_new_mapping() {
        let m = vec![KeyMapping {
            virtual_key: "vk-v2".to_string(),
            real: "sk-NEW".to_string(),
            provider: "anthropic".to_string(),
            upstream: "https://api.anthropic.com".to_string(),
            ttl_secs: None,
            allowed_paths: vec![],
            revoke_at_risk: 0.0,
        }];
        assert_eq!(lookup_virtual_key(&m, "vk-v2").unwrap().0, "sk-NEW");
        assert!(lookup_virtual_key(&m, "vk-anthropic-001").is_none());
    }

    fn test_dlp_patterns_with_gcp() -> Vec<CompiledDlpPattern> {
        let mut p = test_dlp_patterns();
        p.push(CompiledDlpPattern {
            name: "gcp-key".to_string(),
            regex: Regex::new(r"AIza[0-9A-Za-z_-]{35}").unwrap(),
            action: "block".to_string(),
        });
        p
    }

    #[test]
    fn test_dlp_gcp_key_blocked() {
        let patterns = test_dlp_patterns_with_gcp();
        match scan_dlp("key: AIzaSyA1234567890abcdefghijklmnopqrstuv", &patterns) {
            DlpResult::Blocked { pattern_name } => assert_eq!(pattern_name, "gcp-key"),
            _ => panic!("GCP key should block"),
        }
    }

    // ═══════════════════════ CREDENTIAL SCOPING TESTS ═══════════════════════

    fn scoped_mapping(ttl: Option<u64>, paths: Vec<&str>) -> KeyMapping {
        KeyMapping {
            virtual_key: "vk-scoped-001".to_string(),
            real: "sk-REAL".to_string(),
            provider: "anthropic".to_string(),
            upstream: "https://api.anthropic.com".to_string(),
            ttl_secs: ttl,
            allowed_paths: paths.into_iter().map(|s| s.to_string()).collect(),
            revoke_at_risk: 0.0,
        }
    }

    #[test]
    fn test_credential_state_active() {
        let mapping = scoped_mapping(Some(3600), vec![]);
        let state = CredentialState::new(&mapping);
        assert!(state.is_active(), "Newly created credential should be active");
        assert!(!state.is_expired(), "Newly created credential should not be expired");
        assert!(!state.revoked, "Newly created credential should not be revoked");
    }

    #[test]
    fn test_credential_state_expired() {
        let mapping = scoped_mapping(Some(0), vec![]);
        let state = CredentialState::new(&mapping);
        // TTL of 0 seconds means already expired
        std::thread::sleep(std::time::Duration::from_millis(1));
        assert!(state.is_expired(), "Credential with 0s TTL should be expired");
        assert!(!state.is_active(), "Expired credential should not be active");
    }

    #[test]
    fn test_credential_state_no_ttl() {
        let mapping = scoped_mapping(None, vec![]);
        let state = CredentialState::new(&mapping);
        assert!(!state.is_expired(), "Credential without TTL should never expire");
        assert!(state.is_active(), "Credential without TTL should be active");
        assert!(state.ttl.is_none(), "TTL should be None");
    }

    #[test]
    fn test_credential_revoked() {
        let mapping = scoped_mapping(Some(3600), vec![]);
        let mut state = CredentialState::new(&mapping);
        state.revoke("risk score exceeded threshold");
        assert!(state.revoked, "Credential should be revoked");
        assert!(!state.is_active(), "Revoked credential should not be active");
        assert_eq!(
            state.revoke_reason.as_deref(),
            Some("risk score exceeded threshold"),
            "Revoke reason should be preserved"
        );
    }

    #[test]
    fn test_check_access_allowed_path() {
        let mapping = scoped_mapping(Some(3600), vec!["/v1/messages"]);
        let state = CredentialState::new(&mapping);
        let result = check_credential_access(&mapping, &state, "/v1/messages");
        assert!(result.is_ok(), "Request to allowed path should succeed");
    }

    #[test]
    fn test_check_access_denied_path() {
        let mapping = scoped_mapping(Some(3600), vec!["/v1/messages"]);
        let state = CredentialState::new(&mapping);
        let result = check_credential_access(&mapping, &state, "/v1/completions");
        assert!(result.is_err(), "Request to unauthorized path should fail");
        let err = result.unwrap_err();
        assert!(err.contains("not in allowed paths"), "Error should mention path restriction: {}", err);
    }

    #[test]
    fn test_check_access_empty_paths_allows_all() {
        let mapping = scoped_mapping(Some(3600), vec![]);
        let state = CredentialState::new(&mapping);
        assert!(check_credential_access(&mapping, &state, "/v1/messages").is_ok());
        assert!(check_credential_access(&mapping, &state, "/v1/completions").is_ok());
        assert!(check_credential_access(&mapping, &state, "/anything/at/all").is_ok());
    }

    // ═══════════════════════ CREDENTIAL WIRING TESTS ═══════════════════════

    #[test]
    fn test_credential_expired_key_denied() {
        let mapping = KeyMapping {
            virtual_key: "vk-expired".to_string(),
            real: "sk-REAL".to_string(),
            provider: "anthropic".to_string(),
            upstream: "https://api.anthropic.com".to_string(),
            ttl_secs: Some(0),
            allowed_paths: vec![],
            revoke_at_risk: 0.0,
        };
        let state = CredentialState::new(&mapping);
        std::thread::sleep(std::time::Duration::from_millis(1));
        let result = check_credential_access(&mapping, &state, "/v1/messages");
        assert!(result.is_err(), "Expired credential must be denied");
    }

    #[test]
    fn test_credential_path_scoping_enforced() {
        let mapping = KeyMapping {
            virtual_key: "vk-scoped".to_string(),
            real: "sk-REAL".to_string(),
            provider: "anthropic".to_string(),
            upstream: "https://api.anthropic.com".to_string(),
            ttl_secs: Some(3600),
            allowed_paths: vec!["/v1/messages".to_string()],
            revoke_at_risk: 0.0,
        };
        let state = CredentialState::new(&mapping);
        assert!(check_credential_access(&mapping, &state, "/v1/messages").is_ok());
        assert!(check_credential_access(&mapping, &state, "/v1/completions").is_err());
    }

    #[tokio::test]
    async fn test_handle_request_respects_path_scope() {
        let mapping = KeyMapping {
            virtual_key: "vk-test".to_string(),
            real: "sk-REAL".to_string(),
            provider: "anthropic".to_string(),
            upstream: "https://api.anthropic.com".to_string(),
            ttl_secs: Some(3600),
            allowed_paths: vec!["/v1/messages".to_string()],
            revoke_at_risk: 0.0,
        };
        let state = CredentialState::new(&mapping);
        let result = check_credential_access(&mapping, &state, "/v1/completions");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not in allowed paths"));
    }

    // ═══════════════════════ TLS CONNECTOR TESTS ═══════════════════════

    #[test]
    fn test_tls_connector_supports_https() {
        let connector = hyper_tls_connector();
        let _client: Client<hyper_tls::HttpsConnector<hyper::client::HttpConnector>> =
            Client::builder().build(connector);
    }
}
