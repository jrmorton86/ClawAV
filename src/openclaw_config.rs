//! OpenClaw configuration drift detection.
//!
//! Parses `openclaw.json`, extracts security-critical fields, and compares
//! against a stored baseline to detect regressions (e.g., auth disabled,
//! policies loosened, dangerous flags enabled).

use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;

use crate::scanner::{ScanResult, ScanStatus};

/// A detected configuration drift.
#[derive(Debug, Clone)]
pub struct ConfigDrift {
    pub field: String,
    pub baseline_value: String,
    pub current_value: String,
    pub is_regression: bool,
    pub description: String,
}

/// Fields that indicate a security regression when set to specific values.
const REGRESSION_RULES: &[(&str, &str)] = &[
    ("gateway.auth.mode", "none"),
    ("gateway.bind", "0.0.0.0"),
    ("logging.redactSensitive", "off"),
    ("controlUi.dangerouslyDisableDeviceAuth", "true"),
    ("controlUi.allowInsecureAuth", "true"),
    ("sandbox.mode", ""),           // sandbox disabled
    ("tools.profile", "full"),      // overly permissive tool access
];

/// DM/group policy fields — regression if changed to "open"
const POLICY_OPEN_FIELDS: &[&str] = &[
    "dmPolicy",
    "groupPolicy",
];

/// Extract security-critical fields from OpenClaw JSON config as a flat key-value map.
pub fn extract_security_fields(json_str: &str) -> HashMap<String, String> {
    let mut fields = HashMap::new();
    if let Ok(val) = serde_json::from_str::<Value>(json_str) {
        extract_recursive(&val, "", &mut fields);
    }
    fields
}

fn extract_recursive(val: &Value, prefix: &str, out: &mut HashMap<String, String>) {
    match val {
        Value::Object(map) => {
            for (k, v) in map {
                let key = if prefix.is_empty() { k.clone() } else { format!("{}.{}", prefix, k) };
                extract_recursive(v, &key, out);
            }
        }
        Value::String(s) => { out.insert(prefix.to_string(), s.clone()); }
        Value::Bool(b) => { out.insert(prefix.to_string(), b.to_string()); }
        Value::Number(n) => { out.insert(prefix.to_string(), n.to_string()); }
        _ => {}
    }
}

/// Compare baseline and current fields, returning detected drifts.
pub fn detect_drift(
    baseline: &HashMap<String, String>,
    current: &HashMap<String, String>,
) -> Vec<ConfigDrift> {
    let mut drifts = Vec::new();

    for (field, cur_val) in current {
        if let Some(base_val) = baseline.get(field) {
            if base_val != cur_val {
                let is_regression = is_security_regression(field, cur_val);
                drifts.push(ConfigDrift {
                    field: field.clone(),
                    baseline_value: base_val.clone(),
                    current_value: cur_val.clone(),
                    is_regression,
                    description: if is_regression {
                        format!("{} changed from '{}' to '{}' — SECURITY REGRESSION", field, base_val, cur_val)
                    } else {
                        format!("{} changed from '{}' to '{}'", field, base_val, cur_val)
                    },
                });
            }
        }
    }

    // Check for removed fields that were in baseline
    for (field, base_val) in baseline {
        if !current.contains_key(field) {
            let key_parts: Vec<&str> = field.split('.').collect();
            let is_security = key_parts.iter().any(|p|
                ["auth", "policy", "dmPolicy", "groupPolicy", "bind", "sandbox"].contains(p));
            if is_security {
                drifts.push(ConfigDrift {
                    field: field.clone(),
                    baseline_value: base_val.clone(),
                    current_value: "(removed)".to_string(),
                    is_regression: true,
                    description: format!("{} was '{}', now removed — possible security regression", field, base_val),
                });
            }
        }
    }

    drifts
}

fn is_security_regression(field: &str, new_value: &str) -> bool {
    for (rule_field, bad_value) in REGRESSION_RULES {
        if field.ends_with(rule_field) && new_value == *bad_value {
            return true;
        }
    }
    for policy_field in POLICY_OPEN_FIELDS {
        if field.ends_with(policy_field) && new_value == "open" {
            return true;
        }
    }
    false
}

/// Load baseline from file, or return None if it doesn't exist.
pub fn load_baseline(path: &str) -> Option<HashMap<String, String>> {
    std::fs::read_to_string(path).ok()
        .and_then(|s| serde_json::from_str(&s).ok())
}

/// Save current fields as the new baseline.
pub fn save_baseline(path: &str, fields: &HashMap<String, String>) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(fields)?;
    if let Some(parent) = Path::new(path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, json)?;
    Ok(())
}

/// Run config drift scan: load config, compare to baseline, return results.
pub fn scan_config_drift(config_path: &str, baseline_path: &str) -> Vec<ScanResult> {
    let mut results = Vec::new();

    let config_str = match std::fs::read_to_string(config_path) {
        Ok(s) => s,
        Err(_) => {
            results.push(ScanResult::new("openclaw:drift", ScanStatus::Warn,
                &format!("Cannot read OpenClaw config at {}", config_path)));
            return results;
        }
    };

    let current = extract_security_fields(&config_str);

    match load_baseline(baseline_path) {
        Some(baseline) => {
            let drifts = detect_drift(&baseline, &current);
            if drifts.is_empty() {
                results.push(ScanResult::new("openclaw:drift", ScanStatus::Pass,
                    "No config drift detected"));
            } else {
                for drift in &drifts {
                    let status = if drift.is_regression { ScanStatus::Fail } else { ScanStatus::Warn };
                    results.push(ScanResult::new("openclaw:drift", status, &drift.description));
                }
            }
            // Update baseline with current (so non-regression changes don't re-alert)
            let _ = save_baseline(baseline_path, &current);
        }
        None => {
            // First run — save baseline, no alerts
            let _ = save_baseline(baseline_path, &current);
            results.push(ScanResult::new("openclaw:drift", ScanStatus::Pass,
                "Config drift baseline initialized"));
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> &'static str {
        r#"{
            "channels": {
                "slack": { "dmPolicy": "pairing", "groupPolicy": "allowlist" }
            },
            "gateway": {
                "auth": { "mode": "token", "token": "secret123" },
                "bind": "loopback"
            },
            "logging": { "redactSensitive": "tools" }
        }"#
    }

    #[test]
    fn test_extract_security_fields() {
        let fields = extract_security_fields(sample_config());
        assert_eq!(fields.get("gateway.auth.mode").unwrap(), "token");
        assert_eq!(fields.get("gateway.bind").unwrap(), "loopback");
        assert_eq!(fields.get("channels.slack.dmPolicy").unwrap(), "pairing");
        assert_eq!(fields.get("logging.redactSensitive").unwrap(), "tools");
    }

    #[test]
    fn test_detect_drift_no_change() {
        let baseline = extract_security_fields(sample_config());
        let current = extract_security_fields(sample_config());
        let drifts = detect_drift(&baseline, &current);
        assert!(drifts.is_empty());
    }

    #[test]
    fn test_detect_drift_regression_auth_disabled() {
        let baseline = extract_security_fields(sample_config());
        let mut current = baseline.clone();
        current.insert("gateway.auth.mode".to_string(), "none".to_string());
        let drifts = detect_drift(&baseline, &current);
        assert_eq!(drifts.len(), 1);
        assert!(drifts[0].is_regression);
        assert!(drifts[0].description.contains("SECURITY REGRESSION"));
    }

    #[test]
    fn test_detect_drift_regression_policy_open() {
        let baseline = extract_security_fields(sample_config());
        let mut current = baseline.clone();
        current.insert("channels.slack.dmPolicy".to_string(), "open".to_string());
        let drifts = detect_drift(&baseline, &current);
        assert_eq!(drifts.len(), 1);
        assert!(drifts[0].is_regression);
    }

    #[test]
    fn test_detect_drift_non_regression() {
        let baseline = extract_security_fields(sample_config());
        let mut current = baseline.clone();
        current.insert("gateway.auth.mode".to_string(), "password".to_string());
        let drifts = detect_drift(&baseline, &current);
        assert_eq!(drifts.len(), 1);
        assert!(!drifts[0].is_regression); // password is fine, not a regression
    }

    #[test]
    fn test_detect_drift_removed_security_field() {
        let baseline = extract_security_fields(sample_config());
        let mut current = baseline.clone();
        current.remove("gateway.auth.mode");
        let drifts = detect_drift(&baseline, &current);
        assert!(drifts.iter().any(|d| d.is_regression && d.field == "gateway.auth.mode"));
    }

    #[test]
    fn test_scan_config_drift_no_config() {
        let results = scan_config_drift("/nonexistent/config.json", "/tmp/test-baseline.json");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, ScanStatus::Warn);
    }

    #[test]
    fn test_scan_config_drift_first_run() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("openclaw.json");
        let baseline_path = dir.path().join("baseline.json");
        std::fs::write(&config_path, sample_config()).unwrap();

        let results = scan_config_drift(
            config_path.to_str().unwrap(),
            baseline_path.to_str().unwrap(),
        );
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, ScanStatus::Pass);
        assert!(results[0].details.contains("baseline initialized"));
        // Baseline file should now exist
        assert!(baseline_path.exists());
    }

    #[test]
    fn test_is_security_regression_bind() {
        assert!(is_security_regression("gateway.bind", "0.0.0.0"));
        assert!(!is_security_regression("gateway.bind", "loopback"));
    }

    #[test]
    fn test_is_security_regression_sandbox() {
        assert!(is_security_regression("sandbox.mode", ""));
        assert!(!is_security_regression("sandbox.mode", "strict"));
    }

    #[test]
    fn test_is_security_regression_tools_profile() {
        assert!(is_security_regression("tools.profile", "full"));
        assert!(!is_security_regression("tools.profile", "minimal"));
    }

    #[test]
    fn test_is_security_regression_dangerous_flags() {
        assert!(is_security_regression("controlUi.dangerouslyDisableDeviceAuth", "true"));
        assert!(is_security_regression("controlUi.allowInsecureAuth", "true"));
        assert!(!is_security_regression("controlUi.dangerouslyDisableDeviceAuth", "false"));
    }
}
