// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 JR Morton

//! Compliance report generation for ClawTower.
//!
//! Maps ClawTower alert sources and categories to compliance framework controls
//! (SOC 2, NIST 800-53, CIS Controls v8) and generates structured reports
//! suitable for audit evidence and compliance reviews.
//!
//! # Supported Frameworks
//!
//! - **SOC 2** — Trust Services Criteria (CC series)
//! - **NIST 800-53** — Security and Privacy Controls
//! - **CIS Controls v8** — Center for Internet Security benchmarks
//!
//! # Usage
//!
//! ```text
//! clawtower compliance-report --framework=soc2 --period=30d --format=json --output=report.json
//! ```
//!
//! Reports can be generated even without a running ClawTower instance — an empty
//! data set produces a baseline report showing all controls in `Pass` status.

use chrono::{DateTime, Local};
use serde::Serialize;

// ---------------------------------------------------------------------------
// Control mapping: static table of ClawTower category → framework controls
// ---------------------------------------------------------------------------

/// Maps a ClawTower alert category to compliance framework control IDs.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ControlMapping {
    pub clawtower_category: &'static str,
    pub soc2_controls: &'static [&'static str],
    pub nist_controls: &'static [&'static str],
    pub cis_controls: &'static [&'static str],
    pub mitre_attack: &'static [&'static str],
}

/// All known control mappings between ClawTower categories and compliance frameworks.
#[allow(dead_code)]
pub static CONTROL_MAPPINGS: &[ControlMapping] = &[
    ControlMapping {
        clawtower_category: "behavior:data_exfiltration",
        soc2_controls: &["CC6.1", "CC7.2"],
        nist_controls: &["SC-7", "SI-4"],
        cis_controls: &["13.1"],
        mitre_attack: &["T1048", "T1041"],
    },
    ControlMapping {
        clawtower_category: "behavior:privilege_escalation",
        soc2_controls: &["CC6.1", "CC6.3"],
        nist_controls: &["AC-6", "AU-12"],
        cis_controls: &["5.4"],
        mitre_attack: &["T1548", "T1068"],
    },
    ControlMapping {
        clawtower_category: "sentinel:file_integrity",
        soc2_controls: &["CC8.1"],
        nist_controls: &["SI-7"],
        cis_controls: &["3.14"],
        mitre_attack: &["T1565", "T1485"],
    },
    ControlMapping {
        clawtower_category: "scan:firewall_status",
        soc2_controls: &["CC6.6"],
        nist_controls: &["SC-7"],
        cis_controls: &["4.8"],
        mitre_attack: &["T1562.004"],
    },
    ControlMapping {
        clawtower_category: "capability:envelope_violation",
        soc2_controls: &["CC6.1", "CC6.8"],
        nist_controls: &["AC-3", "AC-25"],
        cis_controls: &["6.1"],
        mitre_attack: &["T1078"],
    },
    ControlMapping {
        clawtower_category: "audit_chain:tamper_detected",
        soc2_controls: &["CC7.2", "CC7.3"],
        nist_controls: &["AU-9", "AU-10"],
        cis_controls: &["8.11"],
        mitre_attack: &["T1070"],
    },
    ControlMapping {
        clawtower_category: "behavior:reconnaissance",
        soc2_controls: &["CC6.1"],
        nist_controls: &["SI-4"],
        cis_controls: &["13.3"],
        mitre_attack: &["T1082", "T1033"],
    },
    ControlMapping {
        clawtower_category: "behavior:persistence",
        soc2_controls: &["CC7.2"],
        nist_controls: &["SI-3", "SI-7"],
        cis_controls: &["2.7"],
        mitre_attack: &["T1053", "T1546"],
    },
    ControlMapping {
        clawtower_category: "behavior:container_escape",
        soc2_controls: &["CC6.1", "CC6.6"],
        nist_controls: &["SC-7", "CM-7"],
        cis_controls: &["16.1"],
        mitre_attack: &["T1611"],
    },
    ControlMapping {
        clawtower_category: "scan:suid_binaries",
        soc2_controls: &["CC6.1"],
        nist_controls: &["AC-6"],
        cis_controls: &["5.4"],
        mitre_attack: &["T1548.001"],
    },
    ControlMapping {
        clawtower_category: "behavior:social_engineering",
        soc2_controls: &["CC6.8", "CC7.2"],
        nist_controls: &["SI-3", "SI-4"],
        cis_controls: &["2.7", "13.1"],
        mitre_attack: &["T1204", "T1566"],
    },
    ControlMapping {
        clawtower_category: "barnacle:supply_chain",
        soc2_controls: &["CC6.8", "CC8.1"],
        nist_controls: &["SI-3", "SI-7"],
        cis_controls: &["2.7", "16.1"],
        mitre_attack: &["T1195"],
    },
    ControlMapping {
        clawtower_category: "sentinel:skill_intake",
        soc2_controls: &["CC6.8", "CC8.1"],
        nist_controls: &["SI-3", "SI-7"],
        cis_controls: &["2.7", "16.1"],
        mitre_attack: &["T1195.002"],
    },
];

// ---------------------------------------------------------------------------
// MITRE ATT&CK technique metadata
// ---------------------------------------------------------------------------

/// Rich metadata for a MITRE ATT&CK technique, providing human-readable
/// names and tactic classifications for technique IDs referenced in control mappings.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct MitreTechnique {
    pub technique_id: &'static str,
    pub technique_name: &'static str,
    pub tactic: &'static str,
}

/// All MITRE ATT&CK techniques referenced by ClawTower control mappings.
#[allow(dead_code)]
pub static MITRE_ATTACK_TECHNIQUES: &[MitreTechnique] = &[
    MitreTechnique { technique_id: "T1041", technique_name: "Exfiltration Over C2 Channel", tactic: "Exfiltration" },
    MitreTechnique { technique_id: "T1048", technique_name: "Exfiltration Over Alternative Protocol", tactic: "Exfiltration" },
    MitreTechnique { technique_id: "T1068", technique_name: "Exploitation for Privilege Escalation", tactic: "Privilege Escalation" },
    MitreTechnique { technique_id: "T1548", technique_name: "Abuse Elevation Control Mechanism", tactic: "Privilege Escalation" },
    MitreTechnique { technique_id: "T1548.001", technique_name: "Setuid and Setgid", tactic: "Privilege Escalation" },
    MitreTechnique { technique_id: "T1565", technique_name: "Data Manipulation", tactic: "Impact" },
    MitreTechnique { technique_id: "T1485", technique_name: "Data Destruction", tactic: "Impact" },
    MitreTechnique { technique_id: "T1562.004", technique_name: "Disable or Modify System Firewall", tactic: "Defense Evasion" },
    MitreTechnique { technique_id: "T1078", technique_name: "Valid Accounts", tactic: "Defense Evasion" },
    MitreTechnique { technique_id: "T1070", technique_name: "Indicator Removal", tactic: "Defense Evasion" },
    MitreTechnique { technique_id: "T1082", technique_name: "System Information Discovery", tactic: "Discovery" },
    MitreTechnique { technique_id: "T1033", technique_name: "System Owner/User Discovery", tactic: "Discovery" },
    MitreTechnique { technique_id: "T1053", technique_name: "Scheduled Task/Job", tactic: "Persistence" },
    MitreTechnique { technique_id: "T1546", technique_name: "Event Triggered Execution", tactic: "Persistence" },
    MitreTechnique { technique_id: "T1611", technique_name: "Escape to Host", tactic: "Privilege Escalation" },
    MitreTechnique { technique_id: "T1204", technique_name: "User Execution", tactic: "Execution" },
    MitreTechnique { technique_id: "T1566", technique_name: "Phishing", tactic: "Initial Access" },
    MitreTechnique { technique_id: "T1195", technique_name: "Supply Chain Compromise", tactic: "Initial Access" },
    MitreTechnique { technique_id: "T1195.002", technique_name: "Compromise Software Supply Chain", tactic: "Initial Access" },
];

/// Look up rich metadata for a MITRE ATT&CK technique by its ID.
///
/// Returns `None` if the technique ID is not in the known table.
#[allow(dead_code)]
pub fn lookup_mitre_technique(technique_id: &str) -> Option<&'static MitreTechnique> {
    MITRE_ATTACK_TECHNIQUES.iter().find(|t| t.technique_id == technique_id)
}

// ---------------------------------------------------------------------------
// Report types
// ---------------------------------------------------------------------------

/// A completed compliance report for a specific framework and time period.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize)]
pub struct ComplianceReport {
    pub framework: String,
    pub period_days: u32,
    pub generated_at: DateTime<Local>,
    pub total_alerts: u64,
    pub alerts_by_severity: AlertSeveritySummary,
    pub control_findings: Vec<ControlFinding>,
    pub scanner_summary: ScannerSummary,
}

/// Breakdown of total alerts by severity level.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize)]
pub struct AlertSeveritySummary {
    pub critical: u64,
    pub warning: u64,
    pub info: u64,
}

/// A single control finding within the compliance report.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize)]
pub struct ControlFinding {
    pub control_id: String,
    pub control_name: String,
    pub alert_count: u64,
    pub highest_severity: String,
    pub status: FindingStatus,
    pub categories: Vec<String>,
}

/// Status of a compliance control finding.
///
/// Variants are ordered by escalation severity: `Pass < Finding < Critical`.
/// This ordering is used by `ControlAccumulator` to track the worst status seen.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum FindingStatus {
    /// No alerts mapped to this control
    Pass,
    /// Warning-level alerts mapped to this control
    Finding,
    /// Critical-level alerts mapped to this control
    Critical,
}

impl std::fmt::Display for FindingStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingStatus::Pass => write!(f, "Pass"),
            FindingStatus::Finding => write!(f, "Finding"),
            FindingStatus::Critical => write!(f, "Critical"),
        }
    }
}

/// Summary of periodic security scanner results.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize)]
pub struct ScannerSummary {
    pub total_scans: u64,
    pub pass_count: u64,
    pub warn_count: u64,
    pub fail_count: u64,
}

// ---------------------------------------------------------------------------
// Well-known control names — unified lookup table
// ---------------------------------------------------------------------------

/// Entry in the unified control name lookup table.
struct ControlNameEntry {
    framework: &'static str,
    id: &'static str,
    name: &'static str,
}

/// Unified lookup table for all framework control names.
/// Consolidates SOC 2, NIST 800-53, and CIS v8 control names into one table.
static CONTROL_NAMES: &[ControlNameEntry] = &[
    // SOC 2 Trust Services Criteria
    ControlNameEntry { framework: "soc2", id: "CC6.1", name: "Logical and Physical Access Controls" },
    ControlNameEntry { framework: "soc2", id: "CC6.3", name: "Role-Based Access and Least Privilege" },
    ControlNameEntry { framework: "soc2", id: "CC6.6", name: "System Boundary Protection" },
    ControlNameEntry { framework: "soc2", id: "CC6.8", name: "Controls Against Unauthorized Software" },
    ControlNameEntry { framework: "soc2", id: "CC7.2", name: "Monitoring for Anomalies and Security Events" },
    ControlNameEntry { framework: "soc2", id: "CC7.3", name: "Evaluation of Security Events" },
    ControlNameEntry { framework: "soc2", id: "CC8.1", name: "Change Management Controls" },
    // NIST 800-53 Rev 5
    ControlNameEntry { framework: "nist-800-53", id: "AC-3", name: "Access Enforcement" },
    ControlNameEntry { framework: "nist-800-53", id: "AC-6", name: "Least Privilege" },
    ControlNameEntry { framework: "nist-800-53", id: "AC-25", name: "Reference Monitor" },
    ControlNameEntry { framework: "nist-800-53", id: "AU-9", name: "Protection of Audit Information" },
    ControlNameEntry { framework: "nist-800-53", id: "AU-10", name: "Non-repudiation" },
    ControlNameEntry { framework: "nist-800-53", id: "AU-12", name: "Audit Record Generation" },
    ControlNameEntry { framework: "nist-800-53", id: "CM-7", name: "Least Functionality" },
    ControlNameEntry { framework: "nist-800-53", id: "SC-7", name: "Boundary Protection" },
    ControlNameEntry { framework: "nist-800-53", id: "SI-3", name: "Malicious Code Protection" },
    ControlNameEntry { framework: "nist-800-53", id: "SI-4", name: "System Monitoring" },
    ControlNameEntry { framework: "nist-800-53", id: "SI-7", name: "Software, Firmware, and Information Integrity" },
    // CIS Controls v8
    ControlNameEntry { framework: "cis-v8", id: "2.7", name: "Allowlist Authorized Scripts" },
    ControlNameEntry { framework: "cis-v8", id: "3.14", name: "Log Sensitive Data Access" },
    ControlNameEntry { framework: "cis-v8", id: "4.8", name: "Uninstall or Disable Unnecessary Services" },
    ControlNameEntry { framework: "cis-v8", id: "5.4", name: "Restrict Administrator Privileges" },
    ControlNameEntry { framework: "cis-v8", id: "6.1", name: "Establish an Access Granting Process" },
    ControlNameEntry { framework: "cis-v8", id: "8.11", name: "Conduct Audit Log Reviews" },
    ControlNameEntry { framework: "cis-v8", id: "13.1", name: "Centralize Security Event Alerting" },
    ControlNameEntry { framework: "cis-v8", id: "13.3", name: "Deploy a Network Intrusion Detection Solution" },
    ControlNameEntry { framework: "cis-v8", id: "16.1", name: "Establish a Secure Application Development Process" },
];

/// Look up the human-readable name for a control ID within a framework.
///
/// For `mitre-attack`, delegates to the MITRE technique table. For all other
/// frameworks, searches the unified `CONTROL_NAMES` table.
fn control_name_for_framework(framework: &str, id: &str) -> String {
    if framework == "mitre-attack" {
        return lookup_mitre_technique(id)
            .map(|t| t.technique_name)
            .unwrap_or("Unknown Technique")
            .to_string();
    }
    CONTROL_NAMES
        .iter()
        .find(|e| e.framework == framework && e.id == id)
        .map(|e| e.name)
        .unwrap_or("Unknown Control")
        .to_string()
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Look up controls for a given ClawTower alert source/category.
///
/// Returns `None` if the category has no known compliance mapping.
#[allow(dead_code)]
pub fn lookup_controls(category: &str) -> Option<&'static ControlMapping> {
    CONTROL_MAPPINGS
        .iter()
        .find(|m| m.clawtower_category == category)
}

/// Get all supported compliance framework identifiers.
#[allow(dead_code)]
pub fn supported_frameworks() -> &'static [&'static str] {
    &["soc2", "nist-800-53", "cis-v8", "mitre-attack"]
}

/// Extract the control IDs relevant to a given framework from a mapping.
///
/// Defaults to SOC 2 controls for unrecognized framework identifiers.
fn get_control_ids_for_framework<'a>(
    mapping: &'a ControlMapping,
    framework: &str,
) -> &'a [&'static str] {
    match framework {
        "soc2" => mapping.soc2_controls,
        "nist-800-53" => mapping.nist_controls,
        "cis-v8" => mapping.cis_controls,
        "mitre-attack" => mapping.mitre_attack,
        _ => mapping.soc2_controls,
    }
}

/// Map an alert severity string to a `FindingStatus`.
///
/// Critical/crit -> `Critical`, warning/warn -> `Finding`, everything else -> `Pass`.
fn severity_to_finding_status(severity: &str) -> FindingStatus {
    match severity.to_lowercase().as_str() {
        "critical" | "crit" => FindingStatus::Critical,
        "warning" | "warn" => FindingStatus::Finding,
        _ => FindingStatus::Pass,
    }
}

/// Accumulated state for a single control while building the report.
struct ControlAccumulator {
    alert_count: u64,
    highest_severity: String,
    status: FindingStatus,
    categories: Vec<String>,
}

impl ControlAccumulator {
    fn new() -> Self {
        Self {
            alert_count: 0,
            highest_severity: "none".to_string(),
            status: FindingStatus::Pass,
            categories: Vec::new(),
        }
    }

    /// Record alerts against this control, escalating status if the new
    /// severity outranks the current one (Pass < Finding < Critical).
    fn record(&mut self, count: u64, severity: &str, source: &str) {
        self.alert_count += count;

        let new_status = severity_to_finding_status(severity);
        if new_status > self.status {
            self.highest_severity = severity.to_string();
            self.status = new_status;
        }

        if !self.categories.contains(&source.to_string()) {
            self.categories.push(source.to_string());
        }
    }
}

/// Generate a compliance report from alert data.
///
/// # Arguments
///
/// * `framework` — One of `"soc2"`, `"nist-800-53"`, or `"cis-v8"`
/// * `period_days` — Reporting period in days (e.g., 30)
/// * `alert_summary` — Slice of `(source, severity, count)` tuples from alert history
/// * `scanner_results` — Slice of `(category, status)` tuples where status is `"pass"`, `"warn"`, or `"fail"`
#[allow(dead_code)]
pub fn generate_report(
    framework: &str,
    period_days: u32,
    alert_summary: &[(String, String, u64)],
    scanner_results: &[(String, String)],
) -> ComplianceReport {
    // Tally alerts by severity
    let mut critical_count: u64 = 0;
    let mut warning_count: u64 = 0;
    let mut info_count: u64 = 0;

    for (_, severity, count) in alert_summary {
        match severity_to_finding_status(severity) {
            FindingStatus::Critical => critical_count += count,
            FindingStatus::Finding => warning_count += count,
            FindingStatus::Pass => info_count += count,
        }
    }

    let total_alerts = critical_count + warning_count + info_count;

    // Collect all unique control IDs for the requested framework, tracking
    // which ClawTower categories map to each control and the highest severity seen.
    let mut control_map: std::collections::BTreeMap<String, ControlAccumulator> =
        std::collections::BTreeMap::new();

    // Seed all controls from the static mapping so every known control appears
    for mapping in CONTROL_MAPPINGS {
        for &cid in get_control_ids_for_framework(mapping, framework) {
            control_map
                .entry(cid.to_string())
                .or_insert_with(ControlAccumulator::new);
        }
    }

    // Map alert data to controls
    for (source, severity, count) in alert_summary {
        if let Some(mapping) = lookup_controls(source) {
            for &cid in get_control_ids_for_framework(mapping, framework) {
                control_map
                    .entry(cid.to_string())
                    .or_insert_with(ControlAccumulator::new)
                    .record(*count, severity, source);
            }
        }
    }

    // Build control findings
    let control_findings: Vec<ControlFinding> = control_map
        .into_iter()
        .map(|(cid, acc)| {
            let control_name = control_name_for_framework(framework, &cid);
            ControlFinding {
                control_id: cid,
                control_name,
                alert_count: acc.alert_count,
                highest_severity: if acc.status == FindingStatus::Pass {
                    "none".to_string()
                } else {
                    acc.highest_severity
                },
                status: acc.status,
                categories: acc.categories,
            }
        })
        .collect();

    // Build scanner summary
    let mut pass_scans: u64 = 0;
    let mut warn_scans: u64 = 0;
    let mut fail_scans: u64 = 0;
    for (_, status) in scanner_results {
        match status.to_lowercase().as_str() {
            "pass" => pass_scans += 1,
            "warn" => warn_scans += 1,
            "fail" => fail_scans += 1,
            _ => {}
        }
    }

    ComplianceReport {
        framework: framework.to_string(),
        period_days,
        generated_at: Local::now(),
        total_alerts,
        alerts_by_severity: AlertSeveritySummary {
            critical: critical_count,
            warning: warning_count,
            info: info_count,
        },
        control_findings,
        scanner_summary: ScannerSummary {
            total_scans: pass_scans + warn_scans + fail_scans,
            pass_count: pass_scans,
            warn_count: warn_scans,
            fail_count: fail_scans,
        },
    }
}

/// Format a compliance report as a JSON string.
#[allow(dead_code)]
pub fn report_to_json(report: &ComplianceReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|e| {
        format!("{{\"error\": \"Failed to serialize report: {}\"}}", e)
    })
}

/// Format a compliance report as human-readable text.
#[allow(dead_code)]
pub fn report_to_text(report: &ComplianceReport) -> String {
    let mut out = String::new();

    // Header
    out.push_str(&format!(
        "ClawTower Compliance Report — {}\n",
        framework_display_name(&report.framework)
    ));
    out.push_str(&"=".repeat(60));
    out.push('\n');
    out.push_str(&format!(
        "Generated: {}\n",
        report.generated_at.format("%Y-%m-%d %H:%M:%S %Z")
    ));
    out.push_str(&format!("Period: {} days\n", report.period_days));
    out.push('\n');

    // Alert summary
    out.push_str("Alert Summary\n");
    out.push_str(&"-".repeat(40));
    out.push('\n');
    out.push_str(&format!("  Total alerts:    {}\n", report.total_alerts));
    out.push_str(&format!(
        "  Critical:        {}\n",
        report.alerts_by_severity.critical
    ));
    out.push_str(&format!(
        "  Warning:         {}\n",
        report.alerts_by_severity.warning
    ));
    out.push_str(&format!(
        "  Info:            {}\n",
        report.alerts_by_severity.info
    ));
    out.push('\n');

    // Scanner summary
    out.push_str("Scanner Summary\n");
    out.push_str(&"-".repeat(40));
    out.push('\n');
    out.push_str(&format!(
        "  Total scans:     {}\n",
        report.scanner_summary.total_scans
    ));
    out.push_str(&format!(
        "  Passed:          {}\n",
        report.scanner_summary.pass_count
    ));
    out.push_str(&format!(
        "  Warnings:        {}\n",
        report.scanner_summary.warn_count
    ));
    out.push_str(&format!(
        "  Failed:          {}\n",
        report.scanner_summary.fail_count
    ));
    out.push('\n');

    // Control findings
    out.push_str("Control Findings\n");
    out.push_str(&"-".repeat(60));
    out.push('\n');

    // Count findings by status
    let pass_count = report
        .control_findings
        .iter()
        .filter(|f| f.status == FindingStatus::Pass)
        .count();
    let finding_count = report
        .control_findings
        .iter()
        .filter(|f| f.status == FindingStatus::Finding)
        .count();
    let critical_count = report
        .control_findings
        .iter()
        .filter(|f| f.status == FindingStatus::Critical)
        .count();

    out.push_str(&format!(
        "  {} controls assessed: {} Pass, {} Finding, {} Critical\n\n",
        report.control_findings.len(),
        pass_count,
        finding_count,
        critical_count,
    ));

    // List non-pass findings first, then pass
    for finding in &report.control_findings {
        if finding.status != FindingStatus::Pass {
            out.push_str(&format!(
                "  [{}] {} — {}\n",
                finding.status, finding.control_id, finding.control_name
            ));
            out.push_str(&format!(
                "         Alerts: {}  Highest: {}\n",
                finding.alert_count, finding.highest_severity
            ));
            if !finding.categories.is_empty() {
                out.push_str(&format!(
                    "         Sources: {}\n",
                    finding.categories.join(", ")
                ));
            }
            out.push('\n');
        }
    }

    // Passing controls (compact)
    let passing: Vec<&ControlFinding> = report
        .control_findings
        .iter()
        .filter(|f| f.status == FindingStatus::Pass)
        .collect();
    if !passing.is_empty() {
        out.push_str("  Passing controls:\n");
        for finding in passing {
            out.push_str(&format!(
                "    [Pass] {} — {}\n",
                finding.control_id, finding.control_name
            ));
        }
    }

    out
}

/// Return a human-readable display name for a framework identifier.
#[allow(dead_code)]
fn framework_display_name(framework: &str) -> &str {
    match framework {
        "soc2" => "SOC 2 Type II",
        "nist-800-53" => "NIST 800-53 Rev 5",
        "cis-v8" => "CIS Controls v8",
        "mitre-attack" => "MITRE ATT&CK",
        _ => framework,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup_controls_data_exfil() {
        let mapping = lookup_controls("behavior:data_exfiltration");
        assert!(mapping.is_some(), "data_exfiltration should have a mapping");
        let m = mapping.unwrap();
        assert!(
            m.soc2_controls.contains(&"CC6.1"),
            "SOC2 should include CC6.1"
        );
        assert!(
            m.soc2_controls.contains(&"CC7.2"),
            "SOC2 should include CC7.2"
        );
        assert!(
            m.nist_controls.contains(&"SC-7"),
            "NIST should include SC-7"
        );
        assert!(
            m.nist_controls.contains(&"SI-4"),
            "NIST should include SI-4"
        );
        assert!(
            m.cis_controls.contains(&"13.1"),
            "CIS should include 13.1"
        );
    }

    #[test]
    fn test_lookup_controls_unknown() {
        let mapping = lookup_controls("nonexistent:category");
        assert!(mapping.is_none(), "unknown category should return None");
    }

    #[test]
    fn test_supported_frameworks() {
        let frameworks = supported_frameworks();
        assert_eq!(frameworks.len(), 4);
        assert!(frameworks.contains(&"soc2"));
        assert!(frameworks.contains(&"nist-800-53"));
        assert!(frameworks.contains(&"cis-v8"));
        assert!(frameworks.contains(&"mitre-attack"));
    }

    #[test]
    fn test_generate_empty_report() {
        let report = generate_report("soc2", 30, &[], &[]);
        assert_eq!(report.framework, "soc2");
        assert_eq!(report.period_days, 30);
        assert_eq!(report.total_alerts, 0);
        assert_eq!(report.alerts_by_severity.critical, 0);
        assert_eq!(report.alerts_by_severity.warning, 0);
        assert_eq!(report.alerts_by_severity.info, 0);
        // All controls should be Pass when no alerts
        for finding in &report.control_findings {
            assert_eq!(
                finding.status,
                FindingStatus::Pass,
                "control {} should be Pass with no alerts",
                finding.control_id
            );
        }
        // Should have seeded controls from static mapping
        assert!(
            !report.control_findings.is_empty(),
            "empty report should still list all known controls"
        );
    }

    #[test]
    fn test_generate_report_with_criticals() {
        let alerts = vec![(
            "behavior:data_exfiltration".to_string(),
            "critical".to_string(),
            5u64,
        )];
        let report = generate_report("soc2", 7, &alerts, &[]);
        assert_eq!(report.total_alerts, 5);
        assert_eq!(report.alerts_by_severity.critical, 5);

        // CC6.1 and CC7.2 should be Critical (data_exfiltration maps to both)
        let cc61 = report
            .control_findings
            .iter()
            .find(|f| f.control_id == "CC6.1")
            .expect("CC6.1 should be present");
        assert_eq!(cc61.status, FindingStatus::Critical);
        assert_eq!(cc61.alert_count, 5);
        assert!(cc61.categories.contains(&"behavior:data_exfiltration".to_string()));

        let cc72 = report
            .control_findings
            .iter()
            .find(|f| f.control_id == "CC7.2")
            .expect("CC7.2 should be present");
        assert_eq!(cc72.status, FindingStatus::Critical);
    }

    #[test]
    fn test_generate_report_with_warnings() {
        let alerts = vec![(
            "scan:firewall_status".to_string(),
            "warning".to_string(),
            3u64,
        )];
        let report = generate_report("soc2", 30, &alerts, &[]);
        assert_eq!(report.total_alerts, 3);
        assert_eq!(report.alerts_by_severity.warning, 3);

        // CC6.6 should be Finding (firewall_status maps to CC6.6 in SOC2)
        let cc66 = report
            .control_findings
            .iter()
            .find(|f| f.control_id == "CC6.6")
            .expect("CC6.6 should be present");
        assert_eq!(cc66.status, FindingStatus::Finding);
        assert_eq!(cc66.alert_count, 3);
    }

    #[test]
    fn test_report_to_json() {
        let report = generate_report("soc2", 30, &[], &[]);
        let json = report_to_json(&report);

        // Should be valid JSON
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("report_to_json should produce valid JSON");

        assert_eq!(parsed["framework"], "soc2");
        assert_eq!(parsed["period_days"], 30);
        assert_eq!(parsed["total_alerts"], 0);
        assert!(
            parsed["control_findings"].is_array(),
            "control_findings should be a JSON array"
        );
        assert!(
            parsed["scanner_summary"].is_object(),
            "scanner_summary should be a JSON object"
        );
    }

    #[test]
    fn test_report_to_text() {
        let alerts = vec![(
            "behavior:privilege_escalation".to_string(),
            "critical".to_string(),
            2u64,
        )];
        let scanners = vec![
            ("firewall".to_string(), "pass".to_string()),
            ("auditd".to_string(), "warn".to_string()),
        ];
        let report = generate_report("soc2", 30, &alerts, &scanners);
        let text = report_to_text(&report);

        assert!(
            text.contains("SOC 2 Type II"),
            "text output should contain framework display name"
        );
        assert!(
            text.contains("30 days"),
            "text output should contain period"
        );
        assert!(
            text.contains("Control Findings"),
            "text output should contain findings section"
        );
        assert!(
            text.contains("[Critical]"),
            "text output should show Critical status"
        );
        assert!(
            text.contains("CC6.1"),
            "text output should list affected control"
        );
    }

    #[test]
    fn test_finding_status_display() {
        assert_eq!(FindingStatus::Pass.to_string(), "Pass");
        assert_eq!(FindingStatus::Finding.to_string(), "Finding");
        assert_eq!(FindingStatus::Critical.to_string(), "Critical");
    }

    #[test]
    fn test_control_mapping_completeness() {
        // Every mapping must have at least one SOC2 control
        for mapping in CONTROL_MAPPINGS {
            assert!(
                !mapping.soc2_controls.is_empty(),
                "mapping for {} should have at least one SOC2 control",
                mapping.clawtower_category
            );
            assert!(
                !mapping.nist_controls.is_empty(),
                "mapping for {} should have at least one NIST control",
                mapping.clawtower_category
            );
            assert!(
                !mapping.cis_controls.is_empty(),
                "mapping for {} should have at least one CIS control",
                mapping.clawtower_category
            );
        }
    }

    #[test]
    fn test_nist_framework_report() {
        let alerts = vec![(
            "behavior:data_exfiltration".to_string(),
            "critical".to_string(),
            1u64,
        )];
        let report = generate_report("nist-800-53", 90, &alerts, &[]);
        assert_eq!(report.framework, "nist-800-53");

        // SC-7 and SI-4 should be Critical for data exfiltration in NIST
        let sc7 = report
            .control_findings
            .iter()
            .find(|f| f.control_id == "SC-7")
            .expect("SC-7 should be present");
        assert_eq!(sc7.status, FindingStatus::Critical);
    }

    #[test]
    fn test_scanner_summary() {
        let scanners = vec![
            ("firewall".to_string(), "pass".to_string()),
            ("auditd".to_string(), "pass".to_string()),
            ("suid".to_string(), "warn".to_string()),
            ("docker".to_string(), "fail".to_string()),
        ];
        let report = generate_report("soc2", 30, &[], &scanners);
        assert_eq!(report.scanner_summary.total_scans, 4);
        assert_eq!(report.scanner_summary.pass_count, 2);
        assert_eq!(report.scanner_summary.warn_count, 1);
        assert_eq!(report.scanner_summary.fail_count, 1);
    }

    #[test]
    fn test_control_mapping_has_mitre_attack() {
        for mapping in CONTROL_MAPPINGS {
            assert!(
                !mapping.mitre_attack.is_empty(),
                "mapping for {} should have at least one ATT&CK technique",
                mapping.clawtower_category
            );
        }
    }

    #[test]
    fn test_data_exfil_maps_to_t1048() {
        let mapping = lookup_controls("behavior:data_exfiltration").unwrap();
        assert!(
            mapping.mitre_attack.contains(&"T1048"),
            "data_exfiltration should map to T1048 (Exfiltration Over Alternative Protocol)"
        );
    }

    #[test]
    fn test_mitre_technique_lookup_t1048() {
        let tech = lookup_mitre_technique("T1048").unwrap();
        assert_eq!(tech.technique_id, "T1048");
        assert_eq!(tech.tactic, "Exfiltration");
        assert!(!tech.technique_name.is_empty());
    }

    #[test]
    fn test_mitre_technique_lookup_unknown() {
        assert!(lookup_mitre_technique("T9999").is_none());
    }

    #[test]
    fn test_supply_chain_categories_have_mappings() {
        assert!(lookup_controls("behavior:social_engineering").is_some());
        assert!(lookup_controls("barnacle:supply_chain").is_some());
        assert!(lookup_controls("sentinel:skill_intake").is_some());
    }

    #[test]
    fn test_mitre_attack_framework_in_supported_list() {
        let frameworks = supported_frameworks();
        assert!(frameworks.contains(&"mitre-attack"), "mitre-attack should be supported");
    }

    #[test]
    fn test_generate_mitre_attack_report() {
        let alerts = vec![(
            "behavior:data_exfiltration".to_string(),
            "critical".to_string(),
            3u64,
        )];
        let report = generate_report("mitre-attack", 30, &alerts, &[]);
        assert_eq!(report.framework, "mitre-attack");
        // T1048 should be present as a control finding
        let t1048 = report.control_findings.iter()
            .find(|f| f.control_id == "T1048")
            .expect("T1048 should be in report");
        assert_eq!(t1048.status, FindingStatus::Critical);
        assert!(t1048.control_name.contains("Exfiltration"));
    }

    #[test]
    fn test_mitre_report_text_output() {
        let alerts = vec![(
            "behavior:persistence".to_string(),
            "warning".to_string(),
            1u64,
        )];
        let report = generate_report("mitre-attack", 7, &alerts, &[]);
        let text = report_to_text(&report);
        assert!(text.contains("MITRE ATT&CK"));
    }

    #[test]
    fn test_severity_escalation() {
        // When both warning and critical alerts hit the same control, status should be Critical
        let alerts = vec![
            (
                "behavior:data_exfiltration".to_string(),
                "warning".to_string(),
                10u64,
            ),
            (
                "behavior:data_exfiltration".to_string(),
                "critical".to_string(),
                1u64,
            ),
        ];
        let report = generate_report("soc2", 30, &alerts, &[]);

        let cc61 = report
            .control_findings
            .iter()
            .find(|f| f.control_id == "CC6.1")
            .expect("CC6.1 should be present");
        assert_eq!(
            cc61.status,
            FindingStatus::Critical,
            "critical should escalate over warning"
        );
        assert_eq!(cc61.alert_count, 11, "should sum both alert entries");
    }
}
