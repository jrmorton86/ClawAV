# P3: Enterprise Assurance & Adoption Package — Design

**Date:** 2026-02-18
**Scope:** Code-first (API + mappings + version tracking). Buyer-facing docs deferred.

## Goal

Extend ClawTower's compliance infrastructure with MITRE ATT&CK technique mapping, expose a unified evidence bundle API endpoint for enterprise procurement, and add policy/IOC version tracking for audit provenance.

## Architecture

Three layers:
1. **MITRE ATT&CK mapping** — Fourth column on `ControlMapping` + rich `MITRE_ATTACK_TECHNIQUES` table with technique names, tactics, and category mappings.
2. **Policy version tracking** — SHA-256 hashes + metadata for loaded policy YAML files and IOC JSON databases, computed once at load time.
3. **Evidence bundle API** — Single `GET /api/evidence` endpoint packaging compliance report, scanner snapshot, audit-chain integrity proof, and policy versions into one JSON response.

## Components

### MITRE ATT&CK Mapping (compliance.rs)

Add `mitre_attack: &'static [&'static str]` to `ControlMapping`. Add `MITRE_ATTACK_TECHNIQUES` static table:

| ClawTower Category | ATT&CK Techniques | Tactic |
|---|---|---|
| `behavior:data_exfiltration` | T1048, T1041 | Exfiltration |
| `behavior:privilege_escalation` | T1548, T1068 | Privilege Escalation |
| `sentinel:file_integrity` | T1565, T1485 | Impact |
| `scan:firewall_status` | T1562.004 | Defense Evasion |
| `capability:envelope_violation` | T1078 | Defense Evasion |
| `audit_chain:tamper_detected` | T1070 | Defense Evasion |
| `behavior:reconnaissance` | T1082, T1033 | Discovery |
| `behavior:persistence` | T1053, T1546 | Persistence |
| `behavior:container_escape` | T1611 | Privilege Escalation |
| `scan:suid_binaries` | T1548.001 | Privilege Escalation |
| `behavior:social_engineering` | T1204, T1566 | Initial Access |
| `barnacle:supply_chain` | T1195 | Initial Access |
| `sentinel:skill_intake` | T1195.002 | Initial Access |

`generate_report("mitre-attack", ...)` produces reports with technique IDs as "controls" grouped by tactic.

### Policy Version Tracking (policy.rs, barnacle.rs)

**PolicyEngine:** Add `loaded_files: Vec<PolicyFileInfo>` populated during `load()`. `PolicyFileInfo` = `{ filename, sha256, rules_count }`.

**BarnacleDefenseEngine:** Add `db_hashes: HashMap<String, String>` populated during `load()`. Method `db_info()` returns `Vec<IocDbInfo>` with `{ filename, version, sha256 }`.

### Evidence Bundle API (api.rs, main.rs)

Refactor `handle()` to take `Arc<ApiContext>` instead of 5+ individual params.

`GET /api/evidence?framework=soc2&period=30` returns:
- `compliance_report` — Full `ComplianceReport` for requested framework/period
- `scanner_snapshot` — Current `ScanResult` array from `SharedScanResults`
- `audit_chain_proof` — Entry count, integrity status, head hash from `AuditChain::verify()`
- `policy_versions` — SHA-256 hashes + rule counts for policy files and IOC databases
