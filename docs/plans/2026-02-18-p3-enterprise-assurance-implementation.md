# P3: Enterprise Assurance — Code Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add MITRE ATT&CK mapping, policy version tracking, and an evidence bundle API endpoint to ClawTower's enterprise compliance infrastructure.

**Architecture:** Three independent layers — (A) extend `compliance.rs` with ATT&CK technique mappings as a fourth framework column plus a rich technique metadata table, (B) add SHA-256 hash tracking to `policy.rs` and `barnacle.rs` at load time, (C) refactor `api.rs` to use an `ApiContext` struct and add a `GET /api/evidence` endpoint that assembles compliance reports, scanner snapshots, audit chain proofs, and policy version info into one JSON bundle.

**Tech Stack:** Rust, existing crates (sha2, serde, serde_json, hyper, chrono, tokio)

---

## Group A: MITRE ATT&CK Mapping

### Task 1: Add mitre_attack field to ControlMapping and populate all categories

**Files:**
- Modify: `src/compliance.rs:32-105` (ControlMapping struct + CONTROL_MAPPINGS table)

**Context:**
`ControlMapping` (line 35) has three framework fields: `soc2_controls`, `nist_controls`, `cis_controls`. Each is `&'static [&'static str]`. The `CONTROL_MAPPINGS` static slice (line 44) has 10 entries mapping ClawTower categories. We need to add a fourth field for MITRE ATT&CK technique IDs.

**Step 1: Write the failing tests**

Add to the existing `#[cfg(test)] mod tests` at the bottom of `compliance.rs`:

```rust
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
```

**Step 2: Run tests to verify they fail**

Run: `~/.cargo/bin/cargo test test_control_mapping_has_mitre -- --nocapture`
Expected: FAIL — no field `mitre_attack` on `ControlMapping`

**Step 3: Implement**

1. Add field to `ControlMapping` struct:
```rust
pub mitre_attack: &'static [&'static str],
```

2. Add `mitre_attack` to every entry in `CONTROL_MAPPINGS`:

| clawtower_category | mitre_attack |
|---|---|
| `behavior:data_exfiltration` | `&["T1048", "T1041"]` |
| `behavior:privilege_escalation` | `&["T1548", "T1068"]` |
| `sentinel:file_integrity` | `&["T1565", "T1485"]` |
| `scan:firewall_status` | `&["T1562.004"]` |
| `capability:envelope_violation` | `&["T1078"]` |
| `audit_chain:tamper_detected` | `&["T1070"]` |
| `behavior:reconnaissance` | `&["T1082", "T1033"]` |
| `behavior:persistence` | `&["T1053", "T1546"]` |
| `behavior:container_escape` | `&["T1611"]` |
| `scan:suid_binaries` | `&["T1548.001"]` |

**Step 4: Run tests to verify they pass**

Run: `~/.cargo/bin/cargo test compliance -- --nocapture`
Expected: All compliance tests PASS

**Step 5: Commit**

```bash
git add src/compliance.rs
git commit -m "feat(compliance): add MITRE ATT&CK technique IDs to ControlMapping"
```

---

### Task 2: Add MITRE_ATTACK_TECHNIQUES rich metadata table

**Files:**
- Modify: `src/compliance.rs` (new static table, new lookup functions)

**Context:**
The fourth-column technique IDs from Task 1 give the mapping, but enterprise buyers want technique names and tactic groupings in reports. We need a separate lookup table that enriches technique IDs with human-readable metadata. Also need to add 3 new supply-chain categories from P2 work.

**Step 1: Write the failing tests**

```rust
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
    // New P2 categories added to CONTROL_MAPPINGS
    assert!(lookup_controls("behavior:social_engineering").is_some());
    assert!(lookup_controls("barnacle:supply_chain").is_some());
    assert!(lookup_controls("sentinel:skill_intake").is_some());
}
```

**Step 2: Run tests to verify they fail**

Run: `~/.cargo/bin/cargo test test_mitre_technique -- --nocapture`
Expected: FAIL — function `lookup_mitre_technique` doesn't exist

**Step 3: Implement**

1. Add struct:
```rust
#[derive(Debug, Clone)]
pub struct MitreTechnique {
    pub technique_id: &'static str,
    pub technique_name: &'static str,
    pub tactic: &'static str,
}
```

2. Add static table `MITRE_ATTACK_TECHNIQUES`:
```rust
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
```

3. Add lookup function:
```rust
pub fn lookup_mitre_technique(technique_id: &str) -> Option<&'static MitreTechnique> {
    MITRE_ATTACK_TECHNIQUES.iter().find(|t| t.technique_id == technique_id)
}
```

4. Add 3 new entries to `CONTROL_MAPPINGS` for P2 supply-chain categories:
```rust
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
```

**Step 4: Run tests**

Run: `~/.cargo/bin/cargo test compliance -- --nocapture`
Expected: All compliance tests PASS

**Step 5: Commit**

```bash
git add src/compliance.rs
git commit -m "feat(compliance): add MITRE ATT&CK technique metadata table and supply-chain category mappings"
```

---

### Task 3: Add "mitre-attack" as a supported framework in generate_report()

**Files:**
- Modify: `src/compliance.rs:233-262` (supported_frameworks, control_name_for_framework)
- Modify: `src/compliance.rs:273-414` (generate_report — framework branching)

**Context:**
`generate_report()` uses `match framework` blocks to select which control IDs to use from each `ControlMapping`. Currently handles `"soc2"`, `"nist-800-53"`, `"cis-v8"`. Need to add `"mitre-attack"` which selects the new `mitre_attack` field. The `control_name_for_framework()` function needs a MITRE variant that looks up technique names from the rich table.

**Step 1: Write the failing tests**

```rust
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
```

**Step 2: Run tests to verify they fail**

Run: `~/.cargo/bin/cargo test test_mitre_attack_framework -- --nocapture`
Expected: FAIL — "mitre-attack" not in supported_frameworks()

**Step 3: Implement**

1. Update `supported_frameworks()`:
```rust
pub fn supported_frameworks() -> &'static [&'static str] {
    &["soc2", "nist-800-53", "cis-v8", "mitre-attack"]
}
```

2. Add `mitre_technique_name()` function:
```rust
fn mitre_technique_name(id: &str) -> &'static str {
    lookup_mitre_technique(id).map(|t| t.technique_name).unwrap_or("Unknown Technique")
}
```

3. Update `control_name_for_framework()`:
```rust
"mitre-attack" => mitre_technique_name(id),
```

4. Update `framework_display_name()`:
```rust
"mitre-attack" => "MITRE ATT&CK",
```

5. In `generate_report()`, add `"mitre-attack"` arm to every `match framework` block that selects control IDs:
```rust
"mitre-attack" => mapping.mitre_attack,
```

**Step 4: Run tests**

Run: `~/.cargo/bin/cargo test compliance -- --nocapture`
Expected: All compliance tests PASS

**Step 5: Commit**

```bash
git add src/compliance.rs
git commit -m "feat(compliance): add mitre-attack as supported report framework"
```

---

## Group B: Policy Version Tracking

### Task 4: Add PolicyFileInfo tracking to PolicyEngine::load()

**Files:**
- Modify: `src/policy.rs:85-190` (PolicyEngine struct + load method)

**Context:**
`PolicyEngine` (line 85) is `struct PolicyEngine { rules: Vec<PolicyRule> }`. The `load()` method (line 129) reads each YAML file as a string, parses it, and merges rules. We need to hash the raw bytes before parsing and store file metadata. The SHA-256 crate `sha2` is already a dependency (used in audit_chain.rs, barnacle.rs).

**Step 1: Write the failing tests**

```rust
#[test]
fn test_policy_file_info_populated_on_load() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("test.yaml"), sample_yaml()).unwrap();
    let engine = PolicyEngine::load(dir.path()).unwrap();
    let info = engine.file_info();
    assert_eq!(info.len(), 1);
    assert_eq!(info[0].filename, "test.yaml");
    assert_eq!(info[0].rules_count, 4); // sample_yaml has 4 rules
    assert_eq!(info[0].sha256.len(), 64); // SHA-256 hex = 64 chars
}

#[test]
fn test_policy_file_info_empty_dir() {
    let dir = tempfile::tempdir().unwrap();
    let engine = PolicyEngine::load(dir.path()).unwrap();
    assert!(engine.file_info().is_empty());
}
```

**Step 2: Run tests to verify they fail**

Run: `~/.cargo/bin/cargo test test_policy_file_info -- --nocapture`
Expected: FAIL — no method `file_info` on `PolicyEngine`

**Step 3: Implement**

1. Add imports at top of `policy.rs`:
```rust
use sha2::{Sha256, Digest};
```

2. Add struct:
```rust
#[derive(Debug, Clone, Serialize)]
pub struct PolicyFileInfo {
    pub filename: String,
    pub sha256: String,
    pub rules_count: usize,
}
```

3. Add field to `PolicyEngine`:
```rust
pub struct PolicyEngine {
    rules: Vec<PolicyRule>,
    loaded_files: Vec<PolicyFileInfo>,
}
```

4. Update `PolicyEngine::new()`:
```rust
pub fn new() -> Self {
    Self { rules: Vec::new(), loaded_files: Vec::new() }
}
```

5. In `load()`, after reading content (line 170) and parsing `pf` (line 178), add:
```rust
let mut hasher = Sha256::new();
hasher.update(content.as_bytes());
let sha256 = format!("{:x}", hasher.finalize());
let rules_count = pf.rules.len();
// ... after merge_rules ...
loaded_files.push(PolicyFileInfo {
    filename: path.file_name().unwrap().to_string_lossy().to_string(),
    sha256,
    rules_count,
});
```

Declare `let mut loaded_files: Vec<PolicyFileInfo> = Vec::new();` near `all_rules` and return it in the struct: `Ok(Self { rules: all_rules, loaded_files })`.

6. Add accessor:
```rust
pub fn file_info(&self) -> &[PolicyFileInfo] {
    &self.loaded_files
}
```

7. Update `load_from_str()` test helper (line 377) to include `loaded_files: vec![]`.

**Step 4: Run tests**

Run: `~/.cargo/bin/cargo test policy -- --nocapture`
Expected: All policy tests PASS

**Step 5: Commit**

```bash
git add src/policy.rs
git commit -m "feat(policy): track SHA-256 hashes and rule counts for loaded policy files"
```

---

### Task 5: Add db_hashes to BarnacleDefenseEngine and db_info() method

**Files:**
- Modify: `src/barnacle.rs:55-60` (BarnacleDefenseEngine struct)
- Modify: `src/barnacle.rs:129-183` (load method)

**Context:**
`BarnacleDefenseEngine` already has `db_versions: HashMap<String, String>` (added in P2 Task 1) populated during `load()`. We need to add parallel `db_hashes: HashMap<String, String>` tracking SHA-256 of each JSON file's raw bytes, plus a `db_info()` method returning structured info. SHA-256 is already imported in barnacle.rs (`use sha2::{Digest, Sha256}`).

**Step 1: Write the failing tests**

```rust
#[test]
fn test_engine_db_info_populated() {
    let dir = tempfile::tempdir().unwrap();
    let content = r#"{"version":"1.0.0","patterns":[]}"#;
    std::fs::write(dir.path().join("supply-chain-ioc.json"), content).unwrap();
    let engine = BarnacleDefenseEngine::load(dir.path()).unwrap();
    let info = engine.db_info();
    assert!(!info.is_empty());
    let sci = info.iter().find(|i| i.filename == "supply-chain-ioc.json").unwrap();
    assert_eq!(sci.version, Some("1.0.0".to_string()));
    assert_eq!(sci.sha256.len(), 64);
}
```

**Step 2: Run test to verify it fails**

Run: `~/.cargo/bin/cargo test test_engine_db_info -- --nocapture`
Expected: FAIL — no method `db_info` on `BarnacleDefenseEngine`

**Step 3: Implement**

1. Add struct:
```rust
#[derive(Debug, Clone, Serialize)]
pub struct IocDbInfo {
    pub filename: String,
    pub version: Option<String>,
    pub sha256: String,
}
```

2. Add field to `BarnacleDefenseEngine`:
```rust
db_hashes: HashMap<String, String>,
```

3. In `load()`, after reading each JSON file's raw bytes (use `std::fs::read` instead of or in addition to the current load), compute SHA-256:
```rust
let raw_bytes = std::fs::read(&file_path)?;
let mut hasher = Sha256::new();
hasher.update(&raw_bytes);
let hash = format!("{:x}", hasher.finalize());
engine.db_hashes.insert(db_name.to_string(), hash);
```

4. Add method:
```rust
pub fn db_info(&self) -> Vec<IocDbInfo> {
    self.db_hashes.iter().map(|(name, hash)| {
        IocDbInfo {
            filename: format!("{}.json", name),
            version: self.db_versions.get(name).cloned(),
            sha256: hash.clone(),
        }
    }).collect()
}
```

5. Initialize `db_hashes: HashMap::new()` in the engine constructor within `load()`.

**Step 4: Run tests**

Run: `~/.cargo/bin/cargo test barnacle -- --nocapture`
Expected: All barnacle tests PASS

**Step 5: Commit**

```bash
git add src/barnacle.rs
git commit -m "feat(barnacle): track SHA-256 hashes for IOC database files"
```

---

## Group C: Evidence Bundle API

### Task 6: Refactor handle() to use Arc<ApiContext>

**Files:**
- Modify: `src/api.rs:28-155` (types + handle signature)
- Modify: `src/api.rs:322-350` (run_api_server)
- Modify: `src/api.rs:352-512` (all tests calling handle())

**Context:**
`handle()` (line 151) takes 6 parameters. Adding scanner results, audit chain path, policy dir, etc. would make it unmanageable. Refactor to `Arc<ApiContext>`. This is a pure refactor — zero behavior change.

The existing tests (lines 357-512) call `handle()` directly with individual args. All 8 test functions need updating to construct `ApiContext` instead.

**Step 1: Write the failing test**

```rust
#[test]
fn test_api_context_construction() {
    let ctx = ApiContext {
        store: new_shared_store(100),
        start_time: Instant::now(),
        auth_token: "test".to_string(),
        pending_store: Arc::new(Mutex::new(Vec::new())),
        response_tx: None,
        scan_results: None,
        audit_chain_path: None,
        policy_dir: None,
        barnacle_dir: None,
        active_profile: None,
    };
    assert_eq!(ctx.auth_token, "test");
}
```

**Step 2: Run test to verify it fails**

Run: `~/.cargo/bin/cargo test test_api_context -- --nocapture`
Expected: FAIL — `ApiContext` doesn't exist

**Step 3: Implement**

1. Add `ApiContext` struct after the existing type definitions (after line 87):
```rust
use crate::scanner::SharedScanResults;
use std::path::PathBuf;

pub struct ApiContext {
    pub store: SharedAlertStore,
    pub start_time: Instant,
    pub auth_token: String,
    pub pending_store: SharedPendingActions,
    pub response_tx: Option<Arc<mpsc::Sender<ResponseRequest>>>,
    // Evidence bundle fields (all optional for backward compat)
    pub scan_results: Option<SharedScanResults>,
    pub audit_chain_path: Option<PathBuf>,
    pub policy_dir: Option<PathBuf>,
    pub barnacle_dir: Option<PathBuf>,
    pub active_profile: Option<String>,
}
```

2. Change `handle()` signature from 6 params to:
```rust
async fn handle(
    req: Request<Body>,
    ctx: Arc<ApiContext>,
) -> Result<Response<Body>, Infallible>
```

3. Replace all `store`, `auth_token`, `start_time`, `pending_store`, `response_tx` references in `handle()` body with `ctx.store`, `ctx.auth_token`, `ctx.start_time`, `ctx.pending_store`, `ctx.response_tx`.

4. Update auth check: `if !ctx.auth_token.is_empty()` and compare with `ctx.auth_token.as_str()`.

5. Update `run_api_server()` to construct `Arc<ApiContext>`:
```rust
pub async fn run_api_server(
    bind: &str,
    port: u16,
    store: SharedAlertStore,
    auth_token: String,
    pending_store: SharedPendingActions,
    response_tx: Option<mpsc::Sender<ResponseRequest>>,
) -> anyhow::Result<()> {
    let addr: SocketAddr = format!("{}:{}", bind, port).parse()?;
    let ctx = Arc::new(ApiContext {
        store,
        start_time: Instant::now(),
        auth_token,
        pending_store,
        response_tx: response_tx.map(Arc::new),
        scan_results: None,
        audit_chain_path: None,
        policy_dir: None,
        barnacle_dir: None,
        active_profile: None,
    });

    let make_svc = make_service_fn(move |_conn| {
        let ctx = ctx.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                handle(req, ctx.clone())
            }))
        }
    });
    // ...
}
```

6. Add `run_api_server_with_context()` that takes `Arc<ApiContext>` directly (used by main.rs when wiring evidence fields):
```rust
pub async fn run_api_server_with_context(
    bind: &str,
    port: u16,
    ctx: Arc<ApiContext>,
) -> anyhow::Result<()> {
    let addr: SocketAddr = format!("{}:{}", bind, port).parse()?;
    let make_svc = make_service_fn(move |_conn| {
        let ctx = ctx.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                handle(req, ctx.clone())
            }))
        }
    });
    eprintln!("API server listening on {}", addr);
    Server::bind(&addr).serve(make_svc).await?;
    Ok(())
}
```

7. Update ALL existing tests. Each test currently constructs individual args — change to build `Arc<ApiContext>`. Create a test helper:
```rust
fn test_ctx(auth_token: &str) -> Arc<ApiContext> {
    Arc::new(ApiContext {
        store: new_shared_store(100),
        start_time: Instant::now(),
        auth_token: auth_token.to_string(),
        pending_store: Arc::new(Mutex::new(Vec::new())),
        response_tx: None,
        scan_results: None,
        audit_chain_path: None,
        policy_dir: None,
        barnacle_dir: None,
        active_profile: None,
    })
}
```

Then each test becomes:
```rust
// Before:
let store = new_shared_store(100);
let token = Arc::new("secret-token-123".to_string());
let pending: SharedPendingActions = Arc::new(Mutex::new(Vec::new()));
let resp = handle(req, store, Instant::now(), token, pending, None).await.unwrap();

// After:
let ctx = test_ctx("secret-token-123");
let resp = handle(req, ctx).await.unwrap();
```

For `test_ring_buffer_capacity` and `test_count_by_severity` which test `AlertRingBuffer` directly (not `handle()`), no changes needed.

For `test_status_includes_parity_counters` which needs a custom store:
```rust
fn test_ctx_with_store(auth_token: &str, store: SharedAlertStore) -> Arc<ApiContext> {
    Arc::new(ApiContext {
        store,
        start_time: Instant::now(),
        auth_token: auth_token.to_string(),
        pending_store: Arc::new(Mutex::new(Vec::new())),
        response_tx: None,
        scan_results: None,
        audit_chain_path: None,
        policy_dir: None,
        barnacle_dir: None,
        active_profile: None,
    })
}
```

**Step 4: Run tests**

Run: `~/.cargo/bin/cargo test api -- --nocapture`
Expected: All API tests PASS (same behavior, new structure)

**Step 5: Commit**

```bash
git add src/api.rs
git commit -m "refactor(api): extract ApiContext struct to consolidate handler parameters"
```

---

### Task 7: Add GET /api/evidence endpoint

**Files:**
- Modify: `src/api.rs` (new match arm in handle(), new response types)

**Context:**
With `ApiContext` in place, the evidence endpoint reads from `ctx.scan_results`, `ctx.audit_chain_path`, `ctx.policy_dir`, and `ctx.barnacle_dir`. It calls `compliance::generate_report()`, `AuditChain::verify()`, and assembles everything into a single JSON response.

**Step 1: Write the failing tests**

```rust
#[tokio::test]
async fn test_evidence_endpoint_returns_200() {
    let ctx = test_ctx("");
    let req = Request::builder()
        .uri("/api/evidence")
        .body(Body::empty())
        .unwrap();
    let resp = handle(req, ctx).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = hyper::body::to_bytes(resp.into_body()).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json.get("compliance_report").is_some());
    assert!(json.get("scanner_snapshot").is_some());
    assert!(json.get("audit_chain_proof").is_some());
    assert!(json.get("policy_versions").is_some());
    assert!(json.get("clawtower_version").is_some());
}

#[tokio::test]
async fn test_evidence_endpoint_accepts_framework_param() {
    let ctx = test_ctx("");
    let req = Request::builder()
        .uri("/api/evidence?framework=mitre-attack&period=7")
        .body(Body::empty())
        .unwrap();
    let resp = handle(req, ctx).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = hyper::body::to_bytes(resp.into_body()).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["compliance_report"]["framework"], "mitre-attack");
    assert_eq!(json["compliance_report"]["period_days"], 7);
}

#[tokio::test]
async fn test_evidence_endpoint_requires_auth() {
    let ctx = test_ctx("secret");
    let req = Request::builder()
        .uri("/api/evidence")
        .body(Body::empty())
        .unwrap();
    let resp = handle(req, ctx).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
```

**Step 2: Run tests to verify they fail**

Run: `~/.cargo/bin/cargo test test_evidence -- --nocapture`
Expected: FAIL — `/api/evidence` returns 404 (falls through to default match arm)

**Step 3: Implement**

1. Add response types:
```rust
#[derive(Serialize)]
struct EvidenceBundle {
    generated_at: String,
    clawtower_version: &'static str,
    compliance_report: crate::compliance::ComplianceReport,
    scanner_snapshot: Vec<ScannerSnapshotEntry>,
    audit_chain_proof: AuditChainProof,
    policy_versions: PolicyVersions,
}

#[derive(Serialize)]
struct ScannerSnapshotEntry {
    category: String,
    status: String,
    details: String,
    timestamp: String,
}

#[derive(Serialize)]
struct AuditChainProof {
    chain_file: Option<String>,
    total_entries: Option<u64>,
    integrity_verified: bool,
    verification_error: Option<String>,
}

#[derive(Serialize)]
struct PolicyVersions {
    policies: Vec<serde_json::Value>,
    ioc_databases: Vec<serde_json::Value>,
    active_profile: Option<String>,
}
```

2. Add URL query parameter parsing helper:
```rust
fn parse_query_params(uri: &hyper::Uri) -> std::collections::HashMap<String, String> {
    uri.query()
        .map(|q| {
            q.split('&')
                .filter_map(|pair| {
                    let mut parts = pair.splitn(2, '=');
                    Some((parts.next()?.to_string(), parts.next().unwrap_or("").to_string()))
                })
                .collect()
        })
        .unwrap_or_default()
}
```

3. Add match arm in `handle()` for `"/api/evidence"`:
```rust
path if path.starts_with("/api/evidence") => {
    let params = parse_query_params(req.uri());
    let framework = params.get("framework").map(|s| s.as_str()).unwrap_or("soc2");
    let period: u32 = params.get("period").and_then(|s| s.parse().ok()).unwrap_or(30);

    // Build alert summary from store
    let store = ctx.store.lock().await;
    let alert_summary: Vec<(String, String, u64)> = {
        let mut counts: std::collections::HashMap<(String, String), u64> = std::collections::HashMap::new();
        for alert in store.last_n(store.len()) {
            *counts.entry((alert.source.clone(), alert.severity.to_string())).or_insert(0) += 1;
        }
        counts.into_iter().map(|((s, sev), c)| (s, sev, c)).collect()
    };
    drop(store);

    // Build scanner snapshot
    let scanner_snapshot: Vec<ScannerSnapshotEntry> = if let Some(ref sr) = ctx.scan_results {
        let results = sr.lock().unwrap();
        results.iter().map(|r| ScannerSnapshotEntry {
            category: r.category.clone(),
            status: r.status.to_string(),
            details: r.details.clone(),
            timestamp: r.timestamp.to_rfc3339(),
        }).collect()
    } else {
        vec![]
    };

    let scanner_tuples: Vec<(String, String)> = scanner_snapshot.iter()
        .map(|s| (s.category.clone(), s.status.to_lowercase()))
        .collect();

    // Generate compliance report
    let report = crate::compliance::generate_report(framework, period, &alert_summary, &scanner_tuples);

    // Verify audit chain
    let audit_proof = if let Some(ref path) = ctx.audit_chain_path {
        match crate::audit_chain::AuditChain::verify(path) {
            Ok(count) => AuditChainProof {
                chain_file: Some(path.display().to_string()),
                total_entries: Some(count),
                integrity_verified: true,
                verification_error: None,
            },
            Err(e) => AuditChainProof {
                chain_file: Some(path.display().to_string()),
                total_entries: None,
                integrity_verified: false,
                verification_error: Some(e.to_string()),
            },
        }
    } else {
        AuditChainProof {
            chain_file: None,
            total_entries: None,
            integrity_verified: false,
            verification_error: Some("Audit chain path not configured".to_string()),
        }
    };

    // Policy versions (populated in Task 8 wiring — for now return empty)
    let policy_versions = PolicyVersions {
        policies: vec![],
        ioc_databases: vec![],
        active_profile: ctx.active_profile.clone(),
    };

    let bundle = EvidenceBundle {
        generated_at: chrono::Local::now().to_rfc3339(),
        clawtower_version: env!("CARGO_PKG_VERSION"),
        compliance_report: report,
        scanner_snapshot,
        audit_chain_proof: audit_proof,
        policy_versions,
    };

    json_response(StatusCode::OK, serde_json::to_string(&bundle).unwrap())
}
```

4. Add `use chrono;` import if not present, and add HTML link for evidence endpoint on the index page.

**Step 4: Run tests**

Run: `~/.cargo/bin/cargo test api -- --nocapture`
Expected: All API tests PASS

**Step 5: Commit**

```bash
git add src/api.rs
git commit -m "feat(api): add GET /api/evidence endpoint for enterprise evidence bundles"
```

---

### Task 8: Wire evidence context into ApiContext from main.rs

**Files:**
- Modify: `src/main.rs:981-994` (API server spawn block)
- Modify: `src/main.rs:1064-1072` (scanner spawn block — hoist scan_store)
- Modify: `src/api.rs:322-350` (update run_api_server to accept full context)

**Context:**
Currently in `main.rs`:
- `scan_store` is created inside a block scope (line 1067) and moved into the scanner task. It needs to be hoisted and cloned so the API can also read it.
- `run_api_server()` is called on line 990 with individual args. Switch to `run_api_server_with_context()` passing a fully wired `ApiContext`.

**Step 1: Write the failing test**

This is a wiring task — verified by integration. Add a doc comment to `run_api_server_with_context` describing the evidence fields.

**Step 2: Implement**

1. In `main.rs`, hoist `scan_store` before the API spawn block:
```rust
// Create shared scan results store (shared between scanner and API)
let scan_store = scanner::new_shared_scan_results();
```

2. Update scanner spawn block (line 1064-1072) to use the hoisted `scan_store`:
```rust
{
    let tx = raw_tx.clone();
    let scan_store = scan_store.clone();
    let interval = config.scans.interval;
    // ...
}
```

3. Update API spawn block (line 982-994) to construct `ApiContext`:
```rust
if config.api.enabled {
    let ctx = Arc::new(api::ApiContext {
        store: alert_store.clone(),
        start_time: std::time::Instant::now(),
        auth_token: config.api.auth_token.clone(),
        pending_store: pending_store.clone(),
        response_tx: response_tx.clone().map(Arc::new),
        scan_results: Some(scan_store.clone()),
        audit_chain_path: Some(PathBuf::from(&config.general.audit_chain_path)),
        policy_dir: Some(PathBuf::from(&config.policy.policy_dir)),
        barnacle_dir: Some(PathBuf::from(&config.barnacle.config_dir)),
        active_profile: profile_name.clone(),
    });
    let bind = config.api.bind.clone();
    let port = config.api.port;
    tokio::spawn(async move {
        if let Err(e) = api::run_api_server_with_context(&bind, port, ctx).await {
            eprintln!("API server error: {}", e);
        }
    });
}
```

4. Check that `config.general.audit_chain_path` exists (it may be `config.general.audit_log` or similar — look up the actual field name and use it). If the field doesn't exist, use the default path `/var/log/clawtower/audit.chain`.

5. Check that `config.policy.policy_dir` exists. If it's `config.policy.dirs` (a Vec), use the first entry or a sensible default.

6. Check that `config.barnacle.config_dir` exists. If it's named differently (e.g., `vendor_dir`), use the correct field name.

**Step 3: Run full test suite**

Run: `~/.cargo/bin/cargo test -- --nocapture`
Expected: All tests PASS

**Step 4: Run build check**

Run: `~/.cargo/bin/cargo build 2>&1 | head -30`
Expected: Compiles without errors

**Step 5: Commit**

```bash
git add src/main.rs src/api.rs
git commit -m "feat(api): wire evidence context (scan results, audit chain, policy paths) into API server"
```

---

## Verification

After all tasks complete:

1. **Unit tests**: `~/.cargo/bin/cargo test` — all tests pass
2. **Build**: `~/.cargo/bin/cargo build` — compiles cleanly
3. **Key behaviors to verify**:
   - `generate_report("mitre-attack", ...)` produces a report with ATT&CK technique IDs as findings
   - `lookup_mitre_technique("T1048")` returns correct technique metadata
   - Supply-chain categories (`behavior:social_engineering`, `barnacle:supply_chain`, `sentinel:skill_intake`) have control mappings
   - `PolicyEngine::load()` populates `file_info()` with filenames, SHA-256 hashes, and rule counts
   - `BarnacleDefenseEngine::load()` populates `db_info()` with filenames, versions, and SHA-256 hashes
   - `GET /api/evidence` returns a JSON bundle with compliance report, scanner snapshot, audit chain proof, and policy versions
   - Evidence endpoint respects bearer auth when configured
   - Evidence endpoint accepts `?framework=mitre-attack&period=7` parameters
