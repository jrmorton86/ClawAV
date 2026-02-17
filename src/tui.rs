//! Terminal User Interface (TUI) dashboard.
//!
//! Provides a tabbed dashboard using ratatui/crossterm with panels for:
//! - **Alerts**: Real-time alert feed with color-coded severity
//! - **Network**: Filtered network activity alerts
//! - **Falco**: Filtered Falco eBPF alerts
//! - **FIM**: Filtered Samhain file integrity alerts
//! - **System**: Status summary with alert counts
//! - **Config**: Interactive config editor with section sidebar
//!
//! The config editor supports in-place editing of all config fields, bool toggling,
//! sudo-authenticated saves (chattr dance), and action buttons for installing
//! optional tools (Falco, Samhain).

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Tabs},
};
use zeroize::Zeroize;
use std::collections::HashMap;
use std::io;
use tokio::sync::mpsc;
use std::time::Duration;
use std::path::PathBuf;

use crate::alerts::{Alert, AlertStore, Severity};
use crate::config::Config;

#[allow(dead_code)]
pub enum TuiEvent {
    Alert(Alert),
    Tick,
    Quit,
}

/// A single editable field in the config editor panel.
#[derive(Clone)]
#[allow(dead_code)]
pub struct ConfigField {
    pub name: String,
    pub value: String,
    pub section: String,
    pub field_type: FieldType,
}

/// Which panel has keyboard focus in the config editor tab.
#[derive(Clone)]
#[derive(PartialEq)]
pub enum ConfigFocus {
    /// Section sidebar: Up/Down navigates, Enter enters fields.
    Sidebar,
    /// Field list: Up/Down navigates, Enter edits, Backspace returns to sidebar.
    Fields,
}

/// Type of a config field, controlling how it's edited (text input, toggle, number, or action button).
#[derive(Clone)]
pub enum FieldType {
    /// Free-form text input.
    Text,
    /// Boolean toggle (Enter flips value).
    Bool,
    /// Numeric input.
    Number,
    /// Action button — Enter runs the associated command string.
    Action(String),
}

/// Main TUI application state.
///
/// Holds the alert store, tab selection, config editor state, and sudo popup state.
/// Updated by `on_key()` handlers and rendered by the `ui()` function.
pub struct App {
    pub alert_store: AlertStore,
    pub selected_tab: usize,
    pub should_quit: bool,
    pub tab_titles: Vec<String>,
    // Config editor state
    pub config: Option<Config>,
    pub config_path: Option<PathBuf>,
    pub config_sections: Vec<String>,
    pub config_selected_section: usize,
    pub config_fields: Vec<ConfigField>,
    pub config_selected_field: usize,
    pub config_focus: ConfigFocus,
    pub config_editing: bool,
    pub config_edit_buffer: String,
    pub config_saved_message: Option<String>,
    // Sudo popup state
    pub sudo_popup: Option<SudoPopup>,
    // Scroll state per tab (tab index -> ListState)
    pub list_states: [ListState; 5], // tabs 0-4 (alerts, network, falco, fim, system)
    // Alert detail view
    pub detail_alert: Option<Alert>,
    // Search/filter
    pub search_active: bool,
    pub search_buffer: String,
    pub search_filter: String, // committed search (applied on Enter)
    // Pause alert feed
    pub paused: bool,
    // Cached tool installation status
    pub tool_status_cache: HashMap<String, bool>,
    // Muted sources (alerts from these sources are hidden)
    pub muted_sources: Vec<String>,
}

/// State for the modal sudo password prompt overlay.
pub struct SudoPopup {
    /// Action to run after successful authentication.
    pub action: String,
    /// Password being typed (shown as dots).
    pub password: String,
    /// Human-readable description of the pending action.
    pub message: String,
    /// Current progress state.
    pub status: SudoStatus,
}

/// Progress state of a sudo authentication attempt.
pub enum SudoStatus {
    /// Waiting for user to type password.
    WaitingForPassword,
    /// Command is executing.
    Running,
    /// Authentication or command failed with an error message.
    Failed(String),
}

impl App {
    /// Create a new TUI application with default state.
    pub fn new() -> Self {
        Self {
            alert_store: AlertStore::new(500),
            selected_tab: 0,
            should_quit: false,
            tab_titles: vec![
                "Alerts".into(),
                "Network".into(),
                "Falco".into(),
                "FIM".into(),
                "System".into(),
                "Config".into(),
            ],
            config: None,
            config_path: None,
            config_sections: vec![
                "general".into(), "slack".into(), "auditd".into(), "network".into(), 
                "falco".into(), "samhain".into(), "api".into(), "scans".into(), 
                "proxy".into(), "policy".into(), "secureclaw".into(), "netpolicy".into(),
            ],
            config_selected_section: 0,
            config_fields: Vec::new(),
            config_selected_field: 0,
            config_focus: ConfigFocus::Sidebar,
            config_editing: false,
            config_edit_buffer: String::new(),
            config_saved_message: None,
            sudo_popup: None,
            list_states: std::array::from_fn(|_| {
                let mut s = ListState::default();
                s.select(Some(0));
                s
            }),
            detail_alert: None,
            search_active: false,
            search_buffer: String::new(),
            search_filter: String::new(),
            paused: false,
            tool_status_cache: HashMap::new(),
            muted_sources: Vec::new(),
        }
    }

    /// Load configuration from a file and populate the editor fields.
    pub fn load_config(&mut self, path: &PathBuf) -> Result<()> {
        let config = Config::load(path)?;
        self.config = Some(config);
        self.config_path = Some(path.clone());
        self.refresh_fields();
        Ok(())
    }

    /// Rebuild the field list for the currently selected config section.
    pub fn refresh_fields(&mut self) {
        if let Some(ref config) = self.config {
            let section = &self.config_sections[self.config_selected_section];
            self.config_fields = get_section_fields(config, section);
            // Reset field selection if necessary
            if self.config_selected_field >= self.config_fields.len() && !self.config_fields.is_empty() {
                self.config_selected_field = 0;
            }
        }
    }

    /// Check and cache whether a tool is installed (runs `which` once per tool).
    pub fn is_tool_installed(&mut self, tool: &str) -> bool {
        if let Some(&cached) = self.tool_status_cache.get(tool) {
            return cached;
        }
        let installed = std::process::Command::new("which")
            .arg(tool)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        self.tool_status_cache.insert(tool.to_string(), installed);
        installed
    }

    /// Invalidate cached tool status (e.g., after installing).
    pub fn invalidate_tool_cache(&mut self) {
        self.tool_status_cache.clear();
    }

    /// Handle a keyboard event, dispatching to the appropriate tab/panel handler.
    pub fn on_key(&mut self, key: KeyCode, modifiers: KeyModifiers) {
        // Handle sudo popup if active
        if let Some(ref mut popup) = self.sudo_popup {
            match &popup.status {
                SudoStatus::WaitingForPassword => {
                    match key {
                        KeyCode::Esc => { self.sudo_popup = None; return; }
                        KeyCode::Enter => {
                            let password = popup.password.clone();
                            let action = popup.action.clone();
                            popup.status = SudoStatus::Running;
                            self.run_sudo_action(&action, &password);
                            return;
                        }
                        KeyCode::Backspace => { popup.password.pop(); return; }
                        KeyCode::Char(c) => { popup.password.push(c); return; }
                        _ => return,
                    }
                }
                SudoStatus::Running => return,
                SudoStatus::Failed(_) => {
                    // Any key dismisses
                    self.sudo_popup = None;
                    return;
                }
            }
        }

        // Clear saved message on any keypress
        if self.config_saved_message.is_some() {
            self.config_saved_message = None;
        }

        match key {
            KeyCode::Char('q') | KeyCode::Esc if !self.config_editing => self.should_quit = true,
            // Config tab: Left/Right navigate sections, only Tab/BackTab switch tabs
            KeyCode::Tab if !self.config_editing => {
                self.selected_tab = (self.selected_tab + 1) % self.tab_titles.len();
            }
            KeyCode::BackTab if !self.config_editing => {
                if self.selected_tab > 0 {
                    self.selected_tab -= 1;
                } else {
                    self.selected_tab = self.tab_titles.len() - 1;
                }
            }
            KeyCode::Right if !self.config_editing && !(self.selected_tab == 5 && self.config_focus == ConfigFocus::Fields) => {
                self.selected_tab = (self.selected_tab + 1) % self.tab_titles.len();
                if self.selected_tab == 5 { self.config_focus = ConfigFocus::Sidebar; }
            }
            KeyCode::Left if !self.config_editing && !(self.selected_tab == 5 && self.config_focus == ConfigFocus::Fields) => {
                if self.selected_tab > 0 {
                    self.selected_tab -= 1;
                } else {
                    self.selected_tab = self.tab_titles.len() - 1;
                }
                if self.selected_tab == 5 { self.config_focus = ConfigFocus::Sidebar; }
            }
            // Config tab specific keys (including Left/Right for section nav)
            _ if self.selected_tab == 5 => self.handle_config_key(key, modifiers),
            _ => {}
        }
    }

    fn handle_config_key(&mut self, key: KeyCode, modifiers: KeyModifiers) {
        if self.config_editing {
            // Handle editing mode
            match key {
                KeyCode::Enter => {
                    // Confirm edit
                    if let Some(ref mut config) = self.config {
                        let section = &self.config_sections[self.config_selected_section];
                        let field = &self.config_fields[self.config_selected_field];
                        apply_field_to_config(config, section, &field.name, &self.config_edit_buffer);
                        self.refresh_fields();
                    }
                    self.config_editing = false;
                    self.config_edit_buffer.clear();
                }
                KeyCode::Esc => {
                    // Cancel edit
                    self.config_editing = false;
                    self.config_edit_buffer.clear();
                }
                KeyCode::Backspace => {
                    self.config_edit_buffer.pop();
                }
                KeyCode::Char(c) => {
                    self.config_edit_buffer.push(c);
                }
                _ => {}
            }
        } else {
            // Ctrl+S save always available
            if key == KeyCode::Char('s') && modifiers == KeyModifiers::CONTROL {
                if let (Some(ref config), Some(ref path)) = (&self.config, &self.config_path) {
                    if config.save(path).is_ok() {
                        self.config_saved_message = Some("Saved!".to_string());
                    } else if nix_is_root() {
                        self.config_saved_message = Some("Save failed!".to_string());
                    } else {
                        let path_str = path.display().to_string();
                        self.sudo_popup = Some(SudoPopup {
                            action: format!("save_config:{}", path_str),
                            password: String::new(),
                            message: format!("Save config to {}", path_str),
                            status: SudoStatus::WaitingForPassword,
                        });
                        let _ = config.save(&PathBuf::from("/tmp/clawtower-config-save.toml"));
                    }
                }
                return;
            }

            match self.config_focus {
                ConfigFocus::Sidebar => {
                    // Sidebar: Up/Down = sections, Enter = go into fields
                    // Left/Right = switch tabs (handled by parent on_key)
                    match key {
                        KeyCode::Up => {
                            if self.config_selected_section > 0 {
                                self.config_selected_section -= 1;
                                self.config_selected_field = 0;
                                self.refresh_fields();
                            }
                        }
                        KeyCode::Down => {
                            if self.config_selected_section < self.config_sections.len() - 1 {
                                self.config_selected_section += 1;
                                self.config_selected_field = 0;
                                self.refresh_fields();
                            }
                        }
                        KeyCode::Enter => {
                            // Enter the fields panel
                            if !self.config_fields.is_empty() {
                                self.config_focus = ConfigFocus::Fields;
                                self.config_selected_field = 0;
                            }
                        }
                        _ => {}
                    }
                }
                ConfigFocus::Fields => {
                    // Fields: Up/Down = fields, Enter = edit, Backspace = back to sidebar
                    match key {
                        KeyCode::Backspace | KeyCode::Esc => {
                            self.config_focus = ConfigFocus::Sidebar;
                        }
                        KeyCode::Up => {
                            if self.config_selected_field > 0 {
                                self.config_selected_field -= 1;
                            }
                        }
                        KeyCode::Down => {
                            if self.config_selected_field < self.config_fields.len().saturating_sub(1) {
                                self.config_selected_field += 1;
                            }
                        }
                        KeyCode::Enter => {
                            if !self.config_fields.is_empty() {
                                let field = &self.config_fields[self.config_selected_field];
                                match &field.field_type {
                                    FieldType::Bool => {
                                        if let Some(ref mut config) = self.config {
                                            let section = &self.config_sections[self.config_selected_section];
                                            let new_value = if field.value == "true" { "false" } else { "true" };
                                            apply_field_to_config(config, section, &field.name, new_value);
                                            self.refresh_fields();
                                        }
                                    }
                                    FieldType::Action(action) => {
                                        let action = action.clone();
                                        self.run_action(&action);
                                    }
                                    _ => {
                                        self.config_editing = true;
                                        self.config_edit_buffer = field.value.clone();
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    fn run_action(&mut self, action: &str) {
        let needs_sudo = !nix_is_root();
        let description = match action {
            "install_falco" => "Install Falco (apt-get install falco)",
            "install_samhain" => "Install Samhain (apt-get install samhain)",
            _ => return,
        };

        if needs_sudo {
            self.sudo_popup = Some(SudoPopup {
                action: action.to_string(),
                password: String::new(),
                message: description.to_string(),
                status: SudoStatus::WaitingForPassword,
            });
        } else {
            self.run_sudo_action(action, "");
        }
    }

    fn run_sudo_action(&mut self, action: &str, password: &str) {
        let shell_cmd: String = if action.starts_with("save_config:") {
            let path = &action["save_config:".len()..];
            format!(
                "chattr -i '{}' 2>/dev/null; cp /tmp/clawtower-config-save.toml '{}' && chattr +i '{}' && rm -f /tmp/clawtower-config-save.toml && echo 'CONFIG_SAVED'",
                path, path, path
            )
        } else {
            match action {
                "install_falco" => "apt-get update -qq && apt-get install -y -qq falco 2>&1 || dnf install -y falco 2>&1 || echo 'INSTALL_FAILED'".to_string(),
                "install_samhain" => "apt-get update -qq && apt-get install -y -qq samhain 2>&1 || dnf install -y samhain 2>&1 || echo 'INSTALL_FAILED'".to_string(),
                _ => return,
            }
        };
        let shell_cmd = shell_cmd.as_str();

        let result = if nix_is_root() || password.is_empty() {
            std::process::Command::new("bash")
                .args(["-c", shell_cmd])
                .output()
        } else {
            // Pipe password to sudo -S
            use std::io::Write;
            let mut child = match std::process::Command::new("sudo")
                .args(["-S", "bash", "-c", shell_cmd])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn() {
                    Ok(c) => c,
                    Err(e) => {
                        self.sudo_popup = Some(SudoPopup {
                            action: action.to_string(),
                            password: String::new(),
                            message: String::new(),
                            status: SudoStatus::Failed(format!("Failed to spawn sudo: {}", e)),
                        });
                        return;
                    }
                };
            if let Some(ref mut stdin) = child.stdin {
                let _ = writeln!(stdin, "{}", password);
            }
            child.wait_with_output()
        };

        self.sudo_popup = None;

        match result {
            Ok(output) => {
                let out = String::from_utf8_lossy(&output.stdout);
                let err = String::from_utf8_lossy(&output.stderr);
                if out.contains("CONFIG_SAVED") {
                    self.config_saved_message = Some("✅ Saved!".to_string());
                } else if output.status.success() && !out.contains("INSTALL_FAILED") {
                    self.config_saved_message = Some("✅ Installed! Refresh with Left/Right.".to_string());
                } else if err.contains("incorrect password") || err.contains("Sorry, try again") {
                    self.config_saved_message = Some("❌ Wrong password".to_string());
                } else {
                    self.config_saved_message = Some(format!("❌ Install failed: {}", err.chars().take(80).collect::<String>()));
                }
            }
            Err(e) => {
                self.config_saved_message = Some(format!("❌ {}", e));
            }
        }
        self.refresh_fields();
    }
}

fn nix_is_root() -> bool {
    unsafe { libc::getuid() == 0 }
}

fn get_section_fields(config: &Config, section: &str) -> Vec<ConfigField> {
    match section {
        "general" => vec![
            ConfigField {
                name: "watched_user".to_string(),
                value: config.general.watched_user.clone().unwrap_or_default(),
                section: section.to_string(),
                field_type: FieldType::Text,
            },
            ConfigField {
                name: "watched_users".to_string(),
                value: config.general.watched_users.join(","),
                section: section.to_string(),
                field_type: FieldType::Text,
            },
            ConfigField {
                name: "watch_all_users".to_string(),
                value: config.general.watch_all_users.to_string(),
                section: section.to_string(),
                field_type: FieldType::Bool,
            },
            ConfigField {
                name: "min_alert_level".to_string(),
                value: config.general.min_alert_level.clone(),
                section: section.to_string(),
                field_type: FieldType::Text,
            },
            ConfigField {
                name: "log_file".to_string(),
                value: config.general.log_file.clone(),
                section: section.to_string(),
                field_type: FieldType::Text,
            },
        ],
        "slack" => vec![
            ConfigField {
                name: "enabled".to_string(),
                value: config.slack.enabled.unwrap_or(false).to_string(),
                section: section.to_string(),
                field_type: FieldType::Bool,
            },
            ConfigField {
                name: "webhook_url".to_string(),
                value: config.slack.webhook_url.clone(),
                section: section.to_string(),
                field_type: FieldType::Text,
            },
            ConfigField {
                name: "backup_webhook_url".to_string(),
                value: config.slack.backup_webhook_url.clone(),
                section: section.to_string(),
                field_type: FieldType::Text,
            },
            ConfigField {
                name: "channel".to_string(),
                value: config.slack.channel.clone(),
                section: section.to_string(),
                field_type: FieldType::Text,
            },
            ConfigField {
                name: "min_slack_level".to_string(),
                value: config.slack.min_slack_level.clone(),
                section: section.to_string(),
                field_type: FieldType::Text,
            },
        ],
        "auditd" => vec![
            ConfigField {
                name: "enabled".to_string(),
                value: config.auditd.enabled.to_string(),
                section: section.to_string(),
                field_type: FieldType::Bool,
            },
            ConfigField {
                name: "log_path".to_string(),
                value: config.auditd.log_path.clone(),
                section: section.to_string(),
                field_type: FieldType::Text,
            },
        ],
        "network" => vec![
            ConfigField {
                name: "enabled".to_string(),
                value: config.network.enabled.to_string(),
                section: section.to_string(),
                field_type: FieldType::Bool,
            },
            ConfigField {
                name: "log_path".to_string(),
                value: config.network.log_path.clone(),
                section: section.to_string(),
                field_type: FieldType::Text,
            },
            ConfigField {
                name: "log_prefix".to_string(),
                value: config.network.log_prefix.clone(),
                section: section.to_string(),
                field_type: FieldType::Text,
            },
            ConfigField {
                name: "source".to_string(),
                value: config.network.source.clone(),
                section: section.to_string(),
                field_type: FieldType::Text,
            },
        ],
        "falco" => {
            let falco_installed = std::process::Command::new("which")
                .arg("falco")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            let mut fields = vec![
                ConfigField {
                    name: "enabled".to_string(),
                    value: config.falco.enabled.to_string(),
                    section: section.to_string(),
                    field_type: FieldType::Bool,
                },
                ConfigField {
                    name: "log_path".to_string(),
                    value: config.falco.log_path.clone(),
                    section: section.to_string(),
                    field_type: FieldType::Text,
                },
                ConfigField {
                    name: "status".to_string(),
                    value: if falco_installed { "✅ installed".to_string() } else { "❌ not installed".to_string() },
                    section: section.to_string(),
                    field_type: FieldType::Text,
                },
            ];
            if !falco_installed {
                fields.push(ConfigField {
                    name: "▶ Install Falco".to_string(),
                    value: "Press Enter to install".to_string(),
                    section: section.to_string(),
                    field_type: FieldType::Action("install_falco".to_string()),
                });
            }
            fields
        },
        "samhain" => {
            let samhain_installed = std::process::Command::new("which")
                .arg("samhain")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            let mut fields = vec![
                ConfigField {
                    name: "enabled".to_string(),
                    value: config.samhain.enabled.to_string(),
                    section: section.to_string(),
                    field_type: FieldType::Bool,
                },
                ConfigField {
                    name: "log_path".to_string(),
                    value: config.samhain.log_path.clone(),
                    section: section.to_string(),
                    field_type: FieldType::Text,
                },
                ConfigField {
                    name: "status".to_string(),
                    value: if samhain_installed { "✅ installed".to_string() } else { "❌ not installed".to_string() },
                    section: section.to_string(),
                    field_type: FieldType::Text,
                },
            ];
            if !samhain_installed {
                fields.push(ConfigField {
                    name: "▶ Install Samhain".to_string(),
                    value: "Press Enter to install".to_string(),
                    section: section.to_string(),
                    field_type: FieldType::Action("install_samhain".to_string()),
                });
            }
            fields
        },
        "api" => vec![
            ConfigField {
                name: "enabled".to_string(),
                value: config.api.enabled.to_string(),
                section: section.to_string(),
                field_type: FieldType::Bool,
            },
            ConfigField {
                name: "bind".to_string(),
                value: config.api.bind.clone(),
                section: section.to_string(),
                field_type: FieldType::Text,
            },
            ConfigField {
                name: "port".to_string(),
                value: config.api.port.to_string(),
                section: section.to_string(),
                field_type: FieldType::Number,
            },
        ],
        "scans" => vec![
            ConfigField {
                name: "interval".to_string(),
                value: config.scans.interval.to_string(),
                section: section.to_string(),
                field_type: FieldType::Number,
            },
        ],
        "proxy" => vec![
            ConfigField {
                name: "enabled".to_string(),
                value: config.proxy.enabled.to_string(),
                section: section.to_string(),
                field_type: FieldType::Bool,
            },
            ConfigField {
                name: "bind".to_string(),
                value: config.proxy.bind.clone(),
                section: section.to_string(),
                field_type: FieldType::Text,
            },
            ConfigField {
                name: "port".to_string(),
                value: config.proxy.port.to_string(),
                section: section.to_string(),
                field_type: FieldType::Number,
            },
        ],
        "policy" => vec![
            ConfigField {
                name: "enabled".to_string(),
                value: config.policy.enabled.to_string(),
                section: section.to_string(),
                field_type: FieldType::Bool,
            },
            ConfigField {
                name: "dir".to_string(),
                value: config.policy.dir.clone(),
                section: section.to_string(),
                field_type: FieldType::Text,
            },
        ],
        "secureclaw" => vec![
            ConfigField {
                name: "enabled".to_string(),
                value: config.secureclaw.enabled.to_string(),
                section: section.to_string(),
                field_type: FieldType::Bool,
            },
            ConfigField {
                name: "vendor_dir".to_string(),
                value: config.secureclaw.vendor_dir.clone(),
                section: section.to_string(),
                field_type: FieldType::Text,
            },
        ],
        "netpolicy" => vec![
            ConfigField {
                name: "enabled".to_string(),
                value: config.netpolicy.enabled.to_string(),
                section: section.to_string(),
                field_type: FieldType::Bool,
            },
            ConfigField {
                name: "mode".to_string(),
                value: config.netpolicy.mode.clone(),
                section: section.to_string(),
                field_type: FieldType::Text,
            },
            ConfigField {
                name: "allowed_ports".to_string(),
                value: config.netpolicy.allowed_ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(","),
                section: section.to_string(),
                field_type: FieldType::Text,
            },
        ],
        _ => Vec::new(),
    }
}

fn apply_field_to_config(config: &mut Config, section: &str, field_name: &str, value: &str) {
    match section {
        "general" => match field_name {
            "watched_user" => config.general.watched_user = if value.is_empty() { None } else { Some(value.to_string()) },
            "watched_users" => config.general.watched_users = value.split(',').filter(|s| !s.trim().is_empty()).map(|s| s.trim().to_string()).collect(),
            "watch_all_users" => config.general.watch_all_users = value == "true",
            "min_alert_level" => config.general.min_alert_level = value.to_string(),
            "log_file" => config.general.log_file = value.to_string(),
            _ => {}
        },
        "slack" => match field_name {
            "enabled" => config.slack.enabled = Some(value == "true"),
            "webhook_url" => config.slack.webhook_url = value.to_string(),
            "backup_webhook_url" => config.slack.backup_webhook_url = value.to_string(),
            "channel" => config.slack.channel = value.to_string(),
            "min_slack_level" => config.slack.min_slack_level = value.to_string(),
            _ => {}
        },
        "auditd" => match field_name {
            "enabled" => config.auditd.enabled = value == "true",
            "log_path" => config.auditd.log_path = value.to_string(),
            _ => {}
        },
        "network" => match field_name {
            "enabled" => config.network.enabled = value == "true",
            "log_path" => config.network.log_path = value.to_string(),
            "log_prefix" => config.network.log_prefix = value.to_string(),
            "source" => config.network.source = value.to_string(),
            _ => {}
        },
        "falco" => match field_name {
            "enabled" => config.falco.enabled = value == "true",
            "log_path" => config.falco.log_path = value.to_string(),
            _ => {}
        },
        "samhain" => match field_name {
            "enabled" => config.samhain.enabled = value == "true",
            "log_path" => config.samhain.log_path = value.to_string(),
            _ => {}
        },
        "api" => match field_name {
            "enabled" => config.api.enabled = value == "true",
            "bind" => config.api.bind = value.to_string(),
            "port" => if let Ok(port) = value.parse::<u16>() { config.api.port = port; },
            _ => {}
        },
        "scans" => match field_name {
            "interval" => if let Ok(interval) = value.parse::<u64>() { config.scans.interval = interval; },
            _ => {}
        },
        "proxy" => match field_name {
            "enabled" => config.proxy.enabled = value == "true",
            "bind" => config.proxy.bind = value.to_string(),
            "port" => if let Ok(port) = value.parse::<u16>() { config.proxy.port = port; },
            _ => {}
        },
        "policy" => match field_name {
            "enabled" => config.policy.enabled = value == "true",
            "dir" => config.policy.dir = value.to_string(),
            _ => {}
        },
        "secureclaw" => match field_name {
            "enabled" => config.secureclaw.enabled = value == "true",
            "vendor_dir" => config.secureclaw.vendor_dir = value.to_string(),
            _ => {}
        },
        "netpolicy" => match field_name {
            "enabled" => config.netpolicy.enabled = value == "true",
            "mode" => config.netpolicy.mode = value.to_string(),
            "allowed_ports" => {
                config.netpolicy.allowed_ports = value
                    .split(',')
                    .filter_map(|s| s.trim().parse::<u16>().ok())
                    .collect();
            },
            _ => {}
        },
        _ => {}
    }
}

fn render_alerts_tab(f: &mut Frame, area: Rect, app: &App) {
    let items: Vec<ListItem> = app
        .alert_store
        .alerts()
        .iter()
        .rev()
        .map(|alert| {
            let style = match alert.severity {
                Severity::Critical => Style::default().fg(Color::Red).bold(),
                Severity::Warning => Style::default().fg(Color::Yellow),
                Severity::Info => Style::default().fg(Color::Gray),
            };
            ListItem::new(alert.to_string()).style(style)
        })
        .collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" Alert Feed "));
    f.render_widget(list, area);
}

fn render_network_tab(f: &mut Frame, area: Rect, app: &App) {
    let network_alerts: Vec<ListItem> = app
        .alert_store
        .alerts()
        .iter()
        .rev()
        .filter(|a| a.source == "network")
        .map(|alert| {
            let style = match alert.severity {
                Severity::Critical => Style::default().fg(Color::Red).bold(),
                Severity::Warning => Style::default().fg(Color::Yellow),
                Severity::Info => Style::default().fg(Color::Gray),
            };
            ListItem::new(alert.to_string()).style(style)
        })
        .collect();

    let list = List::new(network_alerts)
        .block(Block::default().borders(Borders::ALL).title(" Network Activity "));
    f.render_widget(list, area);
}

fn render_falco_tab(f: &mut Frame, area: Rect, app: &App) {
    let falco_alerts: Vec<ListItem> = app
        .alert_store
        .alerts()
        .iter()
        .rev()
        .filter(|a| a.source == "falco")
        .map(|alert| {
            let style = match alert.severity {
                Severity::Critical => Style::default().fg(Color::Red).bold(),
                Severity::Warning => Style::default().fg(Color::Yellow),
                Severity::Info => Style::default().fg(Color::Gray),
            };
            ListItem::new(alert.to_string()).style(style)
        })
        .collect();

    let list = List::new(falco_alerts)
        .block(Block::default().borders(Borders::ALL).title(" Falco eBPF Alerts "));
    f.render_widget(list, area);
}

fn render_fim_tab(f: &mut Frame, area: Rect, app: &App) {
    let fim_alerts: Vec<ListItem> = app
        .alert_store
        .alerts()
        .iter()
        .rev()
        .filter(|a| a.source == "samhain")
        .map(|alert| {
            let style = match alert.severity {
                Severity::Critical => Style::default().fg(Color::Red).bold(),
                Severity::Warning => Style::default().fg(Color::Yellow),
                Severity::Info => Style::default().fg(Color::Gray),
            };
            ListItem::new(alert.to_string()).style(style)
        })
        .collect();

    let list = List::new(fim_alerts)
        .block(Block::default().borders(Borders::ALL).title(" File Integrity (Samhain) "));
    f.render_widget(list, area);
}

fn render_system_tab(f: &mut Frame, area: Rect, app: &App) {
    let info_count = app.alert_store.count_by_severity(&Severity::Info);
    let warn_count = app.alert_store.count_by_severity(&Severity::Warning);
    let crit_count = app.alert_store.count_by_severity(&Severity::Critical);

    let text = vec![
        Line::from(vec![
            Span::styled(format!("ClawTower v{}", env!("CARGO_PKG_VERSION")), Style::default().fg(Color::Cyan).bold()),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::raw("Status: "),
            Span::styled("ACTIVE", Style::default().fg(Color::Green).bold()),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(format!("  ℹ️  Info:     {}", info_count), Style::default().fg(Color::Gray)),
        ]),
        Line::from(vec![
            Span::styled(format!("  ⚠️  Warnings: {}", warn_count), Style::default().fg(Color::Yellow)),
        ]),
        Line::from(vec![
            Span::styled(format!("  🔴 Critical: {}", crit_count), Style::default().fg(Color::Red)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::raw("Press "),
            Span::styled("Tab", Style::default().fg(Color::Cyan)),
            Span::raw(" to switch panels, "),
            Span::styled("q", Style::default().fg(Color::Cyan)),
            Span::raw(" to quit"),
        ]),
    ];

    let paragraph = Paragraph::new(text)
        .block(Block::default().borders(Borders::ALL).title(" System Status "));
    f.render_widget(paragraph, area);
}

fn render_config_tab(f: &mut Frame, area: Rect, app: &App) {
    if app.config.is_none() {
        let text = vec![
            Line::from(vec![
                Span::styled("No config loaded", Style::default().fg(Color::Red).bold()),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::raw("Config file path not provided or failed to load."),
            ]),
        ];
        let paragraph = Paragraph::new(text)
            .block(Block::default().borders(Borders::ALL).title(" Config Editor "));
        f.render_widget(paragraph, area);
        return;
    }

    // Split into left (sections list, 25%) and right (fields, 75%)
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(25), Constraint::Percentage(75)])
        .split(area);

    let sidebar_focused = app.config_focus == ConfigFocus::Sidebar;
    let fields_focused = app.config_focus == ConfigFocus::Fields;

    // Left: section list
    let section_items: Vec<ListItem> = app.config_sections.iter().enumerate().map(|(i, s)| {
        let style = if i == app.config_selected_section {
            if sidebar_focused {
                Style::default().fg(Color::Cyan).bold().add_modifier(Modifier::REVERSED)
            } else {
                Style::default().fg(Color::Cyan).bold()
            }
        } else {
            Style::default().fg(Color::DarkGray)
        };
        ListItem::new(format!("  {}", s)).style(style)
    }).collect();

    let sidebar_border = if sidebar_focused { Color::Cyan } else { Color::DarkGray };
    let sidebar_title = if sidebar_focused { " Sections (↑↓ Enter) " } else { " Sections " };
    let sections_list = List::new(section_items)
        .block(Block::default().borders(Borders::ALL)
            .border_style(Style::default().fg(sidebar_border))
            .title(sidebar_title));
    f.render_widget(sections_list, chunks[0]);

    // Right: fields for selected section
    let field_items: Vec<ListItem> = app.config_fields.iter().enumerate().map(|(i, field)| {
        let is_selected = i == app.config_selected_field && fields_focused;
        let is_editing = is_selected && app.config_editing;

        let value_display = if is_editing {
            format!("{}▌", app.config_edit_buffer)
        } else {
            field.value.clone()
        };

        let style = if is_selected {
            Style::default().fg(Color::Cyan).add_modifier(Modifier::REVERSED)
        } else if fields_focused {
            Style::default().fg(Color::White)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        ListItem::new(format!("  {}: {}", field.name, value_display)).style(style)
    }).collect();

    let fields_border = if fields_focused { Color::Cyan } else { Color::DarkGray };
    let title = if let Some(ref msg) = app.config_saved_message {
        format!(" {} — {} ", app.config_sections[app.config_selected_section], msg)
    } else if fields_focused {
        format!(" [{}] — Enter to edit, Backspace to go back, Ctrl+S save ", app.config_sections[app.config_selected_section])
    } else {
        format!(" [{}] ", app.config_sections[app.config_selected_section])
    };

    let fields_list = List::new(field_items)
        .block(Block::default().borders(Borders::ALL)
            .border_style(Style::default().fg(fields_border))
            .title(title));
    f.render_widget(fields_list, chunks[1]);
}

fn ui(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(f.area());

    // Tab bar
    let titles: Vec<Line> = app.tab_titles.iter().map(|t| Line::from(t.as_str())).collect();
    let tabs = Tabs::new(titles)
        .block(Block::default().borders(Borders::ALL).title(" 🛡️ ClawTower "))
        .select(app.selected_tab)
        .style(Style::default().fg(Color::White))
        .highlight_style(Style::default().fg(Color::Cyan).bold());
    f.render_widget(tabs, chunks[0]);

    // Content area
    match app.selected_tab {
        0 => render_alerts_tab(f, chunks[1], app),
        1 => render_network_tab(f, chunks[1], app),
        2 => render_falco_tab(f, chunks[1], app),
        3 => render_fim_tab(f, chunks[1], app),
        4 => render_system_tab(f, chunks[1], app),
        5 => render_config_tab(f, chunks[1], app),
        _ => {}
    }

    // Sudo popup overlay
    if let Some(ref popup) = app.sudo_popup {
        render_sudo_popup(f, f.area(), popup);
    }
}

fn render_sudo_popup(f: &mut Frame, area: Rect, popup: &SudoPopup) {
    // Center a popup box
    let popup_width = 60.min(area.width.saturating_sub(4));
    let popup_height = 9.min(area.height.saturating_sub(2));
    let x = (area.width.saturating_sub(popup_width)) / 2;
    let y = (area.height.saturating_sub(popup_height)) / 2;
    let popup_area = Rect::new(x, y, popup_width, popup_height);

    // Clear background
    let clear = Block::default().style(Style::default().bg(Color::Black));
    f.render_widget(clear, popup_area);

    let lines = match &popup.status {
        SudoStatus::WaitingForPassword => {
            let dots = "•".repeat(popup.password.len());
            vec![
                Line::from(Span::styled("🔒 Sudo Authentication Required", Style::default().fg(Color::Yellow).bold())),
                Line::from(""),
                Line::from(Span::raw(&popup.message)),
                Line::from(""),
                Line::from(vec![
                    Span::styled("Password: ", Style::default().fg(Color::Cyan)),
                    Span::styled(format!("{}▌", dots), Style::default().fg(Color::White)),
                ]),
                Line::from(""),
                Line::from(Span::styled("Enter to confirm · Esc to cancel", Style::default().fg(Color::DarkGray))),
            ]
        }
        SudoStatus::Running => {
            vec![
                Line::from(Span::styled("⏳ Running...", Style::default().fg(Color::Yellow).bold())),
                Line::from(""),
                Line::from(Span::raw(&popup.message)),
            ]
        }
        SudoStatus::Failed(msg) => {
            vec![
                Line::from(Span::styled("❌ Failed", Style::default().fg(Color::Red).bold())),
                Line::from(""),
                Line::from(Span::raw(msg.as_str())),
                Line::from(""),
                Line::from(Span::styled("Press any key to dismiss", Style::default().fg(Color::DarkGray))),
            ]
        }
    };

    let paragraph = Paragraph::new(lines)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow))
            .title(" Authentication "))
        .alignment(ratatui::layout::Alignment::Center);
    f.render_widget(paragraph, popup_area);
}

/// Run the TUI dashboard, blocking until the user quits.
///
/// Drains alerts from the channel, renders the UI at 10fps, and handles keyboard input.
pub async fn run_tui(mut alert_rx: mpsc::Receiver<Alert>, config_path: Option<PathBuf>) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();

    // Load config if provided
    if let Some(path) = config_path {
        if let Err(e) = app.load_config(&path) {
            eprintln!("Failed to load config: {}", e);
        }
    }

    loop {
        terminal.draw(|f| ui(f, &app))?;

        // Check for keyboard events (non-blocking)
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    app.on_key(key.code, key.modifiers);
                }
            }
        }

        // Drain alert channel
        while let Ok(alert) = alert_rx.try_recv() {
            app.alert_store.push(alert);
        }

        if app.should_quit {
            break;
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}