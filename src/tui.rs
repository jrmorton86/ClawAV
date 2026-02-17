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
use std::path::{Path, PathBuf};

use crate::alerts::{Alert, AlertStore, Severity};
use crate::config::Config;
use crate::response::{PendingAction, PendingStatus, ResponseRequest, SharedPendingActions};

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
    /// Selectable from a list of valid options (includes booleans).
    Enum(Vec<String>),
    /// Numeric input.
    Number,
    /// Action button — Enter runs the associated command string.
    Action(String),
}

/// State for an active inline dropdown picker overlay.
pub struct DropdownState {
    /// Index of the field this dropdown is attached to.
    pub field_index: usize,
    /// Valid options to choose from.
    pub options: Vec<String>,
    /// Currently highlighted option index.
    pub selected: usize,
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
    pub config_dropdown: Option<DropdownState>,
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
    // Response engine integration
    pub pending_actions: SharedPendingActions,
    pub response_tx: Option<mpsc::Sender<ResponseRequest>>,
    pub approval_popup: Option<ApprovalPopup>,
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

impl Drop for SudoPopup {
    fn drop(&mut self) {
        self.password.zeroize();
    }
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

/// State for the response engine approval popup.
pub struct ApprovalPopup {
    /// The pending action being reviewed.
    pub action_id: String,
    pub threat_source: String,
    pub threat_message: String,
    pub severity: Severity,
    pub actions_display: Vec<String>,
    pub playbook: Option<String>,
    /// Currently selected: 0 = Approve, 1 = Deny
    pub selected: usize,
    /// Optional message/annotation
    pub message_buffer: String,
    /// Whether the message field is being edited
    pub editing_message: bool,
}

impl App {
    /// Create a new TUI application with default state.
    pub fn new(pending_actions: SharedPendingActions, response_tx: Option<mpsc::Sender<ResponseRequest>>) -> Self {
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
                "response".into(),
            ],
            config_selected_section: 0,
            config_fields: Vec::new(),
            config_selected_field: 0,
            config_focus: ConfigFocus::Sidebar,
            config_editing: false,
            config_edit_buffer: String::new(),
            config_dropdown: None,
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
            pending_actions,
            response_tx,
            approval_popup: None,
        }
    }

    /// Load configuration from a file and populate the editor fields.
    pub fn load_config(&mut self, path: &Path) -> Result<()> {
        let config = Config::load(path)?;
        self.config = Some(config);
        self.config_path = Some(path.to_path_buf());
        self.refresh_fields();
        Ok(())
    }

    /// Rebuild the field list for the currently selected config section.
    pub fn refresh_fields(&mut self) {
        // Pre-cache tool status before borrowing config
        let _ = self.is_tool_installed("falco");
        let _ = self.is_tool_installed("samhain");
        if let Some(ref config) = self.config {
            let section = &self.config_sections[self.config_selected_section];
            self.config_fields = get_section_fields(config, section, &self.tool_status_cache);
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

        // Handle approval popup if active
        if let Some(ref mut popup) = self.approval_popup {
            if popup.editing_message {
                match key {
                    KeyCode::Esc => { popup.editing_message = false; }
                    KeyCode::Backspace => { popup.message_buffer.pop(); }
                    KeyCode::Char(c) => { popup.message_buffer.push(c); }
                    KeyCode::Enter => { popup.editing_message = false; }
                    _ => {}
                }
                return;
            }
            match key {
                KeyCode::Up | KeyCode::Down => {
                    popup.selected = if popup.selected == 0 { 1 } else { 0 };
                }
                KeyCode::Char('m') => {
                    popup.editing_message = true;
                }
                KeyCode::Enter => {
                    let approved = popup.selected == 0;
                    let action_id = popup.action_id.clone();
                    let msg = if popup.message_buffer.is_empty() { None } else { Some(popup.message_buffer.clone()) };
                    self.approval_popup = None;

                    // Send resolution
                    if let Some(ref tx) = self.response_tx {
                        let resolve = ResponseRequest::Resolve {
                            id: action_id,
                            approved,
                            by: "admin".to_string(),
                            message: msg,
                            surface: "tui".to_string(),
                        };
                        let _ = tx.try_send(resolve);
                    }
                }
                KeyCode::Esc => {
                    self.approval_popup = None;
                }
                _ => {}
            }
            return;
        }

        // Clear saved message on any keypress
        if self.config_saved_message.is_some() {
            self.config_saved_message = None;
        }

        // Search mode input
        if self.search_active {
            match key {
                KeyCode::Enter => {
                    self.search_filter = self.search_buffer.clone();
                    self.search_active = false;
                }
                KeyCode::Esc => {
                    self.search_active = false;
                    self.search_buffer.clear();
                }
                KeyCode::Backspace => { self.search_buffer.pop(); }
                KeyCode::Char(c) => { self.search_buffer.push(c); }
                _ => {}
            }
            return;
        }

        // Detail view mode
        if self.detail_alert.is_some() {
            match key {
                KeyCode::Esc | KeyCode::Backspace | KeyCode::Char('q') => {
                    self.detail_alert = None;
                }
                KeyCode::Char('m') => {
                    // Mute/unmute the source of the viewed alert
                    if let Some(ref alert) = self.detail_alert {
                        let src = alert.source.clone();
                        if let Some(pos) = self.muted_sources.iter().position(|s| s == &src) {
                            self.muted_sources.remove(pos);
                        } else {
                            self.muted_sources.push(src);
                        }
                    }
                }
                _ => {}
            }
            return;
        }

        match key {
            KeyCode::Char('q') | KeyCode::Esc if !self.config_editing => {
                // If search filter is active, Esc clears it first
                if !self.search_filter.is_empty() && key == KeyCode::Esc {
                    self.search_filter.clear();
                    self.search_buffer.clear();
                } else {
                    self.should_quit = true;
                }
            }
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
            KeyCode::Right if !self.config_editing && (self.selected_tab != 5 || self.config_focus != ConfigFocus::Fields) => {
                self.selected_tab = (self.selected_tab + 1) % self.tab_titles.len();
                if self.selected_tab == 5 { self.config_focus = ConfigFocus::Sidebar; }
            }
            KeyCode::Left if !self.config_editing && (self.selected_tab != 5 || self.config_focus != ConfigFocus::Fields) => {
                if self.selected_tab > 0 {
                    self.selected_tab -= 1;
                } else {
                    self.selected_tab = self.tab_titles.len() - 1;
                }
                if self.selected_tab == 5 { self.config_focus = ConfigFocus::Sidebar; }
            }
            // Alert list tabs (0-3): scroll, select, search, pause
            KeyCode::Up if self.selected_tab <= 3 => {
                let state = &mut self.list_states[self.selected_tab];
                let i = state.selected().unwrap_or(0);
                state.select(Some(i.saturating_sub(1)));
            }
            KeyCode::Down if self.selected_tab <= 3 => {
                let state = &mut self.list_states[self.selected_tab];
                let i = state.selected().unwrap_or(0);
                state.select(Some(i + 1)); // ListState clamps to list len during render
            }
            KeyCode::Enter if self.selected_tab <= 3 => {
                // Open detail view for selected alert
                let tab = self.selected_tab;
                let selected_idx = self.list_states[tab].selected().unwrap_or(0);
                let source_filter: Option<&str> = match tab {
                    1 => Some("network"),
                    2 => Some("falco"),
                    3 => Some("samhain"),
                    _ => None,
                };
                let filtered: Vec<&Alert> = self.alert_store.alerts()
                    .iter()
                    .rev()
                    .filter(|a| {
                        if let Some(src) = source_filter {
                            if a.source != src { return false; }
                        }
                        if self.muted_sources.contains(&a.source) { return false; }
                        if !self.search_filter.is_empty() {
                            let h = a.to_string().to_lowercase();
                            if !h.contains(&self.search_filter.to_lowercase()) { return false; }
                        }
                        true
                    })
                    .collect();
                if let Some(alert) = filtered.get(selected_idx) {
                    self.detail_alert = Some((*alert).clone());
                }
            }
            KeyCode::Char('/') if self.selected_tab <= 3 => {
                self.search_active = true;
                self.search_buffer = self.search_filter.clone();
            }
            KeyCode::Char(' ') if self.selected_tab <= 3 => {
                self.paused = !self.paused;
            }
            // Config tab specific keys
            _ if self.selected_tab == 5 => self.handle_config_key(key, modifiers),
            _ => {}
        }
    }

    fn handle_config_key(&mut self, key: KeyCode, modifiers: KeyModifiers) {
        // Handle dropdown if active
        if let Some(ref mut dropdown) = self.config_dropdown {
            match key {
                KeyCode::Up => {
                    dropdown.selected = dropdown.selected.saturating_sub(1);
                }
                KeyCode::Down => {
                    if dropdown.selected < dropdown.options.len().saturating_sub(1) {
                        dropdown.selected += 1;
                    }
                }
                KeyCode::Enter => {
                    let value = dropdown.options[dropdown.selected].clone();
                    let field_index = dropdown.field_index;
                    self.config_dropdown = None;
                    if let Some(ref mut config) = self.config {
                        let section = &self.config_sections[self.config_selected_section];
                        let field_name = &self.config_fields[field_index].name;
                        apply_field_to_config(config, section, field_name, &value);
                        self.refresh_fields();
                    }
                }
                KeyCode::Esc => {
                    self.config_dropdown = None;
                }
                _ => {}
            }
            return;
        }

        if self.config_editing {
            // Handle editing mode
            match key {
                KeyCode::Enter => {
                    // Validate before applying
                    let field = &self.config_fields[self.config_selected_field];
                    let value = &self.config_edit_buffer;

                    let valid = match &field.field_type {
                        FieldType::Number => value.parse::<u64>().is_ok(),
                        FieldType::Enum(ref options) => options.contains(&value.to_string()),
                        FieldType::Text => true,
                        FieldType::Action(_) => true,
                    };

                    if valid {
                        if let Some(ref mut config) = self.config {
                            let section = &self.config_sections[self.config_selected_section];
                            let field = &self.config_fields[self.config_selected_field];
                            apply_field_to_config(config, section, &field.name, &self.config_edit_buffer);
                            self.refresh_fields();
                        }
                        self.config_editing = false;
                        self.config_edit_buffer.clear();
                    } else {
                        self.config_saved_message = Some(format!(
                            "❌ Invalid {}: \"{}\"",
                            match &field.field_type {
                                FieldType::Number => "number",
                                FieldType::Enum(_) => "selection",
                                _ => "value",
                            },
                            value
                        ));
                    }
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
                                    FieldType::Enum(ref options) => {
                                        let current = &field.value;
                                        let selected = options.iter().position(|o| o == current).unwrap_or(0);
                                        self.config_dropdown = Some(DropdownState {
                                            field_index: self.config_selected_field,
                                            options: options.clone(),
                                            selected,
                                        });
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
        let shell_cmd: String = if let Some(path) = action.strip_prefix("save_config:") {
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
                    self.invalidate_tool_cache();
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

fn get_section_fields(config: &Config, section: &str, tool_cache: &HashMap<String, bool>) -> Vec<ConfigField> {
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
                field_type: FieldType::Enum(vec!["true".into(), "false".into()]),
            },
            ConfigField {
                name: "min_alert_level".to_string(),
                value: config.general.min_alert_level.clone(),
                section: section.to_string(),
                field_type: FieldType::Enum(vec!["info".into(), "warn".into(), "crit".into()]),
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
                field_type: FieldType::Enum(vec!["true".into(), "false".into()]),
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
                field_type: FieldType::Enum(vec!["info".into(), "warn".into(), "crit".into()]),
            },
        ],
        "auditd" => vec![
            ConfigField {
                name: "enabled".to_string(),
                value: config.auditd.enabled.to_string(),
                section: section.to_string(),
                field_type: FieldType::Enum(vec!["true".into(), "false".into()]),
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
                field_type: FieldType::Enum(vec!["true".into(), "false".into()]),
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
            let falco_installed = tool_cache.get("falco").copied().unwrap_or(false);
            let mut fields = vec![
                ConfigField {
                    name: "enabled".to_string(),
                    value: config.falco.enabled.to_string(),
                    section: section.to_string(),
                    field_type: FieldType::Enum(vec!["true".into(), "false".into()]),
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
            let samhain_installed = tool_cache.get("samhain").copied().unwrap_or(false);
            let mut fields = vec![
                ConfigField {
                    name: "enabled".to_string(),
                    value: config.samhain.enabled.to_string(),
                    section: section.to_string(),
                    field_type: FieldType::Enum(vec!["true".into(), "false".into()]),
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
                field_type: FieldType::Enum(vec!["true".into(), "false".into()]),
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
                field_type: FieldType::Enum(vec!["true".into(), "false".into()]),
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
                field_type: FieldType::Enum(vec!["true".into(), "false".into()]),
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
                field_type: FieldType::Enum(vec!["true".into(), "false".into()]),
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
                field_type: FieldType::Enum(vec!["true".into(), "false".into()]),
            },
            ConfigField {
                name: "mode".to_string(),
                value: config.netpolicy.mode.clone(),
                section: section.to_string(),
                field_type: FieldType::Enum(vec!["allow".into(), "deny".into(), "disabled".into()]),
            },
            ConfigField {
                name: "allowed_ports".to_string(),
                value: config.netpolicy.allowed_ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(","),
                section: section.to_string(),
                field_type: FieldType::Text,
            },
        ],
        "response" => vec![
            ConfigField {
                name: "enabled".to_string(),
                value: config.response.enabled.to_string(),
                section: section.to_string(),
                field_type: FieldType::Enum(vec!["true".into(), "false".into()]),
            },
            ConfigField {
                name: "timeout_secs".to_string(),
                value: config.response.timeout_secs.to_string(),
                section: section.to_string(),
                field_type: FieldType::Number,
            },
            ConfigField {
                name: "warning_mode".to_string(),
                value: config.response.warning_mode.clone(),
                section: section.to_string(),
                field_type: FieldType::Enum(vec!["gate".into(), "alert_only".into(), "auto_deny".into()]),
            },
            ConfigField {
                name: "playbook_dir".to_string(),
                value: config.response.playbook_dir.clone(),
                section: section.to_string(),
                field_type: FieldType::Text,
            },
            ConfigField {
                name: "deny_message".to_string(),
                value: config.response.deny_message.clone(),
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
        "scans" => if field_name == "interval" {
            if let Ok(interval) = value.parse::<u64>() { config.scans.interval = interval; }
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
        "response" => match field_name {
            "enabled" => config.response.enabled = value == "true",
            "timeout_secs" => if let Ok(t) = value.parse::<u64>() { config.response.timeout_secs = t; },
            "warning_mode" => config.response.warning_mode = value.to_string(),
            "playbook_dir" => config.response.playbook_dir = value.to_string(),
            "deny_message" => config.response.deny_message = value.to_string(),
            _ => {}
        },
        _ => {}
    }
}

fn render_alert_list(
    f: &mut Frame,
    area: Rect,
    app: &mut App,
    tab_index: usize,
    source_filter: Option<&str>,
    title: &str,
) {
    let alerts = app.alert_store.alerts();
    let filtered: Vec<&Alert> = alerts
        .iter()
        .rev()
        .filter(|a| {
            if let Some(src) = source_filter {
                if a.source != src {
                    return false;
                }
            }
            if app.muted_sources.contains(&a.source) {
                return false;
            }
            if !app.search_filter.is_empty() {
                let haystack = a.to_string().to_lowercase();
                if !haystack.contains(&app.search_filter.to_lowercase()) {
                    return false;
                }
            }
            true
        })
        .collect();

    let now = chrono::Local::now();
    let items: Vec<ListItem> = filtered
        .iter()
        .map(|alert| {
            let age = now.signed_duration_since(alert.timestamp);
            let age_str = if age.num_seconds() < 60 {
                format!("{}s ago", age.num_seconds())
            } else if age.num_minutes() < 60 {
                format!("{}m ago", age.num_minutes())
            } else if age.num_hours() < 24 {
                format!("{}h ago", age.num_hours())
            } else {
                format!("{}d ago", age.num_days())
            };

            let style = match alert.severity {
                Severity::Critical => Style::default().fg(Color::Red).bold(),
                Severity::Warning => Style::default().fg(Color::Yellow),
                Severity::Info => Style::default().fg(Color::Blue),
            };
            ListItem::new(format!(
                "{} {} [{}] {}",
                age_str, alert.severity, alert.source, alert.message
            ))
            .style(style)
        })
        .collect();

    let count = items.len();
    let display_title = format!(" {} ({}) ", title, count);
    let pause_indicator = if app.paused { " ⏸ PAUSED " } else { "" };
    let full_title = format!("{}{}", display_title, pause_indicator);

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(full_title))
        .highlight_style(Style::default().bg(Color::DarkGray).fg(Color::White))
        .highlight_symbol("▶ ");

    f.render_stateful_widget(list, area, &mut app.list_states[tab_index]);
}

fn render_system_tab(f: &mut Frame, area: Rect, app: &App) {
    let info_count = app.alert_store.count_by_severity(&Severity::Info);
    let warn_count = app.alert_store.count_by_severity(&Severity::Warning);
    let crit_count = app.alert_store.count_by_severity(&Severity::Critical);

    let mut text = vec![
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
            Span::styled(format!("  ℹ️  Info:     {}", info_count), Style::default().fg(Color::Blue)),
        ]),
        Line::from(vec![
            Span::styled(format!("  ⚠️  Warnings: {}", warn_count), Style::default().fg(Color::Yellow)),
        ]),
        Line::from(vec![
            Span::styled(format!("  🔴 Critical: {}", crit_count), Style::default().fg(Color::Red)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::raw("Feed: "),
            if app.paused {
                Span::styled("⏸ PAUSED", Style::default().fg(Color::Yellow).bold())
            } else {
                Span::styled("▶ LIVE", Style::default().fg(Color::Green))
            },
        ]),
    ];

    if !app.muted_sources.is_empty() {
        text.push(Line::from(vec![
            Span::styled("Muted: ", Style::default().fg(Color::DarkGray)),
            Span::raw(app.muted_sources.join(", ")),
        ]));
    }

    text.push(Line::from(""));
    text.push(Line::from(vec![
        Span::raw("Press "),
        Span::styled("Tab", Style::default().fg(Color::Cyan)),
        Span::raw(" to switch panels, "),
        Span::styled("q", Style::default().fg(Color::Cyan)),
        Span::raw(" to quit"),
    ]));

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

    // Dropdown overlay
    if let Some(ref dropdown) = app.config_dropdown {
        let max_option_len = dropdown.options.iter().map(|o| o.len()).max().unwrap_or(4);
        let dropdown_width = (max_option_len as u16) + 4;
        let dropdown_height = (dropdown.options.len() as u16) + 2;

        // Position: right side of fields panel, at the field's Y offset
        let fields_area = chunks[1]; // the right panel
        let field_y_offset = dropdown.field_index as u16;
        let x = fields_area.x + fields_area.width.saturating_sub(dropdown_width + 1);
        let y = (fields_area.y + 1 + field_y_offset).min(
            fields_area.y + fields_area.height.saturating_sub(dropdown_height + 1)
        );

        let dropdown_area = Rect::new(x, y, dropdown_width, dropdown_height);

        let items: Vec<ListItem> = dropdown.options.iter().enumerate().map(|(i, opt)| {
            let style = if i == dropdown.selected {
                Style::default().fg(Color::Black).bg(Color::Cyan)
            } else {
                Style::default().fg(Color::White)
            };
            ListItem::new(format!(" {} ", opt)).style(style)
        }).collect();

        let list = List::new(items)
            .block(Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .style(Style::default().bg(Color::Black)));
        f.render_widget(list, dropdown_area);
    }
}

fn render_detail_view(f: &mut Frame, area: Rect, alert: &Alert) {
    let now = chrono::Local::now();
    let age = now.signed_duration_since(alert.timestamp);
    let age_str = if age.num_seconds() < 60 {
        format!("{} seconds ago", age.num_seconds())
    } else if age.num_minutes() < 60 {
        format!("{} minutes ago", age.num_minutes())
    } else if age.num_hours() < 24 {
        format!("{} hours ago", age.num_hours())
    } else {
        format!("{} days ago", age.num_days())
    };

    let severity_style = match alert.severity {
        Severity::Critical => Style::default().fg(Color::Red).bold(),
        Severity::Warning => Style::default().fg(Color::Yellow).bold(),
        Severity::Info => Style::default().fg(Color::Blue).bold(),
    };

    let mut text = vec![
        Line::from(vec![
            Span::styled(format!(" {} ", alert.severity), severity_style),
            Span::raw("  "),
            Span::styled(alert.source.as_str(), Style::default().fg(Color::Cyan).bold()),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Timestamp: ", Style::default().fg(Color::DarkGray)),
            Span::raw(alert.timestamp.format("%Y-%m-%d %H:%M:%S%.3f").to_string()),
            Span::styled(format!("  ({})", age_str), Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Source: ", Style::default().fg(Color::DarkGray)),
            Span::raw(alert.source.as_str()),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Severity: ", Style::default().fg(Color::DarkGray)),
            Span::styled(format!("{}", alert.severity), severity_style),
        ]),
        Line::from(""),
        Line::from(Span::styled("Message:", Style::default().fg(Color::DarkGray))),
        Line::from(""),
    ];

    // Word-wrap the message to fit the area
    let wrap_width = area.width.saturating_sub(4) as usize;
    if wrap_width > 0 {
        let msg_lines: Vec<Line> = alert
            .message
            .chars()
            .collect::<Vec<_>>()
            .chunks(wrap_width)
            .map(|chunk| Line::from(format!("  {}", chunk.iter().collect::<String>())))
            .collect();
        text.extend(msg_lines);
    }

    let paragraph = Paragraph::new(text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Alert Detail ")
                .border_style(Style::default().fg(Color::Cyan)),
        );
    f.render_widget(paragraph, area);
}

fn ui(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // tab bar
            Constraint::Min(0),    // content
            Constraint::Length(1), // footer
        ])
        .split(f.area());

    // Tab bar with dynamic counts
    let alerts = app.alert_store.alerts();
    let total = alerts.len();
    let net_count = alerts.iter().filter(|a| a.source == "network").count();
    let falco_count = alerts.iter().filter(|a| a.source == "falco").count();
    let fim_count = alerts.iter().filter(|a| a.source == "samhain").count();

    let pending_count = {
        if let Ok(pending) = app.pending_actions.try_lock() {
            pending.iter().filter(|a| matches!(a.status, PendingStatus::AwaitingApproval)).count()
        } else {
            0
        }
    };

    let alerts_title = if pending_count > 0 {
        format!("Alerts ({}) 🔴{}", total, pending_count)
    } else {
        format!("Alerts ({})", total)
    };

    let tab_titles: Vec<Line> = vec![
        Line::from(alerts_title),
        Line::from(format!("Network ({})", net_count)),
        Line::from(format!("Falco ({})", falco_count)),
        Line::from(format!("FIM ({})", fim_count)),
        Line::from("System".to_string()),
        Line::from("Config".to_string()),
    ];

    let tabs = Tabs::new(tab_titles)
        .block(Block::default().borders(Borders::ALL).title(" 🛡️ ClawTower "))
        .select(app.selected_tab)
        .style(Style::default().fg(Color::White))
        .highlight_style(Style::default().fg(Color::Cyan).bold());
    f.render_widget(tabs, chunks[0]);

    // Content area — detail view overrides tab content
    if let Some(ref alert) = app.detail_alert.clone() {
        render_detail_view(f, chunks[1], alert);
    } else {
        match app.selected_tab {
            0 => render_alert_list(f, chunks[1], app, 0, None, "Alert Feed"),
            1 => render_alert_list(f, chunks[1], app, 1, Some("network"), "Network Activity"),
            2 => render_alert_list(f, chunks[1], app, 2, Some("falco"), "Falco eBPF Alerts"),
            3 => render_alert_list(f, chunks[1], app, 3, Some("samhain"), "File Integrity"),
            4 => render_system_tab(f, chunks[1], app),
            5 => render_config_tab(f, chunks[1], app),
            _ => {}
        }
    }

    // Footer / status bar
    let footer_text = if app.search_active {
        format!(" 🔍 Search: {}▌  (Enter to apply, Esc to cancel)", app.search_buffer)
    } else if app.detail_alert.is_some() {
        " Esc: back │ m: mute source".to_string()
    } else {
        match app.selected_tab {
            0..=3 => {
                let pause = if app.paused { "Space: resume" } else { "Space: pause" };
                let filter = if !app.search_filter.is_empty() {
                    format!(" │ Filter: \"{}\" (Esc clears)", app.search_filter)
                } else {
                    String::new()
                };
                format!(" Tab: switch │ ↑↓: scroll │ Enter: detail │ /: search │ {}{} │ q: quit", pause, filter)
            }
            4 => " Tab: switch │ q: quit".to_string(),
            5 => {
                if app.config_dropdown.is_some() {
                    " ↑↓: select │ Enter: confirm │ Esc: cancel".to_string()
                } else if app.config_editing {
                    " Enter: confirm │ Esc: cancel".to_string()
                } else if app.config_focus == ConfigFocus::Fields {
                    " ↑↓: navigate │ Enter: edit │ Backspace: sidebar │ Ctrl+S: save │ Tab: switch".to_string()
                } else {
                    " ↑↓: sections │ Enter: fields │ ←→: tabs │ Tab: switch │ q: quit".to_string()
                }
            }
            _ => String::new(),
        }
    };

    let footer = Paragraph::new(Line::from(footer_text))
        .style(Style::default().fg(Color::DarkGray).bg(Color::Black));
    f.render_widget(footer, chunks[2]);

    // Sudo popup overlay
    if let Some(ref popup) = app.sudo_popup {
        render_sudo_popup(f, f.area(), popup);
    }

    // Approval popup overlay
    if let Some(ref popup) = app.approval_popup {
        render_approval_popup(f, f.area(), popup);
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

fn render_approval_popup(f: &mut Frame, area: Rect, popup: &ApprovalPopup) {
    let popup_width = 70.min(area.width.saturating_sub(4));
    let popup_height = (14 + popup.actions_display.len() as u16).min(area.height.saturating_sub(2));
    let x = (area.width.saturating_sub(popup_width)) / 2;
    let y = (area.height.saturating_sub(popup_height)) / 2;
    let popup_area = Rect::new(x, y, popup_width, popup_height);

    let clear = Block::default().style(Style::default().bg(Color::Black));
    f.render_widget(clear, popup_area);

    let severity_style = match popup.severity {
        Severity::Critical => Style::default().fg(Color::Red).bold(),
        Severity::Warning => Style::default().fg(Color::Yellow).bold(),
        Severity::Info => Style::default().fg(Color::Blue).bold(),
    };

    let mut lines = vec![
        Line::from(Span::styled(
            format!("🚨 {} THREAT DETECTED", popup.severity),
            severity_style,
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("Source: ", Style::default().fg(Color::DarkGray)),
            Span::raw(&popup.threat_source),
        ]),
        Line::from(vec![
            Span::styled("Threat: ", Style::default().fg(Color::DarkGray)),
            Span::raw(&popup.threat_message),
        ]),
    ];

    if let Some(ref pb) = popup.playbook {
        lines.push(Line::from(vec![
            Span::styled("Playbook: ", Style::default().fg(Color::DarkGray)),
            Span::styled(pb.as_str(), Style::default().fg(Color::Cyan)),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("Proposed actions:", Style::default().fg(Color::DarkGray))));
    for action in &popup.actions_display {
        lines.push(Line::from(format!("  • {}", action)));
    }

    lines.push(Line::from(""));

    let approve_style = if popup.selected == 0 {
        Style::default().fg(Color::Black).bg(Color::Green).bold()
    } else {
        Style::default().fg(Color::Green)
    };
    let deny_style = if popup.selected == 1 {
        Style::default().fg(Color::Black).bg(Color::Red).bold()
    } else {
        Style::default().fg(Color::Red)
    };

    lines.push(Line::from(vec![
        Span::raw("  "),
        Span::styled(" APPROVE ", approve_style),
        Span::raw("    "),
        Span::styled("  DENY  ", deny_style),
    ]));

    lines.push(Line::from(""));

    let msg_display = if popup.editing_message {
        format!("Note: {}▌", popup.message_buffer)
    } else if popup.message_buffer.is_empty() {
        "Press 'm' to add a note".to_string()
    } else {
        format!("Note: {}", popup.message_buffer)
    };
    lines.push(Line::from(Span::styled(msg_display, Style::default().fg(Color::DarkGray))));

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "↑↓: select │ Enter: confirm │ m: add note │ Esc: dismiss",
        Style::default().fg(Color::DarkGray),
    )));

    let paragraph = Paragraph::new(lines)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Red))
            .title(" ⚡ Action Required ")
            .style(Style::default().bg(Color::Black)));
    f.render_widget(paragraph, popup_area);
}

/// Run the TUI dashboard, blocking until the user quits.
///
/// Drains alerts from the channel, renders the UI at 10fps, and handles keyboard input.
pub async fn run_tui(
    mut alert_rx: mpsc::Receiver<Alert>,
    config_path: Option<PathBuf>,
    pending_actions: SharedPendingActions,
    response_tx: Option<mpsc::Sender<ResponseRequest>>,
) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(pending_actions, response_tx);

    // Load config if provided
    if let Some(path) = config_path {
        if let Err(e) = app.load_config(&path) {
            eprintln!("Failed to load config: {}", e);
        }
    }

    loop {
        terminal.draw(|f| ui(f, &mut app))?;

        // Check for keyboard events (non-blocking)
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    app.on_key(key.code, key.modifiers);
                }
            }
        }

        // Drain alert channel (skip when paused — alerts buffer in channel)
        if !app.paused {
            while let Ok(alert) = alert_rx.try_recv() {
                app.alert_store.push(alert);
            }
        }

        // Check for new pending actions and show popup
        if app.approval_popup.is_none() {
            if let Ok(pending) = app.pending_actions.try_lock() {
                if let Some(action) = pending.iter().find(|a| matches!(a.status, PendingStatus::AwaitingApproval)) {
                    app.approval_popup = Some(ApprovalPopup {
                        action_id: action.id.clone(),
                        threat_source: action.threat_source.clone(),
                        threat_message: action.threat_message.clone(),
                        severity: action.severity.clone(),
                        actions_display: action.actions.iter().map(|a| a.to_string()).collect(),
                        playbook: action.playbook.clone(),
                        selected: 1, // default to DENY for safety
                        message_buffer: String::new(),
                        editing_message: false,
                    });
                }
            }
        }

        if app.should_quit {
            break;
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}