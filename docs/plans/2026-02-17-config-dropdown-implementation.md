# Config Dropdown Picker Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace manual text typing for boolean and enum config fields with an inline dropdown picker.

**Architecture:** All changes in `src/tui.rs`. Replace `FieldType::Bool` with `FieldType::Enum(Vec<String>)`, add `DropdownState` struct, add dropdown keyboard handling and rendering.

**Tech Stack:** Rust, ratatui 0.29

**Important:** No `cargo` on this machine. Edit code, commit, push — CI handles the rest.

---

### Task 1: Add DropdownState and Enum variant, remove Bool

**Files:**
- Modify: `src/tui.rs`

**Step 1: Replace FieldType::Bool with Enum**

Find (around line 64):

```rust
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
```

Replace with:

```rust
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
```

**Step 2: Add DropdownState struct**

After the `FieldType` enum, add:

```rust
/// State for an active inline dropdown picker overlay.
pub struct DropdownState {
    /// Index of the field this dropdown is attached to.
    pub field_index: usize,
    /// Valid options to choose from.
    pub options: Vec<String>,
    /// Currently highlighted option index.
    pub selected: usize,
}
```

**Step 3: Add config_dropdown field to App**

In the `App` struct, after `config_edit_buffer: String,` add:

```rust
    pub config_dropdown: Option<DropdownState>,
```

**Step 4: Initialize in App::new()**

After `config_edit_buffer: String::new(),` add:

```rust
            config_dropdown: None,
```

**Step 5: Commit**

```bash
git add src/tui.rs
git commit -m "feat(tui): add DropdownState struct and Enum field type, remove Bool"
```

---

### Task 2: Update get_section_fields to use Enum

**Files:**
- Modify: `src/tui.rs`

**Step 1: Replace all FieldType::Bool with FieldType::Enum**

In the `get_section_fields` function, do a find-and-replace:

Every instance of:
```rust
                field_type: FieldType::Bool,
```

Replace with:
```rust
                field_type: FieldType::Enum(vec!["true".into(), "false".into()]),
```

There are approximately 10-12 instances across general, slack, auditd, network, falco, samhain, api, proxy, policy, barnacle, netpolicy sections.

**Step 2: Change min_alert_level and min_slack_level to Enum**

Find the `min_alert_level` field in the `"general"` section (it currently uses `FieldType::Text`):

```rust
            ConfigField {
                name: "min_alert_level".to_string(),
                value: config.general.min_alert_level.clone(),
                section: section.to_string(),
                field_type: FieldType::Text,
            },
```

Change to:

```rust
            ConfigField {
                name: "min_alert_level".to_string(),
                value: config.general.min_alert_level.clone(),
                section: section.to_string(),
                field_type: FieldType::Enum(vec!["info".into(), "warn".into(), "crit".into()]),
            },
```

Do the same for `min_slack_level` in the `"slack"` section.

**Step 3: Change netpolicy.mode to Enum**

Find the `mode` field in the `"netpolicy"` section:

```rust
            ConfigField {
                name: "mode".to_string(),
                value: config.netpolicy.mode.clone(),
                section: section.to_string(),
                field_type: FieldType::Text,
            },
```

Change to:

```rust
            ConfigField {
                name: "mode".to_string(),
                value: config.netpolicy.mode.clone(),
                section: section.to_string(),
                field_type: FieldType::Enum(vec!["allow".into(), "deny".into(), "disabled".into()]),
            },
```

**Step 4: Commit**

```bash
git add src/tui.rs
git commit -m "feat(tui): use Enum field type for booleans and known option fields"
```

---

### Task 3: Update keyboard handlers for dropdown

**Files:**
- Modify: `src/tui.rs`

**Step 1: Add dropdown input handler at the top of handle_config_key**

At the very beginning of `handle_config_key`, before the `if self.config_editing {` block, add:

```rust
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
```

**Step 2: Replace the FieldType::Bool match arm in the Enter handler**

In `handle_config_key`, in the `ConfigFocus::Fields` → `KeyCode::Enter` handler, find:

```rust
                                    FieldType::Bool => {
                                        if let Some(ref mut config) = self.config {
                                            let section = &self.config_sections[self.config_selected_section];
                                            let new_value = if field.value == "true" { "false" } else { "true" };
                                            apply_field_to_config(config, section, &field.name, new_value);
                                            self.refresh_fields();
                                        }
                                    }
```

Replace with:

```rust
                                    FieldType::Enum(ref options) => {
                                        let current = &field.value;
                                        let selected = options.iter().position(|o| o == current).unwrap_or(0);
                                        self.config_dropdown = Some(DropdownState {
                                            field_index: self.config_selected_field,
                                            options: options.clone(),
                                            selected,
                                        });
                                    }
```

**Step 3: Update validation in config_editing Enter handler**

In the `if self.config_editing` block where validation happens, find:

```rust
                        FieldType::Bool => value == "true" || value == "false",
```

Replace with:

```rust
                        FieldType::Enum(ref options) => options.contains(&value.to_string()),
```

And in the error message match:

```rust
                                FieldType::Bool => "boolean (true/false)",
```

Replace with:

```rust
                                FieldType::Enum(_) => "selection",
```

**Step 4: Commit**

```bash
git add src/tui.rs
git commit -m "feat(tui): dropdown keyboard handling for Enum fields"
```

---

### Task 4: Render the dropdown overlay

**Files:**
- Modify: `src/tui.rs`

**Step 1: Add dropdown rendering at the end of render_config_tab**

At the very end of the `render_config_tab` function, after the fields list is rendered, add:

```rust
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
```

**Step 2: Commit**

```bash
git add src/tui.rs
git commit -m "feat(tui): render inline dropdown overlay for Enum config fields"
```

---

### Task 5: Update footer hints for dropdown state

**Files:**
- Modify: `src/tui.rs`

**Step 1: Add dropdown hint to footer**

In the `ui()` function where the footer text is computed, find the config tab section. In the `5 =>` arm, add a check for dropdown before the existing checks:

```rust
            5 => {
                if app.config_dropdown.is_some() {
                    " ↑↓: select │ Enter: confirm │ Esc: cancel".to_string()
                } else if app.config_editing {
                    " Enter: confirm │ Esc: cancel".to_string()
                } else if app.config_focus == ConfigFocus::Fields {
```

(The rest stays the same.)

**Step 2: Commit**

```bash
git add src/tui.rs
git commit -m "feat(tui): footer hints for dropdown state"
```

---

### Task 6: Final review and push

**Step 1: Verify no remaining references to FieldType::Bool**

```bash
grep -n "FieldType::Bool" src/tui.rs
```

Should return zero results. If any remain, replace them.

**Step 2: Commit any final fixes and push**

```bash
git push origin main
```

---

## Summary

| Task | What | Est. lines changed |
|---|---|---|
| 1 | DropdownState + Enum variant | ~20 |
| 2 | Field mappings to Enum | ~25 (replacements) |
| 3 | Keyboard handlers | ~35 |
| 4 | Dropdown rendering | ~30 |
| 5 | Footer hints | ~5 |
| 6 | Cleanup + push | ~0 |

Total: ~115 lines added/changed. No new files. Single file modification (`src/tui.rs`).
