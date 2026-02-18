#!/usr/bin/env bash
# ClawTower Interactive Configuration
# Walks you through setting up config.toml with prompts.
set -euo pipefail

CONFIG="${1:-/etc/clawtower/config.toml}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

die() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

[[ -f "$CONFIG" ]] || die "Config not found: $CONFIG"

# Helper: read a value with a default
ask() {
    local prompt="$1"
    local default="$2"
    local var
    if [[ -n "$default" ]]; then
        read -rp "$(echo -e "${CYAN}$prompt${NC} [$default]: ")" var
        echo "${var:-$default}"
    else
        read -rp "$(echo -e "${CYAN}$prompt${NC}: ")" var
        echo "$var"
    fi
}

# Helper: set a TOML value (simple string/number/bool replacement)
set_toml() {
    local key="$1"
    local value="$2"
    # If key exists, replace it. If not, this is a no-op (user can add manually)
    if grep -q "^${key} *=" "$CONFIG" 2>/dev/null; then
        sed -i "s|^${key} *=.*|${key} = ${value}|" "$CONFIG"
    elif grep -q "^#.*${key} *=" "$CONFIG" 2>/dev/null; then
        # Uncomment and set
        sed -i "s|^#.*${key} *=.*|${key} = ${value}|" "$CONFIG"
    fi
}

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║           🛡️  ClawTower Configuration                          ║${NC}"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}║  Press Enter to keep the current/default value.              ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ── General ───────────────────────────────────────────────────────────────────
echo -e "${YELLOW}── General ──${NC}"
WATCHED_USER=$(ask "Watched user UID (run 'id <username>' to find)" "1000")
set_toml "watched_user" "\"$WATCHED_USER\""

WATCH_ALL=$(ask "Watch ALL users? (true/false)" "false")
set_toml "watch_all_users" "$WATCH_ALL"
echo ""

# ── Slack ─────────────────────────────────────────────────────────────────────
echo -e "${YELLOW}── Slack Alerts ──${NC}"
SLACK_ENABLED=$(ask "Enable Slack alerts? (true/false)" "true")
set_toml "enabled" "$SLACK_ENABLED"

if [[ "$SLACK_ENABLED" == "true" ]]; then
    WEBHOOK=$(ask "Slack webhook URL" "")
    if [[ -n "$WEBHOOK" ]]; then
        set_toml "webhook_url" "\"$WEBHOOK\""
    fi

    BACKUP_WEBHOOK=$(ask "Backup webhook URL (optional, press Enter to skip)" "")
    if [[ -n "$BACKUP_WEBHOOK" ]]; then
        set_toml "backup_webhook_url" "\"$BACKUP_WEBHOOK\""
    fi

    CHANNEL=$(ask "Slack channel" "#devops")
    set_toml "channel" "\"$CHANNEL\""

    SLACK_LEVEL=$(ask "Min Slack alert level (info/warning/critical)" "warning")
    set_toml "min_slack_level" "\"$SLACK_LEVEL\""
fi
echo ""

# ── API ───────────────────────────────────────────────────────────────────────
echo -e "${YELLOW}── API Server ──${NC}"
API_ENABLED=$(ask "Enable JSON API? (true/false)" "true")
set_toml "enabled" "$API_ENABLED"

if [[ "$API_ENABLED" == "true" ]]; then
    API_PORT=$(ask "API port" "18791")
    set_toml "port" "$API_PORT"
fi
echo ""

# ── BarnacleDefense ───────────────────────────────────────────────────────────
echo -e "${YELLOW}── BarnacleDefense Pattern Databases ──${NC}"
SC_ENABLED=$(ask "Enable BarnacleDefense patterns? (true/false)" "true")
set_toml "enabled" "$SC_ENABLED"
echo ""

# ── Scans ─────────────────────────────────────────────────────────────────────
echo -e "${YELLOW}── Security Scans ──${NC}"
INTERVAL=$(ask "Scan interval in seconds" "3600")
set_toml "interval" "$INTERVAL"
echo ""

# ── Done ──────────────────────────────────────────────────────────────────────
echo -e "${GREEN}✅ Config updated: $CONFIG${NC}"
echo ""
echo -e "  Review:   ${CYAN}cat $CONFIG${NC}"
echo -e "  Start:    ${CYAN}sudo systemctl start clawtower${NC}"
echo -e "  TUI:      ${CYAN}clawtower $CONFIG${NC}"
echo ""
