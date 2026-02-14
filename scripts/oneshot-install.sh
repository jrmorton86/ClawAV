#!/usr/bin/env bash
# ClawAV Oneshot Installer — Interactive guided install
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/coltz108/ClawAV/main/scripts/oneshot-install.sh | sudo bash
#   curl -sSL https://raw.githubusercontent.com/coltz108/ClawAV/main/scripts/oneshot-install.sh | sudo bash -s -- --version v0.1.0
#
set -euo pipefail

REPO="coltz108/ClawAV"
VERSION="${1:-latest}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log()  { echo -e "${GREEN}[CLAWAV]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
die()  { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

confirm() {
    local prompt="$1"
    local response
    while true; do
        echo -en "${CYAN}${prompt}${NC} " > /dev/tty
        read -r response < /dev/tty
        case "$response" in
            [yY]|[yY][eE][sS]) return 0 ;;
            [nN]|[nN][oO]) return 1 ;;
            *) echo "Please answer yes or no." > /dev/tty ;;
        esac
    done
}

wait_for_enter() {
    echo -en "${CYAN}$1${NC}" > /dev/tty
    read -r < /dev/tty
}

[[ $EUID -eq 0 ]] || die "Must run as root (pipe to sudo bash, or run with sudo)"

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 1: DOWNLOAD
# ═══════════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  🛡️  ClawAV Installer                                        ${NC}"
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  This installer will:"
echo -e "  ${BOLD}1.${NC} Download ClawAV binaries + SecureClaw patterns"
echo -e "  ${BOLD}2.${NC} Let you configure before anything is locked down"
echo -e "  ${BOLD}3.${NC} Lock the installation (immutable — requires recovery to undo)"
echo ""

if ! confirm "Continue? [y/n]"; then
    echo "Aborted."
    exit 0
fi

# ── Detect architecture ──────────────────────────────────────────────────────
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64)   ARCH_LABEL="x86_64" ;;
    aarch64|arm64)   ARCH_LABEL="aarch64" ;;
    *)               die "Unsupported architecture: $ARCH (need x86_64 or aarch64)" ;;
esac
log "Detected architecture: $ARCH_LABEL"

# ── Resolve version ──────────────────────────────────────────────────────────
if [[ "$VERSION" == "latest" ]]; then
    log "Fetching latest release..."
    VERSION=$(curl -sSL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
    [[ -n "$VERSION" ]] || die "Could not determine latest version. Check https://github.com/$REPO/releases"
fi
log "Installing ClawAV $VERSION"

# ── Download binaries ────────────────────────────────────────────────────────
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

BASE_URL="https://github.com/$REPO/releases/download/$VERSION"
CLAWAV_ARTIFACT="clawav-${ARCH_LABEL}-linux"
CLAWSUDO_ARTIFACT="clawsudo-${ARCH_LABEL}-linux"

log "Downloading $CLAWAV_ARTIFACT..."
curl -sSL -f -o "$TMPDIR/clawav" "$BASE_URL/$CLAWAV_ARTIFACT" || die "Failed to download clawav binary. Does $VERSION exist? Check: $BASE_URL/$CLAWAV_ARTIFACT"

log "Downloading $CLAWSUDO_ARTIFACT..."
curl -sSL -f -o "$TMPDIR/clawsudo" "$BASE_URL/$CLAWSUDO_ARTIFACT" || die "Failed to download clawsudo binary. Check: $BASE_URL/$CLAWSUDO_ARTIFACT"

chmod +x "$TMPDIR/clawav" "$TMPDIR/clawsudo"

# ── Download config + policies ───────────────────────────────────────────────
log "Downloading default config and policies..."
curl -sSL -f -o "$TMPDIR/config.toml" "https://raw.githubusercontent.com/$REPO/$VERSION/config.toml" || warn "Could not download config.toml"
mkdir -p "$TMPDIR/policies"
curl -sSL -f -o "$TMPDIR/policies/default.yaml" "https://raw.githubusercontent.com/$REPO/$VERSION/policies/default.yaml" 2>/dev/null || true
curl -sSL -f -o "$TMPDIR/policies/clawsudo.yaml" "https://raw.githubusercontent.com/$REPO/$VERSION/policies/clawsudo.yaml" 2>/dev/null || true

# ── Download SecureClaw patterns ──────────────────────────────────────────────
log "Downloading SecureClaw pattern databases..."
SECURECLAW_BASE="https://raw.githubusercontent.com/adversa-ai/secureclaw/main/secureclaw/skill/configs"
mkdir -p "$TMPDIR/secureclaw"
for pattern in injection-patterns.json dangerous-commands.json privacy-rules.json supply-chain-ioc.json; do
    curl -sSL -f -o "$TMPDIR/secureclaw/$pattern" "$SECURECLAW_BASE/$pattern" 2>/dev/null && \
        log "  ✓ $pattern" || \
        warn "  ✗ $pattern (non-fatal)"
done

# ── Install auditd ───────────────────────────────────────────────────────────
if ! command -v auditctl &>/dev/null; then
    log "Installing auditd..."
    if command -v apt-get &>/dev/null; then
        apt-get update -qq && apt-get install -y -qq auditd
    elif command -v dnf &>/dev/null; then
        dnf install -y -q audit
    elif command -v pacman &>/dev/null; then
        pacman -S --noconfirm audit
    else
        warn "Could not install auditd — install it manually"
    fi
fi

# ── Create directories and install files (NOT locked down yet) ────────────────
log "Setting up directories..."
mkdir -p /etc/clawav/policies /etc/clawav/secureclaw /var/log/clawav /var/run/clawav

# Stop existing service if upgrading
if systemctl is-active --quiet clawav 2>/dev/null; then
    log "Stopping existing ClawAV service..."
    systemctl stop clawav
    sleep 1
fi

# Remove immutable flags if upgrading
chattr -i /usr/local/bin/clawav 2>/dev/null || true
chattr -i /usr/local/bin/clawsudo 2>/dev/null || true
chattr -i /etc/clawav/config.toml 2>/dev/null || true

log "Installing binaries to /usr/local/bin/..."
cp "$TMPDIR/clawav" /usr/local/bin/clawav
cp "$TMPDIR/clawsudo" /usr/local/bin/clawsudo
chmod 755 /usr/local/bin/clawav /usr/local/bin/clawsudo

# Install config (don't overwrite existing)
if [[ ! -f /etc/clawav/config.toml ]]; then
    [[ -f "$TMPDIR/config.toml" ]] && cp "$TMPDIR/config.toml" /etc/clawav/config.toml
fi

# Install policies (don't overwrite existing)
for f in "$TMPDIR"/policies/*.yaml; do
    fname=$(basename "$f")
    [[ -f "/etc/clawav/policies/$fname" ]] || cp "$f" "/etc/clawav/policies/$fname"
done

# Install SecureClaw patterns
for f in "$TMPDIR"/secureclaw/*.json; do
    [[ -f "$f" ]] && cp "$f" "/etc/clawav/secureclaw/"
done

# Install systemd service
cat > /etc/systemd/system/clawav.service <<'EOF'
[Unit]
Description=ClawAV Security Watchdog
After=network.target auditd.service
Wants=auditd.service

[Service]
Type=simple
ExecStart=/usr/local/bin/clawav --headless --config /etc/clawav/config.toml
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable clawav

echo ""
log "✓ Phase 1 complete — files installed (NOT locked down yet)"

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 2: CONFIGURE
# ═══════════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${YELLOW}${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}${BOLD}  ⚙️   CONFIGURATION                                           ${NC}"
echo -e "${YELLOW}${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo ""
CONF="/etc/clawav/config.toml"

# ── Watched User ──────────────────────────────────────────────────────────────
CALLING_USER="${SUDO_USER:-$(whoami)}"
CALLING_UID=$(id -u "$CALLING_USER" 2>/dev/null || echo "1000")
echo ""
echo -e "  ${BOLD}User to monitor:${NC} $CALLING_USER (UID $CALLING_UID)"
echo -en "  ${CYAN}Monitor this user? [Y/n] or enter a different UID: ${NC}" > /dev/tty
read -r user_input < /dev/tty
if [[ -z "$user_input" || "$user_input" =~ ^[yY] ]]; then
    WATCH_UID="$CALLING_UID"
else
    WATCH_UID="$user_input"
fi
sed -i "s/^watched_user = .*/watched_user = \"$WATCH_UID\"/" "$CONF"
log "Watching UID: $WATCH_UID"

# ── Additional Users ──────────────────────────────────────────────────────────
echo ""
echo -en "  ${CYAN}Monitor additional UIDs? (comma-separated, or ENTER to skip): ${NC}" > /dev/tty
read -r extra_uids < /dev/tty
if [[ -n "$extra_uids" ]]; then
    # Build TOML array like ["1000", "1001"]
    UIDS_TOML="[\"$WATCH_UID\""
    IFS=',' read -ra EXTRA <<< "$extra_uids"
    for uid in "${EXTRA[@]}"; do
        uid=$(echo "$uid" | tr -d ' ')
        [[ -n "$uid" ]] && UIDS_TOML+=", \"$uid\""
    done
    UIDS_TOML+="]"
    sed -i "s/^.*watched_users = .*/watched_users = $UIDS_TOML/" "$CONF"
    log "Watching UIDs: $UIDS_TOML"
fi

# ── Slack (Optional) ─────────────────────────────────────────────────────────
echo ""
echo -e "  ${BOLD}Slack Alerts${NC} (optional)"
echo -e "  ClawAV can send alerts to an independent Slack webhook."
echo -en "  ${CYAN}Slack webhook URL (or ENTER to skip): ${NC}" > /dev/tty
read -r slack_url < /dev/tty
if [[ -n "$slack_url" ]]; then
    sed -i "s|^webhook_url = .*|webhook_url = \"$slack_url\"|" "$CONF"
    sed -i "s/^enabled = false/enabled = true/" "$CONF"  # enable slack section
    log "Slack alerts enabled"

    echo -en "  ${CYAN}Slack channel (default: #devops): ${NC}" > /dev/tty
    read -r slack_chan < /dev/tty
    [[ -n "$slack_chan" ]] && sed -i "s|^channel = .*|channel = \"$slack_chan\"|" "$CONF"

    echo -en "  ${CYAN}Backup webhook URL (or ENTER to skip): ${NC}" > /dev/tty
    read -r slack_backup < /dev/tty
    [[ -n "$slack_backup" ]] && sed -i "s|^backup_webhook_url = .*|backup_webhook_url = \"$slack_backup\"|" "$CONF"
else
    log "Slack alerts skipped — alerts go to logs only"
fi

# ── API ───────────────────────────────────────────────────────────────────────
echo ""
echo -e "  ${BOLD}JSON API${NC} (LAN-only status/alerts endpoint)"
echo -en "  ${CYAN}Enable API on port 18791? [Y/n]: ${NC}" > /dev/tty
read -r api_input < /dev/tty
if [[ "$api_input" =~ ^[nN] ]]; then
    sed -i '/^\[api\]/,/^$/s/^enabled = true/enabled = false/' "$CONF"
    log "API disabled"
else
    log "API enabled on port 18791"
fi

# ── SecureClaw ────────────────────────────────────────────────────────────────
echo ""
echo -e "  ${BOLD}SecureClaw${NC} (prompt injection + supply chain detection patterns)"
echo -en "  ${CYAN}Enable SecureClaw? [Y/n]: ${NC}" > /dev/tty
read -r sc_input < /dev/tty
if [[ "$sc_input" =~ ^[nN] ]]; then
    log "SecureClaw disabled"
else
    sed -i '/^\[secureclaw\]/,/^$/s/^enabled = false/enabled = true/' "$CONF"
    sed -i "s|^vendor_dir = .*|vendor_dir = \"/etc/clawav/secureclaw\"|" "$CONF"
    log "SecureClaw enabled"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "  ${GREEN}${BOLD}Configuration summary:${NC}"
echo -e "  ${BOLD}Config file:${NC}    $CONF"
echo -e "  ${BOLD}Watched user:${NC}   UID $WATCH_UID"
if grep -q 'webhook_url = ""' "$CONF" 2>/dev/null || ! grep -q 'webhook_url' "$CONF" 2>/dev/null; then
    echo -e "  ${BOLD}Slack:${NC}          Disabled (logs only)"
else
    echo -e "  ${BOLD}Slack:${NC}          Enabled"
fi
echo ""
echo -e "  ${YELLOW}You can always edit $CONF later (before locking down).${NC}"
echo ""

if ! confirm "Configuration done? Ready to lock down? [y/n]"; then
    echo ""
    echo "  Config saved at /etc/clawav/config.toml"
    echo "  Binaries installed but NOT locked down."
    echo "  Re-run installer when ready to lock down."
    exit 0
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 3: LOCK DOWN (SWALLOWED KEY)
# ═══════════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${RED}${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${RED}${BOLD}  🔒  LOCKING DOWN — THIS IS IRREVERSIBLE WITHOUT RECOVERY     ${NC}"
echo -e "${RED}${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# ── Create system user ────────────────────────────────────────────────────────
if ! id -u clawav &>/dev/null; then
    log "Creating clawav system user..."
    useradd --system --no-create-home --shell /usr/sbin/nologin clawav
fi
chown -R clawav:clawav /etc/clawav /var/log/clawav /var/run/clawav

# ── Set immutable attributes ─────────────────────────────────────────────────
log "Setting immutable flags (chattr +i)..."
chattr +i /usr/local/bin/clawav
chattr +i /usr/local/bin/clawsudo
chattr +i /etc/clawav/config.toml
chattr +i /etc/systemd/system/clawav.service

# ── AppArmor profile ─────────────────────────────────────────────────────────
if command -v apparmor_parser &>/dev/null; then
    log "Installing AppArmor profile..."
    cat > /etc/apparmor.d/clawav.deny-agent <<'APPARMOR'
# Deny AI agent user access to ClawAV paths
/usr/local/bin/clawav r,
/usr/local/bin/clawsudo r,
deny /etc/clawav/** w,
deny /var/log/clawav/** w,
deny /etc/systemd/system/clawav.service w,
APPARMOR
    apparmor_parser -r /etc/apparmor.d/clawav.deny-agent 2>/dev/null || warn "AppArmor profile load failed (non-fatal)"
fi

# ── Kernel hardening ─────────────────────────────────────────────────────────
log "Applying kernel hardening..."
sysctl -w kernel.modules_disabled=1 2>/dev/null || warn "Could not disable module loading"
sysctl -w kernel.yama.ptrace_scope=2 2>/dev/null || warn "Could not set ptrace scope"

# ── Lock audit config ────────────────────────────────────────────────────────
if command -v auditctl &>/dev/null; then
    log "Locking audit configuration..."
    auditctl -e 2 2>/dev/null || warn "Could not lock auditd (may need reboot)"
fi

# ── Start the service ────────────────────────────────────────────────────────
log "Starting ClawAV..."
systemctl start clawav
sleep 2

if systemctl is-active --quiet clawav; then
    log "✓ ClawAV is running"
else
    warn "ClawAV did not start — check: journalctl -u clawav -n 50"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 4: ADMIN KEY
# ═══════════════════════════════════════════════════════════════════════════════
echo ""
echo ""
echo -e "${RED}${BOLD}╔══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}${BOLD}║                                                                  ║${NC}"
echo -e "${RED}${BOLD}║   ⚠️  SAVE YOUR ADMIN KEY — YOU WILL NOT SEE IT AGAIN ⚠️          ║${NC}"
echo -e "${RED}${BOLD}║                                                                  ║${NC}"
echo -e "${RED}${BOLD}║   Your admin key was displayed when ClawAV first started.        ║${NC}"
echo -e "${RED}${BOLD}║   Check the service logs:                                        ║${NC}"
echo -e "${RED}${BOLD}║                                                                  ║${NC}"
echo -e "${RED}${BOLD}║     sudo journalctl -u clawav -n 50 | grep OCAV-                 ║${NC}"
echo -e "${RED}${BOLD}║                                                                  ║${NC}"
echo -e "${RED}${BOLD}║   WITHOUT THIS KEY:                                              ║${NC}"
echo -e "${RED}${BOLD}║   • You cannot pause, configure, or manage ClawAV                ║${NC}"
echo -e "${RED}${BOLD}║   • You cannot update or uninstall it                            ║${NC}"
echo -e "${RED}${BOLD}║   • Your ONLY option is RECOVERY MODE (boot from USB)            ║${NC}"
echo -e "${RED}${BOLD}║                                                                  ║${NC}"
echo -e "${RED}${BOLD}║   Save it in your password manager NOW.                          ║${NC}"
echo -e "${RED}${BOLD}║                                                                  ║${NC}"
echo -e "${RED}${BOLD}╚══════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo ""

# Show the key right here if we can find it
ADMIN_KEY=$(journalctl -u clawav -n 50 --no-pager 2>/dev/null | grep -oP 'OCAV-[a-f0-9]+' | head -1)
if [[ -n "$ADMIN_KEY" ]]; then
    echo -e "  ${BOLD}Your admin key:${NC}"
    echo ""
    echo -e "    ${GREEN}${BOLD}$ADMIN_KEY${NC}"
    echo ""
fi

while true; do
    echo -en "${RED}${BOLD}  Type 'I SAVED MY KEY' to confirm: ${NC}" > /dev/tty
    read -r response < /dev/tty
    if [[ "$response" == "I SAVED MY KEY" ]]; then
        break
    fi
    echo -e "  ${RED}You must type exactly: I SAVED MY KEY${NC}" > /dev/tty
done

echo ""
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  ✅  ClawAV $VERSION installed and locked down                ${NC}"
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}Binaries:${NC}  /usr/local/bin/clawav, /usr/local/bin/clawsudo"
echo -e "  ${BOLD}Config:${NC}    /etc/clawav/config.toml (immutable)"
echo -e "  ${BOLD}Logs:${NC}      journalctl -u clawav -f"
echo -e "  ${BOLD}Status:${NC}    systemctl status clawav"
echo -e "  ${BOLD}Patterns:${NC}  /etc/clawav/secureclaw/"
echo ""
