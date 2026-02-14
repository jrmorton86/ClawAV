#!/usr/bin/env bash
# ClawAV Setup Script — One-shot install
#
# Usage:
#   sudo bash scripts/setup.sh                    # Install pre-built binaries
#   sudo bash scripts/setup.sh --source           # Build from source + install
#   sudo bash scripts/setup.sh --source --auto    # Full unattended: build + install + start
#
# Reversible. Run `clawav harden` to lock down, `clawav uninstall` to remove.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_FROM_SOURCE=false
AUTO_START=false

for arg in "$@"; do
    case "$arg" in
        --source|--build|--from-source)  BUILD_FROM_SOURCE=true ;;
        --auto)                          AUTO_START=true ;;
        --help|-h)
            echo "Usage: sudo bash setup.sh [OPTIONS]"
            echo ""
            echo "  (default)        Install pre-built binaries from target/release/"
            echo "  --source         Build from source (installs Rust if needed)"
            echo "  --auto           Start the service automatically after install"
            echo "  --source --auto  Full unattended: build + install + start"
            echo ""
            exit 0
            ;;
        *) echo "Unknown flag: $arg (try --help)" >&2; exit 1 ;;
    esac
done

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[SETUP]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
info() { echo -e "${CYAN}[INFO]${NC} $*"; }
die()  { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                🛡️  ClawAV Setup                             ║${NC}"
echo -e "${CYAN}║                                                              ║${NC}"
if $BUILD_FROM_SOURCE; then
echo -e "${CYAN}║  Mode: BUILD FROM SOURCE                                     ║${NC}"
else
echo -e "${CYAN}║  Mode: INSTALL PRE-BUILT BINARIES                            ║${NC}"
fi
echo -e "${CYAN}║  Reversible — use 'clawav uninstall' to remove.              ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Preflight ─────────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "Must run as root (sudo bash scripts/setup.sh)"

CLAWAV_BIN="$PROJECT_DIR/target/release/clawav"
CLAWSUDO_BIN="$PROJECT_DIR/target/release/clawsudo"

# ── Build from source (if requested) ─────────────────────────────────────────
if $BUILD_FROM_SOURCE; then
    log "Checking system dependencies..."
    if command -v apt-get &>/dev/null; then
        NEEDED=""
        command -v gcc &>/dev/null || NEEDED="$NEEDED build-essential"
        command -v pkg-config &>/dev/null || NEEDED="$NEEDED pkg-config"
        dpkg -l libssl-dev &>/dev/null 2>&1 || NEEDED="$NEEDED libssl-dev"
        command -v git &>/dev/null || NEEDED="$NEEDED git"
        command -v auditctl &>/dev/null || NEEDED="$NEEDED auditd"
        if [[ -n "$NEEDED" ]]; then
            log "Installing:$NEEDED"
            apt-get update -qq && apt-get install -y -qq $NEEDED
        fi
    elif command -v dnf &>/dev/null; then
        NEEDED=""
        command -v gcc &>/dev/null || NEEDED="$NEEDED gcc"
        command -v pkg-config &>/dev/null || NEEDED="$NEEDED pkg-config"
        command -v git &>/dev/null || NEEDED="$NEEDED git"
        command -v auditctl &>/dev/null || NEEDED="$NEEDED audit"
        [[ -z "$NEEDED" ]] || dnf install -y -q $NEEDED openssl-devel
    elif command -v pacman &>/dev/null; then
        command -v gcc &>/dev/null || pacman -S --noconfirm base-devel
        command -v git &>/dev/null || pacman -S --noconfirm git
    fi

    # Find or install Rust
    export PATH="$HOME/.cargo/bin:/root/.cargo/bin:$PATH"
    for USER_HOME in /home/*/; do
        [[ -f "${USER_HOME}.cargo/bin/cargo" ]] && export PATH="${USER_HOME}.cargo/bin:$PATH"
    done

    if ! command -v cargo &>/dev/null; then
        log "Installing Rust..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable 2>&1 | tail -3
        source "$HOME/.cargo/env" 2>/dev/null || true
        export PATH="$HOME/.cargo/bin:$PATH"
        command -v cargo &>/dev/null || die "Rust installation failed"
    else
        cargo --version &>/dev/null 2>&1 || { rustup default stable 2>/dev/null || rustup toolchain install stable && rustup default stable; }
    fi
    info "Rust: $(rustc --version 2>/dev/null)"

    log "Building ClawAV (this takes ~1 min on Pi, ~10s on desktop)..."
    cd "$PROJECT_DIR"
    cargo build --release 2>&1 | tail -5
    [[ -f "$CLAWAV_BIN" ]] || die "Build failed"
    info "Built: clawav ($(du -h "$CLAWAV_BIN" | cut -f1)), clawsudo ($(du -h "$CLAWSUDO_BIN" | cut -f1))"
else
    [[ -f "$CLAWAV_BIN" ]] || die "Binary not found at $CLAWAV_BIN — build first or use --source"
    info "Using pre-built: clawav ($(du -h "$CLAWAV_BIN" | cut -f1)), clawsudo ($(du -h "$CLAWSUDO_BIN" | cut -f1))"
fi

# ── Install auditd ───────────────────────────────────────────────────────────
if ! command -v auditctl &>/dev/null; then
    log "Installing auditd..."
    command -v apt-get &>/dev/null && apt-get update -qq && apt-get install -y -qq auditd
    command -v dnf &>/dev/null && dnf install -y -q audit
fi

# ── Create directories ───────────────────────────────────────────────────────
log "Creating directories..."
mkdir -p /etc/clawav/policies /var/log/clawav /var/run/clawav
# Ensure agent user can read logs and write to runtime dir
chown -R "${SUDO_USER:-root}:${SUDO_USER:-root}" /var/log/clawav /var/run/clawav 2>/dev/null || true

# ── Stop existing service (avoid "Text file busy") ───────────────────────────
if systemctl is-active --quiet clawav 2>/dev/null; then
    log "Stopping existing ClawAV service..."
    systemctl stop clawav
    sleep 1
fi

# ── Install binaries ─────────────────────────────────────────────────────────
log "Installing binaries..."
rm -f /usr/local/bin/clawav /usr/local/bin/clawsudo
cp "$CLAWAV_BIN" /usr/local/bin/clawav
cp "$CLAWSUDO_BIN" /usr/local/bin/clawsudo
chmod 755 /usr/local/bin/clawav /usr/local/bin/clawsudo

# ── Install config (preserve existing) ───────────────────────────────────────
if [[ -f /etc/clawav/config.toml ]]; then
    warn "Config exists — keeping /etc/clawav/config.toml"
else
    log "Installing default config..."
    cp "$PROJECT_DIR/config.toml" /etc/clawav/config.toml
fi
chmod 644 /etc/clawav/config.toml

# ── Install policies ─────────────────────────────────────────────────────────
if [[ -d "$PROJECT_DIR/policies" ]]; then
    log "Installing policy files..."
    cp "$PROJECT_DIR/policies/"*.yaml /etc/clawav/policies/ 2>/dev/null || true
fi

# ── Build LD_PRELOAD guard (source mode only) ────────────────────────────────
if $BUILD_FROM_SOURCE && [[ -f "$SCRIPT_DIR/build-preload.sh" ]]; then
    log "Building LD_PRELOAD guard..."
    bash "$SCRIPT_DIR/build-preload.sh" 2>/dev/null && info "LD_PRELOAD guard built" || warn "LD_PRELOAD build failed (optional)"
fi

# ── Initialize SecureClaw patterns ────────────────────────────────────────────
if [[ -f "$PROJECT_DIR/.gitmodules" ]] && command -v git &>/dev/null; then
    log "Loading SecureClaw pattern databases..."
    cd "$PROJECT_DIR"
    git submodule update --init vendor/secureclaw 2>/dev/null && info "SecureClaw: 170+ detection patterns loaded" || warn "SecureClaw init failed (optional)"
fi

# ── Install systemd service ──────────────────────────────────────────────────
log "Installing systemd service..."
cat > /etc/systemd/system/clawav.service <<'EOF'
[Unit]
Description=ClawAV Security Watchdog
After=network.target auditd.service
Wants=auditd.service

[Service]
Type=simple
ExecStart=/usr/local/bin/clawav run --headless /etc/clawav/config.toml
Restart=always
RestartSec=5
NoNewPrivileges=true
ReadWritePaths=/var/log/clawav /var/run/clawav /etc/clawav
RuntimeDirectory=clawav
RuntimeDirectoryMode=0750
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable clawav

# ── Set up auditd rules ──────────────────────────────────────────────────────
if command -v auditctl &>/dev/null && [[ -f "$SCRIPT_DIR/setup-auditd.sh" ]]; then
    log "Setting up auditd rules..."
    bash "$SCRIPT_DIR/setup-auditd.sh" 2>/dev/null || warn "Auditd setup had issues"
fi

# ── Auto-start ────────────────────────────────────────────────────────────────
if $AUTO_START; then
    log "Starting ClawAV..."
    systemctl restart clawav
    sleep 2
    if systemctl is-active --quiet clawav; then
        info "✅ ClawAV is running!"
        echo ""
        journalctl -u clawav -n 10 --no-pager 2>/dev/null || true
    else
        warn "Service failed to start — check: journalctl -u clawav -n 20"
    fi
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ✅ ClawAV setup complete!                                  ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}║  Commands:                                                   ║${NC}"
echo -e "${GREEN}║    clawav help             Show all commands                ║${NC}"
echo -e "${GREEN}║    clawav configure        Set up Slack, users, modules     ║${NC}"
echo -e "${GREEN}║    clawav scan             Quick security scan              ║${NC}"
echo -e "${GREEN}║    clawav status           Service status + alerts          ║${NC}"
echo -e "${GREEN}║    clawav tui              Interactive dashboard            ║${NC}"
echo -e "${GREEN}║    clawav logs             Tail live logs                   ║${NC}"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}║  Service:                                                    ║${NC}"
echo -e "${GREEN}║    sudo systemctl start clawav     Start                    ║${NC}"
echo -e "${GREEN}║    sudo systemctl stop clawav      Stop                     ║${NC}"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}║  Next:                                                       ║${NC}"
echo -e "${GREEN}║    1. clawav configure              Set your Slack webhook  ║${NC}"
echo -e "${GREEN}║    2. sudo systemctl start clawav   Start monitoring        ║${NC}"
echo -e "${GREEN}║    3. clawav scan                   Verify security posture ║${NC}"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}║  Optional:                                                   ║${NC}"
echo -e "${GREEN}║    clawav harden           Lock down (admin key required)   ║${NC}"
echo -e "${GREEN}║    clawav uninstall        Remove (admin key required)      ║${NC}"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
