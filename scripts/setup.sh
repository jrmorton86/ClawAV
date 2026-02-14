#!/usr/bin/env bash
# ClawAV Setup Script
#
# Usage:
#   sudo bash scripts/setup.sh              # Install pre-built binaries
#   sudo bash scripts/setup.sh --source     # Build from source + install
#
# Does NOT apply the "swallowed key" hardening — run install.sh for that.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_FROM_SOURCE=false

AUTO_START=false

# Parse flags
for arg in "$@"; do
    case "$arg" in
        --source|--build|--from-source)
            BUILD_FROM_SOURCE=true
            ;;
        --auto)
            AUTO_START=true
            ;;
        --help|-h)
            echo "Usage: sudo bash setup.sh [OPTIONS]"
            echo ""
            echo "  (default)      Install pre-built binaries from target/release/"
            echo "  --source       Build from source first (installs Rust if needed)"
            echo "  --auto         Start the service automatically after install"
            echo "  --source --auto  Full unattended: build + install + start"
            echo ""
            exit 0
            ;;
        *)
            echo "Unknown flag: $arg (try --help)" >&2
            exit 1
            ;;
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
echo -e "${CYAN}║  Will install Rust and build dependencies if needed.         ║${NC}"
else
echo -e "${CYAN}║  Mode: INSTALL PRE-BUILT BINARIES                            ║${NC}"
echo -e "${CYAN}║  Use --source to build from scratch instead.                 ║${NC}"
fi
echo -e "${CYAN}║                                                              ║${NC}"
echo -e "${CYAN}║  No irreversible changes. Run install.sh to harden.          ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Preflight ─────────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "Must run as root (sudo bash scripts/setup.sh)"

# ── Locate or build binaries ──────────────────────────────────────────────────
CLAWAV_BIN="$PROJECT_DIR/target/release/clawav"
CLAWSUDO_BIN="$PROJECT_DIR/target/release/clawsudo"

if $BUILD_FROM_SOURCE; then
    # ── Install system build dependencies ─────────────────────────────────────
    log "Checking system dependencies..."
    if command -v apt-get &>/dev/null; then
        NEEDED=""
        command -v gcc &>/dev/null || NEEDED="$NEEDED build-essential"
        command -v pkg-config &>/dev/null || NEEDED="$NEEDED pkg-config"
        dpkg -l libssl-dev &>/dev/null 2>&1 || NEEDED="$NEEDED libssl-dev"
        command -v git &>/dev/null || NEEDED="$NEEDED git"
        command -v auditctl &>/dev/null || NEEDED="$NEEDED auditd"
        if [[ -n "$NEEDED" ]]; then
            log "Installing system packages:$NEEDED"
            apt-get update -qq
            apt-get install -y -qq $NEEDED
        fi
    elif command -v dnf &>/dev/null; then
        NEEDED=""
        command -v gcc &>/dev/null || NEEDED="$NEEDED gcc"
        command -v pkg-config &>/dev/null || NEEDED="$NEEDED pkg-config"
        command -v git &>/dev/null || NEEDED="$NEEDED git"
        command -v auditctl &>/dev/null || NEEDED="$NEEDED audit"
        if [[ -n "$NEEDED" ]]; then
            log "Installing system packages:$NEEDED"
            dnf install -y -q $NEEDED openssl-devel
        fi
    elif command -v pacman &>/dev/null; then
        command -v gcc &>/dev/null || pacman -S --noconfirm base-devel
        command -v git &>/dev/null || pacman -S --noconfirm git
    fi

    # ── Install Rust if needed ────────────────────────────────────────────────
    export PATH="$HOME/.cargo/bin:/root/.cargo/bin:$PATH"
    for USER_HOME in /home/*/; do
        [[ -f "${USER_HOME}.cargo/bin/cargo" ]] && export PATH="${USER_HOME}.cargo/bin:$PATH"
    done

    if ! command -v cargo &>/dev/null; then
        log "Rust not found — installing via rustup..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable 2>&1 | tail -3
        source "$HOME/.cargo/env" 2>/dev/null || true
        export PATH="$HOME/.cargo/bin:$PATH"
        command -v cargo &>/dev/null || die "Rust installation failed"
        info "Rust installed: $(rustc --version)"
    else
        # Make sure a default toolchain is set
        if ! cargo --version &>/dev/null 2>&1; then
            log "Setting default Rust toolchain..."
            rustup default stable 2>/dev/null || rustup toolchain install stable
            rustup default stable
        fi
        info "Rust found: $(cargo --version 2>/dev/null || echo 'available')"
    fi

    # ── Build ─────────────────────────────────────────────────────────────────
    log "Building ClawAV from source (this may take a few minutes)..."
    cd "$PROJECT_DIR"
    cargo build --release 2>&1 | tail -5
    echo ""

    [[ -f "$CLAWAV_BIN" ]] || die "Build failed — binary not found"
    info "Built: clawav ($(du -h "$CLAWAV_BIN" | cut -f1)), clawsudo ($(du -h "$CLAWSUDO_BIN" | cut -f1))"

else
    # ── Pre-built mode: just check binaries exist ─────────────────────────────
    if [[ ! -f "$CLAWAV_BIN" ]]; then
        die "Pre-built binary not found at $CLAWAV_BIN
  Either build first:  cargo build --release
  Or run with:         sudo bash scripts/setup.sh --source"
    fi
    info "Using pre-built binaries"
    info "  clawav:   $(du -h "$CLAWAV_BIN" | cut -f1)"
    info "  clawsudo: $(du -h "$CLAWSUDO_BIN" | cut -f1)"
fi

# ── Install system deps (auditd) even in pre-built mode ──────────────────────
if ! command -v auditctl &>/dev/null; then
    log "Installing auditd..."
    if command -v apt-get &>/dev/null; then
        apt-get update -qq && apt-get install -y -qq auditd
    elif command -v dnf &>/dev/null; then
        dnf install -y -q audit
    fi
fi

# ── Create directories ────────────────────────────────────────────────────────
log "Creating directories..."
mkdir -p /etc/clawav/policies /var/log/clawav /var/run/clawav

# ── Install binaries ──────────────────────────────────────────────────────────
log "Installing binaries to /usr/local/bin/..."
cp "$CLAWAV_BIN" /usr/local/bin/clawav
cp "$CLAWSUDO_BIN" /usr/local/bin/clawsudo
chmod 755 /usr/local/bin/clawav /usr/local/bin/clawsudo
info "Installed: /usr/local/bin/clawav, /usr/local/bin/clawsudo"

# ── Install config ────────────────────────────────────────────────────────────
if [[ -f /etc/clawav/config.toml ]]; then
    warn "Config already exists at /etc/clawav/config.toml — keeping existing"
else
    log "Installing default config..."
    cp "$PROJECT_DIR/config.toml" /etc/clawav/config.toml
    chmod 640 /etc/clawav/config.toml
    info "Config installed to /etc/clawav/config.toml"
    echo ""
    warn "You should edit /etc/clawav/config.toml before starting:"
    info "  • Set [general] watched_user to your agent's UID"
    info "  • Set [slack] webhook_url for independent alerts"
    info "  • Enable modules you want ([api], [secureclaw], [netpolicy])"
    echo ""
fi

# ── Install policies ──────────────────────────────────────────────────────────
if [[ -d "$PROJECT_DIR/policies" ]] && [[ -n "$(ls -A "$PROJECT_DIR/policies/" 2>/dev/null)" ]]; then
    log "Installing policy files..."
    cp "$PROJECT_DIR/policies/"*.yaml /etc/clawav/policies/ 2>/dev/null || true
    info "Policies installed to /etc/clawav/policies/"
fi

# ── Build LD_PRELOAD guard (optional, source mode only) ──────────────────────
if $BUILD_FROM_SOURCE && [[ -f "$SCRIPT_DIR/build-preload.sh" ]]; then
    log "Building LD_PRELOAD guard..."
    if bash "$SCRIPT_DIR/build-preload.sh" 2>/dev/null; then
        info "LD_PRELOAD guard built (enable later with scripts/enable-preload.sh)"
    else
        warn "LD_PRELOAD build failed (optional — needs gcc and libc headers)"
    fi
fi

# ── Initialize SecureClaw submodule (optional) ────────────────────────────────
if [[ -f "$PROJECT_DIR/.gitmodules" ]] && command -v git &>/dev/null; then
    log "Initializing SecureClaw pattern databases..."
    cd "$PROJECT_DIR"
    if git submodule update --init vendor/secureclaw 2>/dev/null; then
        info "SecureClaw patterns loaded — enable with [secureclaw] enabled = true"
    else
        warn "SecureClaw submodule init failed (optional)"
    fi
fi

# ── Create systemd service ────────────────────────────────────────────────────
log "Installing systemd service..."
cat > /etc/systemd/system/clawav.service <<'EOF'
[Unit]
Description=ClawAV Security Watchdog
After=network.target auditd.service
Wants=auditd.service

[Service]
Type=simple
ExecStart=/usr/local/bin/clawav --headless /etc/clawav/config.toml
Restart=always
RestartSec=5
WatchdogSec=30
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
info "Service installed and enabled (will start on boot)"

# ── Set up auditd rules (if available) ────────────────────────────────────────
if command -v auditctl &>/dev/null; then
    log "Setting up auditd rules..."
    if [[ -f "$SCRIPT_DIR/setup-auditd.sh" ]]; then
        bash "$SCRIPT_DIR/setup-auditd.sh" 2>/dev/null || warn "Auditd setup had issues (check manually)"
    fi
fi

# ── Auto-start if requested ──────────────────────────────────────────────────
if $AUTO_START; then
    log "Starting ClawAV service..."
    systemctl restart clawav
    sleep 2
    if systemctl is-active --quiet clawav; then
        info "✅ ClawAV is running!"
        echo ""
        log "Live logs:"
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
echo -e "${GREEN}║  Binaries:  /usr/local/bin/clawav                           ║${NC}"
echo -e "${GREEN}║             /usr/local/bin/clawsudo                         ║${NC}"
echo -e "${GREEN}║  Config:    /etc/clawav/config.toml                         ║${NC}"
echo -e "${GREEN}║  Policies:  /etc/clawav/policies/                           ║${NC}"
echo -e "${GREEN}║  Logs:      /var/log/clawav/                                ║${NC}"
echo -e "${GREEN}║  Service:   clawav.service                                  ║${NC}"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  Next steps:                                                 ║${NC}"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}║  1. Configure (interactive prompts):                          ║${NC}"
echo -e "${GREEN}║     sudo bash scripts/configure.sh                          ║${NC}"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}║  2. Start the service:                                       ║${NC}"
echo -e "${GREEN}║     sudo systemctl start clawav                             ║${NC}"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}║  3. Check status:                                            ║${NC}"
echo -e "${GREEN}║     sudo systemctl status clawav                            ║${NC}"
echo -e "${GREEN}║     sudo journalctl -u clawav -f                            ║${NC}"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}║  4. Run TUI dashboard (interactive):                         ║${NC}"
echo -e "${GREEN}║     clawav /etc/clawav/config.toml                          ║${NC}"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}║  5. (Optional) Lock it down permanently:                     ║${NC}"
echo -e "${GREEN}║     sudo bash scripts/install.sh                            ║${NC}"
echo -e "${GREEN}║     ⚠️  Irreversible without recovery boot!                  ║${NC}"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
