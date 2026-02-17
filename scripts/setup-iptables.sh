#!/bin/bash
# Setup firewall rules to log openclaw user network activity
# Run as root

set -euo pipefail

WATCHED_USER="openclaw"
WATCHED_UID=$(id -u "$WATCHED_USER" 2>/dev/null || echo "")
LOG_PREFIX="CLAWTOWER_NET"

if [ -z "$WATCHED_UID" ]; then
    echo "ERROR: User '$WATCHED_USER' not found"
    exit 1
fi

# Detect firewall backend
if command -v nft &>/dev/null && nft list ruleset &>/dev/null 2>&1; then
    FW_BACKEND="nftables"
elif command -v iptables &>/dev/null; then
    FW_BACKEND="iptables"
else
    echo "ERROR: Neither iptables nor nftables found"
    exit 1
fi

echo "Detected firewall backend: $FW_BACKEND"
echo "Setting up logging for user $WATCHED_USER (uid=$WATCHED_UID)..."

if [ "$FW_BACKEND" = "iptables" ]; then
    # Define the rule arguments (without iptables command prefix)
    RULE_ARGS="-m owner --uid-owner $WATCHED_UID -m state --state NEW -j LOG --log-prefix ${LOG_PREFIX}:  --log-level 4"

    # Check if rule already exists (idempotent)
    if iptables -C OUTPUT $RULE_ARGS 2>/dev/null; then
        echo "Rule already exists, skipping."
    else
        iptables -A OUTPUT $RULE_ARGS
        echo "iptables rule added."
    fi

    # Verify
    echo ""
    echo "Active rules for uid $WATCHED_UID:"
    iptables -L OUTPUT -n -v | head -3
    iptables -L OUTPUT -n -v | grep "$LOG_PREFIX" && echo "✅ Rule verified active" || echo "❌ Rule NOT found"

else
    # nftables backend
    TABLE_NAME="clawtower"
    CHAIN_NAME="output_log"

    # Check if our table already exists
    if nft list table inet "$TABLE_NAME" &>/dev/null; then
        echo "nftables table '$TABLE_NAME' already exists, skipping."
    else
        nft add table inet "$TABLE_NAME"
        nft add chain inet "$TABLE_NAME" "$CHAIN_NAME" '{ type filter hook output priority 0; policy accept; }'
        nft add rule inet "$TABLE_NAME" "$CHAIN_NAME" meta skuid "$WATCHED_UID" ct state new log prefix "\"${LOG_PREFIX}: \"" level info
        echo "nftables rules added."
    fi

    # Verify
    echo ""
    echo "Active nftables rules:"
    nft list table inet "$TABLE_NAME"
    echo "✅ Rule verified active"
fi

echo ""
echo "Log prefix: $LOG_PREFIX"
echo "Logs will appear in /var/log/syslog or journalctl"
