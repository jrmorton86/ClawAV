#!/bin/bash
set -euo pipefail

RULES_FILE="/etc/audit/rules.d/clawtower.rules"

cat > "$RULES_FILE" << 'EOF'
# ClawTower audit rules — comprehensive monitoring

# === Tamper detection ===
-w /usr/local/bin/clawtower -p a -k clawtower-tamper
-w /etc/clawtower/ -p wa -k clawtower-config
-w /etc/systemd/system/clawtower.service -p wa -k clawtower-tamper
-w /etc/sudoers.d/clawtower-deny -p wa -k clawtower-tamper
-w /etc/apparmor.d/clawtower.deny-agent -p wa -k clawtower-tamper
-w /usr/bin/chattr -p x -k clawtower-tamper

# === Credential file read monitoring (Flag 1 — EXFIL) ===
-w /home/openclaw/.openclaw/agents/main/agent/auth-profiles.json -p r -k clawtower_cred_read
-w /home/openclaw/.aws/credentials -p r -k clawtower_cred_read
-w /home/openclaw/.aws/config -p r -k clawtower_cred_read
-w /home/openclaw/.ssh/id_ed25519 -p r -k clawtower_cred_read
-w /home/openclaw/.ssh/id_rsa -p r -k clawtower_cred_read
-w /home/openclaw/.openclaw/gateway.yaml -p r -k clawtower_cred_read

# === OpenClaw session log monitoring ===
-w /home/openclaw/.openclaw/agents/main/sessions/ -p r -k openclaw_session_read

# === Network connect() monitoring (Flag 6 — ESCAPE) ===
-a always,exit -F arch=b64 -S connect -F uid=1000 -F success=1 -k clawtower_net_connect
EOF

# Reload audit rules
augenrules --load 2>/dev/null || auditctl -R "$RULES_FILE"

echo "Audit rules installed and loaded"
