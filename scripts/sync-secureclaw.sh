#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
echo "Syncing SecureClaw patterns..."
git submodule update --remote vendor/secureclaw
echo "SecureClaw updated to $(cd vendor/secureclaw && git rev-parse --short HEAD)"