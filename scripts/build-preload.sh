#!/bin/bash
# Build libclawtower.so — LD_PRELOAD syscall interception library
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "[BUILD] Compiling libclawtower.so..."
gcc -shared -fPIC -O2 -Wall -Wextra -Wno-nonnull-compare \
    -o "$PROJECT_DIR/libclawtower.so" \
    "$PROJECT_DIR/src/preload/interpose.c" \
    -ldl

echo "[BUILD] Built: $PROJECT_DIR/libclawtower.so"
