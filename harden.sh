#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Running Ubuntu Security Hardening Engine ==="
python3 "${SCRIPT_DIR}/hardening.py" "$@"
