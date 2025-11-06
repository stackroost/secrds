#!/bin/bash
# Quick script to clear all logs and storage

set -e

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    SUDO=""
else
    SUDO="sudo"
fi

echo "Clearing all secrds logs and storage..."

# Stop service
$SUDO systemctl stop secrds 2>/dev/null || true

# Clear storage
$SUDO rm -f /var/lib/secrds/events.json
$SUDO mkdir -p /var/lib/secrds

# Clear logs
$SUDO journalctl --vacuum-time=1s -u secrds > /dev/null 2>&1 || true

# Restart service
$SUDO systemctl start secrds

echo "✓ All cleared! Service restarted."
echo ""
echo "Run test: ./fresh-test.sh"

