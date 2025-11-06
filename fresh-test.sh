#!/bin/bash
# Fresh test script - clears all logs and runs clean test

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    SUDO=""
else
    SUDO="sudo"
fi

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Fresh Test - Clear All & Test${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Step 1: Stop service
echo -e "${YELLOW}[1/5] Stopping service...${NC}"
$SUDO systemctl stop secrds 2>/dev/null || true
sleep 1
echo -e "${GREEN}✓ Service stopped${NC}"
echo ""

# Step 2: Clear storage file
echo -e "${YELLOW}[2/5] Clearing storage file...${NC}"
$SUDO rm -f /var/lib/secrds/events.json
$SUDO mkdir -p /var/lib/secrds
echo -e "${GREEN}✓ Storage cleared${NC}"
echo ""

# Step 3: Clear systemd logs
echo -e "${YELLOW}[3/5] Clearing systemd logs...${NC}"
$SUDO journalctl --vacuum-time=1s -u secrds > /dev/null 2>&1 || true
echo -e "${GREEN}✓ Logs cleared${NC}"
echo ""

# Step 4: Restart service
echo -e "${YELLOW}[4/5] Restarting service...${NC}"
$SUDO systemctl start secrds
sleep 2

if $SUDO systemctl is-active --quiet secrds 2>/dev/null; then
    echo -e "${GREEN}✓ Service started${NC}"
else
    echo -e "${RED}✗ Failed to start service${NC}"
    exit 1
fi
echo ""

# Step 5: Run test
echo -e "${YELLOW}[5/5] Running fresh SSH attack test...${NC}"
echo ""

# Check if sshpass is installed
if ! command -v sshpass &> /dev/null; then
    echo -e "${YELLOW}Installing sshpass...${NC}"
    $SUDO apt-get update -qq && $SUDO apt-get install -y sshpass > /dev/null 2>&1 || {
        echo -e "${RED}Failed to install sshpass${NC}"
        exit 1
    }
fi

# Make test attempts
ATTEMPTS=5
echo -e "${BLUE}Making ${ATTEMPTS} SSH connection attempts...${NC}"
echo ""

for i in $(seq 1 $ATTEMPTS); do
    echo -n "  Attempt $i/$ATTEMPTS... "
    
    # Try SSH with wrong password
    timeout 2 sshpass -p "wrongpass123" ssh -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o PreferredAuthentications=password \
        -o PubkeyAuthentication=no \
        -o ConnectTimeout=2 \
        -o BatchMode=yes \
        root@localhost "exit" 2>/dev/null || true
    
    sleep 0.5
    echo "done"
done

echo ""
echo -e "${YELLOW}Waiting for detection...${NC}"
sleep 3

# Check for alerts
ALERT_COUNT=$(secrds alerts 2>/dev/null | grep -c "SSH_BRUTE_FORCE\|SSH" || echo "0")

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Test Results${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

if [ "$ALERT_COUNT" -gt 0 ]; then
    echo -e "${GREEN}✓ SUCCESS: Alerts detected!${NC}"
    echo ""
    echo -e "${YELLOW}Recent alerts:${NC}"
    secrds alerts --limit 5
    echo ""
    
    # Show debug logs
    echo -e "${YELLOW}Recent debug logs:${NC}"
    $SUDO journalctl -u secrds --no-pager -n 50 2>/dev/null | grep -E "DEBUG|SSH event|Threat detected" | tail -10 || echo "No debug logs found"
    echo ""
    
    echo -e "${GREEN}✓ Fresh test PASSED!${NC}"
else
    echo -e "${RED}✗ FAILED: No alerts detected${NC}"
    echo ""
    
    # Show recent logs
    echo -e "${YELLOW}Recent service logs:${NC}"
    $SUDO journalctl -u secrds --no-pager -n 30 2>/dev/null | tail -20
    echo ""
    
    # Check for events
    echo -e "${YELLOW}Checking for SSH events:${NC}"
    if $SUDO journalctl -u secrds --no-pager 2>/dev/null | grep -q "SSH event received"; then
        echo -e "${GREEN}✓ Events received:${NC}"
        $SUDO journalctl -u secrds --no-pager 2>/dev/null | grep "SSH event received" | tail -5
    else
        echo -e "${RED}✗ No SSH events found${NC}"
    fi
    
    exit 1
fi

echo ""
echo -e "${GREEN}All tests passed!${NC}"

