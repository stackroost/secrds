#!/bin/bash
# Comprehensive fix and test script for secrds detection

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    SUDO=""
    echo -e "${YELLOW}Running as root, skipping sudo${NC}"
else
    SUDO="sudo"
    echo -e "${YELLOW}Not running as root, will use sudo${NC}"
fi

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}secrds Detection Fix & Test Script${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Step 1: Check if service is running
echo -e "${YELLOW}[1/6] Checking service status...${NC}"
if $SUDO systemctl is-active --quiet secrds 2>/dev/null; then
    echo -e "${GREEN}✓ Service is running${NC}"
    SERVICE_RUNNING=true
else
    echo -e "${RED}✗ Service is NOT running${NC}"
    SERVICE_RUNNING=false
fi
echo ""

# Step 2: Rebuild
echo -e "${YELLOW}[2/6] Rebuilding project...${NC}"
if make build; then
    echo -e "${GREEN}✓ Build successful${NC}"
else
    echo -e "${RED}✗ Build failed${NC}"
    exit 1
fi
echo ""

# Step 3: Reinstall
echo -e "${YELLOW}[3/6] Reinstalling...${NC}"
if $SUDO ./install.sh 2>&1 | tail -20; then
    echo -e "${GREEN}✓ Installation complete${NC}"
else
    echo -e "${RED}✗ Installation failed${NC}"
    exit 1
fi
echo ""

# Step 4: Verify service
echo -e "${YELLOW}[4/6] Verifying service...${NC}"
sleep 2
if $SUDO systemctl is-active --quiet secrds 2>/dev/null; then
    echo -e "${GREEN}✓ Service is running${NC}"
else
    echo -e "${YELLOW}⚠ Service not running, attempting to start...${NC}"
    $SUDO systemctl start secrds
    sleep 2
    if $SUDO systemctl is-active --quiet secrds 2>/dev/null; then
        echo -e "${GREEN}✓ Service started${NC}"
    else
        echo -e "${RED}✗ Failed to start service${NC}"
        echo "Check logs: sudo journalctl -u secrds -n 50"
        exit 1
    fi
fi
echo ""

# Step 5: Check eBPF program
echo -e "${YELLOW}[5/6] Checking eBPF program attachment...${NC}"
if $SUDO journalctl -u secrds --no-pager 2>/dev/null | grep -q "Attached kprobe"; then
    echo -e "${GREEN}✓ eBPF program attached${NC}"
    $SUDO journalctl -u secrds --no-pager 2>/dev/null | grep "Attached kprobe" | tail -3
else
    echo -e "${YELLOW}⚠ No kprobe attachment found in logs${NC}"
fi
echo ""

# Step 6: Run test
echo -e "${YELLOW}[6/6] Running SSH attack simulation...${NC}"
echo ""

# Check if sshpass is installed
if ! command -v sshpass &> /dev/null; then
    echo -e "${YELLOW}Installing sshpass for testing...${NC}"
    $SUDO apt-get update -qq && $SUDO apt-get install -y sshpass > /dev/null 2>&1 || {
        echo -e "${RED}Failed to install sshpass. Install manually: apt install sshpass${NC}"
        exit 1
    }
fi

# Clear old alerts for clean test
echo -e "${YELLOW}Clearing old alerts...${NC}"
$SUDO rm -f /var/lib/secrds/events.json
$SUDO systemctl restart secrds
sleep 2

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
    secrds alerts --limit 3
    echo ""
    echo -e "${GREEN}Detection is working correctly!${NC}"
else
    echo -e "${RED}✗ FAILED: No alerts detected${NC}"
    echo ""
    echo -e "${YELLOW}Debugging information:${NC}"
    echo ""
    
    # Check logs
    echo -e "${BLUE}Recent service logs:${NC}"
    $SUDO journalctl -u secrds -n 30 --no-pager 2>/dev/null | tail -20
    echo ""
    
    # Check if events are being received
    echo -e "${BLUE}Checking for SSH events in logs:${NC}"
    if $SUDO journalctl -u secrds --no-pager 2>/dev/null | grep -q "SSH event received"; then
        echo -e "${GREEN}✓ Events are being received${NC}"
        $SUDO journalctl -u secrds --no-pager 2>/dev/null | grep "SSH event received" | tail -5
    else
        echo -e "${RED}✗ No SSH events found in logs${NC}"
        echo ""
        echo -e "${YELLOW}Possible issues:${NC}"
        echo "  1. eBPF program not detecting connections"
        echo "  2. Source IP detection failing (check for 'invalid IP' messages)"
        echo "  3. Kernel doesn't support required kprobes"
        echo ""
        echo -e "${YELLOW}Try manual test:${NC}"
        echo "  /usr/local/bin/secrds-agent"
        echo "  # In another terminal, try: ssh root@localhost"
    fi
    echo ""
    
    # Check storage
    if [ -f "/var/lib/secrds/events.json" ]; then
        echo -e "${BLUE}Storage file contents:${NC}"
        cat /var/lib/secrds/events.json | python3 -m json.tool 2>/dev/null | head -30 || cat /var/lib/secrds/events.json | head -30
    fi
    
    exit 1
fi

echo ""
echo -e "${GREEN}All tests passed!${NC}"

