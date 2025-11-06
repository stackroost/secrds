#!/bin/bash
# Test script to simulate SSH brute force attacks
# This will make multiple failed SSH login attempts

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}SSH Attack Simulation Test${NC}"
echo "================================"
echo ""

# Check if service is running
if ! systemctl is-active --quiet secrds 2>/dev/null; then
    echo -e "${RED}ERROR: secrds service is not running!${NC}"
    echo "Start it with: sudo systemctl start secrds"
    exit 1
fi

echo -e "${GREEN}✓ secrds service is running${NC}"

# Get local IP
LOCAL_IP=$(hostname -I | awk '{print $1}')
echo -e "${YELLOW}Testing from: ${LOCAL_IP}${NC}"
echo ""

# Number of attempts
ATTEMPTS=${1:-10}
echo -e "${YELLOW}Making ${ATTEMPTS} SSH connection attempts...${NC}"
echo ""

# Count successful detections
SUCCESS_COUNT=0

for i in $(seq 1 $ATTEMPTS); do
    echo -n "Attempt $i/$ATTEMPTS... "
    
    # Try SSH connection with wrong password
    timeout 2 sshpass -p "wrongpassword123" ssh -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o PreferredAuthentications=password \
        -o PubkeyAuthentication=no \
        -o ConnectTimeout=2 \
        -o BatchMode=yes \
        root@localhost "exit" 2>/dev/null || true
    
    sleep 0.3
    
    # Check for alerts
    ALERT_COUNT=$(secrds alerts 2>/dev/null | grep -c "SSH_BRUTE_FORCE" || echo "0")
    
    if [ "$ALERT_COUNT" -gt 0 ]; then
        echo -e "${GREEN}✓ Alert detected!${NC}"
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    else
        echo "No alert yet"
    fi
done

echo ""
echo "================================"
echo -e "${YELLOW}Test Results:${NC}"
echo "Attempts made: $ATTEMPTS"
echo "Alerts detected: $SUCCESS_COUNT"

# Show recent alerts
echo ""
echo -e "${YELLOW}Recent alerts:${NC}"
secrds alerts --limit 5

if [ "$SUCCESS_COUNT" -gt 0 ]; then
    echo ""
    echo -e "${GREEN}✓ Test PASSED - Detection is working!${NC}"
    exit 0
else
    echo ""
    echo -e "${RED}✗ Test FAILED - No alerts detected${NC}"
    echo ""
    echo -e "${YELLOW}Troubleshooting steps:${NC}"
    echo "1. Check service logs: sudo journalctl -u secrds -n 50"
    echo "2. Check if eBPF program loaded: sudo journalctl -u secrds | grep 'Attached kprobe'"
    echo "3. Verify service is running: sudo systemctl status secrds"
    echo "4. Check storage file: cat /var/lib/secrds/events.json | jq .alerts"
    exit 1
fi

