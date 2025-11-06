#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Setting up secrds daemon service...${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root (use sudo)${NC}"
    exit 1
fi

# Check if binaries exist
if [ ! -f "target/release/secrds-agent" ]; then
    echo -e "${RED}Error: secrds-agent binary not found. Please build first: make build${NC}"
    exit 1
fi

if [ ! -f "target/release/secrds-cli" ]; then
    echo -e "${RED}Error: secrds-cli binary not found. Please build first: make build${NC}"
    exit 1
fi

# Stop service if running (to avoid "Text file busy" error)
SERVICE_WAS_RUNNING=false
if systemctl is-active --quiet secrds 2>/dev/null; then
    echo -e "${YELLOW}Stopping secrds service to update binaries...${NC}"
    systemctl stop secrds
    SERVICE_WAS_RUNNING=true
    sleep 1
fi

# Install binaries
echo -e "${YELLOW}Installing binaries...${NC}"
# Try to copy, if it fails due to busy file, wait and retry
if ! cp target/release/secrds-agent /usr/local/bin/secrds-agent 2>/dev/null; then
    echo -e "${YELLOW}Waiting for file to be released...${NC}"
    sleep 2
    cp target/release/secrds-agent /usr/local/bin/secrds-agent
fi
chmod +x /usr/local/bin/secrds-agent
cp target/release/secrds-cli /usr/local/bin/secrds
chmod +x /usr/local/bin/secrds
echo -e "${GREEN}Binaries installed${NC}"

# Install kernel programs
echo -e "${YELLOW}Installing kernel programs...${NC}"
mkdir -p /usr/local/lib/secrds
if [ -f "secrds-programs/ssh_kprobe.bpf.o" ]; then
    cp secrds-programs/ssh_kprobe.bpf.o /usr/local/lib/secrds/
    echo -e "${GREEN}SSH kernel program installed${NC}"
fi
if [ -f "secrds-programs/tcp_trace.bpf.o" ]; then
    cp secrds-programs/tcp_trace.bpf.o /usr/local/lib/secrds/
    echo -e "${GREEN}TCP kernel program installed${NC}"
fi

# Install systemd service
echo -e "${YELLOW}Installing systemd service...${NC}"
if [ -f "secrds.service" ]; then
    cp secrds.service /etc/systemd/system/secrds.service
    systemctl daemon-reload
    echo -e "${GREEN}Service file installed${NC}"
else
    echo -e "${RED}Error: secrds.service not found${NC}"
    exit 1
fi

# Create directories
mkdir -p /etc/secrds
mkdir -p /var/lib/secrds
mkdir -p /var/run
mkdir -p /var/log/secrds

# Create default config if it doesn't exist
if [ ! -f "/etc/secrds/config.yaml" ]; then
    echo -e "${YELLOW}Creating default configuration...${NC}"
    cat > /etc/secrds/config.yaml <<EOF
ssh_threshold: 5
ssh_window_seconds: 300
tcp_threshold: 10
tcp_window_seconds: 60
enable_ip_blocking: true
storage_path: "/var/lib/secrds/events.json"
pid_file: "/var/run/secrds.pid"
log_level: "info"
log_file: "/var/log/secrds/agent.log"

# Telegram Bot Configuration
# Get your bot token from @BotFather on Telegram
# Get your chat ID from @userinfobot on Telegram
telegram:
  bot_token: "your_bot_token_here"
  chat_id: "your_chat_id_here"
EOF
    chmod 644 /etc/secrds/config.yaml
    echo -e "${YELLOW}Default config created at /etc/secrds/config.yaml${NC}"
fi

# Enable service
echo -e "${YELLOW}Enabling service...${NC}"
systemctl enable secrds
echo -e "${GREEN}Service enabled for auto-start${NC}"

# Start or restart the service
if [ "$SERVICE_WAS_RUNNING" = true ]; then
    echo -e "${YELLOW}Restarting service...${NC}"
    systemctl start secrds
else
    echo -e "${YELLOW}Starting service...${NC}"
    systemctl start secrds
fi

# Wait a moment for service to start
sleep 2

# Check service status
if systemctl is-active --quiet secrds; then
    echo -e "${GREEN}✓ Service is running successfully!${NC}"
else
    echo -e "${YELLOW}⚠ Service may have issues. Checking status...${NC}"
    systemctl status secrds --no-pager -l || true
fi

echo ""
echo -e "${GREEN}Setup complete!${NC}"
echo ""
echo -e "${YELLOW}Useful commands:${NC}"
echo "  Check status:  systemctl status secrds"
echo "  View logs:     journalctl -u secrds -f"
echo "  Stop service:  systemctl stop secrds"
echo "  Start service: systemctl start secrds"
echo "  Restart:       systemctl restart secrds"
echo "  View alerts:   secrds alerts"
echo "  Check status:  secrds status"
echo ""

