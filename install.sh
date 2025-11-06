#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
INSTALL_PREFIX="${INSTALL_PREFIX:-/usr/local}"
SYSTEMD_DIR="/etc/systemd/system"
CONFIG_DIR="/etc/secrds"
DATA_DIR="/var/lib/secrds"
RUN_DIR="/var/run"

echo -e "${GREEN}Installing secrds Security Monitor${NC}"

# Check if running as root or has sudo
if [ "$EUID" -ne 0 ]; then 
    if ! command -v sudo &> /dev/null; then
        echo -e "${RED}Please run as root or install sudo${NC}"
        exit 1
    fi
    # Not root, will use sudo
    SUDO_CMD="sudo"
else
    # Already root, no sudo needed
    SUDO_CMD=""
fi

# Check prerequisites
echo -e "${YELLOW}Checking prerequisites...${NC}"

# Check kernel version
KERNEL_VERSION=$(uname -r | cut -d. -f1,2)
REQUIRED_VERSION="5.8"
if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$KERNEL_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo -e "${RED}Kernel version $KERNEL_VERSION is too old. Requires 5.8+${NC}"
    exit 1
fi

echo -e "${YELLOW}Checking for Go and system tools...${NC}"

# Check for required tools
for tool in go iptables clang; do
    if ! command -v $tool &> /dev/null; then
        echo -e "${RED}$tool is not installed${NC}"
        exit 1
    fi
done

# Check Go version (requires 1.21+)
GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
REQUIRED_GO_VERSION="1.21"
if [ "$(printf '%s\n' "$REQUIRED_GO_VERSION" "$GO_VERSION" | sort -V | head -n1)" != "$REQUIRED_GO_VERSION" ]; then
    echo -e "${YELLOW}Warning: Go version $GO_VERSION may be too old. Recommended: 1.21+${NC}"
fi

# Build the project
echo -e "${YELLOW}Building project...${NC}"
if [ -f "build.sh" ]; then
    chmod +x build.sh
    ./build.sh
else
    echo -e "${RED}build.sh not found${NC}"
    exit 1
fi

# Create directories
echo -e "${YELLOW}Creating directories...${NC}"
mkdir -p "$CONFIG_DIR"
mkdir -p "$DATA_DIR"
mkdir -p "$RUN_DIR"
mkdir -p "$(dirname $INSTALL_PREFIX/bin)"

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

# Install secrds-agent
if [ -f "target/release/secrds-agent" ]; then
    # Try to copy, if it fails due to busy file, wait and retry
    if ! cp target/release/secrds-agent "$INSTALL_PREFIX/bin/secrds-agent" 2>/dev/null; then
        echo -e "${YELLOW}Waiting for file to be released...${NC}"
        sleep 2
        cp target/release/secrds-agent "$INSTALL_PREFIX/bin/secrds-agent"
    fi
    chmod +x "$INSTALL_PREFIX/bin/secrds-agent"
    echo -e "${GREEN}Installed secrds-agent${NC}"
else
    echo -e "${RED}Error: secrds-agent binary not found${NC}"
    exit 1
fi

# Install secrds-cli as 'secrds'
if [ -f "target/release/secrds-cli" ]; then
    cp target/release/secrds-cli "$INSTALL_PREFIX/bin/secrds"
    chmod +x "$INSTALL_PREFIX/bin/secrds"
    echo -e "${GREEN}Installed secrds CLI${NC}"
else
    echo -e "${RED}Error: secrds-cli binary not found${NC}"
    exit 1
fi

# Install kernel program object files
echo -e "${YELLOW}Installing kernel program object files...${NC}"
mkdir -p /usr/local/lib/secrds
if [ -f "secrds-programs/ssh_kprobe.bpf.o" ]; then
    cp secrds-programs/ssh_kprobe.bpf.o /usr/local/lib/secrds/
    echo -e "${GREEN}Installed SSH kernel program${NC}"
fi
if [ -f "secrds-programs/tcp_trace.bpf.o" ]; then
    cp secrds-programs/tcp_trace.bpf.o /usr/local/lib/secrds/
    echo -e "${GREEN}Installed TCP kernel program${NC}"
fi

# Install systemd service
echo -e "${YELLOW}Installing systemd service...${NC}"
if [ -f "secrds.service" ]; then
    cp secrds.service "$SYSTEMD_DIR/secrds.service"
    systemctl daemon-reload
else
    echo -e "${YELLOW}Warning: secrds.service not found, skipping${NC}"
fi

# Create default config if it doesn't exist
if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
    echo -e "${YELLOW}Creating default configuration...${NC}"
    cat > "$CONFIG_DIR/config.yaml" <<EOF
# secrds Security Monitor Configuration

# SSH Detection Settings
ssh_threshold: 5              # Number of SSH attempts to trigger alert
ssh_window_seconds: 300       # Time window for SSH attempts (5 minutes)

# TCP Detection Settings  
tcp_threshold: 10             # Number of TCP connections to trigger alert
tcp_window_seconds: 60        # Time window for TCP connections (60 seconds)

# IP Blocking
enable_ip_blocking: true      # Automatically block detected threat IPs

# Storage and Logging
storage_path: "$DATA_DIR/events.json"
pid_file: "$RUN_DIR/secrds.pid"
log_level: "info"
log_file: "/var/log/secrds/agent.log"

# Telegram Bot Configuration
# Get your bot token from @BotFather on Telegram
# Get your chat ID from @userinfobot on Telegram
telegram:
  bot_token: "your_bot_token_here"
  chat_id: "your_chat_id_here"
EOF
    chmod 644 "$CONFIG_DIR/config.yaml"
    echo -e "${YELLOW}Please edit $CONFIG_DIR/config.yaml and set your Telegram credentials${NC}"
fi

# Create log directory
mkdir -p /var/log/secrds
chmod 755 /var/log/secrds

# Set proper permissions
chown -R root:root "$CONFIG_DIR"
chown -R root:root "$DATA_DIR"
chmod 755 "$DATA_DIR"

# Enable service
echo -e "${YELLOW}Enabling secrds service...${NC}"
if systemctl is-enabled secrds &>/dev/null; then
    echo -e "${GREEN}Service already enabled${NC}"
else
    systemctl enable secrds
    echo -e "${GREEN}Service enabled for auto-start${NC}"
fi

# Reload systemd to pick up any service file changes
systemctl daemon-reload

# Check if config has Telegram credentials
if grep -q "your_bot_token_here\|your_chat_id_here" "$CONFIG_DIR/config.yaml" 2>/dev/null; then
    echo -e "${YELLOW}Warning: Telegram credentials not configured yet${NC}"
    echo -e "${YELLOW}The service will start but alerts won't be sent to Telegram${NC}"
    echo ""
    echo -e "${YELLOW}To start the service now, run:${NC}"
    echo "  systemctl start secrds"
    echo ""
    echo -e "${YELLOW}To configure Telegram later:${NC}"
    echo "  1. Edit $CONFIG_DIR/config.yaml"
    echo "  2. Set telegram.bot_token and telegram.chat_id"
    echo "  3. Restart: systemctl restart secrds"
else
    # Start or restart the service if config is ready
    if [ "$SERVICE_WAS_RUNNING" = true ]; then
        echo -e "${YELLOW}Restarting service...${NC}"
        if systemctl start secrds; then
            sleep 2
            if systemctl is-active --quiet secrds; then
                echo -e "${GREEN}Service restarted successfully${NC}"
            else
                echo -e "${YELLOW}Service restarted but may have issues. Check: systemctl status secrds${NC}"
            fi
        else
            echo -e "${YELLOW}Failed to restart service. Check: systemctl status secrds${NC}"
        fi
    else
        # Start the service if config is ready
        if systemctl start secrds; then
            sleep 2
            if systemctl is-active --quiet secrds; then
                echo -e "${GREEN}Service started successfully${NC}"
            else
                echo -e "${YELLOW}Service started but may have issues. Check: systemctl status secrds${NC}"
            fi
        else
            echo -e "${YELLOW}Failed to start service. Check: systemctl status secrds${NC}"
        fi
    fi
fi

echo ""
echo -e "${GREEN}Installation complete!${NC}"
echo ""
echo -e "${YELLOW}Useful commands:${NC}"
echo "  Check status:  systemctl status secrds"
echo "  View logs:     journalctl -u secrds -f"
echo "  Stop service:  systemctl stop secrds"
echo "  Start service: systemctl start secrds"
echo "  Restart:       systemctl restart secrds"
echo "  View alerts:   secrds alerts"
echo ""
echo -e "${GREEN}Installation successful!${NC}"

