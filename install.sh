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
CONFIG_DIR="/etc/ebpf-detector"
DATA_DIR="/var/lib/ebpf-detector"
RUN_DIR="/var/run"

echo -e "${GREEN}Installing eBPF Security Monitor${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root (use sudo)${NC}"
    exit 1
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

echo -e "${YELLOW}Checking for Rust, Cargo, and system tools...${NC}"


# Check for required tools
for tool in rustc cargo iptables; do
    if ! command -v $tool &> /dev/null; then
        echo -e "${RED}$tool is not installed${NC}"
        exit 1
    fi
done

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

# Install binaries
echo -e "${YELLOW}Installing binaries...${NC}"
cp target/release/ebpf-detector-agent "$INSTALL_PREFIX/bin/"
cp target/release/ebpf-detector "$INSTALL_PREFIX/bin/"
chmod +x "$INSTALL_PREFIX/bin/ebpf-detector-agent"
chmod +x "$INSTALL_PREFIX/bin/ebpf-detector"

# Install systemd service
echo -e "${YELLOW}Installing systemd service...${NC}"
if [ -f "ebpf-detector.service" ]; then
    cp ebpf-detector.service "$SYSTEMD_DIR/"
    systemctl daemon-reload
else
    echo -e "${YELLOW}Warning: ebpf-detector.service not found, skipping${NC}"
fi

# Create default config if it doesn't exist
if [ ! -f "$CONFIG_DIR/config.toml" ]; then
    echo -e "${YELLOW}Creating default configuration...${NC}"
    cat > "$CONFIG_DIR/config.toml" <<EOF
ssh_threshold = 5
ssh_window_seconds = 300
tcp_threshold = 10
tcp_window_seconds = 60
enable_ip_blocking = true
storage_path = "$DATA_DIR/events.json"
pid_file = "$RUN_DIR/ebpf-detector.pid"
log_level = "info"
log_file = "/var/log/ebpf-detector/agent.log"
EOF
    chmod 644 "$CONFIG_DIR/config.toml"
fi

# Create environment file template
if [ ! -f "$CONFIG_DIR/env.conf" ]; then
    echo -e "${YELLOW}Creating environment configuration template...${NC}"
    cat > "$CONFIG_DIR/env.conf" <<EOF
# Telegram Bot Configuration
# Get your bot token from @BotFather on Telegram
# Get your chat ID from @userinfobot on Telegram
TELEGRAM_BOT_TOKEN=your_bot_token_here
TELEGRAM_CHAT_ID=your_chat_id_here

# Optional: Custom config file path
# EBPF_DETECTOR_CONFIG=/etc/ebpf-detector/config.toml
EOF
    chmod 600 "$CONFIG_DIR/env.conf"
    echo -e "${YELLOW}Please edit $CONFIG_DIR/env.conf and set your Telegram credentials${NC}"
fi

# Create log directory
mkdir -p /var/log/ebpf-detector
chmod 755 /var/log/ebpf-detector

# Set proper permissions
chown -R root:root "$CONFIG_DIR"
chown -R root:root "$DATA_DIR"
chmod 755 "$DATA_DIR"

echo -e "${GREEN}Installation complete!${NC}"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Edit $CONFIG_DIR/env.conf and set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID"
echo "2. Optionally edit $CONFIG_DIR/config.toml to customize thresholds"
echo "3. Start the service: systemctl start ebpf-detector"
echo "4. Enable auto-start: systemctl enable ebpf-detector"
echo "5. Check status: systemctl status ebpf-detector"
echo ""
echo -e "${GREEN}Installation successful!${NC}"

