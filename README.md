## secrds - Security Monitor

A kernel-powered host security monitor that detects SSH brute-force and TCP anomalies (port scans / floods), optionally blocks offending IPs via iptables, and sends alerts to Telegram.

### Components
- **Agent (`secrds-agent`)**: Loads kernel programs, processes events, persists alerts, sends Telegram notifications, and (optionally) blocks IPs.
- **CLI (`secrds`)**: Check status, list recent alerts, view stats, and control the agent.
- **Kernel Programs**: Implemented in C (`secrds-programs`).

### Requirements
- Linux kernel 5.8+ with kernel program features enabled
- Go 1.21 or later
- `clang` and `llvm` (for building kernel programs)
- `iptables` (for optional auto-blocking)
- `systemd` (to run the agent as a service)
- Internet access for Telegram API

### Quick Start
```bash
# 1) Build everything (kernel programs + agent + CLI)
./build.sh

# 2) Install system-wide (requires sudo)
sudo ./install.sh

# 3) Configure Telegram credentials
sudo nano /etc/secrds/config.yaml
# Set telegram.bot_token and telegram.chat_id under the telegram section

# 4) (Optional) Tune thresholds in the same config.yaml file

# 5) Start and enable the service
sudo systemctl start secrds
sudo systemctl enable secrds

# 6) Check status and logs
systemctl status secrds
journalctl -u secrds -f
```

### Installation Details
- `install.sh` will:
  - Build binaries (via `build.sh`)
  - Install `secrds-agent` and `secrds` to `/usr/local/bin/`
  - Install `secrds.service` to `/etc/systemd/system/`
  - Create config at `/etc/secrds/config.yaml` (if missing)
  - Create env file at `/etc/secrds/env.conf` (Telegram settings)
  - Create data dir `/var/lib/secrds` and log dir `/var/log/secrds`

### Configuration
- Main config file: `/etc/secrds/config.yaml` (YAML format)
  - `ssh_threshold` (default 5)
  - `ssh_window_seconds` (default 300)
  - `tcp_threshold` (default 10)
  - `tcp_window_seconds` (default 60)
  - `enable_ip_blocking` (default true)
  - `storage_path` (default `/var/lib/secrds/events.json`)
  - `pid_file` (default `/var/run/secrds.pid`)
  - `log_level` (default `info`)
  - `log_file` (default `/var/log/secrds/agent.log`)

- Telegram configuration (in `config.yaml`):
  - `telegram.bot_token` = your bot token (from Telegram `@BotFather`)
  - `telegram.chat_id` = your chat ID (e.g., via `@userinfobot`)
  - Optional: `SECRDS_CONFIG` environment variable to point to a custom config path
  - Optional: `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` environment variables (override config file)

### Service (systemd)
```bash
sudo systemctl start secrds
sudo systemctl enable secrds
systemctl status secrds
journalctl -u secrds -f
```

### CLI Usage
```bash
# Show agent/service status
secrds status

# Show recent alerts (default 10; customize with --limit)
secrds alerts --limit 20

# Show stats (e.g., blocked IPs, counts)
secrds stats

# Print current config (resolved)
secrds config

# Control the agent
secrds start
secrds stop
secrds restart
```

### Paths
- Config: `/etc/secrds/config.yaml` (includes Telegram settings)
- Data: `/var/lib/secrds/events.json`
- PID: `/var/run/secrds.pid`
- Logs: `/var/log/secrds/agent.log`
- Binaries: `/usr/local/bin/secrds-agent`, `/usr/local/bin/secrds`

### Production Deployment

1. **Build the project:**
   ```bash
   make build
   ```

2. **Install:**
   ```bash
   sudo ./install.sh
   ```

3. **Configure Telegram (required for alerts):**
   ```bash
   sudo nano /etc/secrds/config.yaml
   # Set telegram.bot_token and telegram.chat_id
   ```

4. **Start and enable service:**
   ```bash
   sudo systemctl start secrds
   sudo systemctl enable secrds
   ```

5. **Verify it's running:**
   ```bash
   secrds status
   ```

### Troubleshooting
- Kernel 5.8+ required: `uname -r`
- Build tools: ensure `go`, `clang`, and `llvm` are installed
- Telegram alerts: verify `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` are set and correct
- IP blocking: requires `iptables` and root; see warnings in logs if a rule fails
- View logs: `journalctl -u secrds -f`
- Check alerts: `secrds alerts`

---

Made with Go and kernel programs. Licensed under MIT or Apache-2.0.


