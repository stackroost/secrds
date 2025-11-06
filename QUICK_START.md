# Quick Start Guide - secrds Security Monitor

## Issue: Agent Not Detecting SSH Attacks

If you're seeing "No recent alerts" when SSH attacks occur, follow these steps:

### Step 1: Make sure the service is running

```bash
# Check if service is running
sudo systemctl status secrds

# If not running, start it
sudo systemctl start secrds

# Enable auto-start on boot
sudo systemctl enable secrds
```

### Step 2: Rebuild with updated eBPF program

The eBPF program has been updated to better detect incoming connections:

```bash
# Rebuild everything
make build

# Reinstall
sudo ./install.sh
```

### Step 3: Test the detection

From another server, try multiple SSH login attempts:

```bash
# On attacker server (replace with your server IP)
for i in {1..10}; do
  ssh root@YOUR_SERVER_IP "exit" 2>&1 | head -1
  sleep 0.5
done
```

### Step 4: Check alerts

```bash
# On the monitored server
secrds alerts

# Or with more details
secrds alerts --limit 20
```

### Step 5: View logs

```bash
# View service logs
sudo journalctl -u secrds -f

# Check if events are being received
sudo journalctl -u secrds | grep "SSH event"
```

## Troubleshooting

### If still no alerts:

1. **Check if eBPF program loaded correctly:**
   ```bash
   sudo journalctl -u secrds | grep "Attached kprobe"
   ```

2. **Verify kernel supports eBPF:**
   ```bash
   uname -r  # Should be 5.8+
   ls /sys/fs/bpf  # Should exist
   ```

3. **Check if connections are being tracked:**
   ```bash
   # Monitor in real-time
   sudo journalctl -u secrds -f
   # Then try SSH connections and see if events appear
   ```

4. **Lower thresholds in config:**
   ```bash
   sudo nano /etc/secrds/config.yaml
   # Set ssh_threshold: 2
   # Set ssh_window_seconds: 60
   sudo systemctl restart secrds
   ```

5. **Test with manual run:**
   ```bash
   sudo /usr/local/bin/secrds-agent
   # In another terminal, try SSH connections
   # Press Ctrl+C to stop
   ```

## Important Notes

- The agent must be running **continuously** as a service to detect attacks
- Detection thresholds are now lower (3 attempts in 5 minutes)
- The eBPF program now hooks both incoming and outgoing connections
- Source IP detection has been improved

## Service Management

```bash
# Start service
sudo systemctl start secrds

# Stop service  
sudo systemctl stop secrds

# Restart service
sudo systemctl restart secrds

# Check status
secrds status

# View alerts
secrds alerts
```

