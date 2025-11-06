# Testing Guide - secrds Detection

## Quick Test

Run the comprehensive test script:

```bash
sudo ./fix-and-test.sh
```

This will:
1. Check service status
2. Rebuild the project
3. Reinstall everything
4. Verify service is running
5. Check eBPF program attachment
6. Run SSH attack simulation
7. Verify alerts are generated

## Manual Testing

### Step 1: Ensure service is running

```bash
sudo systemctl status secrds
# If not running:
sudo systemctl start secrds
```

### Step 2: Run test script

```bash
./test-ssh-attacks.sh 10
```

This makes 10 SSH connection attempts and checks for alerts.

### Step 3: Check alerts

```bash
secrds alerts
```

## Debugging

### View real-time logs

```bash
sudo journalctl -u secrds -f
```

Look for:
- `[DEBUG] SSH event received` - Events are being captured
- `[DEBUG] Threat detected` - Threats are being identified
- `Attached kprobe` - eBPF program loaded correctly

### Check if events are received

```bash
sudo journalctl -u secrds | grep "SSH event received"
```

### Check eBPF program attachment

```bash
sudo journalctl -u secrds | grep "Attached kprobe"
```

Should show:
- `Attached kprobe to inet_csk_accept` (incoming connections)
- `Attached kprobe to tcp_v4_connect` (outgoing connections)

### Check storage file

```bash
cat /var/lib/secrds/events.json | jq .
# Or without jq:
cat /var/lib/secrds/events.json
```

## Common Issues

### Issue: No alerts detected

**Possible causes:**

1. **Service not running**
   ```bash
   sudo systemctl start secrds
   ```

2. **eBPF program not attached**
   - Check kernel version: `uname -r` (needs 5.8+)
   - Check logs: `sudo journalctl -u secrds | grep "Attached"`
   - Kernel might not export `inet_csk_accept` symbol

3. **Source IP detection failing**
   - Check logs for "invalid IP" or "0.0.0.0"
   - Socket structure offsets might be wrong for your kernel

4. **Thresholds too high**
   - Check config: `cat /etc/secrds/config.yaml`
   - Default is 3 attempts in 5 minutes
   - Lower if needed: `ssh_threshold: 2`

### Issue: Events received but no alerts

- Check detection thresholds in config
- Check logs for "Threat detected" messages
- Verify threat score calculation

### Issue: Invalid IP addresses

If you see IPs like `0.0.0.0` or invalid addresses:
- Socket structure offsets need adjustment for your kernel
- Try rebuilding with different offsets
- Check kernel version compatibility

## Testing from Remote Server

To test from another server:

```bash
# On remote server
for i in {1..10}; do
  ssh root@TARGET_SERVER_IP "exit" 2>&1 | head -1
  sleep 0.5
done

# On target server
secrds alerts
```

## Configuration

Edit `/etc/secrds/config.yaml`:

```yaml
ssh_threshold: 3          # Number of attempts to trigger alert
ssh_window_seconds: 300   # Time window (5 minutes)
enable_ip_blocking: true  # Auto-block detected IPs
```

Lower thresholds for more sensitive detection:
```yaml
ssh_threshold: 2
ssh_window_seconds: 60
```

## Expected Behavior

After making SSH connection attempts, you should see:

1. **Events in logs:**
   ```
   [DEBUG] SSH event received: IP=127.0.0.1, Port=22, PID=1234, Type=0
   ```

2. **Threat detection:**
   ```
   [DEBUG] Threat detected: IP=127.0.0.1, Type=SSH_BRUTE_FORCE, Severity=MEDIUM, Count=3, Score=9.0
   ```

3. **Alerts:**
   ```
   🟠 [MEDIUM] SSH_BRUTE_FORCE
     Time:   2024-01-01 12:00:00 UTC
     IP:     127.0.0.1
     Count:  3
     Score:  9.0
     Details: Brute force detected: 3 attempts in 5 minutes
   ```

## Performance

- Detection happens in real-time
- Alerts are stored immediately
- Storage file is flushed every 60 seconds
- No performance impact on SSH connections

