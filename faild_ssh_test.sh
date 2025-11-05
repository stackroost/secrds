#!/usr/bin/env bash
# ssh_fail_10.sh — attempt 10 failed SSH logins to localhost (these WILL appear in system auth logs)
set -eu

HOST=127.0.0.1
PORT=22            # change to another port if needed
USER=nonexistent   # intentionally wrong user
PASSWORD=wrongpass
COUNT=10
SLEEP=0.2          # short pause between attempts

command -v sshpass >/dev/null 2>&1 || { echo "Install sshpass first (sudo apt install sshpass)"; exit 1; }

for i in $(seq 1 $COUNT); do
  echo "Attempt $i/$COUNT -> $USER@$HOST:$PORT"
  # Force password auth, disable pubkey so it tries password and fails.
  sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no \
                             -o UserKnownHostsFile=/dev/null \
                             -o PreferredAuthentications=password \
                             -o PubkeyAuthentication=no \
                             -p "$PORT" \
                             -o ConnectTimeout=5 \
                             "$USER@$HOST" "exit" \
  2>/dev/null || true
  sleep "$SLEEP"
done

echo "Done."
