#!/bin/bash
set -e

# Colors
GREEN="\e[32m"
RED="\e[31m"
YELLOW="\e[33m"
RESET="\e[0m"

echo -e "${YELLOW}[*] Cleaning old build artifacts...${RESET}"
cargo clean

echo -e "${YELLOW}[*] Building secrds-ebpf for target bpfel-unknown-none...${RESET}"
cargo +nightly build --release -Z build-std=core -p secrds-ebpf --target bpfel-unknown-none

if [ $? -ne 0 ]; then
    echo -e "${RED}[!] Build failed. Check errors above.${RESET}"
    exit 1
fi

# Ensure target binary exists
EBPF_BIN="target/bpfel-unknown-none/release/secrds_ebpf"
if [ ! -f "$EBPF_BIN" ]; then
    echo -e "${RED}[!] eBPF binary not found at $EBPF_BIN${RESET}"
    exit 1
fi

echo -e "${YELLOW}[*] Copying built binary to /usr/local/lib/secrds/...${RESET}"
sudo mkdir -p /usr/local/lib/secrds
sudo cp "$EBPF_BIN" /usr/local/lib/secrds/secrds-ebpf.o

echo -e "${YELLOW}[*] Loading eBPF program into kernel...${RESET}"
sudo bpftool prog load /usr/local/lib/secrds/secrds-ebpf.o \
  /sys/fs/bpf/secrds_prog type tracepoint pinmaps /sys/fs/bpf/secrds_maps 2>&1 | tee /tmp/secrds_load.log || true

if grep -q "failed" /tmp/secrds_load.log; then
    echo -e "${RED}[!] eBPF load failed. See /tmp/secrds_load.log for verifier output.${RESET}"
    exit 1
else
    echo -e "${GREEN}[+] eBPF program loaded successfully!${RESET}"
fi

echo -e "${YELLOW}[*] Checking loaded programs...${RESET}"
sudo bpftool prog show | grep secrds || echo -e "${RED}[!] No secrds program found.${RESET}"

echo -e "${GREEN}[✓] Done.${RESET}"
