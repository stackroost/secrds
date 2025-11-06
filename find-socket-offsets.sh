#!/bin/bash
# Helper script to find correct socket structure offsets for your kernel

echo "Finding socket structure offsets for kernel $(uname -r)..."
echo ""

# Check if kernel headers are available
if [ -d "/usr/src/linux-headers-$(uname -r)" ]; then
    KERNEL_HEADERS="/usr/src/linux-headers-$(uname -r)"
    echo "Found kernel headers at: $KERNEL_HEADERS"
    echo ""
    
    # Try to find inet_sock structure definition
    if [ -f "$KERNEL_HEADERS/include/net/inet_sock.h" ]; then
        echo "inet_sock structure definition:"
        grep -A 20 "struct inet_sock" "$KERNEL_HEADERS/include/net/inet_sock.h" | head -30
        echo ""
    fi
    
    # Try to find sock structure
    if [ -f "$KERNEL_HEADERS/include/net/sock.h" ]; then
        echo "sock_common structure (first part of sock):"
        grep -A 30 "struct sock_common" "$KERNEL_HEADERS/include/net/sock.h" | head -40
        echo ""
    fi
else
    echo "Kernel headers not found. Install with:"
    echo "  sudo apt-get install linux-headers-$(uname -r)"
    echo ""
fi

# Check available kernel symbols
echo "Checking available kernel symbols for TCP:"
echo ""
echo "inet_csk_accept:"
cat /proc/kallsyms | grep "inet_csk_accept" | head -3
echo ""
echo "tcp_v4_connect:"
cat /proc/kallsyms | grep "tcp_v4_connect" | head -3
echo ""
echo "tcp_v4_syn_recv_sock:"
cat /proc/kallsyms | grep "tcp_v4_syn_recv_sock" | head -3
echo ""

echo "Note: Socket structure offsets vary by kernel version."
echo "The eBPF program tries multiple offsets automatically."
echo "If detection still fails, the offsets for your kernel may need adjustment."

