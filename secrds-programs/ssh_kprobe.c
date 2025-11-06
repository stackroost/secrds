#include "common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, MAX_EVENTS);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} ssh_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_IP_ADDRESSES);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
} ssh_attempts SEC(".maps");

// sockaddr_in structure (simplified for IPv4)
struct sockaddr_in {
    __u16 sin_family;      // AF_INET = 2
    __be16 sin_port;       // Port in network byte order
    struct in_addr {
        __be32 s_addr;      // IP address in network byte order
    } sin_addr;
    __u8 sin_zero[8];      // Padding
};

// Hook into inet_csk_accept to detect incoming SSH connections on the server side
// This is called when the server accepts a new connection
// Based on kernel headers: inet_daddr = sk.__sk_common.skc_daddr
//                          inet_rcv_saddr = sk.__sk_common.skc_rcv_saddr  
//                          inet_dport = sk.__sk_common.skc_dport
// sock_common is at the START of sock structure
SEC("kprobe/inet_csk_accept")
int ssh_kprobe_accept(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
    
    if (!sk) return 0;
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    
    __u32 src_ip = 0;
    __u32 dst_ip = 0;
    __u16 dst_port = 0;
    
    // sock_common is at the start of sock structure
    // struct sock_common layout:
    //   offset 0-3: skc_daddr (destination IP - foreign address)
    //   offset 4-7: skc_rcv_saddr (source IP - bound local address)
    //   offset 8-9: skc_dport (destination port)
    //   offset 10-11: skc_num (local port)
    
    // Read destination port (skc_dport) - offset 8-9 in sock_common (which is at start of sock)
    bpf_probe_read_kernel(&dst_port, sizeof(__u16), (char *)sk + 8);
    dst_port = __builtin_bswap16(dst_port);
    
    // Only process SSH connections (port 22)
    if (dst_port != 22) {
        return 0;
    }
    
    // Read source IP (skc_rcv_saddr) - offset 4-7 in sock_common
    bpf_probe_read_kernel(&src_ip, sizeof(__u32), (char *)sk + 4);
    src_ip = __builtin_bswap32(src_ip);
    
    // Read destination IP (skc_daddr) - offset 0-3 in sock_common
    bpf_probe_read_kernel(&dst_ip, sizeof(__u32), (char *)sk + 0);
    dst_ip = __builtin_bswap32(dst_ip);
    
    // For incoming connections, skc_rcv_saddr is the local bound address (usually 0.0.0.0 or server IP)
    // and skc_daddr is the remote client's IP (what we want!)
    // So we should use skc_daddr as the source IP for tracking
    
    // Use destination address (skc_daddr) as the source IP for incoming connections
    // This is the IP of the client connecting to us
    if (dst_ip != 0) {
        src_ip = dst_ip;  // The "destination" from socket perspective is the client connecting to us
    }
    
    // If we still don't have a valid IP, skip
    if (src_ip == 0) {
        return 0;
    }
    
    // Track attempt
    __u64 *count = bpf_map_lookup_elem(&ssh_attempts, &src_ip);
    __u64 new_count = count ? *count + 1 : 1;
    bpf_map_update_elem(&ssh_attempts, &src_ip, &new_count, BPF_F_CURRENT_CPU);
    
    // Initialize event structure
    struct ssh_event event = {};
    event.ip = src_ip;
    event.port = dst_port;
    event.pid = pid;
    event.event_type = SSH_ATTEMPT;
    event.timestamp = bpf_ktime_get_ns();
    
    bpf_perf_event_output(ctx, &ssh_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

// Also hook tcp_v4_connect for outgoing connections
// This is more reliable as we have sockaddr_in with destination info
SEC("kprobe/tcp_v4_connect")
int ssh_kprobe_tcp_connect(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct sockaddr *uaddr = (struct sockaddr *)PT_REGS_PARM2(ctx);
    
    if (!sk || !uaddr) return 0;
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    
    // Read sockaddr_in structure
    struct sockaddr_in addr = {};
    bpf_probe_read_kernel(&addr, sizeof(addr), uaddr);
    
    // Check if it's IPv4 (AF_INET = 2)
    if (addr.sin_family != 2) {
        return 0;
    }
    
    // Get destination port (convert from network byte order)
    __u16 dst_port = __builtin_bswap16(addr.sin_port);
    
    // Only process SSH connections (port 22)
    if (dst_port != 22) {
        return 0;
    }
    
    // Get destination IP from sockaddr
    __u32 dst_ip = __builtin_bswap32(addr.sin_addr.s_addr);
    
    // For outgoing connections, we want to track the destination IP
    // But for incoming connections (someone connecting TO us), tcp_v4_connect
    // is called on the CLIENT side, not server side
    
    // Try to get source IP from socket (who is connecting)
    __u32 src_ip = 0;
    
    // Read from sock_common (skc_rcv_saddr at offset 4)
    bpf_probe_read_kernel(&src_ip, sizeof(__u32), (char *)sk + 4);
    src_ip = __builtin_bswap32(src_ip);
    
    // If source IP not available, use destination IP
    if (src_ip == 0) {
        src_ip = dst_ip;
    }
    
    // Skip if still invalid
    if (src_ip == 0) {
        return 0;
    }
    
    // Track attempt
    __u64 *count = bpf_map_lookup_elem(&ssh_attempts, &src_ip);
    __u64 new_count = count ? *count + 1 : 1;
    bpf_map_update_elem(&ssh_attempts, &src_ip, &new_count, BPF_F_CURRENT_CPU);
    
    // Initialize event structure
    struct ssh_event event = {};
    event.ip = src_ip;
    event.port = dst_port;
    event.pid = pid;
    event.event_type = SSH_ATTEMPT;
    event.timestamp = bpf_ktime_get_ns();
    
    bpf_perf_event_output(ctx, &ssh_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
