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

// Hook into inet_csk_accept to detect incoming SSH connections on the server side
// This is called when the server accepts a new connection
SEC("kprobe/inet_csk_accept")
int ssh_kprobe_accept(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
    
    if (!sk) return 0;
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    
    // Try to read socket information
    // For IPv4 sockets, we need to access inet_sock structure
    // Common structure layout:
    // struct inet_sock {
    //   struct sock sk;
    //   ...
    //   __be16 inet_sport;  // source port
    //   __be16 inet_dport;  // destination port  
    //   __be32 inet_saddr;  // source address
    //   __be32 inet_daddr;  // destination address
    // }
    
    __u32 src_ip = 0;
    __u32 dst_ip = 0;
    __u16 src_port = 0;
    __u16 dst_port = 0;
    
    // Try to read destination port (offset varies by kernel, try common ones)
    // inet_sock->inet_dport is typically around offset 72-80 from sock
    bpf_probe_read_kernel(&dst_port, sizeof(dst_port), (char *)sk + 72);
    dst_port = __builtin_bswap16(dst_port);
    
    // Only process SSH connections (port 22)
    if (dst_port != 22) {
        return 0;
    }
    
    // Try to read source IP (inet_saddr, typically offset 64-68)
    bpf_probe_read_kernel(&src_ip, sizeof(src_ip), (char *)sk + 64);
    src_ip = __builtin_bswap32(src_ip);
    
    // Try alternative offsets if first attempt failed
    if (src_ip == 0) {
        bpf_probe_read_kernel(&src_ip, sizeof(src_ip), (char *)sk + 68);
        src_ip = __builtin_bswap32(src_ip);
    }
    if (src_ip == 0) {
        bpf_probe_read_kernel(&src_ip, sizeof(src_ip), (char *)sk + 60);
        src_ip = __builtin_bswap32(src_ip);
    }
    
    // Read destination IP
    bpf_probe_read_kernel(&dst_ip, sizeof(dst_ip), (char *)sk + 56);
    dst_ip = __builtin_bswap32(dst_ip);
    if (dst_ip == 0) {
        bpf_probe_read_kernel(&dst_ip, sizeof(dst_ip), (char *)sk + 52);
        dst_ip = __builtin_bswap32(dst_ip);
    }
    
    // If we still don't have source IP, skip (invalid socket)
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

// Also hook tcp_v4_connect for outgoing connections (in case server connects out)
// This helps track both directions
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
    
    // Get destination IP
    __u32 dst_ip = __builtin_bswap32(addr.sin_addr.s_addr);
    
    // For outgoing connections, the "source" from our perspective is the destination
    // We want to track who we're connecting TO (for server-initiated connections)
    // But for incoming connections, we use inet_csk_accept
    
    // Try to get source IP from socket
    __u32 src_ip = 0;
    
    // Read from inet_sock structure (common offsets)
    bpf_probe_read_kernel(&src_ip, sizeof(src_ip), (char *)sk + 64);
    src_ip = __builtin_bswap32(src_ip);
    if (src_ip == 0) {
        bpf_probe_read_kernel(&src_ip, sizeof(src_ip), (char *)sk + 68);
        src_ip = __builtin_bswap32(src_ip);
    }
    
    // Use destination IP if source IP not available (outgoing connection)
    if (src_ip == 0) {
        src_ip = dst_ip;
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
