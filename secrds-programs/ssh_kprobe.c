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
    __u16 src_port = 0;
    
    // Try multiple offsets for destination port (inet_dport)
    // Offset varies significantly by kernel version (5.15 uses different offsets than 5.8)
    // Common offsets: 70, 72, 74, 76, 78, 80, 82, 84, 86
    // For kernel 5.15, inet_dport might be at offset 76-80
    for (int offset = 70; offset <= 86; offset += 2) {
        bpf_probe_read_kernel(&dst_port, sizeof(__u16), (char *)sk + offset);
        dst_port = __builtin_bswap16(dst_port);
        if (dst_port == 22) {
            break;
        }
        dst_port = 0; // Reset if not found
    }
    
    // Only process SSH connections (port 22)
    if (dst_port != 22) {
        return 0;
    }
    
    // Try multiple offsets for source IP (inet_saddr)
    // For kernel 5.15, offsets might be different
    // Try inet_sock offsets first: 56, 60, 64, 68, 72, 76, 80
    for (int offset = 56; offset <= 80; offset += 4) {
        bpf_probe_read_kernel(&src_ip, sizeof(__u32), (char *)sk + offset);
        src_ip = __builtin_bswap32(src_ip);
        // Accept any non-zero IP (including 127.0.0.1)
        if (src_ip != 0) {
            break;
        }
    }
    
    // If we still don't have source IP, try reading from sock_common
    // skc_rcv_saddr is typically at offset 20-28 in sock_common (which is at start of sock)
    if (src_ip == 0) {
        for (int offset = 20; offset <= 32; offset += 4) {
            bpf_probe_read_kernel(&src_ip, sizeof(__u32), (char *)sk + offset);
            src_ip = __builtin_bswap32(src_ip);
            if (src_ip != 0) {
                break;
            }
        }
    }
    
    // Last resort: try reading from skc_daddr (destination address in sock_common)
    // Sometimes the source is stored where we expect destination
    if (src_ip == 0) {
        for (int offset = 24; offset <= 36; offset += 4) {
            bpf_probe_read_kernel(&src_ip, sizeof(__u32), (char *)sk + offset);
            src_ip = __builtin_bswap32(src_ip);
            if (src_ip != 0 && src_ip != 0x0100007f) { // Skip 127.0.0.1 here as it might be dst
                break;
            }
        }
    }
    
    // Read destination IP (inet_daddr) - try multiple offsets
    for (int offset = 52; offset <= 72; offset += 4) {
        bpf_probe_read_kernel(&dst_ip, sizeof(__u32), (char *)sk + offset);
        dst_ip = __builtin_bswap32(dst_ip);
        if (dst_ip != 0) {
            break;
        }
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
    
    // Get destination IP
    __u32 dst_ip = __builtin_bswap32(addr.sin_addr.s_addr);
    
    // For incoming connections TO this server, we want the source IP
    // But tcp_v4_connect is called on the CLIENT side, so we need to
    // detect when someone connects TO us (incoming)
    // The destination IP in sockaddr is where we're connecting TO
    // If dst_ip is our server's IP or 0.0.0.0, this might be an incoming connection
    
    // Try to get source IP from socket (who is connecting)
    __u32 src_ip = 0;
    
    // Try multiple offsets for source IP
    for (int offset = 56; offset <= 76; offset += 4) {
        bpf_probe_read_kernel(&src_ip, sizeof(__u32), (char *)sk + offset);
        src_ip = __builtin_bswap32(src_ip);
        if (src_ip != 0) {
            break;
        }
    }
    
    // Also try sock_common offsets
    if (src_ip == 0) {
        for (int offset = 20; offset <= 28; offset += 4) {
            bpf_probe_read_kernel(&src_ip, sizeof(__u32), (char *)sk + offset);
            src_ip = __builtin_bswap32(src_ip);
            if (src_ip != 0) {
                break;
            }
        }
    }
    
    // Use destination IP if source IP not available
    // This handles the case where we can't read source IP from socket
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
