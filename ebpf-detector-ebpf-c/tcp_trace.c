#include "common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, MAX_EVENTS);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct tcp_event));
} tcp_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_IP_ADDRESSES);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
} tcp_connection_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_IP_ADDRESSES);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
} tcp_port_scan SEC(".maps");

SEC("kprobe/tcp_v4_connect")
int tcp_connect(struct pt_regs *ctx)
{
    
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    
    __u32 src_ip = 0;
    __u16 dst_port = 0;
    
    __u64 *count = bpf_map_lookup_elem(&tcp_connection_count, &src_ip);
    __u64 new_count = count ? *count + 1 : 1;
    bpf_map_update_elem(&tcp_connection_count, &src_ip, &new_count, BPF_ANY);
    
    struct tcp_event event = {
        .src_ip = src_ip,
        .dst_ip = 0,
        .src_port = 0,
        .dst_port = dst_port,
        .event_type = TCP_CONNECT,
        .timestamp = bpf_ktime_get_ns(),
    };
    
    bpf_perf_event_output(ctx, &tcp_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

SEC("tracepoint/sock/inet_sock_set_state")
int tcp_state_change(void *ctx)
{
    __u32 src_ip = 0;
    __u16 dst_port = 0;
    __u8 newstate = 0;
    
    if (newstate == TCP_SYN_SENT || newstate == TCP_SYN_RECV) {
        __u64 *count = bpf_map_lookup_elem(&tcp_connection_count, &src_ip);
        __u64 new_count = count ? *count + 1 : 1;
        bpf_map_update_elem(&tcp_connection_count, &src_ip, &new_count, BPF_ANY);
        
        struct tcp_event event = {
            .src_ip = src_ip,
            .dst_ip = 0,
            .src_port = 0,
            .dst_port = dst_port,
            .event_type = TCP_CONNECT,
            .timestamp = bpf_ktime_get_ns(),
        };
        
        bpf_perf_event_output(ctx, &tcp_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    }
    
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

