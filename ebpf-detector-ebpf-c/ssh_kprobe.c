#include "common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, MAX_EVENTS);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct ssh_event));
} ssh_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_IP_ADDRESSES);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
} ssh_failure_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_IP_ADDRESSES);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
} ssh_attempts SEC(".maps");

SEC("kprobe/do_execve")
int ssh_kprobe_execve(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 ip = 0; 
    
    __u64 *count = bpf_map_lookup_elem(&ssh_attempts, &ip);
    __u64 new_count = count ? *count + 1 : 1;
    bpf_map_update_elem(&ssh_attempts, &ip, &new_count, BPF_ANY);
    
    struct ssh_event event = {
        .ip = ip,
        .port = 22,
        .pid = pid,
        .event_type = SSH_ATTEMPT,
        .timestamp = bpf_ktime_get_ns(),
    };
    
    bpf_perf_event_output(ctx, &ssh_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int ssh_tracepoint_write(void *ctx)
{
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 ip = 0;
    
    __u64 *count = bpf_map_lookup_elem(&ssh_failure_count, &ip);
    __u64 new_count = count ? *count + 1 : 1;
    bpf_map_update_elem(&ssh_failure_count, &ip, &new_count, BPF_ANY);
    
    struct ssh_event event = {
        .ip = ip,
        .port = 22,
        .pid = pid,
        .event_type = SSH_FAILURE,
        .timestamp = bpf_ktime_get_ns(),
    };
    
    bpf_perf_event_output(ctx, &ssh_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

