// bpf/ssh_accept.bpf.c
// Compile target: clang -O2 -g -target bpf -c ssh_accept.bpf.c -o ssh_accept.bpf.o

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ptrace.h>
#include <linux/sched.h>

// Tracepoint struct definition for sys_exit
struct trace_event_raw_sys_exit {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    long id;
    long ret;
};

// Event we send to userland
struct accept_event {
    __u32 pid;
    __u32 tgid;
    int fd;                // returned fd from accept4
    __u64 ts_ns;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 0);
} events SEC(".maps");

// Helper function to handle accept/accept4 exit
static __always_inline int handle_accept_exit(struct trace_event_raw_sys_exit *ctx)
{
    int retval = (int)ctx->ret;
    if (retval < 0) {
        // accept failed
        return 0;
    }

    struct accept_event ev = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    ev.pid = (__u32)pid_tgid;           // tid
    ev.tgid = (__u32)(pid_tgid >> 32);  // pid (tgid)
    ev.fd = retval;
    ev.ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));

    // send to userland
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
    return 0;
}

// tracepoint: sys_exit_accept4
SEC("tracepoint/syscalls/sys_exit_accept4")
int trace_exit_accept4(struct trace_event_raw_sys_exit *ctx)
{
    return handle_accept_exit(ctx);
}

// tracepoint: sys_exit_accept (for systems using accept instead of accept4)
SEC("tracepoint/syscalls/sys_exit_accept")
int trace_exit_accept(struct trace_event_raw_sys_exit *ctx)
{
    return handle_accept_exit(ctx);
}

char _license[] SEC("license") = "GPL";
