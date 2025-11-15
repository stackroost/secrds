#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/ptrace.h>
#include <linux/sched.h>

struct auth_event {
    __u32 pid;
    __u32 tgid;
    __s32 ret_code;
    __u64 ts_ns;
    char comm[16];
    __u8 is_failure;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 0);
} auth_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 1024);
} pid_socket_map SEC(".maps");

SEC("uprobe")
int uprobe_pam_authenticate(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)pid_tgid;
    __u32 tgid = (__u32)(pid_tgid >> 32);

    char comm[16] = {};
    bpf_get_current_comm(&comm, sizeof(comm));

    if (comm[0] != 's' || comm[1] != 's' || comm[2] != 'h' || comm[3] != 'd') {
        return 0;
    }
    return 0;
}

SEC("uretprobe")
int uretprobe_pam_authenticate(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)pid_tgid;
    __u32 tgid = (__u32)(pid_tgid >> 32);

    char comm[16] = {};
    bpf_get_current_comm(&comm, sizeof(comm));

    if (comm[0] != 's' || comm[1] != 's' || comm[2] != 'h' || comm[3] != 'd') {
        return 0;
    }

    long ret = PT_REGS_RC(ctx);

    struct auth_event ev = {};
    ev.pid = pid;
    ev.tgid = tgid;
    ev.ret_code = (__s32)ret;
    ev.ts_ns = bpf_ktime_get_ns();

    ev.is_failure = (ret != 0) ? 1 : 0;

    __builtin_memset(&ev.comm, 0, sizeof(ev.comm));
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));

    bpf_perf_event_output(ctx, &auth_events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));

    return 0;
}

char _license[] SEC("license") = "GPL";