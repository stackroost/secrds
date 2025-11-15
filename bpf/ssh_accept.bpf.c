

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/in.h>

struct sock;

struct inet_sock {
    __be16 inet_sport;
    __be16 inet_dport;
    __be32 inet_rcv_saddr;
    __be32 inet_daddr;
};

struct trace_event_raw_sys_exit {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    long id;
    long ret;
};

struct accept_event {
    __u32 pid;
    __u32 tgid;
    int fd;                
    __u64 ts_ns;
    char comm[16];
    __be32 peer_ip;        
    __be16 peer_port;      
    __be32 local_ip;       
    __be16 local_port;     
    __u8 has_sock_info;    
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 0);
} events SEC(".maps");

static __always_inline void extract_sock_info(struct sock *sk, struct accept_event *ev)
{
    if (!sk) {
        ev->has_sock_info = 0;
        return;
    }

    struct inet_sock inet = {};
    
    
    __u16 sport, dport;
    __u32 rcv_saddr, daddr;
    
    bpf_probe_read_kernel(&sport, sizeof(sport), (char *)sk + 200);
    bpf_probe_read_kernel(&dport, sizeof(dport), (char *)sk + 202);
    bpf_probe_read_kernel(&rcv_saddr, sizeof(rcv_saddr), (char *)sk + 204);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), (char *)sk + 208);
    
    bpf_probe_read_kernel(&inet.inet_sport, sizeof(inet.inet_sport), 
                          (char *)sk + 72);
    bpf_probe_read_kernel(&inet.inet_dport, sizeof(inet.inet_dport), 
                          (char *)sk + 74);
    bpf_probe_read_kernel(&inet.inet_rcv_saddr, sizeof(inet.inet_rcv_saddr), 
                          (char *)sk + 76);
    bpf_probe_read_kernel(&inet.inet_daddr, sizeof(inet.inet_daddr), 
                          (char *)sk + 80);
    
    ev->peer_ip = inet.inet_daddr;
    ev->peer_port = inet.inet_dport;
    ev->local_ip = inet.inet_rcv_saddr;
    ev->local_port = inet.inet_sport;
    
    ev->has_sock_info = 1;
}


SEC("kretprobe/inet_csk_accept")
int kretprobe_inet_csk_accept(struct pt_regs *ctx)
{
    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
    if (!newsk) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct accept_event ev = {};
    ev.pid = (__u32)pid_tgid;
    ev.tgid = (__u32)(pid_tgid >> 32);
    ev.fd = -1;  
    ev.ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    
    extract_sock_info(newsk, &ev);
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
    
    return 0;
}

static __always_inline int handle_accept_exit(struct trace_event_raw_sys_exit *ctx)
{
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int trace_exit_accept4(struct trace_event_raw_sys_exit *ctx)
{
    return handle_accept_exit(ctx);
}

SEC("tracepoint/syscalls/sys_exit_accept")
int trace_exit_accept(struct trace_event_raw_sys_exit *ctx)
{
    return handle_accept_exit(ctx);
}

char _license[] SEC("license") = "GPL";
