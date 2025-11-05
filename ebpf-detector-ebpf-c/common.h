#ifndef COMMON_H
#define COMMON_H

// Basic type definitions for eBPF (always define)
#ifndef __u64
typedef unsigned long long __u64;
#endif
#ifndef __u32
typedef unsigned int __u32;
#endif
#ifndef __u16
typedef unsigned short __u16;
#endif
#ifndef __u8
typedef unsigned char __u8;
#endif
#ifndef __s32
typedef int __s32;
#endif
#ifndef __s64
typedef long long __s64;
#endif
#ifndef __be16
typedef __u16 __be16;
#endif
#ifndef __be32
typedef __u32 __be32;
#endif
#ifndef __wsum
typedef __u32 __wsum;
#endif

// BPF map type definitions
#ifndef BPF_MAP_TYPE_PERF_EVENT_ARRAY
#define BPF_MAP_TYPE_PERF_EVENT_ARRAY 4
#endif
#ifndef BPF_MAP_TYPE_HASH
#define BPF_MAP_TYPE_HASH 1
#endif
#ifndef BPF_ANY
#define BPF_ANY 0
#endif
#ifndef BPF_F_CURRENT_CPU
#define BPF_F_CURRENT_CPU 0xffffffffULL
#endif

// TCP state definitions
#ifndef TCP_SYN_SENT
#define TCP_SYN_SENT 2
#endif
#ifndef TCP_SYN_RECV
#define TCP_SYN_RECV 3
#endif

// Minimal pt_regs structure for x86_64 (for kprobe access)
struct pt_regs {
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long rbp;
    unsigned long rbx;
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long rax;
    unsigned long rcx;
    unsigned long rdx;
    unsigned long rsi;
    unsigned long rdi;  // PT_REGS_PARM1
    unsigned long orig_rax;
    unsigned long rip;
    unsigned long cs;
    unsigned long eflags;
    unsigned long rsp;
    unsigned long ss;
};

#define MAX_IP_ADDRESSES 1024
#define MAX_EVENTS 1024

struct ssh_event {
    __u32 ip;
    __u16 port;
    __u32 pid;
    __u8 event_type;
    __u64 timestamp;
};

struct tcp_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 event_type;
    __u64 timestamp;
};

enum event_type {
    SSH_ATTEMPT = 0,
    SSH_FAILURE = 1,
    SSH_SUCCESS = 2,
    TCP_CONNECT = 3,
    TCP_ACCEPT = 4,
    TCP_CLOSE = 5,
};

#endif // COMMON_H

