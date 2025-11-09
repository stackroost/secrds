#![no_std]
#![no_main]
#![allow(static_mut_refs)]
#![allow(unused_must_use)]

use aya_ebpf::{
    helpers::{bpf_ktime_get_ns},
    macros::{kprobe, map, tracepoint},
    maps::{Array, LruHashMap, RingBuf},
    programs::{ProbeContext, TracePointContext},
};

// ======== Struct Definitions ========

#[repr(C)]
pub struct TraceEventRawInetSockSetState {
    _pad: [u8; 8],
    skaddr: u64,
    oldstate: i32,
    newstate: i32,
    sport: u16,
    dport: u16,
    family: u16,
    protocol: u16,
    saddr: [u8; 4],
    daddr: [u8; 4],
}

#[repr(C)]
pub struct NetEvent {
    ts_ns: u64,
    ifindex: u32,
    family: u8,
    etype: u8,
    tcp_flags: u8,
    src_cat: u8,
    v4: EventV4,
}

#[repr(C)]
pub struct EventV4 {
    saddr: u32,
    daddr: u32,
    sport: u16,
    dport: u16,
}

#[repr(C)]
pub struct StatWin {
    first_ts: u64,
    last_ts: u64,
    syn_count: u32,
    ssh_count: u32,
    rst_count: u32,
}

// ======== Constants ========

const AF_INET: u16 = 2;
const IPPROTO_TCP: u16 = 6;
const SSH_PORT: u16 = 22;

// TCP States
const TCP_ESTABLISHED: i32 = 1;
const TCP_SYN_SENT: i32 = 2;
const TCP_SYN_RECV: i32 = 3;
const TCP_CLOSE: i32 = 7;
const TCP_LISTEN: i32 = 10;
const TCP_NEW_SYN_RECV: i32 = 12;

// Detection Thresholds
const SCAN_WINDOW_NS: u64 = 5_000_000_000;
const SCAN_THRESH: u32 = 20;
const BRUTE_THRESH: u32 = 40;

// Event Types
const EVT_SSH_ATTEMPT: u8 = 2;
const EVT_PORT_SCAN: u8 = 3;
const EVT_SSH_BRUTE: u8 = 4;
const EVT_TCP_RST_FLOOD: u8 = 5;

// Source Categories
const SRC_PUBLIC: u8 = 0;
const SRC_RFC1918: u8 = 1;
const SRC_CGNAT: u8 = 2;
const SRC_LOOP: u8 = 3;

// ======== eBPF Maps ========

// Put debug/format strings into a stable .rodata section to avoid
// relocations against compiler-generated `.rodata.str1.1` which
// libbpf rejects when loading eBPF objects.
#[link_section = ".rodata"]
#[no_mangle]
pub static F_INET_SOCK_SET_STATE: [u8; 54] = *b"inet_sock_set_state: old=%d new=%d sport=%d dport=%d\n\0";

#[link_section = ".rodata"]
#[no_mangle]
pub static F_SSH_SYN_DETECTED: [u8; 36] = *b"SSH SYN detected saddr=%x count=%d\n\0";

#[link_section = ".rodata"]
#[no_mangle]
pub static F_SSH_SESSION_CLOSED: [u8; 29] = *b"SSH session closed saddr=%x\n\0";

#[link_section = ".rodata"]
#[no_mangle]
pub static F_KPROBE_TCP_V4_CONNECT: [u8; 31] = *b"kprobe: tcp_v4_connect called\n\0";

#[link_section = ".rodata"]
#[no_mangle]
pub static F_KPROBE_INET_CSK_ACCEPT: [u8; 43] = *b"kprobe: inet_csk_accept called (incoming)\n\0";


#[map]
static mut V4_STATS: LruHashMap<u32, StatWin> = LruHashMap::with_max_entries(65536, 0);

#[map]
static mut EVENTS_RB: RingBuf = RingBuf::with_byte_size(4096, 0);

#[map]
static mut DEBUG_COUNT: Array<u64> = Array::with_max_entries(1, 0);

// ======== Debug Print Wrappers ========

#[inline(always)]
fn klog0(msg: &[u8]) {
    // no-op: plain printk helpers are not available on all kernels
    // keep as a thin wrapper so call sites don't need edits
}

#[inline(always)]
fn klog2(fmt: &[u8], a: i64, b: i64) {
    let args = [a, b];
    // no-op
}

#[inline(always)]
fn klog4(fmt: &[u8], a: i64, b: i64, c: i64, d: i64) {
    let args = [a, b, c, d];
    // no-op
}

// ======== Utility Functions ========

#[inline(always)]
fn src_classify_v4(ip: u32) -> u8 {
    if (ip & 0xFF00_0000) == 0x7F00_0000 {
        SRC_LOOP
    } else if (ip & 0xFF00_0000) == 0x0A00_0000 {
        SRC_RFC1918
    } else if (ip & 0xFFF0_0000) == 0xAC10_0000 {
        SRC_RFC1918
    } else if (ip & 0xFFFF_0000) == 0xC0A8_0000 {
        SRC_RFC1918
    } else if (ip & 0xFFC0_0000) == 0x6440_0000 {
        SRC_CGNAT
    } else {
        SRC_PUBLIC
    }
}

#[inline(always)]
fn push_event_v4(saddr: u32, daddr: u32, sport: u16, dport: u16, etype: u8) {
    let now = unsafe { bpf_ktime_get_ns() };
    let event = NetEvent {
        ts_ns: now,
        ifindex: 0,
        family: AF_INET as u8,
        etype,
        tcp_flags: 0x02,
        src_cat: src_classify_v4(saddr),
        v4: EventV4 { saddr, daddr, sport, dport },
    };

    unsafe {
        if let Some(mut entry) = EVENTS_RB.reserve::<NetEvent>(0) {
            entry.write(event);
            entry.submit(0);
        }
    }
}

// ======== Main eBPF Programs ========

#[tracepoint]
pub fn inet_sock_set_state(ctx: TracePointContext) -> u32 {
    unsafe {
        if let Some(count) = DEBUG_COUNT.get_ptr_mut(0) {
            *count += 1;
        }
    }

    let tp = match unsafe { ctx.read_at::<TraceEventRawInetSockSetState>(0) } {
        Ok(v) => v,
        Err(_) => return 0,
    };

    if tp.family != AF_INET || tp.protocol != IPPROTO_TCP {
        return 0;
    }

    let dport = u16::from_be(tp.dport);
    let sport = u16::from_be(tp.sport);
    let oldstate = tp.oldstate;
    let newstate = tp.newstate;

    let saddr = u32::from_be_bytes(tp.saddr);
    let daddr = u32::from_be_bytes(tp.daddr);

    klog4(
        &F_INET_SOCK_SET_STATE,
        oldstate as i64,
        newstate as i64,
        sport as i64,
        dport as i64,
    );

    let now = unsafe { bpf_ktime_get_ns() };

    unsafe {
        let zero = StatWin {
            first_ts: 0,
            last_ts: 0,
            syn_count: 0,
            ssh_count: 0,
            rst_count: 0,
        };

        let mut_ptr = V4_STATS.get_ptr_mut(&saddr);
        if mut_ptr.is_none() {
            let _ = V4_STATS.insert(&saddr, &zero, 0);
        }

        let mut_ptr = match V4_STATS.get_ptr_mut(&saddr) {
            Some(ptr) => ptr,
            None => return 0,
        };

        let st = &mut *mut_ptr;

        if st.first_ts == 0 || (now - st.first_ts) > SCAN_WINDOW_NS {
            st.first_ts = now;
            st.syn_count = 0;
            st.ssh_count = 0;
            st.rst_count = 0;
        }
        st.last_ts = now;

        // SYN-like transitions
        if newstate == TCP_SYN_SENT || newstate == TCP_SYN_RECV || newstate == TCP_NEW_SYN_RECV {
            st.syn_count += 1;
            if dport == SSH_PORT {
                st.ssh_count += 1;
                klog2(&F_SSH_SYN_DETECTED, saddr as i64, st.ssh_count as i64);
                let etype = if st.ssh_count >= BRUTE_THRESH {
                    EVT_SSH_BRUTE
                } else {
                    EVT_SSH_ATTEMPT
                };
                push_event_v4(saddr, daddr, sport, dport, etype);
            } else if st.syn_count >= SCAN_THRESH {
                push_event_v4(saddr, daddr, sport, dport, EVT_PORT_SCAN);
            }
        }

        // Detect closes (SSH disconnects)
        if newstate == TCP_CLOSE && dport == SSH_PORT {
            klog2(&F_SSH_SESSION_CLOSED, saddr as i64, 0);
        }

        // Detect RST floods
        if newstate == TCP_CLOSE && oldstate != TCP_LISTEN && oldstate != 0 {
            st.rst_count += 1;
            if st.rst_count >= (SCAN_THRESH * 2) {
                push_event_v4(saddr, daddr, sport, dport, EVT_TCP_RST_FLOOD);
            }
        }
    }

    0
}

#[kprobe]
pub fn tcp_v4_connect(_ctx: ProbeContext) -> u32 {
    klog0(&F_KPROBE_TCP_V4_CONNECT);
    0
}

#[kprobe]
pub fn inet_csk_accept(_ctx: ProbeContext) -> u32 {
    klog0(&F_KPROBE_INET_CSK_ACCEPT);
    0
}

// ======== Panic & License ========

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
