use aya_ebpf::{
    macros::{kprobe, map},
    maps::{HashMap, PerfEventArray},
    programs::ProbeContext,
};

use crate::EventType;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct TcpEvent {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub event_type: u8,
    pub timestamp: u64,
}

#[map]
static mut TCP_EVENTS: PerfEventArray<TcpEvent> = PerfEventArray::new(0);

#[map]
static mut TCP_CONNECTION_COUNT: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);

#[map]
static mut TCP_PORT_SCAN: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);

#[kprobe]
pub fn tcp_connect(ctx: ProbeContext) -> u32 {
    match try_tcp_connect(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tcp_connect(ctx: ProbeContext) -> Result<u32, u32> {
    let src_ip: u32 = 0;
    let dst_port: u16 = 0;
    
    unsafe {
        let count = TCP_CONNECTION_COUNT.get(&src_ip).copied().unwrap_or(0);
        let new_count = count + 1;
        let _ = TCP_CONNECTION_COUNT.insert(&src_ip, &new_count, 0);

        let event = TcpEvent {
            src_ip,
            dst_ip: 0,
            src_port: 0,
            dst_port,
            event_type: EventType::TcpConnect as u8,
            timestamp: aya_ebpf::helpers::bpf_ktime_get_ns(),
        };

        TCP_EVENTS.output(&ctx, &event, 0);
    }

    Ok(0)
}

#[kprobe]
pub fn tcp_accept(ctx: ProbeContext) -> u32 {
    match try_tcp_accept(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tcp_accept(ctx: ProbeContext) -> Result<u32, u32> {
    let src_ip: u32 = 0;
    let dst_port: u16 = 0;
    
    unsafe {
        let count = TCP_CONNECTION_COUNT.get(&src_ip).copied().unwrap_or(0);
        let new_count = count + 1;
        let _ = TCP_CONNECTION_COUNT.insert(&src_ip, &new_count, 0);

        let event = TcpEvent {
            src_ip,
            dst_ip: 0,
            src_port: 0,
            dst_port,
            event_type: EventType::TcpAccept as u8,
            timestamp: aya_ebpf::helpers::bpf_ktime_get_ns(),
        };

        TCP_EVENTS.output(&ctx, &event, 0);
    }

    Ok(0)
}
