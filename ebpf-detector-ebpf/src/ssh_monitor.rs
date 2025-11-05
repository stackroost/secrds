use aya_ebpf::{
    macros::{kprobe, map},
    maps::{HashMap, PerfEventArray},
    programs::ProbeContext,
    EbpfContext,
};

use crate::EventType;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SshEvent {
    pub ip: u32,
    pub port: u16,
    pub pid: u32,
    pub event_type: u8,
    pub timestamp: u64,
}

#[map]
static mut SSH_EVENTS: PerfEventArray<SshEvent> = PerfEventArray::new(0);

#[map]
static mut SSH_FAILURE_COUNT: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);

#[map]
static mut SSH_ATTEMPTS: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);

#[kprobe]
pub fn ssh_authentication_failure(ctx: ProbeContext) -> u32 {
    match try_ssh_authentication_failure(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_ssh_authentication_failure(ctx: ProbeContext) -> Result<u32, u32> {
    let pid = ctx.pid();
    
    let ip: u32 = 0;
    
    unsafe {
        let count = SSH_FAILURE_COUNT.get(&ip).copied().unwrap_or(0);
        let new_count = count + 1;
        let _ = SSH_FAILURE_COUNT.insert(&ip, &new_count, 0);

        let event = SshEvent {
            ip,
            port: 22,
            pid,
            event_type: EventType::SshFailure as u8,
            timestamp: aya_ebpf::helpers::bpf_ktime_get_ns(),
        };

        SSH_EVENTS.output(&ctx, &event, 0);
    }

    Ok(0)
}

#[kprobe]
pub fn ssh_connection_attempt(ctx: ProbeContext) -> u32 {
    match try_ssh_connection_attempt(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_ssh_connection_attempt(ctx: ProbeContext) -> Result<u32, u32> {
    let pid = ctx.pid();
    let ip: u32 = 0;
    
    unsafe {
        let count = SSH_ATTEMPTS.get(&ip).copied().unwrap_or(0);
        let new_count = count + 1;
        let _ = SSH_ATTEMPTS.insert(&ip, &new_count, 0);

        let event = SshEvent {
            ip,
            port: 22,
            pid,
            event_type: EventType::SshAttempt as u8,
            timestamp: aya_ebpf::helpers::bpf_ktime_get_ns(),
        };

        SSH_EVENTS.output(&ctx, &event, 0);
    }

    Ok(0)
}
