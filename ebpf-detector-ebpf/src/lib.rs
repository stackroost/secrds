#![no_std]
#![no_main]
#![allow(static_mut_refs)]

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[repr(u8)]
pub enum EventType {
    SshAttempt = 0,
    SshFailure = 1,
    SshSuccess = 2,
    TcpConnect = 3,
    TcpAccept = 4,
    TcpClose = 5,
}

mod ssh_monitor;
mod tcp_monitor;

