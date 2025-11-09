use crate::detector::ThreatDetector;
use aya::{Ebpf, maps::RingBuf, programs::TracePoint};
use aya_log::EbpfLogger;
use log::{info, warn};
use std::{mem, path::Path, sync::Arc, thread, time::Duration};

#[repr(C)]
#[derive(Clone, Copy)]
struct EventV4 {
    saddr: u32,
    daddr: u32,
    sport: u16,
    dport: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NetEvent {
    ts_ns: u64,
    ifindex: u32,
    family: u8,
    etype: u8,
    tcp_flags: u8,
    src_cat: u8,
    v4: EventV4,
}

const AF_INET: u8 = 2;
const EVT_SSH_ATTEMPT: u8 = 2;
const EVT_SSH_BRUTE: u8 = 4;

pub struct EventProcessor {
    detector: Arc<ThreatDetector>,
    ssh_port: u16,
}

impl EventProcessor {
    pub fn new(detector: Arc<ThreatDetector>, ssh_port: u16) -> Self {
        Self { detector, ssh_port }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        // Try multiple known eBPF object paths
        let candidates = [
            "/usr/local/lib/secrds/secrds-ebpf.o",
            "/usr/local/lib/secrds/secrds-ebpf.bpf.o",
            "target/release/bpf/secrds-ebpf.o",
            "target/bpfel-unknown-none/release/secrds-ebpf",
            "../target/release/bpf/secrds-ebpf.o",
        ];

        // Load eBPF
        let mut bpf = {
            let mut loaded: Option<Ebpf> = None;
            for p in candidates {
                if Path::new(p).exists() {
                    match Ebpf::load_file(p) {
                        Ok(obj) => {
                            info!("Loaded eBPF program from: {}", p);
                            loaded = Some(obj);
                            break;
                        }
                        Err(e) => warn!("Found {}, but failed to load eBPF: {}", p, e),
                    }
                }
            }
            loaded.ok_or_else(|| anyhow::anyhow!("eBPF program not found in known locations"))?
        };

        // Initialize Aya eBPF logger (non-fatal)
        if let Err(e) = EbpfLogger::init(&mut bpf) {
            warn!("eBPF logger init failed: {}", e);
        }

        // Attach to tracepoint from eBPF program
        let tp: &mut TracePoint = bpf
            .program_mut("inet_sock_set_state")
            .ok_or_else(|| anyhow::anyhow!("tracepoint program `inet_sock_set_state` not found"))?
            .try_into()?;

        tp.load()?;
        tp.attach("sock", "inet_sock_set_state")?;
        info!("Attached tracepoint sock/inet_sock_set_state");

        // Clone for thread
        let detector = Arc::clone(&self.detector);
        let ssh_port = self.ssh_port;

        // Move bpf into thread
        thread::spawn(move || {
            let mut bpf_thread = bpf;

            // Create ring buffer inside the thread
            let events = match bpf_thread.map_mut("EVENTS_RB") {
                Some(map) => map,
                None => {
                    warn!("ring buffer map `EVENTS_RB` not found");
                    return;
                }
            };

            let mut ring = match RingBuf::try_from(events) {
                Ok(r) => r,
                Err(e) => {
                    warn!("Failed to create RingBuf: {}", e);
                    return;
                }
            };

            loop {
                // ✅ Aya 0.12: `next()` returns Option<RingBufItem>
                if let Some(data) = ring.next() {
                    if data.len() < mem::size_of::<NetEvent>() {
                        continue;
                    }

                    let evt = unsafe { *(data.as_ptr() as *const NetEvent) };

                    if evt.family == AF_INET {
                        let dport = u16::from_be(evt.v4.dport);
                        if dport == ssh_port {
                            match evt.etype {
                                EVT_SSH_ATTEMPT | EVT_SSH_BRUTE => {
                                    let det = Arc::clone(&detector);
                                    let saddr = evt.v4.saddr;
                                    let dport_copy = dport;
                                    tokio::spawn(async move {
                                        let event_type = 1u8; // SSH_FAILURE
                                        if let Err(e) = det
                                            .process_ssh_event(saddr, dport_copy, 0, event_type)
                                            .await
                                        {
                                            warn!("Failed to process SSH event: {}", e);
                                        }
                                    });
                                }
                                _ => {}
                            }
                        }
                    }
                } else {
                    // No events currently available
                    thread::sleep(Duration::from_millis(100));
                }
            }
        });

        info!("Event processing loop started successfully.");
        Ok(())
    }
}
