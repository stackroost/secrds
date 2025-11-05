use crate::ebpf_loader::EbpfLoader;
use crate::threat_detector::ThreatDetector;
use anyhow::Context;
use log::{error, info, warn};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct SshEvent {
    pub ip: u32,
    pub port: u16,
    pub pid: u32,
    pub event_type: u8,
    pub timestamp: u64,
}

#[derive(Debug, Clone)]
pub struct TcpEvent {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub event_type: u8,
    pub timestamp: u64,
}

pub struct EventProcessor {
    ebpf_loader: EbpfLoader,
    threat_detector: Arc<ThreatDetector>,
}

impl EventProcessor {
    pub fn new(
        ebpf_loader: EbpfLoader,
        threat_detector: Arc<ThreatDetector>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            ebpf_loader,
            threat_detector,
        })
    }

    pub async fn process_events(&mut self) -> anyhow::Result<()> {
        info!("Starting event processing loop");

        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    fn parse_ssh_event(&self, data: &[u8]) -> anyhow::Result<SshEvent> {
        if data.len() < 16 {
            anyhow::bail!("Invalid SSH event data size");
        }
        Ok(SshEvent {
            ip: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            port: u16::from_le_bytes([data[4], data[5]]),
            pid: u32::from_le_bytes([data[6], data[7], data[8], data[9]]),
            event_type: data[10],
            timestamp: u64::from_le_bytes([
                data[11], data[12], data[13], data[14],
                data[15], data[16], data[17], data[18],
            ]),
        })
    }

    fn parse_tcp_event(&self, data: &[u8]) -> anyhow::Result<TcpEvent> {
        if data.len() < 20 {
            anyhow::bail!("Invalid TCP event data size");
        }
        Ok(TcpEvent {
            src_ip: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            dst_ip: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            src_port: u16::from_le_bytes([data[8], data[9]]),
            dst_port: u16::from_le_bytes([data[10], data[11]]),
            event_type: data[12],
            timestamp: u64::from_le_bytes([
                data[13], data[14], data[15], data[16],
                data[17], data[18], data[19], data[20],
            ]),
        })
    }
}

