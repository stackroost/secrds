use crate::config::Config;
use crate::event_processor::{SshEvent, TcpEvent};
use crate::storage::Storage;
use crate::telegram_client::TelegramClient;
use anyhow::Context;
use chrono::{DateTime, Utc};
use log::{error, info, warn};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct ThreatAlert {
    pub ip: IpAddr,
    pub threat_type: ThreatType,
    pub count: u64,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub enum ThreatType {
    SshBruteForce,
    TcpPortScan,
    TcpFlood,
}

pub struct ThreatDetector {
    config: Config,
    storage: Arc<Storage>,
    telegram_client: Arc<TelegramClient>,
    ssh_attempts: HashMap<IpAddr, Vec<SystemTime>>,
    tcp_connections: HashMap<IpAddr, Vec<SystemTime>>,
    blocked_ips: std::collections::HashSet<IpAddr>,
}

impl ThreatDetector {
    pub fn new(
        config: Config,
        storage: Arc<Storage>,
        telegram_client: Arc<TelegramClient>,
    ) -> Self {
        Self {
            config,
            storage,
            telegram_client,
            ssh_attempts: HashMap::new(),
            tcp_connections: HashMap::new(),
            blocked_ips: std::collections::HashSet::new(),
        }
    }

    pub async fn process_ssh_event(&mut self, event: SshEvent) -> anyhow::Result<()> {
        let ip = self.u32_to_ip(event.ip)?;
        
        if self.blocked_ips.contains(&ip) {
            return Ok(());
        }

        let now = SystemTime::now();
        
        let attempts = self.ssh_attempts.entry(ip).or_insert_with(Vec::new);
        attempts.push(now);

        let window = Duration::from_secs(self.config.ssh_window_seconds);
        attempts.retain(|&time| now.duration_since(time).unwrap_or(Duration::ZERO) < window);

        let attempt_count = attempts.len() as u64;
        if attempt_count > self.config.ssh_threshold {
            warn!("SSH brute force detected from IP: {}", ip);
            
            let alert = ThreatAlert {
                ip,
                threat_type: ThreatType::SshBruteForce,
                count: attempt_count,
                timestamp: Utc::now(),
            };

            self.storage.store_alert(&alert).await?;
            
            self.telegram_client.send_alert(&alert).await?;
            
            if self.config.enable_ip_blocking {
                self.block_ip(ip).await?;
                self.storage.add_blocked_ip(&ip.to_string()).await?;
            }
        }

        Ok(())
    }

    pub async fn process_tcp_event(&mut self, event: TcpEvent) -> anyhow::Result<()> {
        let ip = self.u32_to_ip(event.src_ip)?;
        
        if self.blocked_ips.contains(&ip) {
            return Ok(());
        }

        let now = SystemTime::now();
        
        let connections = self.tcp_connections.entry(ip).or_insert_with(Vec::new);
        connections.push(now);

        let window = Duration::from_secs(self.config.tcp_window_seconds);
        connections.retain(|&time| now.duration_since(time).unwrap_or(Duration::ZERO) < window);

        let connection_count = connections.len() as u64;
        if connection_count > self.config.tcp_threshold {
            warn!("TCP flood/port scan detected from IP: {}", ip);
            
            let alert = ThreatAlert {
                ip,
                threat_type: ThreatType::TcpPortScan,
                count: connection_count,
                timestamp: Utc::now(),
            };

            self.storage.store_alert(&alert).await?;
            
            self.telegram_client.send_alert(&alert).await?;
            
            if self.config.enable_ip_blocking {
                self.block_ip(ip).await?;
                self.storage.add_blocked_ip(&ip.to_string()).await?;
            }
        }

        Ok(())
    }

    async fn block_ip(&mut self, ip: IpAddr) -> anyhow::Result<()> {
        self.blocked_ips.insert(ip);
        
        let ip_str = ip.to_string();
        let output = tokio::process::Command::new("iptables")
            .arg("-A")
            .arg("INPUT")
            .arg("-s")
            .arg(&ip_str)
            .arg("-j")
            .arg("DROP")
            .output()
            .await?;

        if !output.status.success() {
            warn!("Failed to block IP {} with iptables", ip_str);
        } else {
            info!("Blocked IP: {}", ip_str);
        }

        Ok(())
    }

    fn u32_to_ip(&self, ip: u32) -> anyhow::Result<IpAddr> {
        let bytes = ip.to_be_bytes();
        Ok(IpAddr::from(bytes))
    }
}

