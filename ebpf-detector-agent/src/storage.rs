use crate::threat_detector::{ThreatAlert, ThreatType};
use anyhow::Context;
use chrono::{DateTime, Utc};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredAlert {
    pub ip: String,
    pub threat_type: String,
    pub count: u64,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StorageData {
    alerts: Vec<StoredAlert>,
    blocked_ips: Vec<String>,
    statistics: Statistics,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Statistics {
    pub total_alerts: u64,
    pub ssh_brute_force_count: u64,
    pub tcp_port_scan_count: u64,
    pub tcp_flood_count: u64,
    pub blocked_ips_count: u64,
}

pub struct Storage {
    path: PathBuf,
    data: Arc<RwLock<StorageData>>,
}

impl Storage {
    pub fn new(path: PathBuf) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory: {:?}", parent))?;
        }

        let data = if path.exists() {
            let content = fs::read_to_string(&path)
                .with_context(|| format!("Failed to read storage file: {:?}", path))?;
            serde_json::from_str(&content)
                .unwrap_or_else(|_| StorageData {
                    alerts: Vec::new(),
                    blocked_ips: Vec::new(),
                    statistics: Statistics::default(),
                })
        } else {
            StorageData {
                alerts: Vec::new(),
                blocked_ips: Vec::new(),
                statistics: Statistics::default(),
            }
        };

        let storage = Self {
            path,
            data: Arc::new(RwLock::new(data)),
        };

        let storage_path = storage.path.clone();
        let storage_data = storage.data.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                let data = storage_data.read().await;
                let json = match serde_json::to_string_pretty(&*data) {
                    Ok(json) => json,
                    Err(e) => {
                        error!("Failed to serialize storage data: {}", e);
                        continue;
                    }
                };
                
                if let Err(e) = fs::write(&storage_path, json) {
                    error!("Failed to flush storage: {}", e);
                }
            }
        });

        Ok(storage)
    }

    pub async fn store_alert(&self, alert: &ThreatAlert) -> anyhow::Result<()> {
        let mut data = self.data.write().await;

        let stored_alert = StoredAlert {
            ip: alert.ip.to_string(),
            threat_type: match alert.threat_type {
                ThreatType::SshBruteForce => "SSH_BRUTE_FORCE".to_string(),
                ThreatType::TcpPortScan => "TCP_PORT_SCAN".to_string(),
                ThreatType::TcpFlood => "TCP_FLOOD".to_string(),
            },
            count: alert.count,
            timestamp: alert.timestamp,
        };

        data.alerts.push(stored_alert);
        data.statistics.total_alerts += 1;

        match alert.threat_type {
            ThreatType::SshBruteForce => data.statistics.ssh_brute_force_count += 1,
            ThreatType::TcpPortScan => data.statistics.tcp_port_scan_count += 1,
            ThreatType::TcpFlood => data.statistics.tcp_flood_count += 1,
        }

        if data.alerts.len() > 1000 {
            data.alerts.remove(0);
        }

        Ok(())
    }

    pub async fn add_blocked_ip(&self, ip: &str) -> anyhow::Result<()> {
        let mut data = self.data.write().await;
        
        if !data.blocked_ips.contains(&ip.to_string()) {
            data.blocked_ips.push(ip.to_string());
            data.statistics.blocked_ips_count += 1;
        }

        Ok(())
    }

    pub async fn get_alerts(&self, limit: usize) -> Vec<StoredAlert> {
        let data = self.data.read().await;
        data.alerts
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    pub async fn get_statistics(&self) -> Statistics {
        let data = self.data.read().await;
        data.statistics.clone()
    }

    pub async fn flush(&self) -> anyhow::Result<()> {
        let data = self.data.read().await;
        let json = serde_json::to_string_pretty(&*data)
            .context("Failed to serialize storage data")?;
        
        fs::write(&self.path, json)
            .with_context(|| format!("Failed to write storage file: {:?}", self.path))?;

        Ok(())
    }
}

