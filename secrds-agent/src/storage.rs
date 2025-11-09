use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatType {
    #[serde(rename = "SSH_BRUTE_FORCE")]
    SshBruteForce,
    #[serde(rename = "TCP_PORT_SCAN")]
    TcpPortScan,
    #[serde(rename = "TCP_FLOOD")]
    TcpFlood,
}

#[derive(Debug, Clone)]
pub struct Alert {
    pub ip: String,
    pub threat_type: ThreatType,
    pub count: u64,
    pub timestamp: SystemTime,
    pub severity: Option<String>,
    pub details: Option<String>,
    pub score: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Statistics {
    pub total_alerts: u64,
    pub ssh_brute_force_count: u64,
    pub tcp_port_scan_count: u64,
    pub tcp_flood_count: u64,
    pub blocked_ips_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StorageData {
    alerts: Vec<Alert>,
    blocked_ips: Vec<String>,
    statistics: Statistics,
}

pub struct Storage {
    path: PathBuf,
    data: Arc<RwLock<StorageData>>,
    blocked_map: Arc<RwLock<HashMap<String, bool>>>,
}

impl Storage {
    pub fn new(path: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut data = StorageData {
            alerts: Vec::new(),
            blocked_ips: Vec::new(),
            statistics: Statistics {
                total_alerts: 0,
                ssh_brute_force_count: 0,
                tcp_port_scan_count: 0,
                tcp_flood_count: 0,
                blocked_ips_count: 0,
            },
        };

        if path.exists() {
            if let Ok(content) = fs::read_to_string(&path) {
                if let Ok(loaded) = serde_json::from_str::<StorageData>(&content) {
                    data = loaded;
                }
            }
        }

        let blocked_map: HashMap<String, bool> = data.blocked_ips.iter().map(|ip| (ip.clone(), true)).collect();

        let storage = Self {
            path,
            data: Arc::new(RwLock::new(data)),
            blocked_map: Arc::new(RwLock::new(blocked_map)),
        };

        let storage_clone = storage.clone_for_background();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                if let Err(e) = storage_clone.flush() {
                    log::error!("Failed to flush storage: {}", e);
                }
            }
        });

        Ok(storage)
    }

    fn clone_for_background(&self) -> BackgroundStorage {
        BackgroundStorage {
            path: self.path.clone(),
            data: Arc::clone(&self.data),
            blocked_map: Arc::clone(&self.blocked_map),
        }
    }

    pub fn store_alert(&self, alert: Alert) -> anyhow::Result<()> {
        let mut data = self.data.write().unwrap();
        data.alerts.push(alert.clone());
        data.statistics.total_alerts += 1;

        match alert.threat_type {
            ThreatType::SshBruteForce => {
                data.statistics.ssh_brute_force_count += 1;
            }
            ThreatType::TcpPortScan => {
                data.statistics.tcp_port_scan_count += 1;
            }
            ThreatType::TcpFlood => {
                data.statistics.tcp_flood_count += 1;
            }
        }

        if data.alerts.len() > 1000 {
            let len = data.alerts.len();
            let keep = data.alerts.split_off(len - 1000);
            data.alerts = keep;
        }

        Ok(())
    }

    pub fn add_blocked_ip(&self, ip: String) -> anyhow::Result<()> {
        let mut blocked_map = self.blocked_map.write().unwrap();
        if blocked_map.contains_key(&ip) {
            return Ok(());
        }

        let mut data = self.data.write().unwrap();
        data.blocked_ips.push(ip.clone());
        blocked_map.insert(ip, true);
        data.statistics.blocked_ips_count += 1;

        Ok(())
    }

    pub fn get_alerts(&self, limit: usize) -> Vec<Alert> {
        let data = self.data.read().unwrap();
        let mut alerts = data.alerts.clone();
        if alerts.len() > limit {
            alerts = alerts.split_off(alerts.len() - limit);
        }
        alerts.reverse();
        alerts
    }

    pub fn get_statistics(&self) -> Statistics {
        let data = self.data.read().unwrap();
        data.statistics.clone()
    }

    pub fn is_blocked(&self, ip: &str) -> bool {
        let blocked_map = self.blocked_map.read().unwrap();
        blocked_map.get(ip).copied().unwrap_or(false)
    }

    pub fn flush(&self) -> anyhow::Result<()> {
        let data = self.data.read().unwrap();
        let json = serde_json::to_string_pretty(&*data)?;
        fs::write(&self.path, json)?;
        Ok(())
    }
}

struct BackgroundStorage {
    path: PathBuf,
    data: Arc<RwLock<StorageData>>,
    blocked_map: Arc<RwLock<HashMap<String, bool>>>,
}

impl BackgroundStorage {
    fn flush(&self) -> anyhow::Result<()> {
        let data = self.data.read().unwrap();
        let json = serde_json::to_string_pretty(&*data)?;
        fs::write(&self.path, json)?;
        Ok(())
    }
}

impl Serialize for Alert {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("Alert", 7)?;
        state.serialize_field("ip", &self.ip)?;
        state.serialize_field("threat_type", &self.threat_type)?;
        state.serialize_field("count", &self.count)?;
        let timestamp = self.timestamp.duration_since(UNIX_EPOCH).unwrap().as_secs();
        state.serialize_field("timestamp", &timestamp)?;
        state.serialize_field("severity", &self.severity)?;
        state.serialize_field("details", &self.details)?;
        state.serialize_field("score", &self.score)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for Alert {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct AlertHelper {
            ip: String,
            threat_type: ThreatType,
            count: u64,
            timestamp: u64,
            severity: Option<String>,
            details: Option<String>,
            score: Option<f64>,
        }

        let helper = AlertHelper::deserialize(deserializer)?;
        Ok(Alert {
            ip: helper.ip,
            threat_type: helper.threat_type,
            count: helper.count,
            timestamp: UNIX_EPOCH + Duration::from_secs(helper.timestamp),
            severity: helper.severity,
            details: helper.details,
            score: helper.score,
        })
    }
}

