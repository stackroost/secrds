use crate::config::Config;
use crate::storage::{Alert, Storage, ThreatType};
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl ToString for ThreatSeverity {
    fn to_string(&self) -> String {
        match self {
            ThreatSeverity::Low => "LOW".to_string(),
            ThreatSeverity::Medium => "MEDIUM".to_string(),
            ThreatSeverity::High => "HIGH".to_string(),
            ThreatSeverity::Critical => "CRITICAL".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SSHEventDetail {
    pub timestamp: SystemTime,
    pub event_type: u8,
    pub port: u16,
    pub pid: u32,
}

#[derive(Debug, Clone)]
pub struct TCPConnectionDetail {
    pub timestamp: SystemTime,
    pub src_port: u16,
    pub dst_port: u16,
    pub event_type: u8,
}

#[derive(Debug)]
struct IPBehavior {
    ssh_events: Vec<SSHEventDetail>,
    tcp_connections: Vec<TCPConnectionDetail>,
    failed_ssh_count: u64,
    successful_ssh_count: u64,
    unique_ports: std::collections::HashSet<u16>,
    first_seen: SystemTime,
    last_seen: SystemTime,
    total_connections: u64,
}

#[derive(Debug)]
pub struct ThreatInfo {
    pub threat_type: ThreatType,
    pub severity: ThreatSeverity,
    pub count: u64,
    pub details: String,
    pub score: f64,
}

pub struct ThreatDetector {
    config: Arc<Config>,
    storage: Arc<Storage>,
    telegram_client: Arc<Option<TelegramClient>>,
    ip_behaviors: Arc<RwLock<HashMap<String, IPBehavior>>>,
    blocked_ips: Arc<RwLock<HashMap<String, SystemTime>>>,
    whitelist_ips: Arc<HashMap<String, bool>>,
    whitelist_cidrs: Arc<Vec<IpNet>>,
    alert_history: Arc<RwLock<HashMap<String, SystemTime>>>,
}

use crate::telegram::TelegramClient;

impl ThreatDetector {
    pub fn new(
        config: Arc<Config>,
        storage: Arc<Storage>,
        telegram_client: Option<TelegramClient>,
    ) -> Self {
        let mut whitelist_map = HashMap::new();
        for ip in &config.whitelist_ips {
            whitelist_map.insert(ip.clone(), true);
        }

        let mut whitelist_cidrs = Vec::new();
        for cidr_str in &config.whitelist_cidrs {
            if let Ok(cidr) = cidr_str.parse::<IpNet>() {
                whitelist_cidrs.push(cidr);
            }
        }

        let detector = Self {
            config,
            storage,
            telegram_client: Arc::new(telegram_client),
            ip_behaviors: Arc::new(RwLock::new(HashMap::new())),
            blocked_ips: Arc::new(RwLock::new(HashMap::new())),
            whitelist_ips: Arc::new(whitelist_map),
            whitelist_cidrs: Arc::new(whitelist_cidrs),
            alert_history: Arc::new(RwLock::new(HashMap::new())),
        };

        let detector_clone = detector.clone_for_cleanup();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(3600));
            loop {
                interval.tick().await;
                detector_clone.cleanup_stale_behaviors().await;
                if detector_clone.config.block_duration_seconds > 0 {
                    detector_clone.auto_unblock_expired().await;
                }
            }
        });

        detector
    }

    fn clone_for_cleanup(&self) -> CleanupDetector {
        CleanupDetector {
            config: Arc::clone(&self.config),
            storage: Arc::clone(&self.storage),
            ip_behaviors: Arc::clone(&self.ip_behaviors),
            blocked_ips: Arc::clone(&self.blocked_ips),
        }
    }

    pub async fn process_ssh_event(
        &self,
        ip: u32,
        port: u16,
        pid: u32,
        event_type: u8,
    ) -> Result<(), anyhow::Error> {
        let ip_addr = u32_to_ip(ip);
        let ip_str = ip_addr.to_string();

        if ip == 0 || ip_str == "0.0.0.0" {
            return Ok(());
        }

        if self.is_whitelisted(&ip_str) {
            return Ok(());
        }

        if self.storage.is_blocked(&ip_str) {
            return Ok(());
        }

        let mut behaviors = self.ip_behaviors.write().await;
        let behavior = behaviors
            .entry(ip_str.clone())
            .or_insert_with(|| IPBehavior {
                ssh_events: Vec::new(),
                tcp_connections: Vec::new(),
                failed_ssh_count: 0,
                successful_ssh_count: 0,
                unique_ports: std::collections::HashSet::new(),
                first_seen: SystemTime::now(),
                last_seen: SystemTime::now(),
                total_connections: 0,
            });

        let now = SystemTime::now();
        behavior.ssh_events.push(SSHEventDetail {
            timestamp: now,
            event_type,
            port,
            pid,
        });
        behavior.last_seen = now;

        if event_type == 1 {
            behavior.failed_ssh_count += 1;
        } else if event_type == 2 {
            behavior.successful_ssh_count += 1;
        }

        let cutoff = now - Duration::from_secs(86400);
        behavior
            .ssh_events
            .retain(|e| e.timestamp > cutoff);

        drop(behaviors);

        let behavior_clone = self.ip_behaviors.read().await;
        let behavior = behavior_clone.get(&ip_str).unwrap();
        let threats = self.detect_ssh_threats(&ip_str, behavior, now).await;

        for threat in threats {
            self.handle_threat(&ip_str, threat).await?;
        }

        Ok(())
    }

    async fn detect_ssh_threats(
        &self,
        _ip: &str,
        behavior: &IPBehavior,
        now: SystemTime,
    ) -> Vec<ThreatInfo> {
        let mut threats = Vec::new();

        let base_window = self.config.ssh_window();
        let short_window = base_window / 5;
        let medium_window = base_window;
        let long_window = base_window * 3;

        let short_term = count_events_in_window(&behavior.ssh_events, now, short_window);
        let medium_term = count_events_in_window(&behavior.ssh_events, now, medium_window);
        let long_term = count_events_in_window(&behavior.ssh_events, now, long_window);

        let score = calculate_threat_score(short_term, medium_term, long_term);

        let failed_in_short = count_failed_in_window(&behavior.ssh_events, now, short_window);
        let failed_in_medium = count_failed_in_window(&behavior.ssh_events, now, medium_window);

        let threshold = self.config.ssh_threshold;

        if short_term >= threshold * 2 || (short_term >= threshold && failed_in_short >= threshold) {
            threats.push(ThreatInfo {
                threat_type: ThreatType::SshBruteForce,
                severity: ThreatSeverity::Critical,
                count: short_term,
                details: format!("Rapid brute force: {} attempts in 1 minute", short_term),
                score,
            });
        } else if medium_term >= threshold * 3
            || (medium_term >= threshold * 2 && failed_in_medium >= threshold * 2)
        {
            threats.push(ThreatInfo {
                threat_type: ThreatType::SshBruteForce,
                severity: ThreatSeverity::High,
                count: medium_term,
                details: format!("Sustained brute force: {} attempts in 5 minutes", medium_term),
                score,
            });
        } else if medium_term >= threshold {
            threats.push(ThreatInfo {
                threat_type: ThreatType::SshBruteForce,
                severity: ThreatSeverity::Medium,
                count: medium_term,
                details: format!("Brute force detected: {} attempts in 5 minutes", medium_term),
                score,
            });
        } else if long_term >= threshold {
            threats.push(ThreatInfo {
                threat_type: ThreatType::SshBruteForce,
                severity: ThreatSeverity::Low,
                count: long_term,
                details: format!("Suspicious activity: {} attempts in 15 minutes", long_term),
                score,
            });
        }

        let total_attempts = behavior.ssh_events.len() as u64;
        if total_attempts > 0 {
            let failure_rate = behavior.failed_ssh_count as f64 / total_attempts as f64;
            if failure_rate > 0.8 && total_attempts >= 5 {
                threats.push(ThreatInfo {
                    threat_type: ThreatType::SshBruteForce,
                    severity: ThreatSeverity::High,
                    count: behavior.failed_ssh_count,
                    details: format!(
                        "High failure rate: {:.1}% failures ({}/{})",
                        failure_rate * 100.0,
                        behavior.failed_ssh_count,
                        total_attempts
                    ),
                    score: score * failure_rate,
                });
            }
        }

        if behavior.ssh_events.len() >= 3 {
            if detect_rapid_fire_pattern(&behavior.ssh_events, now) {
                threats.push(ThreatInfo {
                    threat_type: ThreatType::SshBruteForce,
                    severity: ThreatSeverity::High,
                    count: behavior.ssh_events.len() as u64,
                    details: "Rapid-fire attack pattern detected".to_string(),
                    score: score * 1.2,
                });
            }
        }

        threats
    }

    async fn handle_threat(&self, ip: &str, threat: ThreatInfo) -> Result<(), anyhow::Error> {
        if threat.severity.to_string() == "LOW" && threat.score < 5.0 {
            return Ok(());
        }

        let alert = Alert {
            ip: ip.to_string(),
            threat_type: threat.threat_type.clone(),
            count: threat.count,
            timestamp: SystemTime::now(),
            severity: Some(threat.severity.to_string()),
            details: Some(threat.details.clone()),
            score: Some(threat.score),
        };

        self.storage.store_alert(alert.clone())?;

        let should_send_alert = matches!(
            threat.severity,
            ThreatSeverity::Critical | ThreatSeverity::High
        );

        if should_send_alert {
            let mut alert_history = self.alert_history.write().await;
            alert_history.insert(ip.to_string(), SystemTime::now());
            drop(alert_history);

            if let Some(ref client) = *self.telegram_client {
                if let Err(e) = client.send_alert(&alert).await {
                    log::error!("Failed to send Telegram alert: {}", e);
                }
            }
        } else {
            let alert_history = self.alert_history.read().await;
            if let Some(last_alert) = alert_history.get(ip) {
                if last_alert.elapsed().unwrap_or(Duration::from_secs(0)) < Duration::from_secs(300) {
                    return Ok(());
                }
            }
            drop(alert_history);

            let mut alert_history = self.alert_history.write().await;
            alert_history.insert(ip.to_string(), SystemTime::now());
            drop(alert_history);

            if let Some(ref client) = *self.telegram_client {
                if let Err(e) = client.send_alert(&alert).await {
                    log::error!("Failed to send Telegram alert: {}", e);
                }
            }
        }

        let should_block = matches!(threat.severity, ThreatSeverity::Critical)
            || (matches!(threat.severity, ThreatSeverity::High) && threat.score > 50.0)
            || threat.score > 100.0;

        if should_block && self.config.enable_ip_blocking && !self.is_internal_ip(ip) {
            if self.is_whitelisted(ip) {
                log::info!("Skipping block for whitelisted IP {}", ip);
                return Ok(());
            }

            if let Err(e) = self.block_ip(ip).await {
                log::error!("Failed to block IP {}: {}", ip, e);
            } else {
                let mut blocked = self.blocked_ips.write().await;
                blocked.insert(ip.to_string(), SystemTime::now());
                drop(blocked);
                self.storage.add_blocked_ip(ip.to_string())?;
                let threat_type_str = format!("{:?}", threat.threat_type);
                log::info!(
                    "Auto-blocked IP {} due to {} threat (severity: {}, score: {:.1})",
                    ip,
                    threat_type_str,
                    threat.severity.to_string(),
                    threat.score
                );
            }
        }

        Ok(())
    }

    async fn block_ip(&self, ip: &str) -> Result<(), anyhow::Error> {
        if ip.parse::<IpAddr>().is_err() {
            anyhow::bail!("Invalid IP address format: {}", ip);
        }

        let is_ipv6 = ip.parse::<IpAddr>().unwrap().is_ipv6();

        if is_ipv6 {
            let check_cmd = tokio::process::Command::new("ip6tables")
                .args(["-C", "INPUT", "-s", ip, "-j", "DROP"])
                .output()
                .await?;

            if check_cmd.status.success() {
                return Ok(());
            }

            let cmd = tokio::process::Command::new("ip6tables")
                .args([
                    "-I", "INPUT", "1", "-s", ip, "-j", "DROP", "-m", "comment",
                    "--comment", "secrds-block",
                ])
                .output()
                .await?;

            if !cmd.status.success() {
                anyhow::bail!("Failed to block IP with ip6tables");
            }
        } else {
            let check_cmd = tokio::process::Command::new("iptables")
                .args(["-C", "INPUT", "-s", ip, "-j", "DROP"])
                .output()
                .await?;

            if check_cmd.status.success() {
                return Ok(());
            }

            let cmd = tokio::process::Command::new("iptables")
                .args([
                    "-I", "INPUT", "1", "-s", ip, "-j", "DROP", "-m", "comment",
                    "--comment", "secrds-block",
                ])
                .output()
                .await?;

            if !cmd.status.success() {
                anyhow::bail!("Failed to block IP with iptables");
            }
        }

        Ok(())
    }

    fn is_whitelisted(&self, ip: &str) -> bool {
        if self.whitelist_ips.contains_key(ip) {
            return true;
        }

        if let Ok(parsed) = ip.parse::<IpAddr>() {
            for cidr in self.whitelist_cidrs.iter() {
                if cidr.contains(&parsed) {
                    return true;
                }
            }
        }

        false
    }

    fn is_internal_ip(&self, ip: &str) -> bool {
        if let Ok(parsed) = ip.parse::<IpAddr>() {
            if parsed.is_ipv4() {
                let octets = parsed.to_string().split('.').map(|s| s.parse::<u8>().unwrap()).collect::<Vec<_>>();
                if octets[0] == 10 {
                    return true;
                }
                if octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31 {
                    return true;
                }
                if octets[0] == 192 && octets[1] == 168 {
                    return true;
                }
                if octets[0] == 100 && (octets[1] & 0xC0) == 0x40 {
                    return true;
                }
            }
        }
        false
    }

    async fn cleanup_stale_behaviors(&self) {
        let mut behaviors = self.ip_behaviors.write().await;
        let now = SystemTime::now();
        let cutoff = now - Duration::from_secs(86400);
        let mut removed = 0;

        behaviors.retain(|ip, behavior| {
            if behavior.last_seen < cutoff && !self.storage.is_blocked(ip) {
                removed += 1;
                false
            } else {
                true
            }
        });

        if removed > 0 {
            log::info!("Cleaned up {} stale IP behaviors", removed);
        }
    }

    async fn auto_unblock_expired(&self) {
        let mut blocked = self.blocked_ips.write().await;
        let now = SystemTime::now();
        let block_duration = Duration::from_secs(self.config.block_duration_seconds);
        let mut unblocked = 0;

        let ips_to_unblock: Vec<String> = blocked
            .iter()
            .filter_map(|(ip, block_time)| {
                if now.duration_since(*block_time).unwrap_or_default() >= block_duration {
                    Some(ip.clone())
                } else {
                    None
                }
            })
            .collect();

        for ip in ips_to_unblock {
            if let Err(e) = self.unblock_ip(&ip).await {
                log::error!("Failed to unblock IP {}: {}", ip, e);
                continue;
            }
            blocked.remove(&ip);
            unblocked += 1;
            log::info!("Auto-unblocked IP {} (block duration expired)", ip);
        }

        if unblocked > 0 {
            log::info!("Auto-unblocked {} expired IPs", unblocked);
        }
    }

    async fn unblock_ip(&self, ip: &str) -> Result<(), anyhow::Error> {
        if ip.parse::<IpAddr>().is_err() {
            anyhow::bail!("Invalid IP address format: {}", ip);
        }

        let is_ipv6 = ip.parse::<IpAddr>().unwrap().is_ipv6();

        if is_ipv6 {
            let cmd = tokio::process::Command::new("ip6tables")
                .args([
                    "-D", "INPUT", "-s", ip, "-j", "DROP", "-m", "comment",
                    "--comment", "secrds-block",
                ])
                .output()
                .await?;

            if !cmd.status.success() {
                let cmd2 = tokio::process::Command::new("ip6tables")
                    .args(["-D", "INPUT", "-s", ip, "-j", "DROP"])
                    .output()
                    .await?;

                if !cmd2.status.success() {
                    anyhow::bail!("Failed to unblock IP with ip6tables");
                }
            }
        } else {
            let cmd = tokio::process::Command::new("iptables")
                .args([
                    "-D", "INPUT", "-s", ip, "-j", "DROP", "-m", "comment",
                    "--comment", "secrds-block",
                ])
                .output()
                .await?;

            if !cmd.status.success() {
                let cmd2 = tokio::process::Command::new("iptables")
                    .args(["-D", "INPUT", "-s", ip, "-j", "DROP"])
                    .output()
                    .await?;

                if !cmd2.status.success() {
                    anyhow::bail!("Failed to unblock IP with iptables");
                }
            }
        }

        Ok(())
    }
}

struct CleanupDetector {
    config: Arc<Config>,
    storage: Arc<Storage>,
    ip_behaviors: Arc<RwLock<HashMap<String, IPBehavior>>>,
    blocked_ips: Arc<RwLock<HashMap<String, SystemTime>>>,
}

impl CleanupDetector {
    async fn cleanup_stale_behaviors(&self) {
        let mut behaviors = self.ip_behaviors.write().await;
        let now = SystemTime::now();
        let cutoff = now - Duration::from_secs(86400);
        let mut removed = 0;

        behaviors.retain(|ip, behavior| {
            if behavior.last_seen < cutoff && !self.storage.is_blocked(ip) {
                removed += 1;
                false
            } else {
                true
            }
        });

        if removed > 0 {
            log::info!("Cleaned up {} stale IP behaviors", removed);
        }
    }

    async fn auto_unblock_expired(&self) {
        let mut blocked = self.blocked_ips.write().await;
        let now = SystemTime::now();
        let block_duration = Duration::from_secs(self.config.block_duration_seconds);
        let mut unblocked = 0;

        let ips_to_unblock: Vec<String> = blocked
            .iter()
            .filter_map(|(ip, block_time)| {
                if now.duration_since(*block_time).unwrap_or_default() >= block_duration {
                    Some(ip.clone())
                } else {
                    None
                }
            })
            .collect();

        for ip in ips_to_unblock {
            blocked.remove(&ip);
            unblocked += 1;
        }

        if unblocked > 0 {
            log::info!("Auto-unblocked {} expired IPs", unblocked);
        }
    }
}

fn u32_to_ip(ip: u32) -> std::net::Ipv4Addr {
    std::net::Ipv4Addr::new(
        ((ip >> 24) & 0xFF) as u8,
        ((ip >> 16) & 0xFF) as u8,
        ((ip >> 8) & 0xFF) as u8,
        (ip & 0xFF) as u8,
    )
}

fn count_events_in_window(events: &[SSHEventDetail], now: SystemTime, window: Duration) -> u64 {
    let cutoff = now - window;
    events
        .iter()
        .filter(|e| e.timestamp > cutoff)
        .count() as u64
}

fn count_failed_in_window(events: &[SSHEventDetail], now: SystemTime, window: Duration) -> u64 {
    let cutoff = now - window;
    events
        .iter()
        .filter(|e| e.timestamp > cutoff && e.event_type == 1)
        .count() as u64
}

fn calculate_threat_score(short: u64, medium: u64, long: u64) -> f64 {
    short as f64 * 3.0 + medium as f64 * 1.5 + long as f64 * 0.5
}

fn detect_rapid_fire_pattern(events: &[SSHEventDetail], _now: SystemTime) -> bool {
    if events.len() < 3 {
        return false;
    }

    let recent_events: Vec<_> = if events.len() > 5 {
        events.iter().rev().take(5).collect()
    } else {
        events.iter().rev().collect()
    };

    for i in 1..recent_events.len() {
        let time_diff = recent_events[i - 1]
            .timestamp
            .duration_since(recent_events[i].timestamp)
            .unwrap_or_default();
        if time_diff < Duration::from_secs(2) && recent_events[i].event_type == 1 {
            return true;
        }
    }

    false
}

