use crate::storage::Storage;
use anyhow::Context;
use log::info;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct HealthStatus {
    pub is_healthy: bool,
    pub uptime_seconds: u64,
    pub events_processed: u64,
    pub alerts_generated: u64,
    pub blocked_ips: u64,
}

#[derive(Clone)]
pub struct HealthChecker {
    storage: Arc<Storage>,
    start_time: Arc<std::time::Instant>,
    events_processed: Arc<RwLock<u64>>,
}

impl HealthChecker {
    pub fn new(storage: Arc<Storage>) -> Self {
        Self {
            storage,
            start_time: Arc::new(std::time::Instant::now()),
            events_processed: Arc::new(RwLock::new(0)),
        }
    }

    pub async fn increment_events(&self) {
        let mut count = self.events_processed.write().await;
        *count += 1;
    }

    pub async fn check_health(&self) -> anyhow::Result<HealthStatus> {
        let uptime = self.start_time.elapsed().as_secs();
        let stats = self.storage.get_statistics().await;
        let events = *self.events_processed.read().await;

        let is_healthy = uptime > 5;

        Ok(HealthStatus {
            is_healthy,
            uptime_seconds: uptime,
            events_processed: events,
            alerts_generated: stats.total_alerts,
            blocked_ips: stats.blocked_ips_count,
        })
    }

    pub async fn run_periodic_check(&self) -> anyhow::Result<()> {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        
        loop {
            interval.tick().await;
            
            match self.check_health().await {
                Ok(status) => {
                    if !status.is_healthy {
                        log::warn!("Health check failed: service may be unhealthy");
                    } else {
                        info!(
                            "Health check: uptime={}s, events={}, alerts={}, blocked_ips={}",
                            status.uptime_seconds,
                            status.events_processed,
                            status.alerts_generated,
                            status.blocked_ips
                        );
                    }
                }
                Err(e) => {
                    log::error!("Health check error: {}", e);
                }
            }
        }
    }
}

