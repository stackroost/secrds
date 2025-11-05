use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

const STORAGE_FILE: &str = "/var/lib/ebpf-detector/events.json";

#[derive(Debug, Serialize, Deserialize)]
struct StorageData {
    alerts: Vec<Alert>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Alert {
    ip: String,
    threat_type: String,
    count: u64,
    timestamp: String,
}

pub async fn run(limit: usize) -> anyhow::Result<()> {
    let storage_path = PathBuf::from(STORAGE_FILE);

    if !storage_path.exists() {
        println!("No alerts found");
        return Ok(());
    }

    let content = fs::read_to_string(&storage_path)
        .context("Failed to read storage file")?;
    
    let data: StorageData = serde_json::from_str(&content)
        .context("Failed to parse storage file")?;

    let alerts: Vec<_> = data.alerts.iter().rev().take(limit).collect();

    if alerts.is_empty() {
        println!("No recent alerts");
        return Ok(());
    }

    println!("Recent Alerts (showing last {}):\n", alerts.len());
    println!("{:<20} {:<20} {:<15} {}", "IP", "Threat Type", "Count", "Timestamp");
    println!("{}", "-".repeat(80));

    for alert in alerts {
        println!(
            "{:<20} {:<20} {:<15} {}",
            alert.ip,
            alert.threat_type,
            alert.count,
            alert.timestamp
        );
    }

    Ok(())
}

