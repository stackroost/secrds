use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

const STORAGE_FILE: &str = "/var/lib/ebpf-detector/events.json";

#[derive(Debug, Serialize, Deserialize)]
struct StorageData {
    alerts: Vec<serde_json::Value>,
    blocked_ips: Vec<String>,
    statistics: Statistics,
}

#[derive(Debug, Serialize, Deserialize)]
struct Statistics {
    total_alerts: u64,
    ssh_brute_force_count: u64,
    tcp_port_scan_count: u64,
    tcp_flood_count: u64,
    blocked_ips_count: u64,
}

pub async fn run() -> anyhow::Result<()> {
    let storage_path = PathBuf::from(STORAGE_FILE);

    if !storage_path.exists() {
        println!("No statistics available");
        return Ok(());
    }

    let content = fs::read_to_string(&storage_path)
        .context("Failed to read storage file")?;
    
    let data: StorageData = serde_json::from_str(&content)
        .context("Failed to parse storage file")?;

    println!("Statistics:\n");
    println!("Total Alerts: {}", data.statistics.total_alerts);
    println!("SSH Brute Force: {}", data.statistics.ssh_brute_force_count);
    println!("TCP Port Scans: {}", data.statistics.tcp_port_scan_count);
    println!("TCP Floods: {}", data.statistics.tcp_flood_count);
    println!("Blocked IPs: {}", data.statistics.blocked_ips_count);
    println!("\nTotal Blocked IPs: {}", data.blocked_ips.len());

    if !data.blocked_ips.is_empty() {
        println!("\nBlocked IPs:");
        for ip in data.blocked_ips.iter().take(20) {
            println!("  - {}", ip);
        }
        if data.blocked_ips.len() > 20 {
            println!("  ... and {} more", data.blocked_ips.len() - 20);
        }
    }

    Ok(())
}

