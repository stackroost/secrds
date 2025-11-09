use anyhow::Result;
use serde_json;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

pub fn alerts(limit: usize) -> Result<()> {
    let storage_path = get_storage_path()?;
    if !storage_path.exists() {
        println!("No alerts found.");
        return Ok(());
    }

    let content = fs::read_to_string(&storage_path)?;
    let data: serde_json::Value = serde_json::from_str(&content)?;

    if let Some(alerts) = data.get("alerts").and_then(|a| a.as_array()) {
        let alerts: Vec<_> = alerts.iter().rev().take(limit).collect();
        if alerts.is_empty() {
            println!("No alerts found.");
            return Ok(());
        }

        println!("Recent Alerts (showing {}):\n", alerts.len());
        for alert in alerts {
            let ip = alert.get("ip").and_then(|v| v.as_str()).unwrap_or("N/A");
            let threat_type = alert
                .get("threat_type")
                .and_then(|v| v.as_str())
                .unwrap_or("N/A");
            let count = alert.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
            let severity = alert
                .get("severity")
                .and_then(|v| v.as_str())
                .unwrap_or("UNKNOWN");
            let timestamp = alert
                .get("timestamp")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            println!("IP: {}", ip);
            println!("Threat: {}", threat_type);
            println!("Severity: {}", severity);
            println!("Count: {}", count);
            println!("Timestamp: {}", timestamp);
            if let Some(details) = alert.get("details").and_then(|v| v.as_str()) {
                println!("Details: {}", details);
            }
            println!();
        }
    } else {
        println!("No alerts found.");
    }

    Ok(())
}

pub fn clean(all: bool) -> Result<()> {
    let log_dir = "/var/log/secrds";
    let mut cleaned = false;

    println!("Cleaning log files...");
    if let Ok(entries) = fs::read_dir(log_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("log") {
                if let Ok(metadata) = fs::metadata(&path) {
                    if fs::remove_file(&path).is_ok() {
                        let size_kb = metadata.len() as f64 / 1024.0;
                        println!("✓ Removed: {} ({:.2} KB)", path.display(), size_kb);
                        cleaned = true;
                    }
                }
            }
        }
    }

    if all {
        println!("\nCleaning event storage...");
        let storage_path = get_storage_path()?;
        if storage_path.exists() {
            if let Ok(metadata) = fs::metadata(&storage_path) {
                if fs::remove_file(&storage_path).is_ok() {
                    let size_kb = metadata.len() as f64 / 1024.0;
                    println!("✓ Removed: {} ({:.2} KB)", storage_path.display(), size_kb);
                    cleaned = true;
                }
            }
        }

        println!("\nStopping secrds service to unload eBPF programs...");
        if stop_service().is_ok() {
            println!("✓ Service stopped (eBPF programs and maps automatically unloaded)");
            cleaned = true;
        } else {
            println!("Warning: Failed to stop service. You may need to run: sudo systemctl stop secrds");
        }
    }

    if !cleaned {
        println!("No files to clean.");
    } else {
        println!("\n✓ Cleanup completed successfully!");
        if !all {
            println!("Tip: Use --all flag to also clear event storage data and kernel-level resources");
        } else {
            println!("\nNote: Service has been stopped. Restart with: sudo systemctl start secrds");
        }
    }

    Ok(())
}

pub fn config() -> Result<()> {
    let config_path = std::env::var("SECRDS_CONFIG")
        .unwrap_or_else(|_| "/etc/secrds/config.yaml".to_string());

    if PathBuf::from(&config_path).exists() {
        let content = fs::read_to_string(&config_path)?;
        println!("Configuration file: {}", config_path);
        println!("\n{}", content);
    } else {
        println!("Configuration file not found: {}", config_path);
    }

    Ok(())
}

pub fn restart() -> Result<()> {
    stop_service()?;
    std::thread::sleep(std::time::Duration::from_secs(2));
    start_service()?;
    println!("Service restarted successfully");
    Ok(())
}

pub fn start() -> Result<()> {
    start_service()?;
    println!("Service started successfully");
    Ok(())
}

pub fn stats() -> Result<()> {
    let storage_path = get_storage_path()?;
    if !storage_path.exists() {
        println!("No statistics available.");
        return Ok(());
    }

    let content = fs::read_to_string(&storage_path)?;
    let data: serde_json::Value = serde_json::from_str(&content)?;

    if let Some(stats) = data.get("statistics") {
        println!("Statistics:\n");
        println!(
            "Total Alerts: {}",
            stats.get("total_alerts").and_then(|v| v.as_u64()).unwrap_or(0)
        );
        println!(
            "SSH Brute Force: {}",
            stats
                .get("ssh_brute_force_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
        );
        println!(
            "TCP Port Scan: {}",
            stats
                .get("tcp_port_scan_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
        );
        println!(
            "TCP Flood: {}",
            stats
                .get("tcp_flood_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
        );
        println!(
            "Blocked IPs: {}",
            stats
                .get("blocked_ips_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
        );
    } else {
        println!("No statistics available.");
    }

    Ok(())
}

pub fn status() -> Result<()> {
    let output = Command::new("systemctl")
        .args(["is-active", "secrds"])
        .output()?;

    if output.status.success() {
        let status = String::from_utf8_lossy(&output.stdout);
        println!("Service status: {}", status.trim());
    } else {
        println!("Service status: inactive");
    }

    Ok(())
}

pub fn stop() -> Result<()> {
    stop_service()?;
    println!("Service stopped successfully");
    Ok(())
}

fn get_storage_path() -> Result<PathBuf> {
    let config_path = std::env::var("SECRDS_CONFIG")
        .unwrap_or_else(|_| "/etc/secrds/config.yaml".to_string());

    let default_path = "/var/lib/secrds/events.json".to_string();

    if PathBuf::from(&config_path).exists() {
        let content = fs::read_to_string(&config_path)?;
        if let Ok(config) = serde_yaml::from_str::<serde_json::Value>(&content) {
            if let Some(path) = config.get("storage_path").and_then(|v| v.as_str()) {
                return Ok(PathBuf::from(path));
            }
        }
    }

    Ok(PathBuf::from(default_path))
}

fn start_service() -> Result<()> {
    let status = if std::env::var("USER").unwrap_or_default() == "root" {
        Command::new("systemctl").args(["start", "secrds"]).status()?
    } else {
        Command::new("sudo")
            .args(["systemctl", "start", "secrds"])
            .status()?
    };

    if !status.success() {
        anyhow::bail!("Failed to start service");
    }
    Ok(())
}

fn stop_service() -> Result<()> {
    let status = if std::env::var("USER").unwrap_or_default() == "root" {
        Command::new("systemctl").args(["stop", "secrds"]).status()?
    } else {
        Command::new("sudo")
            .args(["systemctl", "stop", "secrds"])
            .status()?
    };

    if !status.success() {
        anyhow::bail!("Failed to stop service");
    }
    Ok(())
}

