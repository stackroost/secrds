use anyhow::Context;
use std::env;
use std::fs;
use std::path::PathBuf;

const DEFAULT_CONFIG: &str = "/etc/ebpf-detector/config.toml";

pub async fn run() -> anyhow::Result<()> {
    let config_path = if let Ok(path) = env::var("EBPF_DETECTOR_CONFIG") {
        PathBuf::from(path)
    } else {
        PathBuf::from(DEFAULT_CONFIG)
    };

    if !config_path.exists() {
        println!("No configuration file found at: {:?}", config_path);
        println!("Using default configuration:");
        println!();
        println!("SSH Threshold: 5 failures in 5 minutes");
        println!("TCP Threshold: 10 connections in 1 minute");
        println!("IP Blocking: Enabled");
        return Ok(());
    }

    let content = fs::read_to_string(&config_path)
        .context("Failed to read config file")?;

    println!("Configuration from: {:?}\n", config_path);
    println!("{}", content);

    Ok(())
}

