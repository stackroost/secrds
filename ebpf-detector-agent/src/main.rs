use anyhow::Context;
use log::{error, info, warn};
use std::env;
use std::path::PathBuf;

mod config;
mod daemon;
mod ebpf_loader;
mod event_processor;
mod health;
mod storage;
mod telegram_client;
mod threat_detector;

use config::Config;
use daemon::Daemon;
use storage::Storage;

fn get_storage_path() -> PathBuf {
    let is_root = unsafe { libc::getuid() == 0 };
    
    if is_root {
        PathBuf::from("/var/lib/ebpf-detector/events.json")
    } else {
        let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home).join(".local/share/ebpf-detector/events.json")
    }
}

fn get_telegram_token() -> anyhow::Result<String> {
    if let Ok(token) = env::var("TELEGRAM_BOT_TOKEN") {
        return Ok(token);
    }
    
    if let Ok(config_path) = env::var("EBPF_DETECTOR_CONFIG") {
        if let Ok(config_str) = std::fs::read_to_string(&config_path) {
            if let Ok(toml_value) = toml::from_str::<toml::Value>(&config_str) {
                if let Some(token) = toml_value.get("telegram_bot_token")
                    .and_then(|v| v.as_str()) {
                    return Ok(token.to_string());
                }
            }
        }
    }
    
    let default_config = PathBuf::from("/etc/ebpf-detector/config.toml");
    if default_config.exists() {
        if let Ok(config_str) = std::fs::read_to_string(&default_config) {
            if let Ok(toml_value) = toml::from_str::<toml::Value>(&config_str) {
                if let Some(token) = toml_value.get("telegram_bot_token")
                    .and_then(|v| v.as_str()) {
                    return Ok(token.to_string());
                }
            }
        }
    }
    
    anyhow::bail!(
        "TELEGRAM_BOT_TOKEN not found. Please set it as:\n\
        1. Environment variable: export TELEGRAM_BOT_TOKEN='your_token'\n\
        2. Config file: Add 'telegram_bot_token = \"your_token\"' to /etc/ebpf-detector/config.toml\n\
        Note: When using sudo, use 'sudo -E' to preserve environment variables, or set it in config file."
    )
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::load().context("Failed to load configuration")?;
    
    let log_level = std::env::var("RUST_LOG")
        .unwrap_or_else(|_| config.log_level.clone());
    
    env_logger::Builder::from_env(
        env_logger::Env::default().filter_or("RUST_LOG", log_level)
    )
    .target(env_logger::Target::Stderr)
    .init();

    config.validate().context("Invalid configuration")?;

    let telegram_token = get_telegram_token()
        .context("Failed to get Telegram bot token")?;

    info!("Starting eBPF Security Monitor Agent");

    let storage_path = get_storage_path();
    let is_root = unsafe { libc::getuid() == 0 };
    
    if !is_root {
        warn!("Running as non-root user. Using user storage: {:?}", storage_path);
    }

    let storage = Storage::new(storage_path)
        .context("Failed to initialize storage")?;

    let mut daemon = Daemon::new(config, storage, telegram_token)
        .context("Failed to create daemon")?;

    daemon.run().await.context("Daemon runtime error")?;

    Ok(())
}

