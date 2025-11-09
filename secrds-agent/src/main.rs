mod config;
mod detector;
mod processor;
mod storage;
mod telegram;

use anyhow::Result;
use config::Config;
use detector::ThreatDetector;
use processor::EventProcessor;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use storage::Storage;
use telegram::TelegramClient;
use tokio::signal;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    let config = Arc::new(Config::load()?);
    
    if config.telegram.bot_token.is_empty() {
        anyhow::bail!("TELEGRAM_BOT_TOKEN not set. Please set it in /etc/secrds/config.yaml (telegram.bot_token) or as TELEGRAM_BOT_TOKEN environment variable");
    }

    let storage = Arc::new(Storage::new(&config.storage_path)?);

    let telegram_client = if !config.telegram.bot_token.is_empty() {
        Some(TelegramClient::new(
            config.telegram.bot_token.clone(),
            config.telegram.chat_id.clone(),
        )?)
    } else {
        None
    };

    let threat_detector = Arc::new(ThreatDetector::new(
        Arc::clone(&config),
        Arc::clone(&storage),
        telegram_client,
    ));

    let event_processor = EventProcessor::new(Arc::clone(&threat_detector), config.ssh_port);

    if let Err(e) = event_processor.start().await {
        log::error!("Failed to start event processor: {}", e);
        anyhow::bail!("Failed to start event processor: {}", e);
    }

    write_pid_file(&config.pid_file)?;

    log::info!("secrds Security Monitor started successfully");
    log::info!("Monitoring SSH connections on port {}...", config.ssh_port);

    signal::ctrl_c().await?;
    log::info!("Shutting down...");

    if let Err(e) = storage.flush() {
        log::error!("Error flushing storage: {}", e);
    }

    if let Err(e) = fs::remove_file(&config.pid_file) {
        log::error!("Error removing PID file: {}", e);
    }

    Ok(())
}

fn write_pid_file(path: &str) -> Result<()> {
    if let Some(parent) = PathBuf::from(path).parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, format!("{}\n", std::process::id()))?;
    Ok(())
}

