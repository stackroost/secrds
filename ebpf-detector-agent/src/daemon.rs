use crate::config::Config;
use crate::ebpf_loader::EbpfLoader;
use crate::event_processor::EventProcessor;
use crate::health::HealthChecker;
use crate::storage::Storage;
use crate::telegram_client::TelegramClient;
use crate::threat_detector::ThreatDetector;
use anyhow::Context;
use log::{error, info, warn};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::signal;
use tokio::sync::broadcast;

pub struct Daemon {
    config: Config,
    storage: Arc<Storage>,
    telegram_client: Arc<TelegramClient>,
    threat_detector: Arc<ThreatDetector>,
    pid_file: PathBuf,
}

impl Daemon {
    pub fn new(
        config: Config,
        storage: Storage,
        telegram_token: String,
    ) -> anyhow::Result<Self> {
        let storage = Arc::new(storage);
        let telegram_client = Arc::new(TelegramClient::new(telegram_token));
        let threat_detector = Arc::new(ThreatDetector::new(
            config.clone(),
            storage.clone(),
            telegram_client.clone(),
        ));

        Ok(Self {
            config: config.clone(),
            storage,
            telegram_client,
            threat_detector,
            pid_file: config.pid_file.clone(),
        })
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        self.daemonize()?;

        self.write_pid_file()?;

        info!("Daemon started with PID: {}", std::process::id());

        let mut ebpf_loader = EbpfLoader::new()
            .context("Failed to create eBPF loader")?;
        
        ebpf_loader.load_rust_programs()
            .context("Failed to load Rust eBPF programs")?;
        
        ebpf_loader.load_c_programs()
            .context("Failed to load C eBPF programs")?;

        let health_checker = HealthChecker::new(self.storage.clone());
        let health_checker_clone = health_checker.clone();
        
        tokio::spawn(async move {
            if let Err(e) = health_checker_clone.run_periodic_check().await {
                error!("Health checker error: {}", e);
            }
        });

        let mut event_processor = EventProcessor::new(
            ebpf_loader,
            self.threat_detector.clone(),
        )
        .context("Failed to create event processor")?;

        let event_handle = tokio::spawn(async move {
            event_processor.process_events().await
        });

        let (shutdown_tx, mut shutdown_rx) = broadcast::channel::<()>(1);
        let shutdown_tx_clone = shutdown_tx.clone();

        #[cfg(unix)]
        {
            let shutdown_tx_sigterm = shutdown_tx_clone.clone();
            tokio::spawn(async move {
                use signal::unix::{signal, SignalKind};
                let mut sigterm = signal(SignalKind::terminate())
                    .expect("Failed to register SIGTERM handler");
                let mut sigint = signal(SignalKind::interrupt())
                    .expect("Failed to register SIGINT handler");

                tokio::select! {
                    _ = sigterm.recv() => {
                        info!("Received SIGTERM, shutting down gracefully...");
                        shutdown_tx_sigterm.send(()).ok();
                    }
                    _ = sigint.recv() => {
                        info!("Received SIGINT, shutting down gracefully...");
                        shutdown_tx_clone.send(()).ok();
                    }
                }
            });
        }

        #[cfg(not(unix))]
        {
            let shutdown_tx_ctrl_c = shutdown_tx_clone.clone();
            tokio::spawn(async move {
                signal::ctrl_c().await.expect("Failed to register Ctrl+C handler");
                info!("Received shutdown signal, shutting down gracefully...");
                shutdown_tx_ctrl_c.send(()).ok();
            });
        }

        tokio::select! {
            result = event_handle => {
                if let Err(e) = result {
                    error!("Event processor error: {}", e);
                }
            }
            _ = shutdown_rx.recv() => {
                info!("Shutdown signal received");
            }
        }

        self.cleanup()?;
        Ok(())
    }

    fn daemonize(&self) -> anyhow::Result<()> {
        unsafe {
            let pid = libc::fork();
            
            match pid {
                -1 => anyhow::bail!("Failed to fork process"),
                0 => {
                    let sid = libc::setsid();
                    if sid == -1 {
                        anyhow::bail!("Failed to create new session");
                    }
                    
                    libc::chdir("/\0".as_ptr() as *const i8);
                    
                    Ok(())
                }
                _ => {
                    std::process::exit(0);
                }
            }
        }
    }

    fn write_pid_file(&self) -> anyhow::Result<()> {
        if let Some(parent) = self.pid_file.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory: {:?}", parent))?;
        }

        let pid = std::process::id();
        fs::write(&self.pid_file, pid.to_string())
            .with_context(|| format!("Failed to write PID file: {:?}", self.pid_file))?;

        Ok(())
    }

    fn cleanup(&self) -> anyhow::Result<()> {
        if self.pid_file.exists() {
            fs::remove_file(&self.pid_file)
                .with_context(|| format!("Failed to remove PID file: {:?}", self.pid_file))?;
        }
        info!("Daemon cleanup complete");
        Ok(())
    }
}

