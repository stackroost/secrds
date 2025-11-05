use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::env;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub ssh_threshold: u64,
    pub ssh_window_seconds: u64,
    pub tcp_threshold: u64,
    pub tcp_window_seconds: u64,
    pub enable_ip_blocking: bool,
    pub storage_path: PathBuf,
    pub pid_file: PathBuf,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_log_file")]
    pub log_file: PathBuf,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_file() -> PathBuf {
    PathBuf::from("/var/log/ebpf-detector/agent.log")
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ssh_threshold: 5,
            ssh_window_seconds: 300,
            tcp_threshold: 10,
            tcp_window_seconds: 60,
            enable_ip_blocking: true,
            storage_path: PathBuf::from("/var/lib/ebpf-detector/events.json"),
            pid_file: PathBuf::from("/var/run/ebpf-detector.pid"),
            log_level: default_log_level(),
            log_file: default_log_file(),
        }
    }
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        if let Ok(config_path) = env::var("EBPF_DETECTOR_CONFIG") {
            let config_str = std::fs::read_to_string(&config_path)
                .with_context(|| format!("Failed to read config file: {}", config_path))?;
            let config: Config = toml::from_str(&config_str)
                .context("Failed to parse config file")?;
            return Ok(config);
        }

        let default_config = PathBuf::from("/etc/ebpf-detector/config.toml");
        if default_config.exists() {
            let config_str = std::fs::read_to_string(&default_config)
                .context("Failed to read default config file")?;
            let config: Config = toml::from_str(&config_str)
                .context("Failed to parse config file")?;
            return Ok(config);
        }

        Ok(Config::default())
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.ssh_threshold == 0 {
            anyhow::bail!("ssh_threshold must be greater than 0");
        }
        if self.ssh_window_seconds == 0 {
            anyhow::bail!("ssh_window_seconds must be greater than 0");
        }
        if self.tcp_threshold == 0 {
            anyhow::bail!("tcp_threshold must be greater than 0");
        }
        if self.tcp_window_seconds == 0 {
            anyhow::bail!("tcp_window_seconds must be greater than 0");
        }
        Ok(())
    }
}

