use serde::{Deserialize, Serialize};
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_ssh_threshold")]
    pub ssh_threshold: u64,
    #[serde(default = "default_ssh_window")]
    pub ssh_window_seconds: u64,
    #[serde(default = "default_ssh_port")]
    pub ssh_port: u16,
    #[serde(default = "default_tcp_threshold")]
    pub tcp_threshold: u64,
    #[serde(default = "default_tcp_window")]
    pub tcp_window_seconds: u64,
    #[serde(default = "default_enable_blocking")]
    pub enable_ip_blocking: bool,
    #[serde(default = "default_block_duration")]
    pub block_duration_seconds: u64,
    #[serde(default)]
    pub whitelist_ips: Vec<String>,
    #[serde(default)]
    pub whitelist_cidrs: Vec<String>,
    #[serde(default = "default_storage_path")]
    pub storage_path: String,
    #[serde(default = "default_pid_file")]
    pub pid_file: String,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_log_file")]
    pub log_file: String,
    #[serde(default)]
    pub telegram: TelegramConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelegramConfig {
    #[serde(default)]
    pub bot_token: String,
    #[serde(default)]
    pub chat_id: String,
}

fn default_ssh_threshold() -> u64 {
    5
}

fn default_ssh_window() -> u64 {
    300
}

fn default_ssh_port() -> u16 {
    22
}

fn default_tcp_threshold() -> u64 {
    10
}

fn default_tcp_window() -> u64 {
    60
}

fn default_enable_blocking() -> bool {
    true
}

fn default_block_duration() -> u64 {
    86400
}

fn default_storage_path() -> String {
    "/var/lib/secrds/events.json".to_string()
}

fn default_pid_file() -> String {
    "/var/run/secrds.pid".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_file() -> String {
    "/var/log/secrds/agent.log".to_string()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ssh_threshold: default_ssh_threshold(),
            ssh_window_seconds: default_ssh_window(),
            ssh_port: default_ssh_port(),
            tcp_threshold: default_tcp_threshold(),
            tcp_window_seconds: default_tcp_window(),
            enable_ip_blocking: default_enable_blocking(),
            block_duration_seconds: default_block_duration(),
            whitelist_ips: Vec::new(),
            whitelist_cidrs: Vec::new(),
            storage_path: default_storage_path(),
            pid_file: default_pid_file(),
            log_level: default_log_level(),
            log_file: default_log_file(),
            telegram: TelegramConfig::default(),
        }
    }
}

impl Default for TelegramConfig {
    fn default() -> Self {
        Self {
            bot_token: String::new(),
            chat_id: String::new(),
        }
    }
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        let config_path = std::env::var("SECRDS_CONFIG")
            .unwrap_or_else(|_| "/etc/secrds/config.yaml".to_string());

        let mut config = Self::default();

        if PathBuf::from(&config_path).exists() {
            let content = fs::read_to_string(&config_path)?;
            config = serde_yaml::from_str(&content)
                .or_else(|_| serde_json::from_str(&content))?;
        }

        // Override with environment variables
        if let Ok(token) = std::env::var("TELEGRAM_BOT_TOKEN") {
            config.telegram.bot_token = token;
        }
        if let Ok(chat_id) = std::env::var("TELEGRAM_CHAT_ID") {
            config.telegram.chat_id = chat_id;
        }

        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.ssh_threshold == 0 {
            anyhow::bail!("ssh_threshold must be greater than 0");
        }
        if self.ssh_window_seconds == 0 || self.ssh_window_seconds > 86400 {
            anyhow::bail!("ssh_window_seconds must be between 1 and 86400");
        }
        if self.ssh_port == 0 || self.ssh_port > 65535 {
            anyhow::bail!("ssh_port must be between 1 and 65535");
        }
        if self.tcp_threshold == 0 {
            anyhow::bail!("tcp_threshold must be greater than 0");
        }
        if self.tcp_window_seconds == 0 || self.tcp_window_seconds > 86400 {
            anyhow::bail!("tcp_window_seconds must be between 1 and 86400");
        }
        if self.storage_path.is_empty() {
            anyhow::bail!("storage_path cannot be empty");
        }
        if self.pid_file.is_empty() {
            anyhow::bail!("pid_file cannot be empty");
        }

        for ip in &self.whitelist_ips {
            ip.parse::<IpAddr>()
                .map_err(|e| anyhow::anyhow!("invalid IP in whitelist: {}: {}", ip, e))?;
        }

        for cidr in &self.whitelist_cidrs {
            cidr.parse::<ipnet::IpNet>()
                .map_err(|e| anyhow::anyhow!("invalid CIDR in whitelist: {}: {}", cidr, e))?;
        }

        Ok(())
    }

    pub fn ssh_window(&self) -> Duration {
        Duration::from_secs(self.ssh_window_seconds)
    }

    pub fn tcp_window(&self) -> Duration {
        Duration::from_secs(self.tcp_window_seconds)
    }
}

