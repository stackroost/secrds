use crate::threat_detector::{ThreatAlert, ThreatType};
use anyhow::Context;
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const TELEGRAM_API_URL: &str = "https://api.telegram.org/bot";

#[derive(Debug, Serialize)]
struct SendMessageRequest {
    chat_id: String,
    text: String,
    parse_mode: String,
}

#[derive(Debug, Deserialize)]
struct TelegramResponse {
    ok: bool,
    description: Option<String>,
}

pub struct TelegramClient {
    bot_token: String,
    client: reqwest::Client,
    chat_id: Option<String>,
}

impl TelegramClient {
    pub fn new(bot_token: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            bot_token,
            client,
            chat_id: std::env::var("TELEGRAM_CHAT_ID").ok(),
        }
    }

    pub async fn send_alert(&self, alert: &ThreatAlert) -> anyhow::Result<()> {
        let chat_id = self.chat_id.as_ref()
            .context("TELEGRAM_CHAT_ID environment variable not set")?;

        let message = self.format_alert(alert);
        
        let url = format!("{}{}/sendMessage", TELEGRAM_API_URL, self.bot_token);
        
        let request = SendMessageRequest {
            chat_id: chat_id.clone(),
            text: message,
            parse_mode: "Markdown".to_string(),
        };

        let mut retries = 3;
        while retries > 0 {
            match self.client
                .post(&url)
                .json(&request)
                .send()
                .await
            {
                Ok(response) => {
                    if response.status().is_success() {
                        info!("Telegram alert sent successfully for IP: {}", alert.ip);
                        return Ok(());
                    } else {
                        let error_text = response.text().await.unwrap_or_default();
                        warn!("Telegram API error: {}", error_text);
                    }
                }
                Err(e) => {
                    warn!("Failed to send Telegram alert: {}", e);
                }
            }

            retries -= 1;
            if retries > 0 {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }

        error!("Failed to send Telegram alert after retries");
        Ok(())
    }

    fn format_alert(&self, alert: &ThreatAlert) -> String {
        let threat_name = match alert.threat_type {
            ThreatType::SshBruteForce => "SSH Brute Force",
            ThreatType::TcpPortScan => "TCP Port Scan",
            ThreatType::TcpFlood => "TCP Flood",
        };

        format!(
            "*Security Alert*\n\n\
            *Threat Type:* {}\n\
            *Source IP:* {}\n\
            *Attempt Count:* {}\n\
            *Timestamp:* {}",
            threat_name,
            alert.ip,
            alert.count,
            alert.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
        )
    }
}

