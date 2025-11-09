use crate::storage::Alert;
use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};

const TELEGRAM_API_URL: &str = "https://api.telegram.org/bot";

pub struct TelegramClient {
    bot_token: String,
    chat_id: String,
    client: Client,
}

#[derive(Serialize)]
struct SendMessageRequest {
    chat_id: String,
    text: String,
    #[serde(rename = "parse_mode")]
    parse_mode: String,
}

#[derive(Deserialize)]
struct TelegramResponse {
    ok: bool,
    description: Option<String>,
}

impl TelegramClient {
    pub fn new(bot_token: String, chat_id: String) -> Result<Self> {
        if chat_id.is_empty() {
            anyhow::bail!("TELEGRAM_CHAT_ID not set");
        }

        Ok(Self {
            bot_token,
            chat_id,
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()?,
        })
    }

    pub async fn send_alert(&self, alert: &Alert) -> Result<()> {
        let message = self.format_alert(alert);
        let url = format!("{}{}/sendMessage", TELEGRAM_API_URL, self.bot_token);

        let request = SendMessageRequest {
            chat_id: self.chat_id.clone(),
            text: message,
            parse_mode: "Markdown".to_string(),
        };

        let mut retries = 3;
        while retries > 0 {
            let response = self.client.post(&url).json(&request).send().await?;

            if response.status().is_success() {
                return Ok(());
            }

            if let Ok(tg_resp) = response.json::<TelegramResponse>().await {
                if let Some(desc) = tg_resp.description {
                    log::error!("Telegram API error: {}", desc);
                }
            }

            retries -= 1;
            if retries > 0 {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }

        anyhow::bail!("Failed to send Telegram alert after retries");
    }

    fn format_alert(&self, alert: &Alert) -> String {
        let threat_name = match alert.threat_type {
            crate::storage::ThreatType::SshBruteForce => "SSH Brute Force",
            crate::storage::ThreatType::TcpPortScan => "TCP Port Scan",
            crate::storage::ThreatType::TcpFlood => "TCP Flood",
        };

        let severity_emoji = alert
            .severity
            .as_ref()
            .map(|s| match s.as_str() {
                "CRITICAL" => "🚨",
                "HIGH" => "🔴",
                "MEDIUM" => "🟠",
                "LOW" => "🟡",
                _ => "⚠️",
            })
            .unwrap_or("⚠️");

        let timestamp = alert
            .timestamp
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let dt = chrono::DateTime::<chrono::Utc>::from_timestamp(timestamp as i64, 0)
            .unwrap_or_default();
        let time_str = dt.format("%Y-%m-%d %H:%M:%S UTC").to_string();

        let mut message = format!(
            "{} *Security Alert*\n\n\
            *Threat Type:* {}\n\
            *Severity:* {}\n\
            *Source IP:* `{}`\n\
            *Attempt Count:* {}\n\
            *Timestamp:* {}",
            severity_emoji,
            threat_name,
            alert.severity.as_deref().unwrap_or("UNKNOWN"),
            alert.ip,
            alert.count,
            time_str
        );

        if let Some(ref details) = alert.details {
            message.push_str(&format!("\n*Details:* {}", details));
        }

        if let Some(score) = alert.score {
            message.push_str(&format!("\n*Threat Score:* {:.1}", score));
        }

        message
    }
}

