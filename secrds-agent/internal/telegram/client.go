package telegram

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const TelegramAPIURL = "https://api.telegram.org/bot"

type Client struct {
	botToken string
	chatID   string
	client   *http.Client
}

func New(botToken string, chatID string) (*Client, error) {
	if chatID == "" {
		return nil, fmt.Errorf("TELEGRAM_CHAT_ID not set. Please set it in /etc/secrds/config.yaml (telegram.chat_id) or as TELEGRAM_CHAT_ID environment variable")
	}

	return &Client{
		botToken: botToken,
		chatID:   chatID,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}, nil
}

type SendMessageRequest struct {
	ChatID    string `json:"chat_id"`
	Text      string `json:"text"`
	ParseMode string `json:"parse_mode"`
}

type TelegramResponse struct {
	OK          bool   `json:"ok"`
	Description string `json:"description,omitempty"`
}

func (c *Client) SendAlert(alert *Alert) error {
	message := c.formatAlert(alert)
	url := fmt.Sprintf("%s%s/sendMessage", TelegramAPIURL, c.botToken)

	req := SendMessageRequest{
		ChatID:    c.chatID,
		Text:      message,
		ParseMode: "Markdown",
	}

	jsonData, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	retries := 3
	for retries > 0 {
		resp, err := c.client.Post(url, "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			retries--
			if retries > 0 {
				time.Sleep(1 * time.Second)
			}
			continue
		}

		if resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			return nil
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var tgResp TelegramResponse
		if err := json.Unmarshal(body, &tgResp); err == nil {
			fmt.Printf("Telegram API error: %s\n", tgResp.Description)
		}

		retries--
		if retries > 0 {
			time.Sleep(1 * time.Second)
		}
	}

	return fmt.Errorf("failed to send Telegram alert after retries")
}

func (c *Client) formatAlert(alert *Alert) string {
	threatName := alert.ThreatType
	switch alert.ThreatType {
	case "SSH_BRUTE_FORCE":
		threatName = "SSH Brute Force"
	case "TCP_PORT_SCAN":
		threatName = "TCP Port Scan"
	case "TCP_FLOOD":
		threatName = "TCP Flood"
	}

	// Determine severity emoji
	severityEmoji := "⚠️"
	if alert.Severity != "" {
		switch alert.Severity {
		case "CRITICAL":
			severityEmoji = "🚨"
		case "HIGH":
			severityEmoji = "🔴"
		case "MEDIUM":
			severityEmoji = "🟠"
		case "LOW":
			severityEmoji = "🟡"
		}
	}

	message := fmt.Sprintf(
		"%s *Security Alert*\n\n"+
			"*Threat Type:* %s\n"+
			"*Severity:* %s\n"+
			"*Source IP:* `%s`\n"+
			"*Attempt Count:* %d\n"+
			"*Timestamp:* %s",
		severityEmoji,
		threatName,
		alert.Severity,
		alert.IP,
		alert.Count,
		alert.Timestamp.Format("2006-01-02 15:04:05 UTC"),
	)

	if alert.Details != "" {
		message += fmt.Sprintf("\n*Details:* %s", alert.Details)
	}

	if alert.Score > 0 {
		message += fmt.Sprintf("\n*Threat Score:* %.1f", alert.Score)
	}

	return message
}

type Alert struct {
	IP         string
	ThreatType string
	Count      uint64
	Timestamp  time.Time
	Severity   string
	Details    string
	Score      float64
}

