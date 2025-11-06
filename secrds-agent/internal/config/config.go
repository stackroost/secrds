package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	SSHThreshold      uint64 `yaml:"ssh_threshold" json:"ssh_threshold"`
	SSHWindowSeconds  uint64 `yaml:"ssh_window_seconds" json:"ssh_window_seconds"`
	TCPThreshold      uint64 `yaml:"tcp_threshold" json:"tcp_threshold"`
	TCPWindowSeconds  uint64 `yaml:"tcp_window_seconds" json:"tcp_window_seconds"`
	EnableIPBlocking  bool   `yaml:"enable_ip_blocking" json:"enable_ip_blocking"`
	StoragePath       string `yaml:"storage_path" json:"storage_path"`
	PIDFile           string `yaml:"pid_file" json:"pid_file"`
	LogLevel          string `yaml:"log_level" json:"log_level"`
	LogFile           string `yaml:"log_file" json:"log_file"`
	Telegram          TelegramConfig `yaml:"telegram" json:"telegram"`
}

type TelegramConfig struct {
	BotToken string `yaml:"bot_token" json:"bot_token"`
	ChatID   string `yaml:"chat_id" json:"chat_id"`
}

func Default() *Config {
	return &Config{
		SSHThreshold:     5,  // 5 attempts in 5 minutes triggers alert
		SSHWindowSeconds: 300,
		TCPThreshold:     10, // 10 connections in 60 seconds triggers alert
		TCPWindowSeconds: 60,
		EnableIPBlocking: true,
		StoragePath:      "/var/lib/secrds/events.json",
		PIDFile:          "/var/run/secrds.pid",
		LogLevel:         "info",
		LogFile:          "/var/log/secrds/agent.log",
	}
}

func Load() (*Config, error) {
	configPath := os.Getenv("SECRDS_CONFIG")
	if configPath == "" {
		configPath = "/etc/secrds/config.yaml"
	}

	cfg := Default()

	// Try to load config file
	if _, err := os.Stat(configPath); err == nil {
		data, err := os.ReadFile(configPath)
		if err == nil {
			// Try YAML first (preferred)
			if err := yaml.Unmarshal(data, cfg); err == nil {
				// Config loaded successfully
			} else if err := json.Unmarshal(data, cfg); err == nil {
				// JSON fallback worked
			}
		}
	}

	// Try to load env file as fallback (for backward compatibility)
	// But don't fail if we can't read it
	envPath := os.Getenv("SECRDS_ENV_FILE")
	if envPath == "" {
		envPath = "/etc/secrds/env.conf"
	}
	if err := LoadEnvFile(envPath); err == nil {
		// If env file loaded successfully, override config with env vars
		if botToken := os.Getenv("TELEGRAM_BOT_TOKEN"); botToken != "" {
			cfg.Telegram.BotToken = botToken
		}
		if chatID := os.Getenv("TELEGRAM_CHAT_ID"); chatID != "" {
			cfg.Telegram.ChatID = chatID
		}
	}

	// Also check environment variables directly (highest priority)
	if botToken := os.Getenv("TELEGRAM_BOT_TOKEN"); botToken != "" {
		cfg.Telegram.BotToken = botToken
	}
	if chatID := os.Getenv("TELEGRAM_CHAT_ID"); chatID != "" {
		cfg.Telegram.ChatID = chatID
	}

	return cfg, nil
}

func (c *Config) Validate() error {
	if c.SSHThreshold == 0 {
		return fmt.Errorf("ssh_threshold must be greater than 0")
	}
	if c.SSHWindowSeconds == 0 {
		return fmt.Errorf("ssh_window_seconds must be greater than 0")
	}
	if c.TCPThreshold == 0 {
		return fmt.Errorf("tcp_threshold must be greater than 0")
	}
	if c.TCPWindowSeconds == 0 {
		return fmt.Errorf("tcp_window_seconds must be greater than 0")
	}
	return nil
}

func (c *Config) SSHWindow() time.Duration {
	return time.Duration(c.SSHWindowSeconds) * time.Second
}

func (c *Config) TCPWindow() time.Duration {
	return time.Duration(c.TCPWindowSeconds) * time.Second
}

