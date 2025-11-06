package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type ThreatType string

const (
	ThreatTypeSSHBruteForce ThreatType = "SSH_BRUTE_FORCE"
	ThreatTypeTCPPortScan   ThreatType = "TCP_PORT_SCAN"
	ThreatTypeTCPFlood      ThreatType = "TCP_FLOOD"
)

type Alert struct {
	IP          string    `json:"ip"`
	ThreatType  ThreatType `json:"threat_type"`
	Count       uint64    `json:"count"`
	Timestamp   time.Time `json:"timestamp"`
	Severity    string    `json:"severity,omitempty"`
	Details     string    `json:"details,omitempty"`
	Score       float64   `json:"score,omitempty"`
}

type Statistics struct {
	TotalAlerts        uint64 `json:"total_alerts"`
	SSHBruteForceCount uint64 `json:"ssh_brute_force_count"`
	TCPPortScanCount   uint64 `json:"tcp_port_scan_count"`
	TCPFloodCount      uint64 `json:"tcp_flood_count"`
	BlockedIPsCount    uint64 `json:"blocked_ips_count"`
}

type StorageData struct {
	Alerts     []Alert     `json:"alerts"`
	BlockedIPs []string    `json:"blocked_ips"`
	Statistics Statistics  `json:"statistics"`
}

type Storage struct {
	path string
	mu   sync.RWMutex
	data *StorageData
}

func New(path string) (*Storage, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %w", err)
	}

	s := &Storage{
		path: path,
		data: &StorageData{
			Alerts:     []Alert{},
			BlockedIPs: []string{},
			Statistics: Statistics{},
		},
	}

	// Load existing data if available
	if data, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(data, s.data); err != nil {
			// If unmarshal fails, use default empty data
			s.data = &StorageData{
				Alerts:     []Alert{},
				BlockedIPs: []string{},
				Statistics: Statistics{},
			}
		}
	}

	// Start periodic flush
	go s.periodicFlush()

	return s, nil
}

func (s *Storage) periodicFlush() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if err := s.Flush(); err != nil {
			fmt.Printf("Failed to flush storage: %v\n", err)
		}
	}
}

func (s *Storage) StoreAlert(alert *Alert) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.data.Alerts = append(s.data.Alerts, *alert)
	s.data.Statistics.TotalAlerts++

	switch alert.ThreatType {
	case ThreatTypeSSHBruteForce:
		s.data.Statistics.SSHBruteForceCount++
	case ThreatTypeTCPPortScan:
		s.data.Statistics.TCPPortScanCount++
	case ThreatTypeTCPFlood:
		s.data.Statistics.TCPFloodCount++
	}

	// Keep only last 1000 alerts
	if len(s.data.Alerts) > 1000 {
		s.data.Alerts = s.data.Alerts[len(s.data.Alerts)-1000:]
	}

	return nil
}

func (s *Storage) AddBlockedIP(ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if already blocked
	for _, blocked := range s.data.BlockedIPs {
		if blocked == ip {
			return nil
		}
	}

	s.data.BlockedIPs = append(s.data.BlockedIPs, ip)
	s.data.Statistics.BlockedIPsCount++
	return nil
}

func (s *Storage) GetAlerts(limit int) []Alert {
	s.mu.RLock()
	defer s.mu.RUnlock()

	alerts := s.data.Alerts
	if len(alerts) > limit {
		alerts = alerts[len(alerts)-limit:]
	}

	// Reverse to show newest first
	result := make([]Alert, len(alerts))
	for i := range alerts {
		result[len(alerts)-1-i] = alerts[i]
	}

	return result
}

func (s *Storage) GetStatistics() Statistics {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.data.Statistics
}

func (s *Storage) IsBlocked(ip string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, blocked := range s.data.BlockedIPs {
		if blocked == ip {
			return true
		}
	}
	return false
}

func (s *Storage) Flush() error {
	s.mu.RLock()
	data := s.data
	s.mu.RUnlock()

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal storage data: %w", err)
	}

	if err := os.WriteFile(s.path, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write storage file: %w", err)
	}

	return nil
}

