package detector

import (
	"fmt"
	"net"
	"os/exec"
	"sync"
	"time"

	"github.com/secrds/secrds-agent/internal/config"
	"github.com/secrds/secrds-agent/internal/storage"
	"github.com/secrds/secrds-agent/internal/telegram"
)

// EventType constants matching common.h
const (
	SSH_ATTEMPT = 0
	SSH_FAILURE = 1
	SSH_SUCCESS = 2
	TCP_CONNECT = 3
	TCP_ACCEPT  = 4
	TCP_CLOSE   = 5
)

// ThreatSeverity levels
type ThreatSeverity string

const (
	SeverityLow      ThreatSeverity = "LOW"
	SeverityMedium   ThreatSeverity = "MEDIUM"
	SeverityHigh     ThreatSeverity = "HIGH"
	SeverityCritical ThreatSeverity = "CRITICAL"
)

// SSHEventDetail tracks detailed SSH event information
type SSHEventDetail struct {
	Timestamp time.Time
	EventType uint8
	Port      uint16
	PID       uint32
}

// TCPConnectionDetail tracks TCP connection details
type TCPConnectionDetail struct {
	Timestamp time.Time
	SrcPort   uint16
	DstPort   uint16
	EventType uint8
}

// IPBehavior tracks behavioral patterns for an IP
type IPBehavior struct {
	SSHEvents         []SSHEventDetail
	TCPConnections    []TCPConnectionDetail
	FailedSSHCount    uint64
	SuccessfulSSHCount uint64
	UniquePorts       map[uint16]bool
	FirstSeen         time.Time
	LastSeen          time.Time
	TotalConnections  uint64
}

type ThreatDetector struct {
	config         *config.Config
	storage        *storage.Storage
	telegramClient *telegram.Client
	mu             sync.RWMutex
	ipBehaviors    map[string]*IPBehavior
	blockedIPs     map[string]bool
}

func New(cfg *config.Config, st *storage.Storage, tg *telegram.Client) *ThreatDetector {
	return &ThreatDetector{
		config:         cfg,
		storage:        st,
		telegramClient: tg,
		ipBehaviors:    make(map[string]*IPBehavior),
		blockedIPs:     make(map[string]bool),
	}
}

func (td *ThreatDetector) ProcessSSHEvent(ip uint32, port uint16, pid uint32, eventType uint8) error {
	ipAddr := u32ToIP(ip)
	ipStr := ipAddr.String()

	// Skip invalid IPs (0.0.0.0 or invalid)
	if ip == 0 || ipStr == "0.0.0.0" {
		fmt.Printf("[DEBUG] Skipping invalid IP: %s\n", ipStr)
		return nil
	}

	// Check if already blocked
	if td.storage.IsBlocked(ipStr) {
		return nil
	}

	td.mu.Lock()
	defer td.mu.Unlock()

	now := time.Now()

	// Get or create IP behavior tracking
	behavior := td.getOrCreateBehavior(ipStr)
	
	// Add event
	event := SSHEventDetail{
		Timestamp: now,
		EventType: eventType,
		Port:      port,
		PID:       pid,
	}
	behavior.SSHEvents = append(behavior.SSHEvents, event)
	behavior.LastSeen = now

	// Track failed vs successful attempts
	if eventType == SSH_FAILURE {
		behavior.FailedSSHCount++
	} else if eventType == SSH_SUCCESS {
		behavior.SuccessfulSSHCount++
	}

	// Clean old events (keep last 24 hours)
	cutoff := now.Add(-24 * time.Hour)
	validEvents := []SSHEventDetail{}
	for _, e := range behavior.SSHEvents {
		if e.Timestamp.After(cutoff) {
			validEvents = append(validEvents, e)
		}
	}
	behavior.SSHEvents = validEvents

	// Advanced threat detection
	threats := td.detectSSHThreats(ipStr, behavior, now)
	
	// Process detected threats
	for _, threat := range threats {
		if err := td.handleThreat(ipStr, threat); err != nil {
			fmt.Printf("Failed to handle threat: %v\n", err)
		}
	}

	return nil
}

func (td *ThreatDetector) ProcessTCPEvent(srcIP, dstIP uint32, srcPort, dstPort uint16, eventType uint8) error {
	ipAddr := u32ToIP(srcIP)
	ipStr := ipAddr.String()

	// Check if already blocked
	if td.storage.IsBlocked(ipStr) {
		return nil
	}

	td.mu.Lock()
	defer td.mu.Unlock()

	now := time.Now()

	// Get or create IP behavior tracking
	behavior := td.getOrCreateBehavior(ipStr)

	// Add connection
	conn := TCPConnectionDetail{
		Timestamp: now,
		SrcPort:   srcPort,
		DstPort:   dstPort,
		EventType: eventType,
	}
	behavior.TCPConnections = append(behavior.TCPConnections, conn)
	behavior.LastSeen = now
	behavior.TotalConnections++

	// Track unique destination ports for port scan detection
	if eventType == TCP_CONNECT {
		if behavior.UniquePorts == nil {
			behavior.UniquePorts = make(map[uint16]bool)
		}
		behavior.UniquePorts[dstPort] = true
	}

	// Clean old connections (keep last 24 hours)
	cutoff := now.Add(-24 * time.Hour)
	validConns := []TCPConnectionDetail{}
	for _, c := range behavior.TCPConnections {
		if c.Timestamp.After(cutoff) {
			validConns = append(validConns, c)
		}
	}
	behavior.TCPConnections = validConns

	// Advanced threat detection
	threats := td.detectTCPThreats(ipStr, behavior, now)

	// Process detected threats
	for _, threat := range threats {
		if err := td.handleThreat(ipStr, threat); err != nil {
			fmt.Printf("Failed to handle threat: %v\n", err)
		}
	}

	return nil
}

// ThreatInfo contains detailed threat information
type ThreatInfo struct {
	ThreatType storage.ThreatType
	Severity   ThreatSeverity
	Count      uint64
	Details    string
	Score      float64
}

func (td *ThreatDetector) detectSSHThreats(ip string, behavior *IPBehavior, now time.Time) []ThreatInfo {
	var threats []ThreatInfo

	// Multi-window analysis
	shortWindow := 1 * time.Minute
	mediumWindow := 5 * time.Minute
	longWindow := 15 * time.Minute

	shortTerm := td.countEventsInWindow(behavior.SSHEvents, now, shortWindow)
	mediumTerm := td.countEventsInWindow(behavior.SSHEvents, now, mediumWindow)
	longTerm := td.countEventsInWindow(behavior.SSHEvents, now, longWindow)

	// Calculate threat score with exponential weighting
	score := td.calculateThreatScore(shortTerm, mediumTerm, longTerm)

	// Failed login analysis
	failedInShort := td.countFailedInWindow(behavior.SSHEvents, now, shortWindow)
	failedInMedium := td.countFailedInWindow(behavior.SSHEvents, now, mediumWindow)

	// Use config threshold for detection
	threshold := td.config.SSHThreshold
	if threshold == 0 {
		threshold = 3 // Default fallback
	}

	// Pattern 1: Rapid brute force attack (high frequency in short window)
	// Critical: 2x threshold in 1 minute
	if shortTerm >= threshold*2 || (shortTerm >= threshold && failedInShort >= threshold) {
		threats = append(threats, ThreatInfo{
			ThreatType: storage.ThreatTypeSSHBruteForce,
			Severity:   SeverityCritical,
			Count:      shortTerm,
			Details:    fmt.Sprintf("Rapid brute force: %d attempts in 1 minute", shortTerm),
			Score:      score,
		})
	} else if mediumTerm >= threshold*3 || (mediumTerm >= threshold*2 && failedInMedium >= threshold*2) {
		// High: 3x threshold in 5 minutes
		threats = append(threats, ThreatInfo{
			ThreatType: storage.ThreatTypeSSHBruteForce,
			Severity:   SeverityHigh,
			Count:      mediumTerm,
			Details:    fmt.Sprintf("Sustained brute force: %d attempts in 5 minutes", mediumTerm),
			Score:      score,
		})
	} else if mediumTerm >= threshold {
		// Medium: threshold or more in 5 minutes
		threats = append(threats, ThreatInfo{
			ThreatType: storage.ThreatTypeSSHBruteForce,
			Severity:   SeverityMedium,
			Count:      mediumTerm,
			Details:    fmt.Sprintf("Brute force detected: %d attempts in 5 minutes", mediumTerm),
			Score:      score,
		})
	} else if longTerm >= threshold {
		// Low: threshold or more in 15 minutes
		threats = append(threats, ThreatInfo{
			ThreatType: storage.ThreatTypeSSHBruteForce,
			Severity:   SeverityLow,
			Count:      longTerm,
			Details:    fmt.Sprintf("Suspicious activity: %d attempts in 15 minutes", longTerm),
			Score:      score,
		})
	}

	// Pattern 2: High failure rate (suspicious activity)
	totalAttempts := uint64(len(behavior.SSHEvents))
	if totalAttempts > 0 {
		failureRate := float64(behavior.FailedSSHCount) / float64(totalAttempts)
		if failureRate > 0.8 && totalAttempts >= 5 {
			threats = append(threats, ThreatInfo{
				ThreatType: storage.ThreatTypeSSHBruteForce,
				Severity:   SeverityHigh,
				Count:      behavior.FailedSSHCount,
				Details:    fmt.Sprintf("High failure rate: %.1f%% failures (%d/%d)", failureRate*100, behavior.FailedSSHCount, totalAttempts),
				Score:      score * failureRate,
			})
		}
	}

	// Pattern 3: Timing pattern analysis (rapid-fire attempts)
	if len(behavior.SSHEvents) >= 3 {
		rapidFire := td.detectRapidFirePattern(behavior.SSHEvents, now)
		if rapidFire {
			threats = append(threats, ThreatInfo{
				ThreatType: storage.ThreatTypeSSHBruteForce,
				Severity:   SeverityHigh,
				Count:      uint64(len(behavior.SSHEvents)),
				Details:    "Rapid-fire attack pattern detected",
				Score:      score * 1.2,
			})
		}
	}

	return threats
}

func (td *ThreatDetector) detectTCPThreats(ip string, behavior *IPBehavior, now time.Time) []ThreatInfo {
	var threats []ThreatInfo

	// Multi-window analysis
	shortWindow := 30 * time.Second
	mediumWindow := 2 * time.Minute
	longWindow := 10 * time.Minute

	shortTerm := td.countConnectionsInWindow(behavior.TCPConnections, now, shortWindow)
	mediumTerm := td.countConnectionsInWindow(behavior.TCPConnections, now, mediumWindow)
	longTerm := td.countConnectionsInWindow(behavior.TCPConnections, now, longWindow)

	// Calculate threat score
	score := td.calculateThreatScore(shortTerm, mediumTerm, longTerm)

	// Port scanning detection
	uniquePorts := len(behavior.UniquePorts)
	portScanThreshold := 5

	// Pattern 1: Port scanning (many unique ports)
	if uniquePorts >= portScanThreshold*3 {
		threats = append(threats, ThreatInfo{
			ThreatType: storage.ThreatTypeTCPPortScan,
			Severity:   SeverityCritical,
			Count:      uint64(uniquePorts),
			Details:    fmt.Sprintf("Aggressive port scan: %d unique ports scanned", uniquePorts),
			Score:      score * float64(uniquePorts) / 10,
		})
	} else if uniquePorts >= portScanThreshold*2 {
		threats = append(threats, ThreatInfo{
			ThreatType: storage.ThreatTypeTCPPortScan,
			Severity:   SeverityHigh,
			Count:      uint64(uniquePorts),
			Details:    fmt.Sprintf("Port scan detected: %d unique ports", uniquePorts),
			Score:      score * float64(uniquePorts) / 10,
		})
	} else if uniquePorts >= portScanThreshold {
		threats = append(threats, ThreatInfo{
			ThreatType: storage.ThreatTypeTCPPortScan,
			Severity:   SeverityMedium,
			Count:      uint64(uniquePorts),
			Details:    fmt.Sprintf("Suspicious port activity: %d unique ports", uniquePorts),
			Score:      score * float64(uniquePorts) / 10,
		})
	}

	// Pattern 2: Connection flood
	if shortTerm >= 50 {
		threats = append(threats, ThreatInfo{
			ThreatType: storage.ThreatTypeTCPFlood,
			Severity:   SeverityCritical,
			Count:      shortTerm,
			Details:    fmt.Sprintf("Connection flood: %d connections in 30 seconds", shortTerm),
			Score:      score,
		})
	} else if mediumTerm >= 100 {
		threats = append(threats, ThreatInfo{
			ThreatType: storage.ThreatTypeTCPFlood,
			Severity:   SeverityHigh,
			Count:      mediumTerm,
			Details:    fmt.Sprintf("Sustained flood: %d connections in 2 minutes", mediumTerm),
			Score:      score,
		})
	} else if longTerm >= 200 {
		threats = append(threats, ThreatInfo{
			ThreatType: storage.ThreatTypeTCPFlood,
			Severity:   SeverityMedium,
			Count:      longTerm,
			Details:    fmt.Sprintf("High connection volume: %d connections in 10 minutes", longTerm),
			Score:      score,
		})
	}

	// Pattern 3: Sequential port scanning pattern
	if uniquePorts >= portScanThreshold {
		sequential := td.detectSequentialPortScan(behavior.TCPConnections)
		if sequential {
			threats = append(threats, ThreatInfo{
				ThreatType: storage.ThreatTypeTCPPortScan,
				Severity:   SeverityHigh,
				Count:      uint64(uniquePorts),
				Details:    "Sequential port scan pattern detected",
				Score:      score * 1.3,
			})
		}
	}

	return threats
}

// Helper functions

func (td *ThreatDetector) getOrCreateBehavior(ip string) *IPBehavior {
	if behavior, exists := td.ipBehaviors[ip]; exists {
		return behavior
	}
	behavior := &IPBehavior{
		SSHEvents:         []SSHEventDetail{},
		TCPConnections:    []TCPConnectionDetail{},
		UniquePorts:       make(map[uint16]bool),
		FirstSeen:         time.Now(),
		LastSeen:          time.Now(),
		FailedSSHCount:    0,
		SuccessfulSSHCount: 0,
	}
	td.ipBehaviors[ip] = behavior
	return behavior
}

func (td *ThreatDetector) countEventsInWindow(events []SSHEventDetail, now time.Time, window time.Duration) uint64 {
	count := uint64(0)
	cutoff := now.Add(-window)
	for _, e := range events {
		if e.Timestamp.After(cutoff) {
			count++
		}
	}
	return count
}

func (td *ThreatDetector) countConnectionsInWindow(conns []TCPConnectionDetail, now time.Time, window time.Duration) uint64 {
	count := uint64(0)
	cutoff := now.Add(-window)
	for _, c := range conns {
		if c.Timestamp.After(cutoff) {
			count++
		}
	}
	return count
}

func (td *ThreatDetector) countFailedInWindow(events []SSHEventDetail, now time.Time, window time.Duration) uint64 {
	count := uint64(0)
	cutoff := now.Add(-window)
	for _, e := range events {
		if e.Timestamp.After(cutoff) && e.EventType == SSH_FAILURE {
			count++
		}
	}
	return count
}

func (td *ThreatDetector) calculateThreatScore(short, medium, long uint64) float64 {
	// Exponential weighting: recent events are more significant
	score := float64(short)*3.0 + float64(medium)*1.5 + float64(long)*0.5
	return score
}

func (td *ThreatDetector) detectRapidFirePattern(events []SSHEventDetail, now time.Time) bool {
	if len(events) < 3 {
		return false
	}

	// Check last 5 events for rapid-fire pattern (multiple attempts within 5 seconds)
	recentEvents := events
	if len(events) > 5 {
		recentEvents = events[len(events)-5:]
	}

	for i := 1; i < len(recentEvents); i++ {
		timeDiff := recentEvents[i].Timestamp.Sub(recentEvents[i-1].Timestamp)
		if timeDiff < 2*time.Second && recentEvents[i].EventType == SSH_FAILURE {
			return true
		}
	}

	return false
}

func (td *ThreatDetector) detectSequentialPortScan(conns []TCPConnectionDetail) bool {
	if len(conns) < 5 {
		return false
	}

	// Check if ports are being scanned sequentially
	recentConns := conns
	if len(conns) > 20 {
		recentConns = conns[len(conns)-20:]
	}

	sequentialCount := 0
	for i := 1; i < len(recentConns); i++ {
		portDiff := int(recentConns[i].DstPort) - int(recentConns[i-1].DstPort)
		if portDiff > 0 && portDiff <= 10 {
			sequentialCount++
		}
	}

	// If more than 30% show sequential pattern, it's likely a scan
	return float64(sequentialCount)/float64(len(recentConns)-1) > 0.3
}

func (td *ThreatDetector) handleThreat(ip string, threat ThreatInfo) error {
	// Alert on all threats (including LOW severity for testing/debugging)
	// In production, you might want to filter LOW severity threats
	fmt.Printf("[DEBUG] Threat detected: IP=%s, Type=%s, Severity=%s, Count=%d, Score=%.1f\n",
		ip, threat.ThreatType, threat.Severity, threat.Count, threat.Score)

	alert := &storage.Alert{
		IP:         ip,
		ThreatType: threat.ThreatType,
		Count:      threat.Count,
		Timestamp:  time.Now(),
		Severity:   string(threat.Severity),
		Details:    threat.Details,
		Score:      threat.Score,
	}

	if err := td.storage.StoreAlert(alert); err != nil {
		return fmt.Errorf("failed to store alert: %w", err)
	}

	// Send Telegram alert
	tgAlert := &telegram.Alert{
		IP:         ip,
		ThreatType: string(threat.ThreatType),
		Count:      threat.Count,
		Timestamp:  time.Now(),
		Severity:   string(threat.Severity),
		Details:    threat.Details,
		Score:      threat.Score,
	}
	if err := td.telegramClient.SendAlert(tgAlert); err != nil {
		fmt.Printf("Failed to send Telegram alert: %v\n", err)
	}

	// Auto-block for CRITICAL threats or high-scoring threats
	shouldBlock := threat.Severity == SeverityCritical || 
		(threat.Severity == SeverityHigh && threat.Score > 50) ||
		(threat.Score > 100)

	if shouldBlock && td.config.EnableIPBlocking {
		if err := td.blockIP(ip); err != nil {
			fmt.Printf("Failed to block IP %s: %v\n", ip, err)
		} else {
			td.storage.AddBlockedIP(ip)
			fmt.Printf("Auto-blocked IP %s due to %s threat (severity: %s, score: %.1f)\n", 
				ip, threat.ThreatType, threat.Severity, threat.Score)
		}
	}

	return nil
}

func (td *ThreatDetector) blockIP(ip string) error {
	cmd := exec.Command("iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to block IP with iptables: %w", err)
	}
	return nil
}

func u32ToIP(ip uint32) net.IP {
	return net.IP{
		byte(ip >> 24),
		byte(ip >> 16),
		byte(ip >> 8),
		byte(ip),
	}
}
