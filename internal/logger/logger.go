package logger

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// Logger handles both console and file logging
type Logger struct {
	consoleLog *log.Logger
	fileLog    *log.Logger
	logFile    *os.File
	logDir     string
	attempts   map[string]int // Track attempts per IP
}

// NewLogger creates a new logger instance
func NewLogger(logDir string) (*Logger, error) {
	// Ensure log directory exists
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	// Create log file with timestamp
	logFileName := filepath.Join(logDir, fmt.Sprintf("secrds-%s.log", time.Now().Format("2006-01-02")))
	logFile, err := os.OpenFile(logFileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	return &Logger{
		consoleLog: log.New(os.Stdout, "", 0),
		fileLog:    log.New(logFile, "", 0),
		logFile:    logFile,
		logDir:     logDir,
		attempts:   make(map[string]int),
	}, nil
}

// Close closes the log file
func (l *Logger) Close() error {
	if l.logFile != nil {
		return l.logFile.Close()
	}
	return nil
}

// log writes to both console and file
func (l *Logger) log(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logMessage := fmt.Sprintf("[%s] %s", timestamp, message)
	
	l.consoleLog.Println(logMessage)
	l.fileLog.Println(logMessage)
}

// StartMonitoring logs the start of SSH monitoring
func (l *Logger) StartMonitoring() {
	l.log("starting ssh monitoring")
}

// LogSSHDetected logs SSH detection with IP, attempt count, and time
func (l *Logger) LogSSHDetected(ip string, port int, pid uint32, comm string) {
	// Increment attempt counter for this IP
	l.attempts[ip]++
	attemptCount := l.attempts[ip]
	
	// Format: ssh detected : ip, attempt tried time
	detectionTime := time.Now().Format("2006-01-02 15:04:05")
	message := fmt.Sprintf("ssh detected : %s:%d, attempt %d, time %s (pid=%d, comm=%s)",
		ip, port, attemptCount, detectionTime, pid, comm)
	
	l.log(message)
}

// LogEvent logs a general accept event
func (l *Logger) LogEvent(ip string, port int, pid uint32, comm string) {
	detectionTime := time.Now().Format("2006-01-02 15:04:05")
	message := fmt.Sprintf("accept event: %s:%d (pid=%d, comm=%s, time=%s)",
		ip, port, pid, comm, detectionTime)
	
	l.log(message)
}

// LogError logs an error message
func (l *Logger) LogError(format string, args ...interface{}) {
	l.log("ERROR: "+format, args...)
}

// LogInfo logs an info message
func (l *Logger) LogInfo(format string, args ...interface{}) {
	l.log("INFO: "+format, args...)
}

