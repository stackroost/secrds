package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"secrds/internal/logger"
	"secrds/internal/monitor"
)

func main() {
	// Default log directory - try /var/log/secrds first, fallback to /etc/secrds/logs
	logDir := "/var/log/secrds"
	if _, err := os.Stat("/var/log"); err != nil {
		// Fallback to /etc/secrds/logs if /var/log doesn't exist or isn't writable
		logDir = "/etc/secrds/logs"
	}

	// Initialize logger
	lg, err := logger.NewLogger(logDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer lg.Close()

	// Create monitor
	mon := monitor.NewMonitor(lg)

	// Load BPF object file
	bpfObjFile := "secrds.bpf.o"
	if len(os.Args) > 1 {
		bpfObjFile = os.Args[1]
	}

	if err := mon.LoadBPF(bpfObjFile); err != nil {
		lg.LogError("Failed to load BPF: %v", err)
		os.Exit(1)
	}

	// Attach tracepoints
	if err := mon.Attach(); err != nil {
		lg.LogError("Failed to attach tracepoints: %v", err)
		os.Exit(1)
	}

	// Start perf reader
	if err := mon.StartPerfReader(); err != nil {
		lg.LogError("Failed to start perf reader: %v", err)
		os.Exit(1)
	}
	defer mon.Close()

	// Start monitoring
	lg.StartMonitoring()

	// Handle signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start event processing in goroutine
	go mon.ProcessEvents()

	// Wait for signal
	<-sigChan
	lg.LogInfo("Shutting down...")
	
	// Close monitor (this will gracefully stop the goroutine)
	mon.Close()
	
	lg.LogInfo("Exited")
}

