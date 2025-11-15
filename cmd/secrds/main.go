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

	logDir := "/var/log/secrds"
	if _, err := os.Stat("/var/log"); err != nil {

		logDir = "/etc/secrds/logs"
	}


	lg, err := logger.NewLogger(logDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer lg.Close()


	mon := monitor.NewMonitor(lg)


	bpfObjFile := "secrds.bpf.o"
	if len(os.Args) > 1 {
		bpfObjFile = os.Args[1]
	}

	if err := mon.LoadBPF(bpfObjFile); err != nil {
		lg.LogError("Failed to load BPF: %v", err)
		os.Exit(1)
	}


	authBpfObjFile := "secrds_auth.bpf.o"
	if err := mon.LoadAuthBPF(authBpfObjFile); err != nil {
		lg.LogError("Failed to load auth BPF: %v", err)
		os.Exit(1)
	}


	if err := mon.Attach(); err != nil {
		lg.LogError("Failed to attach tracepoints: %v", err)
		os.Exit(1)
	}


	if err := mon.AttachAuthUprobe(); err != nil {
		lg.LogError("Failed to attach auth uprobes: %v", err)
		os.Exit(1)
	}


	if err := mon.StartPerfReader(); err != nil {
		lg.LogError("Failed to start perf reader: %v", err)
		os.Exit(1)
	}


	if err := mon.StartAuthPerfReader(); err != nil {
		lg.LogError("Failed to start auth perf reader: %v", err)
		os.Exit(1)
	}
	defer mon.Close()


	lg.StartMonitoring()


	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)


	go mon.ProcessEvents()
	go mon.ProcessAuthEvents()


	<-sigChan
	lg.LogInfo("Shutting down...")


	mon.Close()

	lg.LogInfo("Exited")
}

