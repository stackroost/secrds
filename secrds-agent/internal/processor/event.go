package processor

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"

	"github.com/cilium/ebpf/perf"
	"github.com/secrds/secrds-agent/internal/detector"
)

type EventProcessor struct {
	detector *detector.ThreatDetector
	loader   LoaderInterface
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

type LoaderInterface interface {
	GetSSHEvents() *perf.Reader
	GetTCPEvents() *perf.Reader
	Close() error
}

func New(det *detector.ThreatDetector, ld LoaderInterface) *EventProcessor {
	ctx, cancel := context.WithCancel(context.Background())
	return &EventProcessor{
		detector: det,
		loader:   ld,
		ctx:      ctx,
		cancel:   cancel,
	}
}

func (ep *EventProcessor) Start() error {
	sshReader := ep.loader.GetSSHEvents()
	if sshReader == nil {
		return fmt.Errorf("SSH events reader not available")
	}

	// Process SSH events
	ep.wg.Add(1)
	go func() {
		defer ep.wg.Done()
		ep.processSSHEvents(sshReader)
	}()

	// Process TCP events if available
	if tcpReader := ep.loader.GetTCPEvents(); tcpReader != nil {
		ep.wg.Add(1)
		go func() {
			defer ep.wg.Done()
			ep.processTCPEvents(tcpReader)
		}()
	}

	return nil
}

func (ep *EventProcessor) processSSHEvents(reader *perf.Reader) {
	for {
		select {
		case <-ep.ctx.Done():
			return
		default:
		}

		record, err := reader.Read()
		if err != nil {
			// Check if reader is closed - check for various error messages
			errStr := err.Error()
			if errStr == "EOF" || 
				errStr == "perf reader closed" || 
				strings.Contains(errStr, "file already closed") ||
				strings.Contains(errStr, "perf ringbuffer") {
				return
			}
			// Only log non-closure errors
			if !strings.Contains(errStr, "closed") {
				fmt.Printf("Error reading SSH event: %v\n", err)
			}
			continue
		}

		// SSHEvent struct: IP (4) + Port (2) + padding (2) + PID (4) + EventType (1) + padding (3) + Timestamp (8) = 24 bytes
		if len(record.RawSample) < 24 {
			fmt.Printf("Invalid SSH event size: %d bytes (expected 24)\n", len(record.RawSample))
			continue
		}

		event := SSHEvent{
			IP:        binary.LittleEndian.Uint32(record.RawSample[0:4]),
			Port:      binary.LittleEndian.Uint16(record.RawSample[4:6]),
			PID:       binary.LittleEndian.Uint32(record.RawSample[8:12]),
			EventType: record.RawSample[12],
			Timestamp: binary.LittleEndian.Uint64(record.RawSample[16:24]),
		}

		// Debug: Log received events (can be disabled in production)
		ipStr := fmt.Sprintf("%d.%d.%d.%d", 
			byte(event.IP>>24), byte(event.IP>>16), byte(event.IP>>8), byte(event.IP))
		fmt.Printf("[DEBUG] SSH event received: IP=%s, Port=%d, PID=%d, Type=%d\n", 
			ipStr, event.Port, event.PID, event.EventType)

		if err := ep.detector.ProcessSSHEvent(event.IP, event.Port, event.PID, event.EventType); err != nil {
			fmt.Printf("Failed to process SSH event: %v\n", err)
		}
	}
}

func (ep *EventProcessor) processTCPEvents(reader *perf.Reader) {
	for {
		select {
		case <-ep.ctx.Done():
			return
		default:
		}

		record, err := reader.Read()
		if err != nil {
			// Check if reader is closed - check for various error messages
			errStr := err.Error()
			if errStr == "EOF" || 
				errStr == "perf reader closed" || 
				strings.Contains(errStr, "file already closed") ||
				strings.Contains(errStr, "perf ringbuffer") {
				return
			}
			// Only log non-closure errors
			if !strings.Contains(errStr, "closed") {
				fmt.Printf("Error reading TCP event: %v\n", err)
			}
			continue
		}

		if len(record.RawSample) < 24 { // Size of TCPEvent struct
			continue
		}

		event := TCPEvent{
			SrcIP:     binary.LittleEndian.Uint32(record.RawSample[0:4]),
			DstIP:     binary.LittleEndian.Uint32(record.RawSample[4:8]),
			SrcPort:   binary.LittleEndian.Uint16(record.RawSample[8:10]),
			DstPort:   binary.LittleEndian.Uint16(record.RawSample[10:12]),
			EventType: record.RawSample[12],
			Timestamp: binary.LittleEndian.Uint64(record.RawSample[16:24]),
		}

		if err := ep.detector.ProcessTCPEvent(event.SrcIP, event.DstIP, event.SrcPort, event.DstPort, event.EventType); err != nil {
			fmt.Printf("Failed to process TCP event: %v\n", err)
		}
	}
}

type SSHEvent struct {
	IP        uint32
	Port      uint16
	PID       uint32
	EventType uint8
	Timestamp uint64
}

type TCPEvent struct {
	SrcIP     uint32
	DstIP     uint32
	SrcPort   uint16
	DstPort   uint16
	EventType uint8
	Timestamp uint64
}

// Cancel cancels the context to signal goroutines to exit
func (ep *EventProcessor) Cancel() {
	if ep.cancel != nil {
		ep.cancel()
	}
}

// Stop waits for goroutines to finish (assumes Cancel() was called first)
func (ep *EventProcessor) Stop() {
	ep.wg.Wait()
}

