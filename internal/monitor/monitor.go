package monitor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"

	"secrds/internal/logger"
)

// AcceptEvent matches the struct in bpf/ssh_accept.bpf.c
type AcceptEvent struct {
	Pid   uint32
	Tgid  uint32
	Fd    int32
	TsNs  uint64
	Comm  [16]byte
}

// Monitor handles SSH connection monitoring
type Monitor struct {
	logger     *logger.Logger
	collection *ebpf.Collection
	links      []link.Link
	reader     *perf.Reader
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	shuttingDown int32 // atomic flag for shutdown state
}

// NewMonitor creates a new monitor instance
func NewMonitor(logger *logger.Logger) *Monitor {
	ctx, cancel := context.WithCancel(context.Background())
	return &Monitor{
		logger: logger,
		links:  make([]link.Link, 0),
		ctx:    ctx,
		cancel: cancel,
	}
}

// LoadBPF loads the BPF object file
func (m *Monitor) LoadBPF(bpfObjFile string) error {
	// Remove memory limits for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memlock limit: %w", err)
	}

	// Get absolute path
	absPath, err := filepath.Abs(bpfObjFile)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	// Load the BPF object
	spec, err := ebpf.LoadCollectionSpec(absPath)
	if err != nil {
		return fmt.Errorf("failed to load BPF collection spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("failed to create BPF collection: %w", err)
	}

	m.collection = coll

	return nil
}

// Attach attaches tracepoint programs
func (m *Monitor) Attach() error {
	// Attach accept4 tracepoint
	progAccept4 := m.collection.Programs["trace_exit_accept4"]
	if progAccept4 != nil {
		tpAccept4, err := link.Tracepoint("syscalls", "sys_exit_accept4", progAccept4, nil)
		if err != nil {
			m.logger.LogError("Failed to attach tracepoint accept4: %v", err)
		} else {
			m.links = append(m.links, tpAccept4)
			m.logger.LogInfo("Successfully attached to tracepoint: sys_exit_accept4")
		}
	}

	// Attach accept tracepoint
	progAccept := m.collection.Programs["trace_exit_accept"]
	if progAccept != nil {
		tpAccept, err := link.Tracepoint("syscalls", "sys_exit_accept", progAccept, nil)
		if err != nil {
			m.logger.LogError("Failed to attach tracepoint accept: %v", err)
		} else {
			m.links = append(m.links, tpAccept)
			m.logger.LogInfo("Successfully attached to tracepoint: sys_exit_accept")
		}
	}

	if len(m.links) == 0 {
		return fmt.Errorf("failed to attach any tracepoint programs")
	}

	return nil
}

// StartPerfReader starts the perf event reader
func (m *Monitor) StartPerfReader() error {
	// Get the events map
	eventsMap := m.collection.Maps["events"]
	if eventsMap == nil {
		return fmt.Errorf("failed to find events map")
	}

	// Create perf reader
	rd, err := perf.NewReader(eventsMap, 8*os.Getpagesize())
	if err != nil {
		return fmt.Errorf("failed to create perf reader: %w", err)
	}

	m.reader = rd
	return nil
}

// ProcessEvents processes events from the perf reader
func (m *Monitor) ProcessEvents() {
	m.wg.Add(1)
	defer m.wg.Done()

	for {
		// Check if we're shutting down before blocking read
		if atomic.LoadInt32(&m.shuttingDown) != 0 {
			return
		}

		// Check if context is cancelled before blocking read
		select {
		case <-m.ctx.Done():
			return
		default:
		}

		record, err := m.reader.Read()
		if err != nil {
			// If we're shutting down, exit immediately without logging
			if atomic.LoadInt32(&m.shuttingDown) != 0 {
				return
			}

			// Check if context was cancelled (clean shutdown)
			if m.ctx.Err() != nil {
				return
			}

			// Check for closed reader errors (shutdown)
			if err == perf.ErrClosed {
				return
			}

			// Check if error message indicates file/ringbuffer is closed
			errStr := err.Error()
			if strings.Contains(errStr, "file already closed") ||
				strings.Contains(errStr, "perf ringbuffer") ||
				strings.Contains(errStr, "epoll wait") {
				// Reader was closed, exit immediately
				return
			}

			// Only log unexpected errors if not shutting down
			if atomic.LoadInt32(&m.shuttingDown) == 0 {
				m.logger.LogError("Error reading perf event: %v", err)
			}
			continue
		}

		// Check shutdown flag after successful read
		if atomic.LoadInt32(&m.shuttingDown) != 0 {
			return
		}

		// Check context again after successful read (in case shutdown happened during read)
		select {
		case <-m.ctx.Done():
			return
		default:
		}

		if record.LostSamples > 0 {
			m.logger.LogError("Lost %d samples", record.LostSamples)
			continue
		}

		// Parse the event
		if len(record.RawSample) < int(unsafe.Sizeof(AcceptEvent{})) {
			continue
		}

		var ev AcceptEvent
		reader := bytes.NewReader(record.RawSample)
		if err := binary.Read(reader, binary.LittleEndian, &ev); err != nil {
			// Try direct memory copy as fallback
			ev = *(*AcceptEvent)(unsafe.Pointer(&record.RawSample[0]))
		}

		m.handleEvent(&ev)
	}
}

// handleEvent processes a single accept event
func (m *Monitor) handleEvent(ev *AcceptEvent) {
	// Get comm string (null-terminated)
	comm := strings.TrimRight(string(ev.Comm[:]), "\x00")

	// Attempt to resolve socket inode
	inode, err := fdToInode(int(ev.Tgid), int(ev.Fd))
	if err != nil {
		m.logger.LogInfo("Could not resolve /proc/%d/fd/%d (maybe short-lived or permission)",
			ev.Tgid, ev.Fd)
		return
	}

	// Small delay to let socket appear in /proc/net/tcp and establish connection
	time.Sleep(10 * time.Millisecond)

	// Try to get IP and port
	ip, remPort, localPort, err := inodeToIPPort(inode)
	if err != nil {
		// Check if it's a Unix socket
		linkPath := fmt.Sprintf("/proc/%d/fd/%d", ev.Tgid, ev.Fd)
		linkTarget, err := os.Readlink(linkPath)
		if err == nil {
			if strings.HasPrefix(linkTarget, "socket:") {
				m.logger.LogInfo("inode=%d (socket may be Unix domain or already closed)", inode)
			} else {
				m.logger.LogInfo("inode=%d found but /proc/net/tcp lookup failed (fd: %s)", inode, linkTarget)
			}
		} else {
			m.logger.LogInfo("inode=%d found but /proc/net/tcp lookup failed", inode)
		}
		return
	}

	// Check if it's SSH - check both local port (22 = listening) and remote port, or sshd process
	isSSH := localPort == 22 || remPort == 22 || comm == "sshd"
	
	if isSSH {
		m.logger.LogSSHDetected(ip, remPort, ev.Tgid, comm)
	} else {
		m.logger.LogEvent(ip, remPort, ev.Tgid, comm)
	}
}

// Stop stops the monitor gracefully
func (m *Monitor) Stop() {
	// Set shutdown flag first
	atomic.StoreInt32(&m.shuttingDown, 1)
	
	// Cancel context to signal goroutine to stop
	m.cancel()
	
	// Close reader to unblock any Read() calls
	if m.reader != nil {
		m.reader.Close()
	}
	
	// Wait for ProcessEvents goroutine to finish
	m.wg.Wait()
}

// Close closes all resources
func (m *Monitor) Close() error {
	// Stop the monitor first (graceful shutdown)
	m.Stop()

	// Close links
	for _, l := range m.links {
		l.Close()
	}
	// Close collection
	if m.collection != nil {
		m.collection.Close()
	}
	return nil
}

// fdToInode resolves pid + fd -> socket inode
func fdToInode(pid, fd int) (uint64, error) {
	linkPath := fmt.Sprintf("/proc/%d/fd/%d", pid, fd)
	linkTarget, err := os.Readlink(linkPath)
	if err != nil {
		return 0, err
	}

	// linkTarget will be "socket:[12345]" for sockets
	start := strings.Index(linkTarget, "[")
	end := strings.Index(linkTarget, "]")
	if start == -1 || end == -1 || start >= end {
		return 0, fmt.Errorf("invalid socket link format")
	}

	inodeStr := linkTarget[start+1 : end]
	inode, err := strconv.ParseUint(inodeStr, 10, 64)
	if err != nil || inode == 0 {
		return 0, fmt.Errorf("invalid inode")
	}

	return inode, nil
}

// inodeToIPPort finds IP and port from inode in /proc/net/tcp
// Returns: remoteIP, remotePort, localPort, error
func inodeToIPPort(inode uint64) (string, int, int, error) {
	// Try multiple times with increasing delay (socket needs time to establish)
	for retry := 0; retry < 10; retry++ {
		if retry > 0 {
			// Exponential backoff: 5ms, 10ms, 20ms, 40ms, 80ms, 160ms, etc.
			delay := time.Duration(5*(1<<uint(retry-1))) * time.Millisecond
			if delay > 200*time.Millisecond {
				delay = 200 * time.Millisecond
			}
			time.Sleep(delay)
		}

		// Try IPv4 first
		ip, remPort, localPort, err := parseTCPFile("/proc/net/tcp", inode)
		if err == nil {
			return ip, remPort, localPort, nil
		}

		// Try IPv6 if IPv4 fails
		ip, remPort, localPort, err = parseTCPFile("/proc/net/tcp6", inode)
		if err == nil {
			return ip, remPort, localPort, nil
		}
	}

	return "", 0, 0, fmt.Errorf("not found")
}

// parseTCPFile parses /proc/net/tcp and finds entry matching socket inode
// Returns: remoteIP, remotePort, localPort, error
func parseTCPFile(filename string, inode uint64) (string, int, int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", 0, 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	// Skip header line
	if !scanner.Scan() {
		return "", 0, 0, fmt.Errorf("empty file")
	}

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 12 {
			continue
		}

		// Parse: sl local_address rem_address st ...
		if len(fields[1]) == 0 || fields[1][len(fields[1])-1] != ':' {
			continue
		}

		// Extract ports
		localParts := strings.Split(fields[1], ":")
		remParts := strings.Split(fields[2], ":")
		if len(localParts) != 2 || len(remParts) != 2 {
			continue
		}

		// Parse local port
		localPortHex := localParts[1]
		localPort, err := strconv.ParseUint(localPortHex, 16, 32)
		if err != nil {
			continue
		}

		remPortHex := remParts[1]
		remPort, err := strconv.ParseUint(remPortHex, 16, 32)
		if err != nil {
			continue
		}

		// Inode is second-to-last field (before ref count)
		entryInodeStr := fields[len(fields)-2]
		entryInode, err := strconv.ParseUint(entryInodeStr, 10, 64)
		if err != nil {
			continue
		}

		if entryInode == inode && entryInode != 0 {
			// Parse remote IP (hex format, big-endian byte order)
			remIPHex := remParts[0]
			
			// Skip if remote address is 0.0.0.0:0000 (listening socket)
			if remIPHex == "00000000" && remPort == 0 {
				continue
			}

			remIPBytes, err := hex.DecodeString(remIPHex)
			if err != nil || len(remIPBytes) != 4 {
				continue
			}

			// Convert from hex to dotted decimal
			ip := fmt.Sprintf("%d.%d.%d.%d",
				remIPBytes[3], remIPBytes[2], remIPBytes[1], remIPBytes[0])

			// Skip if IP is 0.0.0.0 (listening socket)
			if ip == "0.0.0.0" {
				continue
			}

			// Accept all states except LISTEN (0A)
			// This includes ESTABLISHED (01), SYN_RECV (03), TIME_WAIT (06), etc.
			state := "01" // default
			if len(fields) > 3 {
				state = fields[3]
			}
			
			// Skip LISTEN state (0A) - these are listening sockets, not accepted connections
			if state == "0A" {
				continue
			}

			return ip, int(remPort), int(localPort), nil
		}
	}

	return "", 0, 0, fmt.Errorf("inode not found")
}

