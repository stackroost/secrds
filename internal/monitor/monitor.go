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

type AcceptEvent struct {
	Pid        uint32
	Tgid       uint32
	Fd         int32
	TsNs       uint64
	Comm       [16]byte
	PeerIP     uint32   
	PeerPort   uint16 
	LocalIP    uint32   	
	LocalPort  uint16   
	HasSockInfo uint8 
	_          [3]byte 
}

type AuthEvent struct {
	Pid       uint32
	Tgid      uint32
	RetCode   int32   
	TsNs      uint64
	Comm      [16]byte
	IsFailure uint8  
	_         [3]byte  
}


type Monitor struct {
	logger        *logger.Logger
	collection    *ebpf.Collection
	authCollection *ebpf.Collection 
	links         []link.Link
	reader        *perf.Reader
	authReader    *perf.Reader      
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	shuttingDown  int32             
	failureCounts map[string]int    
	failureMutex  sync.RWMutex      
}

func NewMonitor(logger *logger.Logger) *Monitor {
	ctx, cancel := context.WithCancel(context.Background())
	return &Monitor{
		logger:        logger,
		links:         make([]link.Link, 0),
		ctx:           ctx,
		cancel:        cancel,
		failureCounts: make(map[string]int),
	}
}

func (m *Monitor) LoadBPF(bpfObjFile string) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memlock limit: %w", err)
	}

	absPath, err := filepath.Abs(bpfObjFile)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

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

func (m *Monitor) LoadAuthBPF(bpfObjFile string) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memlock limit: %w", err)
	}

	absPath, err := filepath.Abs(bpfObjFile)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(absPath)
	if err != nil {
		return fmt.Errorf("failed to load auth BPF collection spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("failed to create auth BPF collection: %w", err)
	}

	m.authCollection = coll

	return nil
}

func (m *Monitor) Attach() error {
	progKretprobe := m.collection.Programs["kretprobe_inet_csk_accept"]
	if progKretprobe != nil {
		kp, err := link.Kretprobe("inet_csk_accept", progKretprobe, nil)
		if err != nil {
			m.logger.LogError("Failed to attach kretprobe inet_csk_accept: %v", err)
			m.logger.LogInfo("Falling back to /proc/net/tcp parsing (may have race conditions)")
		} else {
			m.links = append(m.links, kp)
			m.logger.LogInfo("Successfully attached kretprobe: inet_csk_accept (capturing IP/port directly from kernel)")
		}
	}

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
		return fmt.Errorf("failed to attach any programs")
	}

	return nil
}

func (m *Monitor) AttachAuthUprobe() error {
	if m.authCollection == nil {
		return fmt.Errorf("auth BPF collection not loaded")
	}
	
	pamLibPath := "/lib/x86_64-linux-gnu/libpam.so.0"
	if _, err := os.Stat(pamLibPath); err != nil {
		altPaths := []string{
			"/usr/lib/x86_64-linux-gnu/libpam.so.0",
			"/lib/libpam.so.0",
			"/usr/lib/libpam.so.0",
		}
		found := false
		for _, path := range altPaths {
			if _, err := os.Stat(path); err == nil {
				pamLibPath = path
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("libpam.so.0 not found in standard locations")
		}
	}

	up, err := link.OpenExecutable(pamLibPath)
	if err != nil {
		return fmt.Errorf("failed to open executable %s: %w", pamLibPath, err)
	}
	
	progUprobe := m.authCollection.Programs["uprobe_pam_authenticate"]
	if progUprobe != nil {
		uprobeLink, err := up.Uprobe("pam_authenticate", progUprobe, nil)
		if err != nil {
			m.logger.LogInfo("Symbol-based attachment failed, trying offset-based: %v", err)
			uprobeLink, err = up.Uprobe("", progUprobe, &link.UprobeOptions{
				Offset: 0x9940, 
			})
			if err != nil {
				return fmt.Errorf("failed to attach uprobe to pam_authenticate (both symbol and offset failed): %w", err)
			}
			m.logger.LogInfo("Successfully attached uprobe using offset 0x9940")
		} else {
			m.logger.LogInfo("Successfully attached uprobe to pam_authenticate using symbol")
		}
		m.links = append(m.links, uprobeLink)
	} else {
		m.logger.LogError("uprobe_pam_authenticate program not found in BPF collection")
	}

	progUretprobe := m.authCollection.Programs["uretprobe_pam_authenticate"]
	if progUretprobe != nil {
		uretprobeLink, err := up.Uretprobe("pam_authenticate", progUretprobe, nil)
		if err != nil {
			m.logger.LogInfo("Symbol-based uretprobe attachment failed, trying offset-based: %v", err)
			uretprobeLink, err = up.Uretprobe("", progUretprobe, &link.UprobeOptions{
				Offset: 0x9940, 
			})
			if err != nil {
				return fmt.Errorf("failed to attach uretprobe to pam_authenticate (both symbol and offset failed): %w", err)
			}
			m.logger.LogInfo("Successfully attached uretprobe using offset 0x9940")
		} else {
			m.logger.LogInfo("Successfully attached uretprobe to pam_authenticate using symbol")
		}
		m.links = append(m.links, uretprobeLink)
	} else {
		m.logger.LogError("uretprobe_pam_authenticate program not found in BPF collection")
	}

	return nil
}

func (m *Monitor) StartPerfReader() error {
	eventsMap := m.collection.Maps["events"]
	if eventsMap == nil {
		return fmt.Errorf("failed to find events map")
	}

	rd, err := perf.NewReader(eventsMap, 8*os.Getpagesize())
	if err != nil {
		return fmt.Errorf("failed to create perf reader: %w", err)
	}

	m.reader = rd
	return nil
}

func (m *Monitor) StartAuthPerfReader() error {
	if m.authCollection == nil {
		return fmt.Errorf("auth BPF collection not loaded")
	}

	eventsMap := m.authCollection.Maps["auth_events"]
	if eventsMap == nil {
		return fmt.Errorf("failed to find auth_events map")
	}

	rd, err := perf.NewReader(eventsMap, 8*os.Getpagesize())
	if err != nil {
		return fmt.Errorf("failed to create auth perf reader: %w", err)
	}

	m.authReader = rd
	return nil
}

func (m *Monitor) ProcessEvents() {
	m.wg.Add(1)
	defer m.wg.Done()

	for {
		if atomic.LoadInt32(&m.shuttingDown) != 0 {
			return
		}

		select {
		case <-m.ctx.Done():
			return
		default:
		}

		record, err := m.reader.Read()
		if err != nil {
			if atomic.LoadInt32(&m.shuttingDown) != 0 {
				return
			}

			if m.ctx.Err() != nil {
				return
			}

			if err == perf.ErrClosed {
				return
			}

			errStr := err.Error()
			if strings.Contains(errStr, "file already closed") ||
				strings.Contains(errStr, "perf ringbuffer") ||
				strings.Contains(errStr, "epoll wait") {
				return
			}

			if atomic.LoadInt32(&m.shuttingDown) == 0 {
				m.logger.LogError("Error reading perf event: %v", err)
			}
			continue
		}

		if atomic.LoadInt32(&m.shuttingDown) != 0 {
			return
		}

		select {
		case <-m.ctx.Done():
			return
		default:
		}

		if record.LostSamples > 0 {
			m.logger.LogError("Lost %d samples", record.LostSamples)
			continue
		}

		if len(record.RawSample) < int(unsafe.Sizeof(AcceptEvent{})) {
			continue
		}

		var ev AcceptEvent
		reader := bytes.NewReader(record.RawSample)
		if err := binary.Read(reader, binary.LittleEndian, &ev); err != nil {
			ev = *(*AcceptEvent)(unsafe.Pointer(&record.RawSample[0]))
		}
		
		comm := strings.TrimRight(string(ev.Comm[:]), "\x00")
		if comm != "" {
			m.logger.LogInfo("Received event: comm=%s, tgid=%d, fd=%d, has_sock_info=%d, raw_len=%d", 
				comm, ev.Tgid, ev.Fd, ev.HasSockInfo, len(record.RawSample))
		}

		if ev.HasSockInfo == 1 {
			peerIPOffset := 36
			peerPortOffset := 40
			localIPOffset := 42
			localPortOffset := 46
			if len(record.RawSample) >= 49 { 
				ev.PeerIP = binary.BigEndian.Uint32(record.RawSample[peerIPOffset : peerIPOffset+4])
				ev.PeerPort = binary.BigEndian.Uint16(record.RawSample[peerPortOffset : peerPortOffset+2])
				ev.LocalIP = binary.BigEndian.Uint32(record.RawSample[localIPOffset : localIPOffset+4])
				ev.LocalPort = binary.BigEndian.Uint16(record.RawSample[localPortOffset : localPortOffset+2])
			} else {
				ev.HasSockInfo = 0
			}
		}

		m.handleEvent(&ev)
	}
}

func (m *Monitor) ProcessAuthEvents() {
	m.wg.Add(1)
	defer m.wg.Done()

	if m.authReader == nil {
		return
	}

	for {
		if atomic.LoadInt32(&m.shuttingDown) != 0 {
			return
		}

		select {
		case <-m.ctx.Done():
			return
		default:
		}

		record, err := m.authReader.Read()
		if err != nil {
			if atomic.LoadInt32(&m.shuttingDown) != 0 {
				return
			}

			if m.ctx.Err() != nil {
				return
			}

			if err == perf.ErrClosed {
				return
			}

			errStr := err.Error()
			if strings.Contains(errStr, "file already closed") ||
				strings.Contains(errStr, "perf ringbuffer") ||
				strings.Contains(errStr, "epoll wait") {
				return
			}

			if atomic.LoadInt32(&m.shuttingDown) == 0 {
				m.logger.LogError("Error reading auth perf event: %v", err)
			}
			continue
		}

		if atomic.LoadInt32(&m.shuttingDown) != 0 {
			return
		}

		select {
		case <-m.ctx.Done():
			return
		default:
		}

		if record.LostSamples > 0 {
			m.logger.LogError("Lost %d auth samples", record.LostSamples)
			continue
		}

		if len(record.RawSample) < int(unsafe.Sizeof(AuthEvent{})) {
			continue
		}

		var ev AuthEvent
		reader := bytes.NewReader(record.RawSample)
		if err := binary.Read(reader, binary.LittleEndian, &ev); err != nil {
			ev = *(*AuthEvent)(unsafe.Pointer(&record.RawSample[0]))
		}

		comm := strings.TrimRight(string(ev.Comm[:]), "\x00")
		m.logger.LogInfo("Received auth event: comm=%s, tgid=%d, ret_code=%d, is_failure=%d, raw_len=%d",
			comm, ev.Tgid, ev.RetCode, ev.IsFailure, len(record.RawSample))

		m.handleAuthEvent(&ev)
	}
}

func (m *Monitor) extractIPFromProcess(pid uint32) (string, error) {
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	files, err := os.ReadDir(fdDir)
	if err != nil {
		return "", fmt.Errorf("failed to read fd directory: %w", err)
	}

	for _, file := range files {
		fdPath := fmt.Sprintf("%s/%s", fdDir, file.Name())
		linkTarget, err := os.Readlink(fdPath)
		if err != nil {
			continue
		}

		if !strings.HasPrefix(linkTarget, "socket:[") {
			continue
		}

		inode, err := parseInodeFromLink(linkTarget)
		if err != nil {
			continue
		}

		ip, _, _, err := inodeToIPPort(inode)
		if err == nil && ip != "" && ip != "0.0.0.0" {
			return ip, nil
		}
	}

	return "", fmt.Errorf("no socket found for PID %d", pid)
}

func (m *Monitor) handleAuthEvent(ev *AuthEvent) {
	comm := strings.TrimRight(string(ev.Comm[:]), "\x00")

	m.logger.LogInfo("Processing auth event: comm='%s', tgid=%d, ret_code=%d, is_failure=%d",
		comm, ev.Tgid, ev.RetCode, ev.IsFailure)

	if !strings.Contains(comm, "sshd") {
		m.logger.LogInfo("Skipping non-sshd event: comm='%s'", comm)
		return
	}
	
	if comm != "sshd" {
		idx := strings.Index(comm, "sshd")
		if idx >= 0 {
			comm = comm[idx:]
		}
	}

	isFailure := ev.RetCode != 0
	
	var ip string
	var err error
	for retry := 0; retry < 5; retry++ {
		if retry > 0 {
			time.Sleep(time.Duration(retry*10) * time.Millisecond) 
		}
		ip, err = m.extractIPFromProcess(ev.Tgid)
		if err == nil && ip != "" {
			break
		}
	}
	
	if err != nil || ip == "" {
		procPath := fmt.Sprintf("/proc/%d", ev.Tgid)
		if _, err2 := os.Stat(procPath); err2 == nil {
			time.Sleep(50 * time.Millisecond)
			ip, err = m.extractIPFromProcess(ev.Tgid)
		}
		
		if err != nil || ip == "" {
			ip = "unknown"
			m.logger.LogInfo("Could not extract IP for PID %d after retries, using fallback: %v", ev.Tgid, err)
		}
	}

	if isFailure {
		m.failureMutex.Lock()
		m.failureCounts[ip]++
		failureCount := m.failureCounts[ip]
		m.failureMutex.Unlock()

		m.logger.LogSSHDetected(ip, 0, ev.Tgid, comm)
		m.logger.LogInfo("Authentication failure from %s (PAM return code: %d, is_failure flag: %d, total failures: %d)", 
			ip, ev.RetCode, ev.IsFailure, failureCount)
	} else {
		m.failureMutex.Lock()
		delete(m.failureCounts, ip)
		m.failureMutex.Unlock()
		m.logger.LogInfo("Successful authentication from %s (PID: %d)", ip, ev.Tgid)
	}
}

func (m *Monitor) handleEvent(ev *AcceptEvent) {
	comm := strings.TrimRight(string(ev.Comm[:]), "\x00")

	var ip string
	var remPort, localPort int

	if ev.HasSockInfo == 1 {
		ipBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(ipBytes, ev.PeerIP)
		ip = fmt.Sprintf("%d.%d.%d.%d", ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3])

		remPort = int(ev.PeerPort)
		localPort = int(ev.LocalPort)
		
		m.logger.LogInfo("BPF captured: comm=%s, peer=%s:%d, local_port=%d, has_sock_info=%d", 
			comm, ip, remPort, localPort, ev.HasSockInfo)
	} else {
		linkPath := fmt.Sprintf("/proc/%d/fd/%d", ev.Tgid, ev.Fd)
		linkTarget, err := os.Readlink(linkPath)
		if err != nil {
			return
		}

		inode, err := parseInodeFromLink(linkTarget)
		if err != nil {
			return
		}

		time.Sleep(10 * time.Millisecond)

		var err2 error
		ip, remPort, localPort, err2 = inodeToIPPort(inode)
		if err2 != nil {
			return
		}
	}

	isSSH := localPort == 22 || remPort == 22 || comm == "sshd"

	if isSSH {
		m.logger.LogSSHDetected(ip, remPort, ev.Tgid, comm)
	} else {
		m.logger.LogEvent(ip, remPort, ev.Tgid, comm)
	}
}

func (m *Monitor) Stop() {
	atomic.StoreInt32(&m.shuttingDown, 1)
	
	m.cancel()
	
	if m.reader != nil {
		m.reader.Close()
	}
	if m.authReader != nil {
		m.authReader.Close()
	}
	
	m.wg.Wait()
}

func (m *Monitor) Close() error {
	m.Stop()

	for _, l := range m.links {
		l.Close()
	}
	if m.collection != nil {
		m.collection.Close()
	}
	if m.authCollection != nil {
		m.authCollection.Close()
	}
	return nil
}

func parseInodeFromLink(linkTarget string) (uint64, error) {
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

func inodeToIPPort(inode uint64) (string, int, int, error) {
	for retry := 0; retry < 10; retry++ {
		if retry > 0 {
			delay := time.Duration(5*(1<<uint(retry-1))) * time.Millisecond
			if delay > 200*time.Millisecond {
				delay = 200 * time.Millisecond
			}
			time.Sleep(delay)
		}

		ip, remPort, localPort, err := parseTCPFile("/proc/net/tcp", inode)
		if err == nil {
			return ip, remPort, localPort, nil
		}

		ip, remPort, localPort, err = parseTCPFile("/proc/net/tcp6", inode)
		if err == nil {
			return ip, remPort, localPort, nil
		}
	}

	return "", 0, 0, fmt.Errorf("not found")
}

func parseTCPFile(filename string, inode uint64) (string, int, int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", 0, 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	if !scanner.Scan() {
		return "", 0, 0, fmt.Errorf("empty file")
	}
	header := scanner.Text()
	cols := strings.Fields(header)
	var idxLocal, idxRem, idxSt, idxInode int = -1, -1, -1, -1
	for i, c := range cols {
		switch c {
		case "local_address":
			idxLocal = i
		case "rem_address":
			idxRem = i
		case "st":
			idxSt = i
		case "inode":
			idxInode = i
		}
	}
	if idxLocal == -1 { idxLocal = 1 }
	if idxRem == -1 { idxRem = 2 }
	if idxSt == -1 { idxSt = 3 }
	if idxInode == -1 { idxInode = len(cols)-1 } 

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)

		if len(fields) <= idxInode || len(fields) <= idxRem || len(fields) <= idxLocal {
			continue
		}

		entryInodeStr := fields[idxInode]
		entryInode, err := strconv.ParseUint(entryInodeStr, 10, 64)
		if err != nil {
			continue
		}
		if entryInode != inode || entryInode == 0 {
			continue
		}

		localParts := strings.Split(fields[idxLocal], ":")
		remParts := strings.Split(fields[idxRem], ":")
		if len(localParts) != 2 || len(remParts) != 2 {
			continue
		}
		localPortHex := localParts[1]
		remPortHex := remParts[1]

		localPort64, err := strconv.ParseUint(localPortHex, 16, 32)
		if err != nil {
			continue
		}
		remPort64, err := strconv.ParseUint(remPortHex, 16, 32)
		if err != nil {
			continue
		}

		if remParts[0] == "00000000" && remPortHex == "0000" {
			continue
		}

		remIPHex := remParts[0]
		remIP, err := hexIPv4ToDot(remIPHex)
		if err != nil {
			return "", 0, 0, fmt.Errorf("invalid rem ip hex")
		}

		if remIP == "0.0.0.0" {
			continue
		}

		state := fields[idxSt]
		if state == "0A" {
			continue
		}

		return remIP, int(remPort64), int(localPort64), nil
	}

	return "", 0, 0, fmt.Errorf("inode not found")
}

func hexIPv4ToDot(hexStr string) (string, error) {
	if len(hexStr) != 8 {
		return "", fmt.Errorf("unexpected ipv4 hex length")
	}
	b, err := hex.DecodeString(hexStr)
	if err != nil || len(b) != 4 {
		return "", fmt.Errorf("decode failed")
	}
	ip := fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0])
	return ip, nil
}