//go:build linux

// Package capture provides AF_XDP-based high-speed packet capture.
// AF_XDP provides zero-copy packet delivery for 10Gbps+ capture rates.
package capture

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cvalentine99/nfa-linux/internal/models"
)

// AF_XDP socket constants
const (
	AF_XDP                = 44
	SOL_XDP               = 283
	XDP_MMAP_OFFSETS      = 1
	XDP_RX_RING           = 2
	XDP_TX_RING           = 3
	XDP_UMEM_REG          = 4
	XDP_UMEM_FILL_RING    = 5
	XDP_UMEM_COMPLETION_RING = 6
	XDP_STATISTICS        = 7
	XDP_OPTIONS           = 8

	XDP_SHARED_UMEM       = 1 << 0
	XDP_COPY              = 1 << 1
	XDP_ZEROCOPY          = 1 << 2
	XDP_USE_NEED_WAKEUP   = 1 << 3

	XDP_PGOFF_RX_RING          = 0
	XDP_PGOFF_TX_RING          = 0x80000000
	XDP_UMEM_PGOFF_FILL_RING   = 0x100000000
	XDP_UMEM_PGOFF_COMPLETION_RING = 0x180000000
)

// XDP ring descriptor
type xdpDesc struct {
	addr    uint64
	len     uint32
	options uint32
}

// UMEM registration structure
type xdpUmemReg struct {
	addr       uint64
	len        uint64
	chunkSize  uint32
	headroom   uint32
	flags      uint32
	_          uint32 // padding
}

// Ring offsets structure
type xdpRingOffset struct {
	producer uint64
	consumer uint64
	desc     uint64
	flags    uint64
}

// Mmap offsets structure
type xdpMmapOffsets struct {
	rx   xdpRingOffset
	tx   xdpRingOffset
	fr   xdpRingOffset
	cr   xdpRingOffset
}

// XDP statistics from kernel
type xdpStatistics struct {
	rxDropped       uint64
	rxInvalidDescs  uint64
	txInvalidDescs  uint64
	rxRingFull      uint64
	rxFillRingEmpty uint64
	txRingEmpty     uint64
}

// AFXDPEngine implements high-speed packet capture using AF_XDP.
type AFXDPEngine struct {
	config  *Config
	handler PacketHandler
	stats   *afxdpStats
	mu      sync.RWMutex

	// XDP program and link
	xdpProg     *ebpf.Program
	xdpLink     link.Link
	xdpMap      *ebpf.Map
	filterProg  *ebpf.Program

	// Worker management
	workers   []*xdpWorker
	workerWg  sync.WaitGroup
	ctx       context.Context
	cancel    context.CancelFunc

	// Interface info
	ifIndex int
	ifLink  netlink.Link

	// BPF filter state
	currentFilter string
	filterFunc    func([]byte) bool
	filterMu      sync.RWMutex
	
	// Native mode status
	nativeMode bool
}

// afxdpStats holds atomic counters for capture statistics.
type afxdpStats struct {
	packetsReceived  uint64
	packetsDropped   uint64
	bytesReceived    uint64
	filterMatched    uint64
	filterDropped    uint64
	kernelRxDropped  uint64
	kernelRxRingFull uint64
	kernelFillEmpty  uint64
	startTime        time.Time
}

// xdpWorker represents a single XDP socket worker.
type xdpWorker struct {
	id       int
	queueID  int
	engine   *AFXDPEngine
	running  atomic.Bool

	// RACE-4 FIX: Ensure cleanup only runs once
	cleanupOnce sync.Once

	// Socket and UMEM
	fd       int
	umem     []byte
	umemAddr uintptr

	// Rings (mmap'd)
	rxRingMem   []byte
	fillRingMem []byte
	
	// Ring pointers
	rxProd     *uint32
	rxCons     *uint32
	rxDescs    []xdpDesc
	rxMask     uint32
	
	fillProd   *uint32
	fillCons   *uint32
	fillDescs  []uint64
	fillMask   uint32

	// Frame management
	frameSize   uint32
	numFrames   uint32
	freeFrames  []uint64
	framesMu    sync.Mutex

	// Batch processing
	rxBatch []xdpDesc
	
	// Filter function
	filterFunc func([]byte) bool
}

// XDPConfig holds XDP-specific configuration.
type XDPConfig struct {
	FrameSize    uint32
	NumFrames    uint32
	FillRingSize uint32
	CompRingSize uint32
	RxRingSize   uint32
	TxRingSize   uint32
	ZeroCopy     bool
	NeedWakeup   bool
}

// DefaultXDPConfig returns a sensible default XDP configuration.
func DefaultXDPConfig() *XDPConfig {
	return &XDPConfig{
		FrameSize:    4096,
		NumFrames:    8192,
		FillRingSize: 4096,
		CompRingSize: 4096,
		RxRingSize:   4096,
		TxRingSize:   0,
		ZeroCopy:     true,
		NeedWakeup:   true,
	}
}

// NewAFXDPEngine creates a new AF_XDP capture engine.
func NewAFXDPEngine(cfg *Config) (*AFXDPEngine, error) {
	if cfg == nil {
		return nil, errors.New("afxdp: config cannot be nil")
	}

	if cfg.Interface == "" {
		return nil, errors.New("afxdp: interface is required")
	}

	// Get interface info
	iface, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		return nil, fmt.Errorf("afxdp: interface %s not found: %w", cfg.Interface, err)
	}

	// Get netlink handle for the interface
	nlLink, err := netlink.LinkByName(cfg.Interface)
	if err != nil {
		return nil, fmt.Errorf("afxdp: failed to get netlink handle: %w", err)
	}

	numWorkers := cfg.NumWorkers
	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU()
	}

	engine := &AFXDPEngine{
		config:  cfg,
		ifIndex: iface.Index,
		ifLink:  nlLink,
		stats: &afxdpStats{
			startTime: time.Now(),
		},
		workers:       make([]*xdpWorker, numWorkers),
		currentFilter: cfg.BPFFilter,
	}
	
	// Compile initial filter if provided
	if cfg.BPFFilter != "" {
		filterFunc, err := compileBPFFilter(cfg.BPFFilter)
		if err != nil {
			return nil, fmt.Errorf("afxdp: invalid BPF filter: %w", err)
		}
		engine.filterFunc = filterFunc
	}

	return engine, nil
}

// Start begins AF_XDP packet capture.
func (e *AFXDPEngine) Start(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.ctx, e.cancel = context.WithCancel(ctx)
	e.stats.startTime = time.Now()

	// Load and attach XDP program
	if err := e.loadXDPProgram(); err != nil {
		return fmt.Errorf("afxdp: failed to load XDP program: %w", err)
	}

	// Start worker goroutines
	for i := range e.workers {
		queueID := i
		if e.config.QueueID >= 0 {
			queueID = e.config.QueueID
		}

		worker, err := e.createWorker(i, queueID)
		if err != nil {
			// Cleanup already started workers
			e.stopWorkers()
			return fmt.Errorf("afxdp: failed to create worker %d: %w", i, err)
		}

		e.workers[i] = worker
		
		// Register socket FD in xsks_map for XDP redirect
		if e.xdpMap != nil {
			if err := e.xdpMap.Put(uint32(queueID), uint32(worker.fd)); err != nil {
				e.stopWorkers()
				return fmt.Errorf("afxdp: failed to register socket in xsks_map: %w", err)
			}
		}
		
		e.workerWg.Add(1)
		go worker.run(e.ctx, &e.workerWg)
	}
	
	// Start stats collector goroutine
	go e.collectKernelStats(ctx)

	return nil
}

// collectKernelStats periodically reads kernel XDP statistics
// BUG-4 FIX: Stores previous stats per worker and only adds delta to prevent counter explosion
func (e *AFXDPEngine) collectKernelStats(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	
	// BUG-4 FIX: Track previous stats per worker to compute delta
	prevStats := make(map[int]xdpStatistics)
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.mu.RLock()
			for _, w := range e.workers {
				if w != nil && w.fd > 0 {
					currentStats := w.getKernelStats()
					prev := prevStats[w.id]
					
					// BUG-4 FIX: Only add the delta (new drops since last check)
					// Kernel counters are cumulative, so we subtract previous values
					if currentStats.rxDropped > prev.rxDropped {
						atomic.AddUint64(&e.stats.kernelRxDropped, currentStats.rxDropped-prev.rxDropped)
					}
					if currentStats.rxRingFull > prev.rxRingFull {
						atomic.AddUint64(&e.stats.kernelRxRingFull, currentStats.rxRingFull-prev.rxRingFull)
					}
					if currentStats.rxFillRingEmpty > prev.rxFillRingEmpty {
						atomic.AddUint64(&e.stats.kernelFillEmpty, currentStats.rxFillRingEmpty-prev.rxFillRingEmpty)
					}
					
					// Store current as previous for next iteration
					prevStats[w.id] = currentStats
				}
			}
			e.mu.RUnlock()
		}
	}
}

// getKernelStats reads XDP_STATISTICS from the socket
func (w *xdpWorker) getKernelStats() xdpStatistics {
	var stats xdpStatistics
	statsLen := uint32(unsafe.Sizeof(stats))
	
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT,
		uintptr(w.fd), SOL_XDP, XDP_STATISTICS,
		uintptr(unsafe.Pointer(&stats)),
		uintptr(unsafe.Pointer(&statsLen)), 0)
	if errno != 0 {
		return xdpStatistics{}
	}
	return stats
}

// createWorker creates and initializes an XDP worker with proper ring setup
func (e *AFXDPEngine) createWorker(id, queueID int) (*xdpWorker, error) {
	xdpCfg := DefaultXDPConfig()

	worker := &xdpWorker{
		id:         id,
		queueID:    queueID,
		engine:     e,
		frameSize:  xdpCfg.FrameSize,
		numFrames:  xdpCfg.NumFrames,
		rxBatch:    make([]xdpDesc, 64),
		filterFunc: e.filterFunc,
	}

	// Create AF_XDP socket
	fd, err := unix.Socket(AF_XDP, unix.SOCK_RAW, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to create AF_XDP socket: %w", err)
	}
	worker.fd = fd

	// Allocate UMEM
	umemSize := uint64(xdpCfg.NumFrames) * uint64(xdpCfg.FrameSize)
	umem, err := unix.Mmap(-1, 0, int(umemSize),
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_POPULATE)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("failed to allocate UMEM: %w", err)
	}
	worker.umem = umem
	worker.umemAddr = uintptr(unsafe.Pointer(&umem[0]))

	// Register UMEM with socket
	umemReg := xdpUmemReg{
		addr:      uint64(worker.umemAddr),
		len:       umemSize,
		chunkSize: xdpCfg.FrameSize,
		headroom:  0,
		flags:     0,
	}

	_, _, errno := unix.Syscall6(unix.SYS_SETSOCKOPT,
		uintptr(fd), SOL_XDP, XDP_UMEM_REG,
		uintptr(unsafe.Pointer(&umemReg)),
		unsafe.Sizeof(umemReg), 0)
	if errno != 0 {
		unix.Munmap(umem)
		unix.Close(fd)
		return nil, fmt.Errorf("failed to register UMEM: %w", errno)
	}

	// Set up fill ring
	fillRingSize := xdpCfg.FillRingSize
	_, _, errno = unix.Syscall6(unix.SYS_SETSOCKOPT,
		uintptr(fd), SOL_XDP, XDP_UMEM_FILL_RING,
		uintptr(unsafe.Pointer(&fillRingSize)),
		unsafe.Sizeof(fillRingSize), 0)
	if errno != 0 {
		unix.Munmap(umem)
		unix.Close(fd)
		return nil, fmt.Errorf("failed to set fill ring size: %w", errno)
	}

	// Set up RX ring
	rxRingSize := xdpCfg.RxRingSize
	_, _, errno = unix.Syscall6(unix.SYS_SETSOCKOPT,
		uintptr(fd), SOL_XDP, XDP_RX_RING,
		uintptr(unsafe.Pointer(&rxRingSize)),
		unsafe.Sizeof(rxRingSize), 0)
	if errno != 0 {
		unix.Munmap(umem)
		unix.Close(fd)
		return nil, fmt.Errorf("failed to set RX ring size: %w", errno)
	}

	// Get mmap offsets
	var offsets xdpMmapOffsets
	offsetsLen := uint32(unsafe.Sizeof(offsets))
	_, _, errno = unix.Syscall6(unix.SYS_GETSOCKOPT,
		uintptr(fd), SOL_XDP, XDP_MMAP_OFFSETS,
		uintptr(unsafe.Pointer(&offsets)),
		uintptr(unsafe.Pointer(&offsetsLen)), 0)
	if errno != 0 {
		unix.Munmap(umem)
		unix.Close(fd)
		return nil, fmt.Errorf("failed to get mmap offsets: %w", errno)
	}

	// Mmap the RX ring
	rxRingMemSize := offsets.rx.desc + uint64(rxRingSize)*uint64(unsafe.Sizeof(xdpDesc{}))
	rxRingMem, err := unix.Mmap(fd, XDP_PGOFF_RX_RING, int(rxRingMemSize),
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		unix.Munmap(umem)
		unix.Close(fd)
		return nil, fmt.Errorf("failed to mmap RX ring: %w", err)
	}
	worker.rxRingMem = rxRingMem
	
	// Set up RX ring pointers
	worker.rxProd = (*uint32)(unsafe.Pointer(&rxRingMem[offsets.rx.producer]))
	worker.rxCons = (*uint32)(unsafe.Pointer(&rxRingMem[offsets.rx.consumer]))
	worker.rxMask = rxRingSize - 1
	
	// Create slice over the descriptors
	rxDescPtr := unsafe.Pointer(&rxRingMem[offsets.rx.desc])
	worker.rxDescs = unsafe.Slice((*xdpDesc)(rxDescPtr), rxRingSize)

	// Mmap the fill ring
	fillRingMemSize := offsets.fr.desc + uint64(fillRingSize)*8 // uint64 addresses
	fillRingMem, err := unix.Mmap(fd, int64(XDP_UMEM_PGOFF_FILL_RING), int(fillRingMemSize),
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		unix.Munmap(rxRingMem)
		unix.Munmap(umem)
		unix.Close(fd)
		return nil, fmt.Errorf("failed to mmap fill ring: %w", err)
	}
	worker.fillRingMem = fillRingMem
	
	// Set up fill ring pointers
	worker.fillProd = (*uint32)(unsafe.Pointer(&fillRingMem[offsets.fr.producer]))
	worker.fillCons = (*uint32)(unsafe.Pointer(&fillRingMem[offsets.fr.consumer]))
	worker.fillMask = fillRingSize - 1
	
	// Create slice over the fill ring addresses
	fillDescPtr := unsafe.Pointer(&fillRingMem[offsets.fr.desc])
	worker.fillDescs = unsafe.Slice((*uint64)(fillDescPtr), fillRingSize)

	// Initialize free frames list
	worker.freeFrames = make([]uint64, 0, xdpCfg.NumFrames)
	for i := uint32(0); i < xdpCfg.NumFrames; i++ {
		worker.freeFrames = append(worker.freeFrames, uint64(i)*uint64(xdpCfg.FrameSize))
	}

	// Bind socket to interface and queue - try native mode first
	sa := &unix.SockaddrXDP{
		Flags:   XDP_USE_NEED_WAKEUP,
		Ifindex: uint32(e.ifIndex),
		QueueID: uint32(queueID),
	}

	// Try zero-copy native mode first
	if xdpCfg.ZeroCopy {
		sa.Flags |= XDP_ZEROCOPY
	}

	bindErr := unix.Bind(fd, sa)
	if bindErr != nil {
		// Try copy mode
		sa.Flags = XDP_COPY | XDP_USE_NEED_WAKEUP
		bindErr = unix.Bind(fd, sa)
		if bindErr != nil {
			unix.Munmap(fillRingMem)
			unix.Munmap(rxRingMem)
			unix.Munmap(umem)
			unix.Close(fd)
			return nil, fmt.Errorf("failed to bind socket: %w", bindErr)
		}
	}
	
	// Initial fill ring population - give kernel all frames
	if err := worker.initialFillRing(); err != nil {
		unix.Munmap(fillRingMem)
		unix.Munmap(rxRingMem)
		unix.Munmap(umem)
		unix.Close(fd)
		return nil, fmt.Errorf("failed to populate fill ring: %w", err)
	}

	return worker, nil
}

// initialFillRing populates the fill ring with all available frames
func (w *xdpWorker) initialFillRing() error {
	w.framesMu.Lock()
	defer w.framesMu.Unlock()
	
	prod := atomic.LoadUint32(w.fillProd)
	
	// Add all free frames to fill ring
	for i, addr := range w.freeFrames {
		idx := (prod + uint32(i)) & w.fillMask
		w.fillDescs[idx] = addr
	}
	
	// Update producer
	atomic.StoreUint32(w.fillProd, prod+uint32(len(w.freeFrames)))
	
	// Clear free frames - they're now owned by kernel
	w.freeFrames = w.freeFrames[:0]
	
	return nil
}

// stopWorkers stops all workers
func (e *AFXDPEngine) stopWorkers() {
	for _, w := range e.workers {
		if w != nil {
			w.cleanup()
		}
	}
}

// cleanup releases worker resources
// RACE-4 FIX: Uses sync.Once to prevent double cleanup from defer + stopWorkers()
func (w *xdpWorker) cleanup() {
	w.cleanupOnce.Do(func() {
		if w.fillRingMem != nil {
			unix.Munmap(w.fillRingMem)
			w.fillRingMem = nil
		}
		if w.rxRingMem != nil {
			unix.Munmap(w.rxRingMem)
			w.rxRingMem = nil
		}
		if w.umem != nil {
			unix.Munmap(w.umem)
			w.umem = nil
		}
		if w.fd > 0 {
			unix.Close(w.fd)
			w.fd = 0
		}
	})
}

// Stop halts AF_XDP packet capture.
func (e *AFXDPEngine) Stop() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.cancel != nil {
		e.cancel()
	}

	// Wait for workers to finish
	e.workerWg.Wait()

	// Cleanup workers
	e.stopWorkers()

	// Detach XDP program
	if e.xdpLink != nil {
		e.xdpLink.Close()
		e.xdpLink = nil
	}

	if e.filterProg != nil {
		e.filterProg.Close()
		e.filterProg = nil
	}

	if e.xdpProg != nil {
		e.xdpProg.Close()
		e.xdpProg = nil
	}

	if e.xdpMap != nil {
		e.xdpMap.Close()
		e.xdpMap = nil
	}

	return nil
}

// Stats returns current capture statistics including kernel stats.
func (e *AFXDPEngine) Stats() *models.CaptureStats {
	received := atomic.LoadUint64(&e.stats.packetsReceived)
	dropped := atomic.LoadUint64(&e.stats.packetsDropped)
	bytes := atomic.LoadUint64(&e.stats.bytesReceived)
	kernelDropped := atomic.LoadUint64(&e.stats.kernelRxDropped)
	filterDropped := atomic.LoadUint64(&e.stats.filterDropped)

	// Total drops = userspace drops + kernel drops + filtered
	totalDropped := dropped + kernelDropped

	elapsed := time.Since(e.stats.startTime).Seconds()
	var pps, bps float64
	if elapsed > 0 {
		pps = float64(received) / elapsed
		bps = float64(bytes) / elapsed
	}

	return &models.CaptureStats{
		PacketsReceived:  received,
		PacketsDropped:   totalDropped,
		PacketsFiltered:  filterDropped,
		BytesReceived:    bytes,
		PacketsPerSecond: pps,
		BytesPerSecond:   bps,
		StartTime:        e.stats.startTime,
		LastUpdate:       time.Now(),
		Interface:        e.config.Interface,
		PromiscuousMode:  e.config.Promiscuous,
		CaptureFilter:    e.config.BPFFilter,
		NativeMode:       e.nativeMode,
	}
}

// SetHandler sets the packet handler callback.
func (e *AFXDPEngine) SetHandler(handler PacketHandler) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.handler = handler
}

// SetBPFFilter sets a BPF filter at runtime.
func (e *AFXDPEngine) SetBPFFilter(filter string) error {
	e.filterMu.Lock()
	defer e.filterMu.Unlock()

	// Store the filter
	e.currentFilter = filter
	e.config.BPFFilter = filter

	// If no filter, clear filter function
	if filter == "" {
		e.filterFunc = nil
		e.mu.Lock()
		for _, w := range e.workers {
			if w != nil {
				w.setFilter(nil)
			}
		}
		e.mu.Unlock()
		return nil
	}

	// Compile the BPF filter
	filterFunc, err := compileBPFFilter(filter)
	if err != nil {
		return fmt.Errorf("afxdp: failed to compile BPF filter: %w", err)
	}

	// Store and distribute to workers
	e.filterFunc = filterFunc
	e.mu.Lock()
	for _, w := range e.workers {
		if w != nil {
			w.setFilter(filterFunc)
		}
	}
	e.mu.Unlock()

	return nil
}

// compileBPFFilter compiles a BPF filter expression into a filter function
func compileBPFFilter(filter string) (func([]byte) bool, error) {
	switch {
	case filter == "":
		return nil, nil
	
	case filter == "tcp":
		return func(data []byte) bool {
			if len(data) < 24 {
				return false
			}
			etherType := binary.BigEndian.Uint16(data[12:14])
			if etherType != 0x0800 {
				return false
			}
			return data[23] == 6 // TCP protocol
		}, nil
	
	case filter == "udp":
		return func(data []byte) bool {
			if len(data) < 24 {
				return false
			}
			etherType := binary.BigEndian.Uint16(data[12:14])
			if etherType != 0x0800 {
				return false
			}
			return data[23] == 17 // UDP protocol
		}, nil
	
	case filter == "icmp":
		return func(data []byte) bool {
			if len(data) < 24 {
				return false
			}
			etherType := binary.BigEndian.Uint16(data[12:14])
			if etherType != 0x0800 {
				return false
			}
			return data[23] == 1 // ICMP protocol
		}, nil
	
	case strings.HasPrefix(filter, "port "):
		portStr := strings.TrimPrefix(filter, "port ")
		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid port filter '%s': %w", filter, err)
		}
		portBytes := uint16(port)
		return func(data []byte) bool {
			if len(data) < 36 {
				return false
			}
			etherType := binary.BigEndian.Uint16(data[12:14])
			if etherType != 0x0800 {
				return false
			}
			ihl := int(data[14]&0x0F) * 4
			if len(data) < 14+ihl+4 {
				return false
			}
			srcPort := binary.BigEndian.Uint16(data[14+ihl : 14+ihl+2])
			dstPort := binary.BigEndian.Uint16(data[14+ihl+2 : 14+ihl+4])
			return srcPort == portBytes || dstPort == portBytes
		}, nil

	case strings.HasPrefix(filter, "host "):
		hostStr := strings.TrimPrefix(filter, "host ")
		hostIP := net.ParseIP(hostStr)
		if hostIP == nil {
			return nil, fmt.Errorf("invalid host filter '%s': invalid IP address", filter)
		}
		hostIP4 := hostIP.To4()
		if hostIP4 == nil {
			return nil, fmt.Errorf("invalid host filter '%s': only IPv4 supported", filter)
		}
		return func(data []byte) bool {
			if len(data) < 34 {
				return false
			}
			etherType := binary.BigEndian.Uint16(data[12:14])
			if etherType != 0x0800 {
				return false
			}
			return bytes.Equal(data[26:30], hostIP4) || bytes.Equal(data[30:34], hostIP4)
		}, nil

	default:
		return nil, fmt.Errorf("unsupported BPF filter '%s': only 'tcp', 'udp', 'icmp', 'port N', 'host IP' are supported", filter)
	}
}

// setFilter sets the software filter function for a worker
func (w *xdpWorker) setFilter(filterFunc func([]byte) bool) {
	w.framesMu.Lock()
	defer w.framesMu.Unlock()
	w.filterFunc = filterFunc
}

// loadXDPProgram loads and attaches the XDP program.
func (e *AFXDPEngine) loadXDPProgram() error {
	// Create XSKMAP for socket redirect
	mapSpec := &ebpf.MapSpec{
		Name:       "xsks_map",
		Type:       ebpf.XSKMap,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: uint32(len(e.workers)),
	}

	xskMap, err := ebpf.NewMap(mapSpec)
	if err != nil {
		// XSKMAP not supported, fall back to simple XDP_PASS
		return e.loadFallbackProgram()
	}
	e.xdpMap = xskMap

	// Create XDP program with redirect to XSKMAP
	redirectSpec := &ebpf.ProgramSpec{
		Name:    "xdp_sock_prog",
		Type:    ebpf.XDP,
		License: "GPL",
		Instructions: asm.Instructions{
			// r2 = *(u32 *)(r1 + 4)  ; load rx_queue_index from xdp_md
			asm.LoadMem(asm.R2, asm.R1, 4, asm.Word),
			// r1 = map_fd
			asm.LoadMapPtr(asm.R1, xskMap.FD()),
			// r3 = XDP_PASS (fallback action)
			asm.LoadImm(asm.R3, 2, asm.DWord),
			// call bpf_redirect_map(map, index, flags)
			asm.FnRedirectMap.Call(),
			// exit with return value
			asm.Return(),
		},
	}

	prog, err := ebpf.NewProgram(redirectSpec)
	if err != nil {
		xskMap.Close()
		return e.loadFallbackProgram()
	}
	e.xdpProg = prog

	// Try native mode first, fall back to generic
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   e.xdpProg,
		Interface: e.ifIndex,
		Flags:     link.XDPDriverMode, // Try native/driver mode first
	})
	if err != nil {
		// Fall back to generic mode
		xdpLink, err = link.AttachXDP(link.XDPOptions{
			Program:   e.xdpProg,
			Interface: e.ifIndex,
			Flags:     link.XDPGenericMode,
		})
		if err != nil {
			e.xdpProg.Close()
			e.xdpMap.Close()
			return fmt.Errorf("failed to attach XDP program: %w", err)
		}
		e.nativeMode = false
	} else {
		e.nativeMode = true
	}
	e.xdpLink = xdpLink

	return nil
}

// loadFallbackProgram loads a simple XDP_PASS program when XSKMAP isn't available
func (e *AFXDPEngine) loadFallbackProgram() error {
	progSpec := &ebpf.ProgramSpec{
		Name:    "xdp_pass",
		Type:    ebpf.XDP,
		License: "GPL",
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 2, asm.DWord), // XDP_PASS
			asm.Return(),
		},
	}

	prog, err := ebpf.NewProgram(progSpec)
	if err != nil {
		return fmt.Errorf("failed to create fallback XDP program: %w", err)
	}
	e.xdpProg = prog

	// Try native mode first
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: e.ifIndex,
		Flags:     link.XDPDriverMode,
	})
	if err != nil {
		// Fall back to generic mode
		xdpLink, err = link.AttachXDP(link.XDPOptions{
			Program:   prog,
			Interface: e.ifIndex,
			Flags:     link.XDPGenericMode,
		})
		if err != nil {
			prog.Close()
			return fmt.Errorf("failed to attach XDP program: %w", err)
		}
		e.nativeMode = false
	} else {
		e.nativeMode = true
	}
	e.xdpLink = xdpLink
	return nil
}

// run is the main loop for an XDP worker.
func (w *xdpWorker) run(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	w.running.Store(true)
	defer w.running.Store(false)
	defer w.cleanup()

	// Set up epoll for socket polling
	epfd, err := unix.EpollCreate1(0)
	if err != nil {
		atomic.AddUint64(&w.engine.stats.packetsDropped, 1)
		return
	}
	defer unix.Close(epfd)

	event := unix.EpollEvent{
		Events: unix.EPOLLIN,
		Fd:     int32(w.fd),
	}
	if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, w.fd, &event); err != nil {
		return
	}

	events := make([]unix.EpollEvent, 1)
	pollTimeout := 100 // milliseconds

	for {
		select {
		case <-ctx.Done():
			return
		default:
			n, err := unix.EpollWait(epfd, events, pollTimeout)
			if err != nil {
				if err == syscall.EINTR {
					continue
				}
				return
			}

			if n > 0 {
				w.processRxRing()
			}

			// Refill the fill ring with processed frames
			w.refillFillRing()
		}
	}
}

// processRxRing processes packets from the RX ring using proper ring access
func (w *xdpWorker) processRxRing() {
	w.engine.mu.RLock()
	handler := w.engine.handler
	w.engine.mu.RUnlock()

	if handler == nil {
		return
	}

	// Read producer index (written by kernel)
	prod := atomic.LoadUint32(w.rxProd)
	cons := atomic.LoadUint32(w.rxCons)
	
	// Process all available entries
	for cons != prod {
		idx := cons & w.rxMask
		desc := w.rxDescs[idx]
		
		// Get packet data from UMEM
		addr := desc.addr
		length := desc.len
		
		if addr < uint64(len(w.umem)) && addr+uint64(length) <= uint64(len(w.umem)) {
			data := w.umem[addr : addr+uint64(length)]
			w.processPacket(data, time.Now().UnixNano())
			
			// Return frame to free list
			w.framesMu.Lock()
			w.freeFrames = append(w.freeFrames, addr)
			w.framesMu.Unlock()
		}
		
		cons++
	}
	
	// Update consumer index
	atomic.StoreUint32(w.rxCons, cons)
}

// refillFillRing refills the fill ring with free frames
func (w *xdpWorker) refillFillRing() {
	w.framesMu.Lock()
	defer w.framesMu.Unlock()
	
	if len(w.freeFrames) == 0 {
		return
	}
	
	prod := atomic.LoadUint32(w.fillProd)
	cons := atomic.LoadUint32(w.fillCons)
	
	// Calculate available space
	free := w.fillMask + 1 - (prod - cons)
	if free == 0 {
		return
	}
	
	// Add frames to fill ring
	toAdd := uint32(len(w.freeFrames))
	if toAdd > free {
		toAdd = free
	}
	
	for i := uint32(0); i < toAdd; i++ {
		idx := (prod + i) & w.fillMask
		w.fillDescs[idx] = w.freeFrames[i]
	}
	
	// Update producer
	atomic.StoreUint32(w.fillProd, prod+toAdd)
	
	// Remove used frames from free list
	w.freeFrames = w.freeFrames[toAdd:]
}

// processPacket processes a single packet with filter enforcement
func (w *xdpWorker) processPacket(data []byte, timestampNano int64) {
	w.engine.mu.RLock()
	handler := w.engine.handler
	w.engine.mu.RUnlock()

	if handler == nil {
		return
	}

	// Apply BPF filter if set
	if w.filterFunc != nil {
		if !w.filterFunc(data) {
			atomic.AddUint64(&w.engine.stats.filterDropped, 1)
			return
		}
		atomic.AddUint64(&w.engine.stats.filterMatched, 1)
	}

	// Update stats
	atomic.AddUint64(&w.engine.stats.packetsReceived, 1)
	atomic.AddUint64(&w.engine.stats.bytesReceived, uint64(len(data)))

	// Create packet info
	info := &models.PacketInfo{
		TimestampNano: timestampNano,
		Length:        uint32(len(data)),
		CaptureLength: uint32(len(data)),
		Interface:     w.engine.config.Interface,
	}

	// Parse basic headers
	if len(data) >= 14 {
		info.DstMAC = net.HardwareAddr(data[0:6]).String()
		info.SrcMAC = net.HardwareAddr(data[6:12]).String()
		info.EtherType = uint16(data[12])<<8 | uint16(data[13])

		if info.EtherType == 0x0800 && len(data) >= 34 {
			ipHeader := data[14:]
			info.Protocol = ipHeader[9]
			info.SrcIP = net.IP(ipHeader[12:16])
			info.DstIP = net.IP(ipHeader[16:20])

			ihl := int(ipHeader[0]&0x0F) * 4
			if len(data) >= 14+ihl+4 {
				transportHeader := data[14+ihl:]
				if info.Protocol == 6 || info.Protocol == 17 {
					info.SrcPort = uint16(transportHeader[0])<<8 | uint16(transportHeader[1])
					info.DstPort = uint16(transportHeader[2])<<8 | uint16(transportHeader[3])
				}
				if info.Protocol == 6 && len(transportHeader) >= 14 {
					info.TCPFlags = transportHeader[13]
				}
			}
		}

		if info.EtherType == 0x86DD && len(data) >= 54 {
			ipHeader := data[14:]
			info.Protocol = ipHeader[6]
			info.SrcIP = net.IP(ipHeader[8:24])
			info.DstIP = net.IP(ipHeader[24:40])

			if len(data) >= 58 {
				transportHeader := data[54:]
				if info.Protocol == 6 || info.Protocol == 17 {
					info.SrcPort = uint16(transportHeader[0])<<8 | uint16(transportHeader[1])
					info.DstPort = uint16(transportHeader[2])<<8 | uint16(transportHeader[3])
				}
			}
		}
	}

	handler(data, info)
}

// Ensure AFXDPEngine implements Engine interface
var _ Engine = (*AFXDPEngine)(nil)

// Suppress unused import warning for unsafe
var _ = unsafe.Sizeof(0)
