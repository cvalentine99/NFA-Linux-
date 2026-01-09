// Package capture provides the high-speed packet capture engine for NFA-Linux.
// It supports both AF_XDP (preferred for 10Gbps+) and AF_PACKET (fallback).
package capture

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cvalentine99/nfa-linux/internal/metrics"
	"github.com/cvalentine99/nfa-linux/internal/models"
)

// CaptureMode defines the packet capture method.
type CaptureMode int

const (
	// ModeAFXDP uses AF_XDP for high-speed zero-copy capture (preferred).
	ModeAFXDP CaptureMode = iota
	// ModeAFPacket uses AF_PACKET with TPACKET_V3 (fallback).
	ModeAFPacket
	// ModePCAP reads from a PCAP file.
	ModePCAP
)

// Config holds the configuration for the capture engine.
type Config struct {
	// Interface is the network interface to capture from.
	Interface string

	// Mode specifies the capture method (AF_XDP, AF_PACKET, or PCAP).
	Mode CaptureMode

	// PcapFile is the path to a PCAP file (only used in ModePCAP).
	PcapFile string

	// SnapLen is the maximum bytes to capture per packet.
	SnapLen int

	// Promiscuous enables promiscuous mode on the interface.
	Promiscuous bool

	// BPFFilter is an optional BPF filter expression.
	BPFFilter string

	// NumWorkers is the number of worker goroutines for packet processing.
	// Defaults to runtime.NumCPU() if not set.
	NumWorkers int

	// RingBufferSize is the size of the ring buffer in bytes.
	// For AF_XDP, this is per-queue. Default is 64MB.
	RingBufferSize int

	// BatchSize is the number of packets to batch before sending to workers.
	BatchSize int

	// QueueID specifies the NIC queue to capture from (-1 for all queues).
	QueueID int
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig(iface string) *Config {
	return &Config{
		Interface:      iface,
		Mode:           ModeAFXDP,
		SnapLen:        65535,
		Promiscuous:    true,
		NumWorkers:     0, // Will default to NumCPU
		RingBufferSize: 64 * 1024 * 1024, // 64MB
		BatchSize:      64,
		QueueID:        -1,
	}
}

// PacketHandler is a function that processes captured packets.
type PacketHandler func(data []byte, info *models.PacketInfo)

// Engine is the interface for all capture engines.
type Engine interface {
	// Start begins packet capture.
	Start(ctx context.Context) error

	// Stop halts packet capture.
	Stop() error

	// Stats returns current capture statistics.
	Stats() *models.CaptureStats

	// SetHandler sets the packet handler callback.
	SetHandler(handler PacketHandler)

	// SetBPFFilter sets a BPF filter at runtime.
	SetBPFFilter(filter string) error

	// Done returns a channel that is closed when capture is complete (for PCAP mode).
	Done() <-chan struct{}
}

// CaptureEngine is the main capture engine implementation.
type CaptureEngine struct {
	config  *Config
	handler PacketHandler
	stats   *models.CaptureStats
	mu      sync.RWMutex

	// Internal state
	running bool
	cancel  context.CancelFunc

	// Underlying engine (AF_XDP or AF_PACKET)
	engine Engine
}

// New creates a new CaptureEngine with the given configuration.
func New(cfg *Config) (*CaptureEngine, error) {
	if cfg == nil {
		return nil, errors.New("capture: config cannot be nil")
	}

	if cfg.Interface == "" && cfg.Mode != ModePCAP {
		return nil, errors.New("capture: interface is required for live capture")
	}

	if cfg.Mode == ModePCAP && cfg.PcapFile == "" {
		return nil, errors.New("capture: pcap file path is required for PCAP mode")
	}

	ce := &CaptureEngine{
		config: cfg,
		stats: &models.CaptureStats{
			Interface: cfg.Interface,
		},
	}

	return ce, nil
}

// Start begins packet capture.
func (ce *CaptureEngine) Start(ctx context.Context) error {
	ce.mu.Lock()
	if ce.running {
		ce.mu.Unlock()
		return errors.New("capture: engine already running")
	}
	ce.running = true
	ce.mu.Unlock()

	ctx, ce.cancel = context.WithCancel(ctx)

	ce.stats.StartTime = time.Now()
	ce.stats.PromiscuousMode = ce.config.Promiscuous
	ce.stats.CaptureFilter = ce.config.BPFFilter

	var err error
	switch ce.config.Mode {
	case ModeAFXDP:
		err = ce.startAFXDP(ctx)
	case ModeAFPacket:
		err = ce.startAFPacket(ctx)
	case ModePCAP:
		err = ce.startPCAP(ctx)
	default:
		err = fmt.Errorf("capture: unknown mode %d", ce.config.Mode)
	}

	if err != nil {
		ce.mu.Lock()
		ce.running = false
		ce.mu.Unlock()
		return err
	}

	return nil
}

// Stop halts packet capture.
func (ce *CaptureEngine) Stop() error {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	if !ce.running {
		return errors.New("capture: engine not running")
	}

	if ce.cancel != nil {
		ce.cancel()
	}

	ce.running = false
	return nil
}

// Stats returns current capture statistics.
func (ce *CaptureEngine) Stats() *models.CaptureStats {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	// CRITICAL FIX: Get stats from underlying engine if available
	// The underlying engine (PCAPEngine, AFPacketEngine, etc.) tracks actual packet counts
	if ce.engine != nil {
		engineStats := ce.engine.Stats()
		if engineStats != nil {
			// Merge with our stats (hosts, files, etc.)
			engineStats.ActiveFlows = ce.stats.ActiveFlows
			engineStats.ActiveSessions = ce.stats.ActiveSessions
			engineStats.HostsDiscovered = ce.stats.HostsDiscovered
			engineStats.FilesCarved = ce.stats.FilesCarved
			engineStats.LastUpdate = time.Now()
			return engineStats
		}
	}

	stats := *ce.stats
	stats.LastUpdate = time.Now()
	return &stats
}

// SetHandler sets the packet handler callback.
func (ce *CaptureEngine) SetHandler(handler PacketHandler) {
	ce.mu.Lock()
	defer ce.mu.Unlock()
	ce.handler = handler
}

// SetBPFFilter sets a BPF filter at runtime.
func (ce *CaptureEngine) SetBPFFilter(filter string) error {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	ce.config.BPFFilter = filter
	ce.stats.CaptureFilter = filter

	// If engine is running, update the filter
	if ce.engine != nil {
		return ce.engine.SetBPFFilter(filter)
	}

	return nil
}

// IsRunning returns whether the capture engine is currently running.
func (ce *CaptureEngine) IsRunning() bool {
	ce.mu.RLock()
	defer ce.mu.RUnlock()
	return ce.running
}

// updateStats atomically updates capture statistics.
func (ce *CaptureEngine) updateStats(packets, bytes uint64, dropped uint64) {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	ce.stats.PacketsReceived += packets
	ce.stats.BytesReceived += bytes
	ce.stats.PacketsDropped += dropped

	// Update Prometheus metrics
	metrics.PacketsReceived.Add(packets)
	metrics.BytesReceived.Add(bytes)
	metrics.PacketsDropped.Add(dropped)

	elapsed := time.Since(ce.stats.StartTime).Seconds()
	if elapsed > 0 {
		ce.stats.PacketsPerSecond = float64(ce.stats.PacketsReceived) / elapsed
		ce.stats.BytesPerSecond = float64(ce.stats.BytesReceived) / elapsed
		// Update uptime gauge
		metrics.CaptureUptime.Set(elapsed)
	}
}

// processPacket is the internal packet processing function.
func (ce *CaptureEngine) processPacket(data []byte, info *models.PacketInfo) {
	ce.mu.RLock()
	handler := ce.handler
	ce.mu.RUnlock()

	if handler != nil {
		handler(data, info)
	}
}

// startAFXDP starts capture using AF_XDP.
func (ce *CaptureEngine) startAFXDP(ctx context.Context) error {
	engine, err := NewAFXDPEngine(ce.config)
	if err != nil {
		// Fall back to AF_PACKET if AF_XDP is not available
		return ce.startAFPacket(ctx)
	}

	engine.SetHandler(ce.processPacket)
	ce.engine = engine

	return engine.Start(ctx)
}

// startAFPacket starts capture using AF_PACKET with TPACKET_V3.
func (ce *CaptureEngine) startAFPacket(ctx context.Context) error {
	engine, err := NewAFPacketEngine(ce.config)
	if err != nil {
		return fmt.Errorf("capture: failed to create AF_PACKET engine: %w", err)
	}

	engine.SetHandler(ce.processPacket)
	ce.engine = engine

	return engine.Start(ctx)
}

// startPCAP starts capture from a PCAP file.
func (ce *CaptureEngine) startPCAP(ctx context.Context) error {
	engine, err := NewPCAPEngine(ce.config)
	if err != nil {
		return fmt.Errorf("capture: failed to create PCAP engine: %w", err)
	}

	engine.SetHandler(ce.processPacket)
	ce.engine = engine

	return engine.Start(ctx)
}


// Done returns a channel that is closed when capture is complete (for PCAP mode).
func (ce *CaptureEngine) Done() <-chan struct{} {
	ce.mu.RLock()
	defer ce.mu.RUnlock()
	
	if ce.engine != nil {
		return ce.engine.Done()
	}
	// Return a closed channel if no engine
	ch := make(chan struct{})
	close(ch)
	return ch
}
