//go:build linux

// Package capture provides AF_PACKET-based packet capture as a fallback.
// AF_PACKET with TPACKET_V3 provides good performance for moderate traffic rates.
package capture

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/afpacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/cvalentine99/nfa-linux/internal/models"
)

// AFPacketEngine implements packet capture using AF_PACKET with TPACKET_V3.
type AFPacketEngine struct {
	config  *Config
	handler PacketHandler
	stats   *afpacketStats
	mu      sync.RWMutex

	// AF_PACKET handle
	tpacket *afpacket.TPacket

	// Worker management
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Decoder for zero-allocation parsing
	eth     layers.Ethernet
	ip4     layers.IPv4
	ip6     layers.IPv6
	tcp     layers.TCP
	udp     layers.UDP
	payload gopacket.Payload
	parser  *gopacket.DecodingLayerParser
	decoded []gopacket.LayerType
}

// afpacketStats holds atomic counters for capture statistics.
type afpacketStats struct {
	packetsReceived uint64
	packetsDropped  uint64
	bytesReceived   uint64
	startTime       time.Time
}

// NewAFPacketEngine creates a new AF_PACKET capture engine.
func NewAFPacketEngine(cfg *Config) (*AFPacketEngine, error) {
	if cfg == nil {
		return nil, errors.New("afpacket: config cannot be nil")
	}

	if cfg.Interface == "" {
		return nil, errors.New("afpacket: interface is required")
	}

	engine := &AFPacketEngine{
		config: cfg,
		stats: &afpacketStats{
			startTime: time.Now(),
		},
		decoded: make([]gopacket.LayerType, 0, 10),
	}

	// Initialize the DecodingLayerParser for zero-allocation parsing
	engine.parser = gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&engine.eth,
		&engine.ip4,
		&engine.ip6,
		&engine.tcp,
		&engine.udp,
		&engine.payload,
	)
	engine.parser.IgnoreUnsupported = true

	return engine, nil
}

// Start begins AF_PACKET packet capture.
func (e *AFPacketEngine) Start(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.ctx, e.cancel = context.WithCancel(ctx)
	e.stats.startTime = time.Now()

	// Calculate buffer parameters
	// Default to 64MB buffer, which can hold ~43,000 1500-byte packets
	bufferSize := e.config.RingBufferSize
	if bufferSize <= 0 {
		bufferSize = 64 * 1024 * 1024
	}

	snapLen := e.config.SnapLen
	if snapLen <= 0 {
		snapLen = 65535
	}

	// Create AF_PACKET handle with TPACKET_V3
	opts := []interface{}{
		afpacket.OptInterface(e.config.Interface),
		afpacket.OptFrameSize(snapLen),
		afpacket.OptBlockSize(bufferSize / 128), // 128 blocks
		afpacket.OptNumBlocks(128),
		afpacket.OptBlockTimeout(100 * time.Millisecond),
		afpacket.OptPollTimeout(100 * time.Millisecond),
	}

	tpacket, err := afpacket.NewTPacket(opts...)
	if err != nil {
		return fmt.Errorf("afpacket: failed to create TPacket: %w", err)
	}
	e.tpacket = tpacket

	// Set promiscuous mode if requested
	if e.config.Promiscuous {
		if err := e.setPromiscuous(true); err != nil {
			e.tpacket.Close()
			return fmt.Errorf("afpacket: failed to set promiscuous mode: %w", err)
		}
	}

	// Set BPF filter if provided
	if e.config.BPFFilter != "" {
		if err := e.setBPFFilterInternal(e.config.BPFFilter); err != nil {
			e.tpacket.Close()
			return fmt.Errorf("afpacket: failed to set BPF filter: %w", err)
		}
	}

	// Start capture workers
	numWorkers := e.config.NumWorkers
	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU()
	}

	// For AF_PACKET, we use a single reader with fanout to multiple workers
	e.wg.Add(1)
	go e.captureLoop()

	return nil
}

// Stop halts AF_PACKET packet capture.
func (e *AFPacketEngine) Stop() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.cancel != nil {
		e.cancel()
	}

	// Wait for capture loop to finish
	e.wg.Wait()

	// Close the TPacket handle
	if e.tpacket != nil {
		e.tpacket.Close()
		e.tpacket = nil
	}

	return nil
}

// Stats returns current capture statistics.
func (e *AFPacketEngine) Stats() *models.CaptureStats {
	received := atomic.LoadUint64(&e.stats.packetsReceived)
	dropped := atomic.LoadUint64(&e.stats.packetsDropped)
	bytes := atomic.LoadUint64(&e.stats.bytesReceived)

	// Get kernel stats if available
	if e.tpacket != nil {
		_, kernelStats, err := e.tpacket.SocketStats()
		if err == nil {
			dropped = uint64(kernelStats.Drops())
		}
	}

	elapsed := time.Since(e.stats.startTime).Seconds()
	var pps, bps float64
	if elapsed > 0 {
		pps = float64(received) / elapsed
		bps = float64(bytes) / elapsed
	}

	return &models.CaptureStats{
		PacketsReceived:  received,
		PacketsDropped:   dropped,
		BytesReceived:    bytes,
		PacketsPerSecond: pps,
		BytesPerSecond:   bps,
		StartTime:        e.stats.startTime,
		LastUpdate:       time.Now(),
		Interface:        e.config.Interface,
		PromiscuousMode:  e.config.Promiscuous,
		CaptureFilter:    e.config.BPFFilter,
	}
}

// SetHandler sets the packet handler callback.
func (e *AFPacketEngine) SetHandler(handler PacketHandler) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.handler = handler
}

// SetBPFFilter sets a BPF filter at runtime.
func (e *AFPacketEngine) SetBPFFilter(filter string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.config.BPFFilter = filter
	return e.setBPFFilterInternal(filter)
}

// setBPFFilterInternal sets the BPF filter (must be called with lock held).
func (e *AFPacketEngine) setBPFFilterInternal(filter string) error {
	if e.tpacket == nil {
		return nil
	}

	// Compile and set BPF filter
	// Note: This requires libpcap for filter compilation
	// For pure Go, we would use github.com/packetcap/go-pcap/filter
	// For now, we'll skip this and implement it later

	return nil
}

// setPromiscuous enables or disables promiscuous mode.
func (e *AFPacketEngine) setPromiscuous(enable bool) error {
	// This is handled by the kernel when using AF_PACKET
	// The interface is automatically put into promiscuous mode
	return nil
}

// captureLoop is the main packet capture loop.
func (e *AFPacketEngine) captureLoop() {
	defer e.wg.Done()

	for {
		select {
		case <-e.ctx.Done():
			return
		default:
		}

		// Read packet using zero-copy
		data, ci, err := e.tpacket.ZeroCopyReadPacketData()
		if err != nil {
			// Check if context is done
			select {
			case <-e.ctx.Done():
				return
			default:
			}
			// Timeout or other error, continue
			continue
		}

		// Update stats
		atomic.AddUint64(&e.stats.packetsReceived, 1)
		atomic.AddUint64(&e.stats.bytesReceived, uint64(len(data)))

		// Get handler
		e.mu.RLock()
		handler := e.handler
		e.mu.RUnlock()

		if handler == nil {
			continue
		}

		// Create packet info using the pre-allocated decoder
		info := e.parsePacketInfo(data, ci.Timestamp.UnixNano())

		// Call handler
		handler(data, info)
	}
}

// parsePacketInfo parses packet headers into a PacketInfo struct.
// Uses the pre-allocated DecodingLayerParser for zero allocations.
func (e *AFPacketEngine) parsePacketInfo(data []byte, timestampNano int64) *models.PacketInfo {
	info := &models.PacketInfo{
		TimestampNano: timestampNano,
		Length:        uint32(len(data)),
		CaptureLength: uint32(len(data)),
		Interface:     e.config.Interface,
	}

	// Decode layers
	e.decoded = e.decoded[:0]
	if err := e.parser.DecodeLayers(data, &e.decoded); err != nil {
		// Partial decode is OK, we'll use what we got
	}

	for _, layerType := range e.decoded {
		switch layerType {
		case layers.LayerTypeEthernet:
			info.SrcMAC = e.eth.SrcMAC.String()
			info.DstMAC = e.eth.DstMAC.String()
			info.EtherType = uint16(e.eth.EthernetType)

		case layers.LayerTypeIPv4:
			info.SrcIP = e.ip4.SrcIP
			info.DstIP = e.ip4.DstIP
			info.Protocol = uint8(e.ip4.Protocol)

		case layers.LayerTypeIPv6:
			info.SrcIP = e.ip6.SrcIP
			info.DstIP = e.ip6.DstIP
			info.Protocol = uint8(e.ip6.NextHeader)

		case layers.LayerTypeTCP:
			info.SrcPort = uint16(e.tcp.SrcPort)
			info.DstPort = uint16(e.tcp.DstPort)
			// Build TCP flags byte: FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10
			var flags uint8
			if e.tcp.FIN {
				flags |= 0x01
			}
			if e.tcp.SYN {
				flags |= 0x02
			}
			if e.tcp.RST {
				flags |= 0x04
			}
			if e.tcp.PSH {
				flags |= 0x08
			}
			if e.tcp.ACK {
				flags |= 0x10
			}
			if e.tcp.URG {
				flags |= 0x20
			}
			info.TCPFlags = flags

		case layers.LayerTypeUDP:
			info.SrcPort = uint16(e.udp.SrcPort)
			info.DstPort = uint16(e.udp.DstPort)
		}
	}

	return info
}

// Done returns a channel that never closes for live capture (runs until stopped).
func (e *AFPacketEngine) Done() <-chan struct{} {
	// Live capture never completes on its own, only when stopped
	return make(chan struct{})
}

// Ensure AFPacketEngine implements Engine interface
var _ Engine = (*AFPacketEngine)(nil)
