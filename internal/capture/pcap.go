// Package capture provides PCAP file reading for offline analysis.
package capture

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"

	"github.com/cvalentine99/nfa-linux/internal/models"
)

// PCAPEngine implements packet capture from PCAP files.
type PCAPEngine struct {
	config  *Config
	handler PacketHandler
	stats   *pcapStats
	mu      sync.RWMutex
	// Internal state
	handle  *pcap.Handle
	running int32
	cancel  context.CancelFunc
	done    chan struct{} // Signals when PCAP processing is complete
	// Packet parsing
	eth     layers.Ethernet
	ip4     layers.IPv4
	ip6     layers.IPv6
	tcp     layers.TCP
	udp     layers.UDP
	parser  *gopacket.DecodingLayerParser
	decoded []gopacket.LayerType
}

// pcapStats holds PCAP reading statistics.
type pcapStats struct {
	PacketsRead    uint64
	BytesRead      uint64
	ParseErrors    uint64
	StartTime      time.Time
	EndTime        time.Time
}

// NewPCAPEngine creates a new PCAP file reader.
func NewPCAPEngine(cfg *Config) (*PCAPEngine, error) {
	if cfg == nil {
		return nil, errors.New("capture: config cannot be nil")
	}

	if cfg.PcapFile == "" {
		return nil, errors.New("capture: PCAP file path is required")
	}

	e := &PCAPEngine{
		config: cfg,
		stats:  &pcapStats{},
		done:   make(chan struct{}),
	}

	// Initialize packet parser
	e.parser = gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&e.eth, &e.ip4, &e.ip6, &e.tcp, &e.udp,
	)
	e.parser.IgnoreUnsupported = true
	e.decoded = make([]gopacket.LayerType, 0, 10)

	return e, nil
}

// Start begins reading packets from the PCAP file.
func (e *PCAPEngine) Start(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&e.running, 0, 1) {
		return errors.New("capture: engine already running")
	}

	// Open PCAP file
	handle, err := pcap.OpenOffline(e.config.PcapFile)
	if err != nil {
		atomic.StoreInt32(&e.running, 0)
		return fmt.Errorf("capture: failed to open PCAP file: %w", err)
	}
	e.handle = handle

	// Apply BPF filter if specified
	if e.config.BPFFilter != "" {
		if err := handle.SetBPFFilter(e.config.BPFFilter); err != nil {
			handle.Close()
			atomic.StoreInt32(&e.running, 0)
			return fmt.Errorf("capture: failed to set BPF filter: %w", err)
		}
	}

	ctx, e.cancel = context.WithCancel(ctx)
	e.stats.StartTime = time.Now()

	// Start reading packets
	go e.readLoop(ctx)

	return nil
}

// Stop halts packet reading.
func (e *PCAPEngine) Stop() error {
	if !atomic.CompareAndSwapInt32(&e.running, 1, 0) {
		return errors.New("capture: engine not running")
	}

	if e.cancel != nil {
		e.cancel()
	}

	if e.handle != nil {
		e.handle.Close()
	}

	e.stats.EndTime = time.Now()
	return nil
}

// Stats returns current reading statistics.
func (e *PCAPEngine) Stats() *models.CaptureStats {
	return &models.CaptureStats{
		PacketsReceived:  atomic.LoadUint64(&e.stats.PacketsRead),
		BytesReceived:    atomic.LoadUint64(&e.stats.BytesRead),
		PacketsDropped:   0, // No drops in offline mode
		StartTime:        e.stats.StartTime,
		LastUpdate:       time.Now(),
		Interface:        e.config.PcapFile,
		CaptureFilter:    e.config.BPFFilter,
	}
}

// SetHandler sets the packet handler callback.
func (e *PCAPEngine) SetHandler(handler PacketHandler) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.handler = handler
}

// SetBPFFilter sets a BPF filter (only effective before Start).
func (e *PCAPEngine) SetBPFFilter(filter string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.config.BPFFilter = filter

	if e.handle != nil {
		return e.handle.SetBPFFilter(filter)
	}

	return nil
}

// readLoop reads packets from the PCAP file.
func (e *PCAPEngine) readLoop(ctx context.Context) {
	defer close(e.done) // Signal completion when done
	
	packetSource := gopacket.NewPacketSource(e.handle, e.handle.LinkType())
	packetSource.DecodeOptions.Lazy = true
	packetSource.DecodeOptions.NoCopy = true

	for {
		select {
		case <-ctx.Done():
			return
		case packet, ok := <-packetSource.Packets():
			if !ok {
				// End of file
				atomic.StoreInt32(&e.running, 0)
				return
			}

			e.processPacket(packet)
		}
	}
}

// processPacket processes a single packet from the PCAP file.
func (e *PCAPEngine) processPacket(packet gopacket.Packet) {
	data := packet.Data()
	if len(data) == 0 {
		return
	}

	atomic.AddUint64(&e.stats.PacketsRead, 1)
	atomic.AddUint64(&e.stats.BytesRead, uint64(len(data)))

	// Parse packet layers
	info := e.parsePacketInfo(packet)

	// Call handler
	e.mu.RLock()
	handler := e.handler
	e.mu.RUnlock()

	if handler != nil {
		handler(data, info)
	}
}

// parsePacketInfo extracts packet metadata.
func (e *PCAPEngine) parsePacketInfo(packet gopacket.Packet) *models.PacketInfo {
	metadata := packet.Metadata()
	info := &models.PacketInfo{
		TimestampNano: metadata.Timestamp.UnixNano(),
		Length:        uint32(metadata.Length),
		CaptureLength: uint32(metadata.CaptureLength),
		Interface:     e.config.PcapFile,
	}

	// Decode layers
	if err := e.parser.DecodeLayers(packet.Data(), &e.decoded); err != nil {
		atomic.AddUint64(&e.stats.ParseErrors, 1)
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
			// Build TCP flags byte
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

// Ensure PCAPEngine implements Engine interface
var _ Engine = (*PCAPEngine)(nil)


// Done returns a channel that is closed when PCAP processing is complete.
func (e *PCAPEngine) Done() <-chan struct{} {
	return e.done
}
