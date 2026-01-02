// Package reassembly provides memory-safe TCP stream reassembly for NFA-Linux.
// This implementation includes strict memory controls to prevent the documented
// memory explosion issues in gopacket/tcpassembly.
package reassembly

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	stdnet "net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/reassembly"
)

// MemoryConfig holds memory management configuration for the reassembly engine.
// These settings are CRITICAL for preventing memory exhaustion.
type MemoryConfig struct {
	// MaxBufferedPagesPerConnection limits memory per connection.
	// Default: 4000 pages (~7.6MB per connection with 2KB pages)
	MaxBufferedPagesPerConnection int

	// MaxBufferedPagesTotal limits total memory across all connections.
	// Default: 150000 pages (~285MB total)
	MaxBufferedPagesTotal int

	// FlushOlderThan forces flush of connections older than this duration.
	// Default: 30 seconds
	FlushOlderThan time.Duration

	// ConnectionTimeout closes connections with no activity for this duration.
	// Default: 2 minutes
	ConnectionTimeout time.Duration

	// MaxConnections limits the total number of tracked connections.
	// Default: 100000
	MaxConnections int

	// PageSize is the size of each memory page.
	// Default: 2048 bytes
	PageSize int
}

// DefaultMemoryConfig returns a sensible default memory configuration.
func DefaultMemoryConfig() *MemoryConfig {
	return &MemoryConfig{
		MaxBufferedPagesPerConnection: 4000,   // ~7.6MB per connection
		MaxBufferedPagesTotal:         150000, // ~285MB total
		FlushOlderThan:                30 * time.Second,
		ConnectionTimeout:             2 * time.Minute,
		MaxConnections:                100000,
		PageSize:                      2048,
	}
}

// StreamHandler is called when stream data is available.
type StreamHandler func(stream *Stream, data []byte, isClient bool)

// StreamClosedHandler is called when a stream is closed.
type StreamClosedHandler func(stream *Stream)

// Stream represents a TCP stream (one direction of a connection).
type Stream struct {
	ID            string
	ClientIP      stdnet.IP
	ServerIP      stdnet.IP
	ClientPort    uint16
	ServerPort    uint16
	StartTimeNano int64
	LastSeenNano  int64
	ClientBytes   uint64
	ServerBytes   uint64
	State         string
	Protocol      string // Detected application protocol
	
	// Internal state
	mu            sync.Mutex
	bufferedPages int
	closed        bool
	userData      interface{}
}

// SetUserData sets user-defined data on the stream.
func (s *Stream) SetUserData(data interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.userData = data
}

// GetUserData returns user-defined data from the stream.
func (s *Stream) GetUserData() interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.userData
}

// TCPReassembler provides memory-safe TCP stream reassembly.
type TCPReassembler struct {
	config        *MemoryConfig
	streamHandler StreamHandler
	closedHandler StreamClosedHandler
	
	// gopacket assembler
	streamFactory *tcpStreamFactory
	streamPool    *reassembly.StreamPool
	assembler     *reassembly.Assembler
	
	// Memory tracking
	totalPages    int64
	activeStreams int64
	
	// Stream tracking
	streams     map[string]*Stream
	streamsList *list.List
	streamsMu   sync.RWMutex
	
	// Statistics
	stats *ReassemblyStats
	
	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// ReassemblyStats holds reassembly statistics.
type ReassemblyStats struct {
	StreamsCreated     uint64
	StreamsClosed      uint64
	BytesReassembled   uint64
	PacketsProcessed   uint64
	PagesAllocated     uint64
	PagesFreed         uint64
	MemoryLimitHits    uint64
	ConnectionLimitHits uint64
	ForcedFlushes      uint64
}

// tcpStreamFactory creates new TCP streams for gopacket.
type tcpStreamFactory struct {
	reassembler *TCPReassembler
}

// tcpStream implements reassembly.Stream for gopacket.
type tcpStream struct {
	stream      *Stream
	reassembler *TCPReassembler
	isClient    bool
	net, transport gopacket.Flow
}

// NewTCPReassembler creates a new TCP reassembly engine.
func NewTCPReassembler(cfg *MemoryConfig) (*TCPReassembler, error) {
	if cfg == nil {
		cfg = DefaultMemoryConfig()
	}

	tr := &TCPReassembler{
		config:      cfg,
		streams:     make(map[string]*Stream),
		streamsList: list.New(),
		stats:       &ReassemblyStats{},
	}

	// Create stream factory
	tr.streamFactory = &tcpStreamFactory{reassembler: tr}

	// Create stream pool with memory limits
	tr.streamPool = reassembly.NewStreamPool(tr.streamFactory)

	// Create assembler with configuration
	tr.assembler = reassembly.NewAssembler(tr.streamPool)
	tr.assembler.MaxBufferedPagesPerConnection = cfg.MaxBufferedPagesPerConnection
	tr.assembler.MaxBufferedPagesTotal = cfg.MaxBufferedPagesTotal

	return tr, nil
}

// Start begins the reassembly engine.
func (tr *TCPReassembler) Start(ctx context.Context) error {
	tr.ctx, tr.cancel = context.WithCancel(ctx)

	// Start periodic flush goroutine
	tr.wg.Add(1)
	go tr.flushLoop()

	return nil
}

// Stop halts the reassembly engine.
func (tr *TCPReassembler) Stop() error {
	if tr.cancel != nil {
		tr.cancel()
	}

	tr.wg.Wait()

	// Flush all remaining streams
	tr.assembler.FlushAll()

	return nil
}

// SetStreamHandler sets the handler for stream data.
func (tr *TCPReassembler) SetStreamHandler(handler StreamHandler) {
	tr.streamHandler = handler
}

// SetClosedHandler sets the handler for closed streams.
func (tr *TCPReassembler) SetClosedHandler(handler StreamClosedHandler) {
	tr.closedHandler = handler
}

// ProcessPacket processes a TCP packet for reassembly.
func (tr *TCPReassembler) ProcessPacket(packet gopacket.Packet) error {
	// Check connection limit
	if atomic.LoadInt64(&tr.activeStreams) >= int64(tr.config.MaxConnections) {
		atomic.AddUint64(&tr.stats.ConnectionLimitHits, 1)
		return errors.New("connection limit reached")
	}

	// Get TCP layer
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil // Not a TCP packet
	}
	tcp, _ := tcpLayer.(*layers.TCP)

	// Get network layer for flow
	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		return nil
	}

	// Assemble the packet
	tr.assembler.AssembleWithContext(
		netLayer.NetworkFlow(),
		tcp,
		&assemblerContext{
			ci:       packet.Metadata().CaptureInfo,
			timestamp: packet.Metadata().Timestamp,
		},
	)

	atomic.AddUint64(&tr.stats.PacketsProcessed, 1)

	return nil
}

// ProcessTCPSegment processes a raw TCP segment.
func (tr *TCPReassembler) ProcessTCPSegment(
	srcIP, dstIP stdnet.IP,
	srcPort, dstPort uint16,
	seq, ack uint32,
	flags uint8,
	payload []byte,
	timestampNano int64,
) error {
	// Check connection limit
	if atomic.LoadInt64(&tr.activeStreams) >= int64(tr.config.MaxConnections) {
		atomic.AddUint64(&tr.stats.ConnectionLimitHits, 1)
		return errors.New("connection limit reached")
	}

	// Create TCP layer
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     seq,
		Ack:     ack,
		SYN:     flags&0x02 != 0,
		ACK:     flags&0x10 != 0,
		FIN:     flags&0x01 != 0,
		RST:     flags&0x04 != 0,
		PSH:     flags&0x08 != 0,
	}
	tcp.SetNetworkLayerForChecksum(&layers.IPv4{
		SrcIP: srcIP,
		DstIP: dstIP,
	})
	tcp.Payload = payload

	// Create network flow
	netFlow := gopacket.NewFlow(layers.EndpointIPv4, srcIP, dstIP)

	// Assemble
	tr.assembler.AssembleWithContext(
		netFlow,
		tcp,
		&assemblerContext{
			ci: gopacket.CaptureInfo{
				Timestamp:     time.Unix(0, timestampNano),
				CaptureLength: len(payload),
				Length:        len(payload),
			},
			timestamp: time.Unix(0, timestampNano),
		},
	)

	atomic.AddUint64(&tr.stats.PacketsProcessed, 1)

	return nil
}

// Stats returns current reassembly statistics.
func (tr *TCPReassembler) Stats() *ReassemblyStats {
	return &ReassemblyStats{
		StreamsCreated:     atomic.LoadUint64(&tr.stats.StreamsCreated),
		StreamsClosed:      atomic.LoadUint64(&tr.stats.StreamsClosed),
		BytesReassembled:   atomic.LoadUint64(&tr.stats.BytesReassembled),
		PacketsProcessed:   atomic.LoadUint64(&tr.stats.PacketsProcessed),
		PagesAllocated:     atomic.LoadUint64(&tr.stats.PagesAllocated),
		PagesFreed:         atomic.LoadUint64(&tr.stats.PagesFreed),
		MemoryLimitHits:    atomic.LoadUint64(&tr.stats.MemoryLimitHits),
		ConnectionLimitHits: atomic.LoadUint64(&tr.stats.ConnectionLimitHits),
		ForcedFlushes:      atomic.LoadUint64(&tr.stats.ForcedFlushes),
	}
}

// ActiveStreams returns the number of active streams.
func (tr *TCPReassembler) ActiveStreams() int64 {
	return atomic.LoadInt64(&tr.activeStreams)
}

// TotalBufferedPages returns the total number of buffered pages.
func (tr *TCPReassembler) TotalBufferedPages() int64 {
	return atomic.LoadInt64(&tr.totalPages)
}

// flushLoop periodically flushes old connections.
func (tr *TCPReassembler) flushLoop() {
	defer tr.wg.Done()

	ticker := time.NewTicker(tr.config.FlushOlderThan / 2)
	defer ticker.Stop()

	for {
		select {
		case <-tr.ctx.Done():
			return
		case <-ticker.C:
			tr.flushOldConnections()
		}
	}
}

// flushOldConnections flushes connections older than the configured threshold.
func (tr *TCPReassembler) flushOldConnections() {
	cutoff := time.Now().Add(-tr.config.FlushOlderThan)
	flushed, _ := tr.assembler.FlushWithOptions(reassembly.FlushOptions{
		T:  cutoff,
		TC: cutoff,
	})

	if flushed > 0 {
		atomic.AddUint64(&tr.stats.ForcedFlushes, uint64(flushed))
	}
}

// getOrCreateStream gets or creates a stream for the given connection.
func (tr *TCPReassembler) getOrCreateStream(
	clientIP, serverIP stdnet.IP,
	clientPort, serverPort uint16,
	timestampNano int64,
) *Stream {
	key := fmt.Sprintf("%s:%d-%s:%d",
		clientIP.String(), clientPort,
		serverIP.String(), serverPort)

	tr.streamsMu.Lock()
	defer tr.streamsMu.Unlock()

	if stream, ok := tr.streams[key]; ok {
		stream.LastSeenNano = timestampNano
		return stream
	}

	// Create new stream
	stream := &Stream{
		ID:            key,
		ClientIP:      clientIP,
		ServerIP:      serverIP,
		ClientPort:    clientPort,
		ServerPort:    serverPort,
		StartTimeNano: timestampNano,
		LastSeenNano:  timestampNano,
		State:         "ESTABLISHED",
	}

	tr.streams[key] = stream
	tr.streamsList.PushBack(stream)
	atomic.AddInt64(&tr.activeStreams, 1)
	atomic.AddUint64(&tr.stats.StreamsCreated, 1)

	return stream
}

// closeStream closes a stream and removes it from tracking.
func (tr *TCPReassembler) closeStream(stream *Stream) {
	stream.mu.Lock()
	if stream.closed {
		stream.mu.Unlock()
		return
	}
	stream.closed = true
	stream.State = "CLOSED"
	stream.mu.Unlock()

	tr.streamsMu.Lock()
	delete(tr.streams, stream.ID)
	tr.streamsMu.Unlock()

	atomic.AddInt64(&tr.activeStreams, -1)
	atomic.AddUint64(&tr.stats.StreamsClosed, 1)

	// Call closed handler
	if tr.closedHandler != nil {
		tr.closedHandler(stream)
	}
}

// assemblerContext provides context for the gopacket assembler.
type assemblerContext struct {
	ci        gopacket.CaptureInfo
	timestamp time.Time
}

func (c *assemblerContext) GetCaptureInfo() gopacket.CaptureInfo {
	return c.ci
}

// New creates a new stream for the gopacket stream factory.
func (f *tcpStreamFactory) New(net, transport gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	// Determine client/server based on SYN flag
	srcIPRaw := net.Src().Raw()
	dstIPRaw := net.Dst().Raw()
	srcIP := stdnet.IP(srcIPRaw)
	dstIP := stdnet.IP(dstIPRaw)
	
	// Safely extract ports from transport flow
	var srcPort, dstPort uint16
	srcRaw := transport.Src().Raw()
	dstRaw := transport.Dst().Raw()
	if len(srcRaw) >= 2 {
		srcPort = uint16(srcRaw[0])<<8 | uint16(srcRaw[1])
	} else {
		// Fallback to TCP layer ports
		srcPort = uint16(tcp.SrcPort)
	}
	if len(dstRaw) >= 2 {
		dstPort = uint16(dstRaw[0])<<8 | uint16(dstRaw[1])
	} else {
		// Fallback to TCP layer ports
		dstPort = uint16(tcp.DstPort)
	}

	var clientIP, serverIP stdnet.IP
	var clientPort, serverPort uint16

	if tcp.SYN && !tcp.ACK {
		// This is the client initiating
		clientIP = srcIP
		serverIP = dstIP
		clientPort = srcPort
		serverPort = dstPort
	} else {
		// Assume lower port is server
		if srcPort < dstPort {
			serverIP = srcIP
			clientIP = dstIP
			serverPort = srcPort
			clientPort = dstPort
		} else {
			clientIP = srcIP
			serverIP = dstIP
			clientPort = srcPort
			serverPort = dstPort
		}
	}

	timestampNano := ac.GetCaptureInfo().Timestamp.UnixNano()
	stream := f.reassembler.getOrCreateStream(clientIP, serverIP, clientPort, serverPort, timestampNano)

	return &tcpStream{
		stream:      stream,
		reassembler: f.reassembler,
		isClient:    srcIP.Equal(clientIP) && srcPort == clientPort,
		net:         net,
		transport:   transport,
	}
}

// Accept implements reassembly.Stream.
func (s *tcpStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	// Update last seen time
	s.stream.LastSeenNano = ci.Timestamp.UnixNano()
	return true
}

// ReassembledSG implements reassembly.Stream.
func (s *tcpStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	length, _ := sg.Lengths()
	if length == 0 {
		return
	}

	data := sg.Fetch(length)
	
	// Update statistics
	if s.isClient {
		atomic.AddUint64(&s.stream.ClientBytes, uint64(length))
	} else {
		atomic.AddUint64(&s.stream.ServerBytes, uint64(length))
	}
	atomic.AddUint64(&s.reassembler.stats.BytesReassembled, uint64(length))

	// Call stream handler
	if s.reassembler.streamHandler != nil {
		s.reassembler.streamHandler(s.stream, data, s.isClient)
	}
}

// ReassemblyComplete implements reassembly.Stream.
func (s *tcpStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	s.reassembler.closeStream(s.stream)
	return true // Remove from pool
}
