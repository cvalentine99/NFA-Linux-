package reassembly

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestDefaultMemoryConfig(t *testing.T) {
	cfg := DefaultMemoryConfig()

	if cfg.MaxBufferedPagesPerConnection != 4000 {
		t.Errorf("expected MaxBufferedPagesPerConnection 4000, got %d", cfg.MaxBufferedPagesPerConnection)
	}

	if cfg.MaxBufferedPagesTotal != 150000 {
		t.Errorf("expected MaxBufferedPagesTotal 150000, got %d", cfg.MaxBufferedPagesTotal)
	}

	if cfg.FlushOlderThan != 30*time.Second {
		t.Errorf("expected FlushOlderThan 30s, got %v", cfg.FlushOlderThan)
	}

	if cfg.ConnectionTimeout != 2*time.Minute {
		t.Errorf("expected ConnectionTimeout 2m, got %v", cfg.ConnectionTimeout)
	}

	if cfg.MaxConnections != 100000 {
		t.Errorf("expected MaxConnections 100000, got %d", cfg.MaxConnections)
	}
}

func TestTCPReassemblerCreation(t *testing.T) {
	// Test with nil config (should use defaults)
	reassembler, err := NewTCPReassembler(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reassembler == nil {
		t.Fatal("expected non-nil reassembler")
	}

	// Test with custom config
	cfg := &MemoryConfig{
		MaxBufferedPagesPerConnection: 2000,
		MaxBufferedPagesTotal:         50000,
		FlushOlderThan:                15 * time.Second,
		ConnectionTimeout:             1 * time.Minute,
		MaxConnections:                50000,
		PageSize:                      4096,
	}
	reassembler, err = NewTCPReassembler(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reassembler == nil {
		t.Fatal("expected non-nil reassembler")
	}
}

func TestTCPReassemblerStartStop(t *testing.T) {
	reassembler, err := NewTCPReassembler(nil)
	if err != nil {
		t.Fatalf("failed to create reassembler: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = reassembler.Start(ctx)
	if err != nil {
		t.Fatalf("failed to start reassembler: %v", err)
	}

	// Let it run briefly
	time.Sleep(100 * time.Millisecond)

	err = reassembler.Stop()
	if err != nil {
		t.Fatalf("failed to stop reassembler: %v", err)
	}
}

func TestTCPReassemblerStats(t *testing.T) {
	reassembler, err := NewTCPReassembler(nil)
	if err != nil {
		t.Fatalf("failed to create reassembler: %v", err)
	}

	stats := reassembler.Stats()
	if stats == nil {
		t.Fatal("expected non-nil stats")
	}

	if stats.StreamsCreated != 0 {
		t.Errorf("expected 0 streams created, got %d", stats.StreamsCreated)
	}

	if stats.PacketsProcessed != 0 {
		t.Errorf("expected 0 packets processed, got %d", stats.PacketsProcessed)
	}
}

func TestTCPReassemblerHandlers(t *testing.T) {
	reassembler, err := NewTCPReassembler(nil)
	if err != nil {
		t.Fatalf("failed to create reassembler: %v", err)
	}

	streamHandlerCalled := false
	closedHandlerCalled := false

	reassembler.SetStreamHandler(func(stream *Stream, data []byte, isClient bool) {
		streamHandlerCalled = true
	})

	reassembler.SetClosedHandler(func(stream *Stream) {
		closedHandlerCalled = true
	})

	// Handlers should be set but not called yet
	if streamHandlerCalled || closedHandlerCalled {
		t.Error("handlers should not be called before processing packets")
	}
}

func TestTCPReassemblerActiveStreams(t *testing.T) {
	reassembler, err := NewTCPReassembler(nil)
	if err != nil {
		t.Fatalf("failed to create reassembler: %v", err)
	}

	if reassembler.ActiveStreams() != 0 {
		t.Errorf("expected 0 active streams, got %d", reassembler.ActiveStreams())
	}
}

func TestTCPReassemblerTotalBufferedPages(t *testing.T) {
	reassembler, err := NewTCPReassembler(nil)
	if err != nil {
		t.Fatalf("failed to create reassembler: %v", err)
	}

	if reassembler.TotalBufferedPages() != 0 {
		t.Errorf("expected 0 buffered pages, got %d", reassembler.TotalBufferedPages())
	}
}

func TestStreamUserData(t *testing.T) {
	stream := &Stream{
		ID:         "test-stream",
		ClientIP:   net.ParseIP("192.168.1.1"),
		ServerIP:   net.ParseIP("192.168.1.2"),
		ClientPort: 12345,
		ServerPort: 80,
	}

	// Test setting and getting user data
	userData := map[string]string{"key": "value"}
	stream.SetUserData(userData)

	retrieved := stream.GetUserData()
	if retrieved == nil {
		t.Fatal("expected non-nil user data")
	}

	retrievedMap, ok := retrieved.(map[string]string)
	if !ok {
		t.Fatal("expected map[string]string type")
	}

	if retrievedMap["key"] != "value" {
		t.Errorf("expected value 'value', got '%s'", retrievedMap["key"])
	}
}

func TestProcessTCPSegment(t *testing.T) {
	reassembler, err := NewTCPReassembler(nil)
	if err != nil {
		t.Fatalf("failed to create reassembler: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = reassembler.Start(ctx)
	if err != nil {
		t.Fatalf("failed to start reassembler: %v", err)
	}
	defer reassembler.Stop()

	// Process a TCP segment
	srcIP := net.ParseIP("192.168.1.1")
	dstIP := net.ParseIP("192.168.1.2")
	srcPort := uint16(12345)
	dstPort := uint16(80)
	seq := uint32(1000)
	ack := uint32(0)
	flags := uint8(0x02) // SYN
	payload := []byte{}
	timestamp := time.Now().UnixNano()

	err = reassembler.ProcessTCPSegment(srcIP, dstIP, srcPort, dstPort, seq, ack, flags, payload, timestamp)
	if err != nil {
		t.Errorf("unexpected error processing segment: %v", err)
	}

	stats := reassembler.Stats()
	if stats.PacketsProcessed != 1 {
		t.Errorf("expected 1 packet processed, got %d", stats.PacketsProcessed)
	}
}

func BenchmarkTCPReassemblerProcessSegment(b *testing.B) {
	reassembler, err := NewTCPReassembler(nil)
	if err != nil {
		b.Fatalf("failed to create reassembler: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reassembler.Start(ctx)
	defer reassembler.Stop()

	srcIP := net.ParseIP("192.168.1.1")
	dstIP := net.ParseIP("192.168.1.2")
	payload := make([]byte, 1400)
	timestamp := time.Now().UnixNano()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reassembler.ProcessTCPSegment(
			srcIP, dstIP,
			uint16(i%65535), 80,
			uint32(i*1400), 0,
			0x10, // ACK
			payload,
			timestamp,
		)
	}
}
