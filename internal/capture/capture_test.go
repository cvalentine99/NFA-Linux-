package capture

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cvalentine99/nfa-linux/internal/models"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig("eth0")

	if cfg.Interface != "eth0" {
		t.Errorf("expected interface eth0, got %s", cfg.Interface)
	}

	if cfg.Mode != ModeAFXDP {
		t.Errorf("expected mode AF_XDP, got %d", cfg.Mode)
	}

	if cfg.SnapLen != 65535 {
		t.Errorf("expected snaplen 65535, got %d", cfg.SnapLen)
	}

	if !cfg.Promiscuous {
		t.Error("expected promiscuous mode to be enabled")
	}

	if cfg.RingBufferSize != 64*1024*1024 {
		t.Errorf("expected ring buffer size 64MB, got %d", cfg.RingBufferSize)
	}
}

func TestCaptureEngineCreation(t *testing.T) {
	// Test with nil config
	_, err := New(nil)
	if err == nil {
		t.Error("expected error with nil config")
	}

	// Test with empty interface
	cfg := &Config{}
	_, err = New(cfg)
	if err == nil {
		t.Error("expected error with empty interface")
	}

	// Test with valid config
	cfg = DefaultConfig("lo")
	engine, err := New(cfg)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if engine == nil {
		t.Error("expected non-nil engine")
	}
}

func TestCaptureEngineStats(t *testing.T) {
	cfg := DefaultConfig("lo")
	engine, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	stats := engine.Stats()
	if stats == nil {
		t.Fatal("expected non-nil stats")
	}

	if stats.Interface != "lo" {
		t.Errorf("expected interface lo, got %s", stats.Interface)
	}
}

func TestCaptureEngineHandler(t *testing.T) {
	cfg := DefaultConfig("lo")
	engine, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	handlerCalled := false
	engine.SetHandler(func(data []byte, info *models.PacketInfo) {
		handlerCalled = true
	})

	// Handler should be set but not called yet
	if handlerCalled {
		t.Error("handler should not be called before capture starts")
	}
}

func TestCaptureEngineIsRunning(t *testing.T) {
	cfg := DefaultConfig("lo")
	engine, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	if engine.IsRunning() {
		t.Error("engine should not be running initially")
	}
}

func TestCaptureEngineBPFFilter(t *testing.T) {
	cfg := DefaultConfig("lo")
	engine, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	err = engine.SetBPFFilter("tcp port 80")
	if err != nil {
		t.Errorf("unexpected error setting BPF filter: %v", err)
	}

	stats := engine.Stats()
	if stats.CaptureFilter != "tcp port 80" {
		t.Errorf("expected filter 'tcp port 80', got '%s'", stats.CaptureFilter)
	}
}

func TestWorkerPoolConfig(t *testing.T) {
	cfg := DefaultWorkerPoolConfig()

	if cfg.NumWorkers <= 0 {
		t.Error("expected positive number of workers")
	}

	if cfg.BatchSize <= 0 {
		t.Error("expected positive batch size")
	}

	if cfg.ChannelSize <= 0 {
		t.Error("expected positive channel size")
	}
}

func TestWorkerPoolCreation(t *testing.T) {
	// Test with nil config (should use defaults)
	pool := NewWorkerPool(nil)
	if pool == nil {
		t.Fatal("expected non-nil pool")
	}

	// Test with custom config
	cfg := &WorkerPoolConfig{
		NumWorkers:    4,
		BatchSize:     32,
		ChannelSize:   16,
		MaxPacketSize: 9000,
	}
	pool = NewWorkerPool(cfg)
	if pool == nil {
		t.Fatal("expected non-nil pool")
	}
}

func TestWorkerPoolStartStop(t *testing.T) {
	pool := NewWorkerPool(nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool.Start(ctx)

	// Let workers start
	time.Sleep(10 * time.Millisecond)

	pool.Stop()
}

func TestWorkerPoolStats(t *testing.T) {
	pool := NewWorkerPool(nil)

	processed, batches, dropped := pool.Stats()
	if processed != 0 || batches != 0 || dropped != 0 {
		t.Error("expected zero stats initially")
	}
}

func TestBatchAccumulator(t *testing.T) {
	pool := NewWorkerPool(&WorkerPoolConfig{
		NumWorkers:    2,
		BatchSize:     4,
		ChannelSize:   8,
		MaxPacketSize: 1500,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool.Start(ctx)
	defer pool.Stop()

	acc := NewBatchAccumulator(pool, 100*time.Millisecond)

	// Add packets
	for i := 0; i < 10; i++ {
		data := []byte{0x00, 0x01, 0x02, 0x03}
		acc.Add(data, time.Now().UnixNano())
	}

	// Force flush
	acc.Flush()

	// Wait for processing
	time.Sleep(50 * time.Millisecond)
}

func BenchmarkWorkerPoolSubmit(b *testing.B) {
	pool := NewWorkerPool(&WorkerPoolConfig{
		NumWorkers:    8,
		BatchSize:     64,
		ChannelSize:   256,
		MaxPacketSize: 1500,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool.SetHandler(func(data []byte, info *models.PacketInfo) {
		// Simulate minimal processing
	})

	pool.Start(ctx)
	defer pool.Stop()

	data := make([]byte, 1500)
	timestamp := time.Now().UnixNano()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pool.SubmitPacket(data, timestamp)
	}
}

// Additional comprehensive tests for Phase 7

// TestCaptureConfigValidation validates configuration edge cases
func TestCaptureConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name: "valid AF_XDP config",
			config: &Config{
				Interface:      "eth0",
				Mode:           ModeAFXDP,
				Promiscuous:    true,
				SnapLen:        65535,
				RingBufferSize: 64 * 1024 * 1024,
			},
			wantErr: false,
		},
		{
			name: "valid AF_PACKET config",
			config: &Config{
				Interface:      "eth0",
				Mode:           ModeAFPacket,
				Promiscuous:    true,
				SnapLen:        65535,
				RingBufferSize: 32 * 1024 * 1024,
			},
			wantErr: false,
		},
		{
			name: "valid PCAP config",
			config: &Config{
				Interface: "eth0",
				Mode:      ModePCAP,
				SnapLen:   65535,
			},
			wantErr: false,
		},
		{
			name: "zero snaplen should use default",
			config: &Config{
				Interface: "eth0",
				Mode:      ModePCAP,
				SnapLen:   0,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestCaptureModeFallback tests automatic mode fallback
func TestCaptureModeFallback(t *testing.T) {
	cfg := &Config{
		Interface:      "lo",
		Mode:           ModeAFXDP,
		Promiscuous:    false,
		SnapLen:        65535,
		RingBufferSize: 64 * 1024 * 1024,
	}

	engine, err := New(cfg)
	if err != nil {
		// AF_XDP may not be available, which is expected
		t.Logf("AF_XDP not available (expected in test environment): %v", err)
		
		// Try fallback to AF_PACKET
		cfg.Mode = ModeAFPacket
		engine, err = New(cfg)
		if err != nil {
			t.Logf("AF_PACKET not available: %v", err)
			
			// Try fallback to PCAP
			cfg.Mode = ModePCAP
			engine, err = New(cfg)
			if err != nil {
				t.Skipf("No capture mode available in test environment: %v", err)
			}
		}
	}

	if engine != nil {
		stats := engine.Stats()
		t.Logf("Using capture interface: %s", stats.Interface)
	}
}

// TestConcurrentStatsAccess tests thread-safe stats access
func TestConcurrentStatsAccess(t *testing.T) {
	cfg := DefaultConfig("lo")
	engine, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	var wg sync.WaitGroup
	const numGoroutines = 100
	const iterations = 1000

	// Concurrent stats reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				stats := engine.Stats()
				_ = stats.PacketsReceived
				_ = stats.BytesReceived
			}
		}()
	}

	wg.Wait()
}

// TestWorkerPoolBackpressure tests backpressure handling
func TestWorkerPoolBackpressure(t *testing.T) {
	cfg := &WorkerPoolConfig{
		NumWorkers:    1,
		BatchSize:     2,
		ChannelSize:   4,
		MaxPacketSize: 1500,
	}

	pool := NewWorkerPool(cfg)

	// Set a slow handler to cause backpressure
	pool.SetHandler(func(data []byte, info *models.PacketInfo) {
		time.Sleep(10 * time.Millisecond)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool.Start(ctx)
	defer pool.Stop()

	// Submit more packets than the queue can hold
	data := make([]byte, 100)
	for i := 0; i < 100; i++ {
		pool.SubmitPacket(data, time.Now().UnixNano())
	}

	// Wait for processing
	time.Sleep(200 * time.Millisecond)

	_, _, dropped := pool.Stats()
	t.Logf("Dropped packets due to backpressure: %d", dropped)
}

// TestBatchAccumulatorTimeout tests batch timeout flushing
func TestBatchAccumulatorTimeout(t *testing.T) {
	cfg := &WorkerPoolConfig{
		NumWorkers:    2,
		BatchSize:     100, // Large batch size
		ChannelSize:   8,
		MaxPacketSize: 1500,
	}

	pool := NewWorkerPool(cfg)

	var processedCount int64
	pool.SetHandler(func(data []byte, info *models.PacketInfo) {
		atomic.AddInt64(&processedCount, 1)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool.Start(ctx)
	defer pool.Stop()

	// Use short timeout
	acc := NewBatchAccumulator(pool, 50*time.Millisecond)

	// Add fewer packets than batch size
	for i := 0; i < 5; i++ {
		data := []byte{0x00, 0x01, 0x02, 0x03}
		acc.Add(data, time.Now().UnixNano())
	}

	// Wait for timeout flush
	time.Sleep(100 * time.Millisecond)

	if atomic.LoadInt64(&processedCount) != 5 {
		t.Errorf("Expected 5 processed packets, got %d", processedCount)
	}
}

// BenchmarkCaptureEngineStats benchmarks stats retrieval
func BenchmarkCaptureEngineStats(b *testing.B) {
	cfg := DefaultConfig("lo")
	engine, err := New(cfg)
	if err != nil {
		b.Fatalf("failed to create engine: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = engine.Stats()
	}
}

// BenchmarkWorkerPoolParallel benchmarks parallel packet submission
func BenchmarkWorkerPoolParallel(b *testing.B) {
	pool := NewWorkerPool(&WorkerPoolConfig{
		NumWorkers:    8,
		BatchSize:     64,
		ChannelSize:   1024,
		MaxPacketSize: 1500,
	})

	pool.SetHandler(func(data []byte, info *models.PacketInfo) {
		// Minimal processing
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool.Start(ctx)
	defer pool.Stop()

	data := make([]byte, 1500)
	timestamp := time.Now().UnixNano()

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			pool.SubmitPacket(data, timestamp)
		}
	})
}

// BenchmarkBatchAccumulator benchmarks batch accumulation
func BenchmarkBatchAccumulator(b *testing.B) {
	pool := NewWorkerPool(&WorkerPoolConfig{
		NumWorkers:    4,
		BatchSize:     64,
		ChannelSize:   256,
		MaxPacketSize: 1500,
	})

	pool.SetHandler(func(data []byte, info *models.PacketInfo) {})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool.Start(ctx)
	defer pool.Stop()

	acc := NewBatchAccumulator(pool, 100*time.Millisecond)
	data := make([]byte, 1500)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		acc.Add(data, time.Now().UnixNano())
	}
}
