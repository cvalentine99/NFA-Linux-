// Package benchmark provides comprehensive performance benchmarks for NFA-Linux
package benchmark

import (
	"bytes"
	"context"
	"crypto/rand"
	"net"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cvalentine99/nfa-linux/internal/capture"
	"github.com/cvalentine99/nfa-linux/internal/integrity"
	"github.com/cvalentine99/nfa-linux/internal/models"
	"github.com/cvalentine99/nfa-linux/internal/parser"
)

// =============================================================================
// Packet Processing Benchmarks
// =============================================================================

// BenchmarkPacketThroughput measures raw packet processing throughput
func BenchmarkPacketThroughput(b *testing.B) {
	sizes := []int{64, 128, 256, 512, 1024, 1500, 9000}

	for _, size := range sizes {
		b.Run(formatSize(size), func(b *testing.B) {
			data := make([]byte, size)
			rand.Read(data)

			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				// Simulate packet processing
				processPacket(data)
			}
		})
	}
}

// BenchmarkWorkerPoolThroughput measures worker pool throughput
func BenchmarkWorkerPoolThroughput(b *testing.B) {
	workerCounts := []int{1, 2, 4, 8, 16}

	for _, workers := range workerCounts {
		b.Run(formatWorkers(workers), func(b *testing.B) {
			cfg := &capture.WorkerPoolConfig{
				NumWorkers:    workers,
				BatchSize:     64,
				ChannelSize:   4096,
				MaxPacketSize: 1500,
			}

			pool := capture.NewWorkerPool(cfg)

			var processed int64
			pool.SetHandler(func(data []byte, info *models.PacketInfo) {
				atomic.AddInt64(&processed, 1)
			})

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			pool.Start(ctx)
			defer pool.Stop()

			data := make([]byte, 1500)
			timestamp := time.Now().UnixNano()

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				pool.SubmitPacket(data, timestamp)
			}

			// Wait for processing
			time.Sleep(100 * time.Millisecond)
		})
	}
}

// BenchmarkWorkerPoolParallel measures parallel submission performance
func BenchmarkWorkerPoolParallel(b *testing.B) {
	cfg := &capture.WorkerPoolConfig{
		NumWorkers:    runtime.NumCPU(),
		BatchSize:     64,
		ChannelSize:   8192,
		MaxPacketSize: 1500,
	}

	pool := capture.NewWorkerPool(cfg)
	pool.SetHandler(func(data []byte, info *models.PacketInfo) {})

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

// =============================================================================
// Parser Benchmarks
// =============================================================================

// BenchmarkDNSParser measures DNS parsing performance
func BenchmarkDNSParser(b *testing.B) {
	payloads := map[string][]byte{
		"simple_query": {
			0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x06, 'g', 'o', 'o', 'g', 'l', 'e',
			0x03, 'c', 'o', 'm',
			0x00, 0x00, 0x01, 0x00, 0x01,
		},
		"long_domain": createLongDomainQuery(),
	}

	parser := parser.NewDNSParser()

	for name, payload := range payloads {
		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, _ = parser.Parse(payload)
			}
		})
	}
}

// BenchmarkHTTPParser measures HTTP parsing performance
func BenchmarkHTTPParser(b *testing.B) {
	requests := map[string][]byte{
		"simple_get":    []byte("GET / HTTP/1.1\r\nHost: test.com\r\n\r\n"),
		"with_headers":  []byte("GET /api/data HTTP/1.1\r\nHost: api.test.com\r\nUser-Agent: Test/1.0\r\nAccept: application/json\r\nAuthorization: Bearer token123\r\n\r\n"),
		"post_with_body": []byte("POST /api/submit HTTP/1.1\r\nHost: api.test.com\r\nContent-Type: application/json\r\nContent-Length: 50\r\n\r\n{\"key\":\"value\",\"number\":123,\"array\":[1,2,3,4,5]}"),
	}

	parser := parser.NewHTTPParser()

	for name, payload := range requests {
		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, _ = parser.ParseRequest(payload)
			}
		})
	}
}

// BenchmarkTLSParser measures TLS ClientHello parsing performance
func BenchmarkTLSParser(b *testing.B) {
	clientHello := createTLSClientHello()
	parser := parser.NewTLSParser()

	b.SetBytes(int64(len(clientHello)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = parser.ParseClientHello(clientHello)
	}
}

// BenchmarkJA3Computation measures JA3 fingerprint computation
func BenchmarkJA3Computation(b *testing.B) {
	parser := parser.NewTLSParser()
	hello := &parser.TLSClientHello{
		Version:      0x0303,
		CipherSuites: []uint16{0xc02f, 0xc030, 0xc02b, 0xc02c, 0x009e, 0x009f, 0xc027, 0xc028},
		Extensions:   []uint16{0x0000, 0x000b, 0x000a, 0x0023, 0x000d, 0x0005, 0x0010, 0x0011},
		SupportedGroups: []uint16{0x001d, 0x0017, 0x0018, 0x0019, 0x0100},
		ECPointFormats: []uint8{0x00, 0x01, 0x02},
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = parser.ComputeJA3(hello)
	}
}

// BenchmarkJA4Computation measures JA4 fingerprint computation
func BenchmarkJA4Computation(b *testing.B) {
	parser := parser.NewTLSParser()
	hello := &parser.TLSClientHello{
		Version:       0x0303,
		CipherSuites:  []uint16{0x1301, 0x1302, 0x1303, 0xc02f, 0xc030},
		Extensions:    []uint16{0x0000, 0x000b, 0x000a, 0x0023, 0x002b},
		ServerName:    "example.com",
		ALPNProtocols: []string{"h2", "http/1.1"},
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = parser.ComputeJA4(hello)
	}
}

// BenchmarkQUICParser measures QUIC packet parsing performance
func BenchmarkQUICParser(b *testing.B) {
	packets := map[string][]byte{
		"initial": createQUICInitialPacket(),
		"short":   createQUICShortPacket(),
	}

	parser := parser.NewQUICParser()

	for name, packet := range packets {
		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(len(packet)))
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, _ = parser.ParsePacket(packet)
			}
		})
	}
}

// BenchmarkSMBParser measures SMB header parsing performance
func BenchmarkSMBParser(b *testing.B) {
	header := createSMB2Header()
	parser := parser.NewSMBParser()

	b.SetBytes(int64(len(header)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = parser.ParseHeader(header)
	}
}

// =============================================================================
// Hashing Benchmarks
// =============================================================================

// BenchmarkBLAKE3Hashing measures BLAKE3 hashing performance
func BenchmarkBLAKE3Hashing(b *testing.B) {
	sizes := []int{64, 256, 1024, 4096, 16384, 65536, 1048576}
	hasher := integrity.NewBLAKE3Hasher()

	for _, size := range sizes {
		b.Run(formatSize(size), func(b *testing.B) {
			data := make([]byte, size)
			rand.Read(data)

			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_ = hasher.Hash(data)
			}
		})
	}
}

// BenchmarkMerkleTreeCreation measures Merkle tree creation performance
func BenchmarkMerkleTreeCreation(b *testing.B) {
	chunkCounts := []int{4, 16, 64, 256, 1024}

	for _, count := range chunkCounts {
		b.Run(formatChunks(count), func(b *testing.B) {
			chunks := make([][]byte, count)
			for i := range chunks {
				chunks[i] = make([]byte, 1024)
				rand.Read(chunks[i])
			}

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, _ = integrity.NewMerkleTree(chunks)
			}
		})
	}
}

// BenchmarkMerkleProofGeneration measures Merkle proof generation
func BenchmarkMerkleProofGeneration(b *testing.B) {
	chunks := make([][]byte, 1024)
	for i := range chunks {
		chunks[i] = make([]byte, 1024)
		rand.Read(chunks[i])
	}

	tree, _ := integrity.NewMerkleTree(chunks)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = tree.GenerateProof(i % len(chunks))
	}
}

// =============================================================================
// Memory Allocation Benchmarks
// =============================================================================

// BenchmarkPacketAllocation measures packet struct allocation
func BenchmarkPacketAllocation(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		pkt := &models.Packet{
			ID:        "pkt-bench",
			Timestamp: time.Now(),
			Length:    1500,
			SrcIP:     net.ParseIP("192.168.1.1"),
			DstIP:     net.ParseIP("192.168.1.2"),
			Protocol:  "TCP",
			SrcPort:   12345,
			DstPort:   80,
			Payload:   make([]byte, 1460),
		}
		_ = pkt
	}
}

// BenchmarkFlowAllocation measures flow struct allocation
func BenchmarkFlowAllocation(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		flow := &models.Flow{
			ID:        "flow-bench",
			SrcIP:     net.ParseIP("192.168.1.1"),
			DstIP:     net.ParseIP("192.168.1.2"),
			SrcPort:   12345,
			DstPort:   443,
			Protocol:  models.ProtocolTCP,
			StartTime: time.Now(),
			EndTime:   time.Now(),
			BytesSent: 1024,
			BytesRecv: 2048,
		}
		_ = flow
	}
}

// BenchmarkSyncPoolUsage measures sync.Pool effectiveness
func BenchmarkSyncPoolUsage(b *testing.B) {
	pool := &sync.Pool{
		New: func() interface{} {
			return make([]byte, 1500)
		},
	}

	b.Run("with_pool", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			buf := pool.Get().([]byte)
			// Use buffer
			buf[0] = byte(i)
			pool.Put(buf)
		}
	})

	b.Run("without_pool", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			buf := make([]byte, 1500)
			// Use buffer
			buf[0] = byte(i)
			_ = buf
		}
	})
}

// =============================================================================
// Concurrency Benchmarks
// =============================================================================

// BenchmarkAtomicOperations measures atomic operation performance
func BenchmarkAtomicOperations(b *testing.B) {
	b.Run("atomic_add", func(b *testing.B) {
		var counter int64
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				atomic.AddInt64(&counter, 1)
			}
		})
	})

	b.Run("atomic_load_store", func(b *testing.B) {
		var value int64
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				v := atomic.LoadInt64(&value)
				atomic.StoreInt64(&value, v+1)
			}
		})
	})

	b.Run("atomic_cas", func(b *testing.B) {
		var value int64
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				for {
					old := atomic.LoadInt64(&value)
					if atomic.CompareAndSwapInt64(&value, old, old+1) {
						break
					}
				}
			}
		})
	})
}

// BenchmarkMutexContention measures mutex performance under contention
func BenchmarkMutexContention(b *testing.B) {
	b.Run("low_contention", func(b *testing.B) {
		var mu sync.Mutex
		var counter int64

		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				mu.Lock()
				counter++
				mu.Unlock()
			}
		})
	})

	b.Run("rwmutex_read_heavy", func(b *testing.B) {
		var mu sync.RWMutex
		var counter int64

		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				mu.RLock()
				_ = counter
				mu.RUnlock()
			}
		})
	})
}

// BenchmarkChannelThroughput measures channel throughput
func BenchmarkChannelThroughput(b *testing.B) {
	sizes := []int{0, 1, 10, 100, 1000}

	for _, size := range sizes {
		b.Run(formatBuffer(size), func(b *testing.B) {
			ch := make(chan int, size)

			go func() {
				for i := 0; i < b.N; i++ {
					ch <- i
				}
				close(ch)
			}()

			b.ResetTimer()
			for range ch {
			}
		})
	}
}

// =============================================================================
// Helper Functions
// =============================================================================

func processPacket(data []byte) {
	// Simulate minimal packet processing
	_ = len(data)
}

func formatSize(size int) string {
	if size >= 1024*1024 {
		return strconv.Itoa(size/(1024*1024)) + "MB"
	}
	if size >= 1024 {
		return strconv.Itoa(size/1024) + "KB"
	}
	return strconv.Itoa(size) + "B"
}

func formatWorkers(n int) string {
	return strconv.Itoa(n) + "_workers"
}

func formatChunks(n int) string {
	return strconv.Itoa(n) + "_chunks"
}

func formatBuffer(n int) string {
	if n == 0 {
		return "unbuffered"
	}
	return "buf_" + strconv.Itoa(n)
}

func createLongDomainQuery() []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	
	// Long subdomain chain
	for i := 0; i < 10; i++ {
		buf.WriteByte(10)
		buf.WriteString("subdomain" + strconv.Itoa(i))
	}
	buf.WriteByte(7)
	buf.WriteString("example")
	buf.WriteByte(3)
	buf.WriteString("com")
	buf.WriteByte(0)
	buf.Write([]byte{0x00, 0x01, 0x00, 0x01})
	
	return buf.Bytes()
}

func createTLSClientHello() []byte {
	return []byte{
		0x16, 0x03, 0x01, 0x00, 0x5d,
		0x01, 0x00, 0x00, 0x59,
		0x03, 0x03,
		// Random (32 bytes)
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x00,       // Session ID length
		0x00, 0x04, // Cipher suites length
		0xc0, 0x2f, 0xc0, 0x30,
		0x01, 0x00, // Compression
		0x00, 0x1e, // Extensions length
		// SNI extension
		0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x00, 0x0b,
		'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
	}
}

func createQUICInitialPacket() []byte {
	return []byte{
		0xc0,                         // Long header, Initial
		0x00, 0x00, 0x00, 0x01,       // Version
		0x08,                         // DCID length
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DCID
		0x00,                         // SCID length
		0x00,                         // Token length
		0x00, 0x10,                   // Length
		// Encrypted payload
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
}

func createQUICShortPacket() []byte {
	return []byte{
		0x40, // Short header
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DCID
		0x00, 0x01, 0x02, 0x03, // Packet number + payload
	}
}

func createSMB2Header() []byte {
	return []byte{
		0xfe, 'S', 'M', 'B', // Protocol ID
		0x40, 0x00, // Structure size
		0x00, 0x00, // Credit charge
		0x00, 0x00, 0x00, 0x00, // Status
		0x00, 0x00, // Command
		0x00, 0x00, // Credit request
		0x00, 0x00, 0x00, 0x00, // Flags
		0x00, 0x00, 0x00, 0x00, // Next command
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Message ID
		0x00, 0x00, 0x00, 0x00, // Process ID
		0x00, 0x00, 0x00, 0x00, // Tree ID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Session ID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
}
