// Package integration provides end-to-end integration tests for NFA-Linux
package integration

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cvalentine99/nfa-linux/internal/capture"
	"github.com/cvalentine99/nfa-linux/internal/carver"
	"github.com/cvalentine99/nfa-linux/internal/evidence"
	"github.com/cvalentine99/nfa-linux/internal/integrity"
	"github.com/cvalentine99/nfa-linux/internal/ml"
	"github.com/cvalentine99/nfa-linux/internal/models"
	"github.com/cvalentine99/nfa-linux/internal/parser"
	"github.com/cvalentine99/nfa-linux/internal/reassembly"
)

// =============================================================================
// End-to-End Pipeline Tests
// =============================================================================

// TestCaptureToParsingPipeline tests the complete flow from capture to parsing
func TestCaptureToParsingPipeline(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create capture engine
	cfg := capture.DefaultConfig("lo")
	cfg.Mode = capture.ModePCAP // Use PCAP for testing
	
	engine, err := capture.New(cfg)
	if err != nil {
		t.Skipf("Cannot create capture engine: %v", err)
	}

	// Create parsers
	dnsParser := parser.NewDNSParser()
	httpParser := parser.NewHTTPParser()
	tlsParser := parser.NewTLSParser()

	// Track parsed results
	var (
		dnsCount  int64
		httpCount int64
		tlsCount  int64
		mu        sync.Mutex
		results   []interface{}
	)

	// Set up packet handler
	engine.SetHandler(func(data []byte, info *models.PacketInfo) {
		// Try DNS parsing (UDP port 53)
		if info.DstPort == 53 || info.SrcPort == 53 {
			if result, err := dnsParser.Parse(data); err == nil {
				atomic.AddInt64(&dnsCount, 1)
				mu.Lock()
				results = append(results, result)
				mu.Unlock()
			}
		}

		// Try HTTP parsing (TCP port 80)
		if info.DstPort == 80 || info.SrcPort == 80 {
			if result, err := httpParser.ParseRequest(data); err == nil {
				atomic.AddInt64(&httpCount, 1)
				mu.Lock()
				results = append(results, result)
				mu.Unlock()
			}
		}

		// Try TLS parsing (TCP port 443)
		if info.DstPort == 443 || info.SrcPort == 443 {
			if result, err := tlsParser.ParseClientHello(data); err == nil {
				atomic.AddInt64(&tlsCount, 1)
				mu.Lock()
				results = append(results, result)
				mu.Unlock()
			}
		}
	})

	// Start capture
	if err := engine.Start(ctx); err != nil {
		t.Skipf("Cannot start capture: %v", err)
	}

	// Wait for some packets
	time.Sleep(2 * time.Second)

	// Stop capture
	engine.Stop()

	// Log results
	t.Logf("Parsed DNS: %d, HTTP: %d, TLS: %d", dnsCount, httpCount, tlsCount)
}

// TestTCPReassemblyPipeline tests TCP stream reassembly
func TestTCPReassemblyPipeline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create reassembly engine
	cfg := &reassembly.Config{
		MaxBufferedPagesPerConnection: 1000,
		MaxBufferedPagesTotal:         10000,
		MaxConnections:                1000,
		FlushInterval:                 time.Second,
	}

	engine, err := reassembly.New(cfg)
	if err != nil {
		t.Fatalf("Failed to create reassembly engine: %v", err)
	}

	var reassembledStreams int64
	var totalBytes int64

	engine.SetStreamHandler(func(stream *reassembly.Stream) {
		atomic.AddInt64(&reassembledStreams, 1)
		atomic.AddInt64(&totalBytes, int64(len(stream.ClientData)+len(stream.ServerData)))
	})

	engine.Start(ctx)

	// Simulate TCP segments
	srcIP := net.ParseIP("192.168.1.1")
	dstIP := net.ParseIP("192.168.1.2")
	srcPort := uint16(12345)
	dstPort := uint16(80)

	// Send HTTP request in segments
	httpRequest := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	
	// Segment 1
	engine.ProcessTCPSegment(srcIP, dstIP, srcPort, dstPort, 1000, httpRequest[:20], true, false, false, time.Now())
	
	// Segment 2
	engine.ProcessTCPSegment(srcIP, dstIP, srcPort, dstPort, 1020, httpRequest[20:40], false, false, false, time.Now())
	
	// Segment 3 with FIN
	engine.ProcessTCPSegment(srcIP, dstIP, srcPort, dstPort, 1040, httpRequest[40:], false, true, false, time.Now())

	// Wait for processing
	time.Sleep(500 * time.Millisecond)

	engine.Stop()

	t.Logf("Reassembled streams: %d, Total bytes: %d", reassembledStreams, totalBytes)
}

// TestFileCarverPipeline tests file carving from network data
func TestFileCarverPipeline(t *testing.T) {
	// Create temporary output directory
	tmpDir, err := os.MkdirTemp("", "nfa-carver-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := &carver.Config{
		OutputDir:      tmpDir,
		MaxFileSize:    10 * 1024 * 1024, // 10MB
		MinFileSize:    100,
		EnableHashing:  true,
		HashAlgorithm:  "blake3",
		ScanEmbedded:   true,
		ThreatDetection: true,
	}

	carverEngine, err := carver.New(cfg)
	if err != nil {
		t.Fatalf("Failed to create carver: %v", err)
	}

	// Create test data with embedded files
	testData := createTestDataWithFiles(t)

	// Carve files
	results, err := carverEngine.Carve(testData, "192.168.1.1", "192.168.1.2")
	if err != nil {
		t.Fatalf("Carving failed: %v", err)
	}

	t.Logf("Carved %d files", len(results))

	for _, file := range results {
		t.Logf("  - %s (%s, %d bytes, hash: %s)", 
			file.Filename, file.MimeType, file.Size, file.Hash[:16]+"...")
	}
}

// TestEvidencePackagingPipeline tests CASE/UCO evidence packaging
func TestEvidencePackagingPipeline(t *testing.T) {
	// Create temporary output directory
	tmpDir, err := os.MkdirTemp("", "nfa-evidence-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := &evidence.Config{
		CaseName:        "Test Investigation",
		InvestigatorID:  "test-investigator",
		OrganizationID:  "test-org",
		OutputDir:       tmpDir,
		EnableTimestamp: false, // Disable for testing
	}

	packager, err := evidence.New(cfg)
	if err != nil {
		t.Fatalf("Failed to create evidence packager: %v", err)
	}

	// Add test evidence
	flow := &models.Flow{
		ID:        "flow-001",
		SrcIP:     net.ParseIP("192.168.1.1"),
		DstIP:     net.ParseIP("192.168.1.2"),
		SrcPort:   12345,
		DstPort:   443,
		Protocol:  models.ProtocolTCP,
		StartTime: time.Now().Add(-5 * time.Minute),
		EndTime:   time.Now(),
		BytesSent: 1024,
		BytesRecv: 2048,
	}

	packager.AddFlow(flow)

	// Add carved file
	carvedFile := &models.CarvedFile{
		ID:       "file-001",
		Filename: "test.pdf",
		MimeType: "application/pdf",
		Size:     1024,
		Hash:     "abc123def456",
		SrcIP:    "192.168.1.1",
		DstIP:    "192.168.1.2",
	}

	packager.AddFile(carvedFile)

	// Export evidence
	outputPath := filepath.Join(tmpDir, "evidence.json")
	if err := packager.ExportJSON(outputPath); err != nil {
		t.Fatalf("Failed to export evidence: %v", err)
	}

	// Verify output exists
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Error("Evidence file was not created")
	}

	// Read and validate JSON structure
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read evidence file: %v", err)
	}

	if !bytes.Contains(data, []byte("@context")) {
		t.Error("Evidence JSON missing @context")
	}

	if !bytes.Contains(data, []byte("uco-observable")) {
		t.Error("Evidence JSON missing UCO observable references")
	}

	t.Logf("Evidence package size: %d bytes", len(data))
}

// TestIntegrityVerificationPipeline tests BLAKE3 hashing and verification
func TestIntegrityVerificationPipeline(t *testing.T) {
	// Create test data
	testData := []byte("This is test data for integrity verification")

	// Hash the data
	hasher := integrity.NewBLAKE3Hasher()
	hash1 := hasher.Hash(testData)

	// Verify same data produces same hash
	hash2 := hasher.Hash(testData)
	if hash1 != hash2 {
		t.Error("Same data produced different hashes")
	}

	// Verify different data produces different hash
	modifiedData := append(testData, byte('!'))
	hash3 := hasher.Hash(modifiedData)
	if hash1 == hash3 {
		t.Error("Different data produced same hash")
	}

	// Test Merkle tree
	chunks := [][]byte{
		[]byte("chunk1"),
		[]byte("chunk2"),
		[]byte("chunk3"),
		[]byte("chunk4"),
	}

	tree, err := integrity.NewMerkleTree(chunks)
	if err != nil {
		t.Fatalf("Failed to create Merkle tree: %v", err)
	}

	rootHash := tree.Root()
	t.Logf("Merkle root: %s", rootHash)

	// Generate and verify proof for chunk 2
	proof, err := tree.GenerateProof(1)
	if err != nil {
		t.Fatalf("Failed to generate proof: %v", err)
	}

	if !tree.VerifyProof(chunks[1], proof, rootHash) {
		t.Error("Merkle proof verification failed")
	}

	// Test hash chain
	chain := integrity.NewHashChain()
	
	for i := 0; i < 10; i++ {
		chain.Add([]byte("entry " + string(rune('0'+i))))
	}

	if !chain.Verify() {
		t.Error("Hash chain verification failed")
	}

	t.Logf("Hash chain length: %d, head: %s", chain.Length(), chain.Head()[:16]+"...")
}

// TestMLPipelineIntegration tests ML pipeline integration
func TestMLPipelineIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping ML integration test in short mode")
	}

	// Test anomaly detector initialization and basic operation
	detector := ml.NewAnomalyDetector(&ml.AnomalyConfig{
		WindowSize:    100,
		ZScoreThreshold: 3.0,
		IQRMultiplier:   1.5,
		MADMultiplier:   3.0,
	})

	// Feed some normal data points
	for i := 0; i < 50; i++ {
		result := detector.Detect(float64(100 + i%10))
		if result.IsAnomaly {
			t.Logf("Unexpected anomaly at index %d", i)
		}
	}

	// Feed an anomalous data point
	result := detector.Detect(1000.0)
	t.Logf("Anomaly detection result for outlier: IsAnomaly=%v, Score=%.2f", result.IsAnomaly, result.Score)

	// Test traffic classifier initialization
	classifier := ml.NewTrafficClassifier(&ml.ClassifierConfig{
		ConfidenceThreshold: 0.7,
		MaxCacheSize:       1000,
		CacheTTL:           time.Minute * 5,
	})

	// Create a test flow for classification
	testFlow := &models.Flow{
		SrcIP:        net.ParseIP("192.168.1.100"),
		DstIP:        net.ParseIP("8.8.8.8"),
		SrcPort:      54321,
		DstPort:      443,
		Protocol:     models.ProtocolTCP,
		PacketCount:  100,
		ByteCount:    50000,
	}

	classResult := classifier.Classify(testFlow)
	t.Logf("Traffic classification: Category=%s, Confidence=%.2f", classResult.Category, classResult.Confidence)

	// Verify classifier returned a valid result
	if classResult.Category == "" {
		t.Error("Classifier returned empty category")
	}

	t.Log("ML pipeline integration test completed successfully")
}

// =============================================================================
// Stress Tests
// =============================================================================

// TestHighVolumePacketProcessing tests processing under high load
func TestHighVolumePacketProcessing(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create worker pool
	poolCfg := &capture.WorkerPoolConfig{
		NumWorkers:    8,
		BatchSize:     64,
		ChannelSize:   4096,
		MaxPacketSize: 1500,
	}

	pool := capture.NewWorkerPool(poolCfg)

	var processed int64
	pool.SetHandler(func(data []byte, info *models.PacketInfo) {
		atomic.AddInt64(&processed, 1)
	})

	pool.Start(ctx)

	// Generate high volume of packets
	const numPackets = 1000000
	packetData := make([]byte, 1500)
	timestamp := time.Now().UnixNano()

	start := time.Now()

	for i := 0; i < numPackets; i++ {
		pool.SubmitPacket(packetData, timestamp)
	}

	// Wait for processing
	time.Sleep(5 * time.Second)
	pool.Stop()

	elapsed := time.Since(start)
	pps := float64(processed) / elapsed.Seconds()

	t.Logf("Processed %d packets in %v (%.2f pps)", processed, elapsed, pps)

	// Verify we processed most packets
	if processed < numPackets*90/100 {
		t.Errorf("Only processed %d/%d packets (%.1f%%)", 
			processed, numPackets, float64(processed)/float64(numPackets)*100)
	}
}

// TestConcurrentParserAccess tests parsers under concurrent access
func TestConcurrentParserAccess(t *testing.T) {
	dnsParser := parser.NewDNSParser()
	httpParser := parser.NewHTTPParser()
	tlsParser := parser.NewTLSParser()

	// DNS test payload
	dnsPayload := []byte{
		0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x06, 'g', 'o', 'o', 'g', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00, 0x00, 0x01, 0x00, 0x01,
	}

	// HTTP test payload
	httpPayload := []byte("GET / HTTP/1.1\r\nHost: test.com\r\n\r\n")

	var wg sync.WaitGroup
	const numGoroutines = 100
	const iterations = 1000

	for i := 0; i < numGoroutines; i++ {
		wg.Add(3)

		// DNS parser goroutine
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_, _ = dnsParser.Parse(dnsPayload)
			}
		}()

		// HTTP parser goroutine
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_, _ = httpParser.ParseRequest(httpPayload)
			}
		}()

		// TLS parser goroutine
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_, _ = tlsParser.ParseClientHello([]byte{0x16, 0x03, 0x01})
			}
		}()
	}

	wg.Wait()
	t.Log("Concurrent parser access test passed")
}

// TestMemoryStability tests for memory leaks under sustained load
func TestMemoryStability(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory stability test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create reassembly engine with memory limits
	cfg := &reassembly.Config{
		MaxBufferedPagesPerConnection: 100,
		MaxBufferedPagesTotal:         1000,
		MaxConnections:                100,
		FlushInterval:                 100 * time.Millisecond,
	}

	engine, err := reassembly.New(cfg)
	if err != nil {
		t.Fatalf("Failed to create reassembly engine: %v", err)
	}

	engine.SetStreamHandler(func(stream *reassembly.Stream) {
		// Process stream
	})

	engine.Start(ctx)

	// Simulate sustained traffic
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				srcIP := net.ParseIP("192.168.1.1")
				dstIP := net.ParseIP("192.168.1.2")
				data := make([]byte, 1000)
				
				engine.ProcessTCPSegment(
					srcIP, dstIP,
					uint16(time.Now().UnixNano()%65535),
					80,
					uint32(time.Now().UnixNano()),
					data,
					true, false, false,
					time.Now(),
				)
			}
		}
	}()

	// Run for test duration
	<-ctx.Done()
	engine.Stop()

	t.Log("Memory stability test completed")
}

// =============================================================================
// Helper Functions
// =============================================================================

// createTestDataWithFiles creates test data containing embedded files
func createTestDataWithFiles(t *testing.T) []byte {
	t.Helper()

	var buf bytes.Buffer

	// Add some random data
	buf.Write(bytes.Repeat([]byte{0x00}, 100))

	// Add PNG signature
	pngSignature := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	buf.Write(pngSignature)
	
	// Add minimal PNG IHDR chunk
	ihdr := []byte{
		0x00, 0x00, 0x00, 0x0D, // Length
		0x49, 0x48, 0x44, 0x52, // "IHDR"
		0x00, 0x00, 0x00, 0x01, // Width: 1
		0x00, 0x00, 0x00, 0x01, // Height: 1
		0x08, 0x02,             // Bit depth, color type
		0x00, 0x00, 0x00,       // Compression, filter, interlace
		0x90, 0x77, 0x53, 0xDE, // CRC
	}
	buf.Write(ihdr)

	// Add IEND chunk
	iend := []byte{
		0x00, 0x00, 0x00, 0x00, // Length
		0x49, 0x45, 0x4E, 0x44, // "IEND"
		0xAE, 0x42, 0x60, 0x82, // CRC
	}
	buf.Write(iend)

	// Add more random data
	buf.Write(bytes.Repeat([]byte{0xFF}, 100))

	// Add PDF signature
	pdfSignature := []byte("%PDF-1.4\n")
	buf.Write(pdfSignature)
	buf.Write([]byte("1 0 obj\n<< /Type /Catalog >>\nendobj\n"))
	buf.Write([]byte("%%EOF\n"))

	// Add trailing data
	buf.Write(bytes.Repeat([]byte{0x00}, 50))

	return buf.Bytes()
}

// createTCPPacket creates a mock TCP packet for testing
func createTCPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq uint32, payload []byte) []byte {
	// Simplified TCP packet structure for testing
	var buf bytes.Buffer

	// IP header (simplified)
	buf.WriteByte(0x45) // Version + IHL
	buf.WriteByte(0x00) // TOS
	binary.Write(&buf, binary.BigEndian, uint16(40+len(payload))) // Total length
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00}) // ID, flags, fragment
	buf.WriteByte(64) // TTL
	buf.WriteByte(6)  // Protocol: TCP
	buf.Write([]byte{0x00, 0x00}) // Checksum
	buf.Write(srcIP.To4())
	buf.Write(dstIP.To4())

	// TCP header
	binary.Write(&buf, binary.BigEndian, srcPort)
	binary.Write(&buf, binary.BigEndian, dstPort)
	binary.Write(&buf, binary.BigEndian, seq)
	binary.Write(&buf, binary.BigEndian, uint32(0)) // Ack
	buf.WriteByte(0x50) // Data offset
	buf.WriteByte(0x18) // Flags: PSH, ACK
	binary.Write(&buf, binary.BigEndian, uint16(65535)) // Window
	buf.Write([]byte{0x00, 0x00}) // Checksum
	buf.Write([]byte{0x00, 0x00}) // Urgent pointer

	// Payload
	buf.Write(payload)

	return buf.Bytes()
}
