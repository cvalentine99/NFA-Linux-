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
		// Note: DNS parser expects gopacket.Packet, use ParseWithProtection for raw bytes
		if info.DstPort == 53 || info.SrcPort == 53 {
			if result, err := dnsParser.ParseWithProtection(data, info.SrcIP, info.DstIP, info.TimestampNano); err == nil {
				atomic.AddInt64(&dnsCount, 1)
				mu.Lock()
				results = append(results, result)
				mu.Unlock()
			}
		}

		// Try HTTP parsing (TCP port 80)
		if info.DstPort == 80 || info.SrcPort == 80 {
			if result, err := httpParser.ParseRequest(data, info.TimestampNano); err == nil {
				atomic.AddInt64(&httpCount, 1)
				mu.Lock()
				results = append(results, result)
				mu.Unlock()
			}
		}

		// Try TLS parsing (TCP port 443)
		if info.DstPort == 443 || info.SrcPort == 443 {
			if result, err := tlsParser.ParseClientHello(data, info.TimestampNano); err == nil {
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

	// Use SetStreamCompleteHandler for accumulated data access
	engine.SetStreamCompleteHandler(func(stream *reassembly.Stream) {
		atomic.AddInt64(&reassembledStreams, 1)
		atomic.AddInt64(&totalBytes, int64(len(stream.GetClientData())+len(stream.GetServerData())))
	})

	engine.Start(ctx)

	// Simulate TCP segments
	srcIP := net.ParseIP("192.168.1.1")
	dstIP := net.ParseIP("192.168.1.2")
	srcPort := uint16(12345)
	dstPort := uint16(80)

	// Send HTTP request in segments
	httpRequest := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	
	// TCP flags: SYN=0x02, ACK=0x10, FIN=0x01, PSH=0x08
	const (
		FlagSYN = 0x02
		FlagACK = 0x10
		FlagFIN = 0x01
		FlagPSH = 0x08
	)
	
	// Segment 1 (SYN+ACK to establish, then data)
	engine.ProcessTCPSegment(srcIP, dstIP, srcPort, dstPort, 1000, 0, FlagACK|FlagPSH, httpRequest[:20], time.Now().UnixNano())
	
	// Segment 2
	engine.ProcessTCPSegment(srcIP, dstIP, srcPort, dstPort, 1020, 0, FlagACK|FlagPSH, httpRequest[20:40], time.Now().UnixNano())
	
	// Segment 3 with FIN
	engine.ProcessTCPSegment(srcIP, dstIP, srcPort, dstPort, 1040, 0, FlagACK|FlagFIN|FlagPSH, httpRequest[40:], time.Now().UnixNano())

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
		OutputDir:          tmpDir,
		MaxFileSize:        10 * 1024 * 1024, // 10MB
		MinFileSize:        100,
		EnableHashing:      true,
		HashAlgorithm:      "blake3",
		ExtractDocuments:   true,
		ExtractImages:      true,
		ExtractArchives:    true,
		ExtractExecutables: false, // Safety: don't extract executables by default
		MaxFilesPerStream:  100,
		MaxTotalFiles:      1000,
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
		ID:           "flow-001",
		SrcIP:        net.ParseIP("192.168.1.1"),
		DstIP:        net.ParseIP("192.168.1.2"),
		SrcPort:      12345,
		DstPort:      443,
		Protocol:     6, // TCP
		ProtocolName: "TCP",
		StartTime:    time.Now().Add(-5 * time.Minute),
		EndTime:      time.Now(),
		Bytes:        3072,
		Packets:      10,
	}

	packager.AddFlow(flow)

	// Add carved file
	carvedFile := &models.CarvedFile{
		ID:       "file-001",
		Filename: "test.pdf",
		MimeType: "application/pdf",
		Size:     1024,
		Hash:     "abc123def456",
		SourceIP: net.ParseIP("192.168.1.1"),
		DestIP:   net.ParseIP("192.168.1.2"),
	}

	packager.AddFile(carvedFile)

	// Export evidence
	outputPath := filepath.Join(tmpDir, "evidence.json")
	if err := packager.ExportJSONToFile(outputPath); err != nil {
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
	hash1 := hasher.HashHex(testData)

	// Verify same data produces same hash
	hash2 := hasher.HashHex(testData)
	if hash1 != hash2 {
		t.Error("Same data produced different hashes")
	}

	// Verify different data produces different hash
	modifiedData := append(testData, byte('!'))
	hash3 := hasher.HashHex(modifiedData)
	if hash1 == hash3 {
		t.Error("Different data produced same hash")
	}

	// Test Merkle tree
	tree := integrity.NewMerkleTree(integrity.DefaultMerkleTreeConfig())
	
	// Build tree from test data
	testTreeData := []byte("chunk1chunk2chunk3chunk4")
	if err := tree.BuildFromData(testTreeData); err != nil {
		t.Fatalf("Failed to build Merkle tree: %v", err)
	}

	rootHash := tree.RootHex()
	t.Logf("Merkle root: %s", rootHash)

	// Generate and verify proof for leaf 0
	proof, err := tree.GetProof(0)
	if err != nil {
		t.Fatalf("Failed to generate proof: %v", err)
	}

	valid, err := tree.VerifyProof(proof)
	if err != nil || !valid {
		t.Error("Merkle proof verification failed")
	}

	// Test hash chain
	chain := integrity.NewHashChain()
	
	for i := 0; i < 10; i++ {
		chain.Append([]byte("entry "+string(rune('0'+i))), time.Now().UnixNano())
	}

	valid, invalidIdx := chain.Verify()
	if !valid {
		t.Errorf("Hash chain verification failed at index %d", invalidIdx)
	}

	t.Logf("Hash chain length: %d, latest hash: %s", chain.Length(), chain.LatestHash()[:16]+"...")
}

// TestMLPipelineIntegration tests ML pipeline integration
func TestMLPipelineIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping ML integration test in short mode")
	}

	// Test statistical anomaly detector initialization and basic operation
	featureNames := []string{"bytes", "packets", "duration"}
	detector := ml.NewStatisticalAnomalyDetector(ml.DefaultAnomalyConfig(), featureNames)

	// Feed some normal data points to train
	for i := 0; i < 50; i++ {
		features := []float64{float64(100 + i%10), float64(10 + i%5), float64(1 + i%3)}
		detector.Update(features)
	}

	// Detect on normal data
	ctx := context.Background()
	normalFeatures := []float64{105.0, 12.0, 2.0}
	result, err := detector.Detect(ctx, normalFeatures)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}
	t.Logf("Normal data detection: IsAnomaly=%v, Score=%.2f", result.IsAnomaly, result.Score)

	// Test EWMA detector
	ewma := ml.NewEWMADetector(0.3, 3.0)
	
	// Feed normal values
	for i := 0; i < 20; i++ {
		ewma.Update("test_metric", float64(100+i%10))
	}
	
	// Test anomaly detection
	isAnomaly, deviation := ewma.Detect("test_metric", 1000.0)
	t.Logf("EWMA anomaly detection: IsAnomaly=%v, Deviation=%.2f", isAnomaly, deviation)

	// Test DNS tunneling detector
	dnsDetector := ml.NewDNSTunnelingDetector()
	isTunneling, confidence, reason := dnsDetector.Predict("aGVsbG8gd29ybGQ.example.com")
	t.Logf("DNS tunneling detection: IsTunneling=%v, Confidence=%.2f, Reason=%s", isTunneling, confidence, reason)

	// Test DGA detector
	dgaDetector := ml.NewDGADetector()
	isDGA, dgaScore := dgaDetector.Predict("xyzabc123def.com")
	t.Logf("DGA detection: IsDGA=%v, Score=%.2f", isDGA, dgaScore)

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
				_, _ = dnsParser.ParseWithProtection(dnsPayload, net.ParseIP("192.168.1.1"), net.ParseIP("8.8.8.8"), time.Now().UnixNano())
			}
		}()

		// HTTP parser goroutine
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_, _ = httpParser.ParseRequest(httpPayload, time.Now().UnixNano())
			}
		}()

		// TLS parser goroutine
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_, _ = tlsParser.ParseClientHello([]byte{0x16, 0x03, 0x01}, time.Now().UnixNano())
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

	// Use SetStreamCompleteHandler for accumulated data access
	engine.SetStreamCompleteHandler(func(stream *reassembly.Stream) {
		// Process stream
		_ = stream.GetClientData()
		_ = stream.GetServerData()
	})

	engine.Start(ctx)

	// TCP flags
	const FlagACK = 0x10

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
					0,
					FlagACK,
					data,
					time.Now().UnixNano(),
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
