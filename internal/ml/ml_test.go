package ml

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/cvalentine99/nfa-linux/internal/models"
)

func TestFeatureExtractor_ExtractFlowFeatures(t *testing.T) {
	extractor := NewFeatureExtractor()

	flow := &models.Flow{
		ID:           "test-flow-1",
		SrcIP:        net.ParseIP("192.168.1.100"),
		DstIP:        net.ParseIP("10.0.0.1"),
		SrcPort:      45678,
		DstPort:      443,
		Protocol:     6, // TCP
		ProtocolName: "TCP",
		StartTime:    time.Now().Add(-5 * time.Second),
		EndTime:      time.Now(),
		Packets:      100,
		Bytes:        50000,
		PacketCount:  100,
		ByteCount:    50000,
	}

	features := extractor.ExtractFlowFeatures(flow)

	if features == nil {
		t.Fatal("Expected non-nil features")
	}

	// Check basic features
	if features.Duration != 5.0 {
		t.Errorf("Expected duration 5.0, got %f", features.Duration)
	}

	if features.TotalPackets != 100 {
		t.Errorf("Expected 100 packets, got %f", features.TotalPackets)
	}

	if features.TotalBytes != 50000 {
		t.Errorf("Expected 50000 bytes, got %f", features.TotalBytes)
	}

	// Check derived features
	if features.PacketsPerSec != 20.0 {
		t.Errorf("Expected 20 packets/sec, got %f", features.PacketsPerSec)
	}

	if features.BytesPerSec != 10000.0 {
		t.Errorf("Expected 10000 bytes/sec, got %f", features.BytesPerSec)
	}

	// Check protocol flags (float32: 1.0 = true, 0.0 = false)
	if features.IsTCP != 1.0 {
		t.Errorf("Expected IsTCP to be 1.0, got %f", features.IsTCP)
	}

	if features.IsUDP != 0.0 {
		t.Errorf("Expected IsUDP to be 0.0, got %f", features.IsUDP)
	}

	// Check port classification
	if features.IsHTTPS != 1.0 {
		t.Errorf("Expected IsHTTPS to be 1.0 for port 443, got %f", features.IsHTTPS)
	}
}

func TestFeatureExtractor_ToSlice(t *testing.T) {
	extractor := NewFeatureExtractor()

	flow := &models.Flow{
		ID:           "test-flow-2",
		SrcIP:        net.ParseIP("192.168.1.100"),
		DstIP:        net.ParseIP("10.0.0.1"),
		SrcPort:      45678,
		DstPort:      80,
		Protocol:     6, // TCP
		ProtocolName: "TCP",
		StartTime:    time.Now().Add(-1 * time.Second),
		EndTime:      time.Now(),
		Packets:      10,
		Bytes:        1000,
		PacketCount:  10,
		ByteCount:    1000,
	}

	features := extractor.ExtractFlowFeatures(flow)
	slice := features.ToSlice()

	if len(slice) == 0 {
		t.Fatal("Expected non-empty feature slice")
	}

	// Verify slice length matches expected feature count
	expectedFeatures := 38 // Based on ToSlice implementation
	if len(slice) != expectedFeatures {
		t.Errorf("Expected %d features, got %d", expectedFeatures, len(slice))
	}
}

func TestStatisticalAnomalyDetector_Update(t *testing.T) {
	featureNames := []string{"feature1", "feature2", "feature3"}
	detector := NewStatisticalAnomalyDetector(DefaultAnomalyConfig(), featureNames)

	// Add samples
	for i := 0; i < 100; i++ {
		sample := []float64{float64(i), float64(i * 2), float64(i * 3)}
		detector.Update(sample)
	}

	stats := detector.GetStatistics()
	if len(stats) != 3 {
		t.Errorf("Expected 3 feature stats, got %d", len(stats))
	}
}

func TestStatisticalAnomalyDetector_Detect(t *testing.T) {
	featureNames := []string{"feature1", "feature2", "feature3"}
	config := DefaultAnomalyConfig()
	config.MinSamples = 10
	detector := NewStatisticalAnomalyDetector(config, featureNames)

	// Train with normal samples
	for i := 0; i < 100; i++ {
		sample := []float64{10.0, 20.0, 30.0}
		detector.Update(sample)
	}

	ctx := context.Background()

	// Test normal sample
	normalSample := []float64{10.0, 20.0, 30.0}
	result, err := detector.Detect(ctx, normalSample)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if result.IsAnomaly {
		t.Error("Normal sample should not be detected as anomaly")
	}

	// Test anomalous sample (far from mean)
	anomalousSample := []float64{1000.0, 2000.0, 3000.0}
	result, err = detector.Detect(ctx, anomalousSample)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if !result.IsAnomaly {
		t.Error("Anomalous sample should be detected as anomaly")
	}
}

func TestDNSTunnelingDetector_Predict(t *testing.T) {
	detector := NewDNSTunnelingDetector()

	tests := []struct {
		domain          string
		expectTunneling bool
	}{
		{"google.com", false},
		{"example.com", false},
		{"aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q.tunnel.example.com", true}, // Base64-like
		{"very-long-subdomain-that-looks-suspicious-and-encoded.evil.com", true},
	}

	for _, tt := range tests {
		isTunneling, score, _ := detector.Predict(tt.domain)

		if tt.expectTunneling && !isTunneling && score < 0.5 {
			t.Errorf("Expected %s to be detected as tunneling", tt.domain)
		}

		if !tt.expectTunneling && isTunneling && score > 0.8 {
			t.Errorf("Expected %s to NOT be detected as tunneling", tt.domain)
		}
	}
}

func TestDGADetector_Predict(t *testing.T) {
	detector := NewDGADetector()

	tests := []struct {
		domain    string
		expectDGA bool
	}{
		{"google.com", false},
		{"facebook.com", false},
		{"xyzqwerty123abc.com", true}, // Random-looking
		{"asdfjkl.net", true},         // High consonant ratio
	}

	for _, tt := range tests {
		isDGA, score := detector.Predict(tt.domain)

		if tt.expectDGA && !isDGA && score < 0.5 {
			t.Errorf("Expected %s to be detected as DGA (score: %f)", tt.domain, score)
		}

		if !tt.expectDGA && isDGA && score > 0.8 {
			t.Errorf("Expected %s to NOT be detected as DGA (score: %f)", tt.domain, score)
		}
	}
}

func TestTrafficClassifier_ClassifyByPort(t *testing.T) {
	classifier := NewTrafficClassifier(DefaultClassifierConfig())

	tests := []struct {
		port        uint16
		expectedApp string
	}{
		{80, "http"},
		{443, "https"},
		{22, "ssh"},
		{3306, "mysql"},
		{5432, "postgres"},
		{53, "dns"},
	}

	for _, tt := range tests {
		app, ok := classifier.classifyByPort(tt.port)
		if !ok {
			t.Errorf("Expected port %d to be classified", tt.port)
			continue
		}
		if app != tt.expectedApp {
			t.Errorf("Port %d: expected %s, got %s", tt.port, tt.expectedApp, app)
		}
	}
}

func TestTrafficClassifier_Classify(t *testing.T) {
	classifier := NewTrafficClassifier(DefaultClassifierConfig())
	ctx := context.Background()

	flow := &models.Flow{
		ID:       "test-flow",
		DstPort:  443,
		Protocol: 6, // TCP
		Metadata: models.FlowMetadata{
			JA3:        "abc123",
			ServerName: "www.netflix.com",
		},
	}

	result, err := classifier.Classify(ctx, flow)
	if err != nil {
		t.Fatalf("Classification failed: %v", err)
	}

	if result.Application == "" {
		t.Error("Expected non-empty application")
	}

	if result.Category == CategoryUnknown {
		t.Error("Expected known category for HTTPS traffic")
	}
}

func TestThreatClassifier_Classify(t *testing.T) {
	classifier := NewThreatClassifier(DefaultClassifierConfig())
	ctx := context.Background()

	// Test suspicious port
	flow := &models.Flow{
		ID:       "threat-flow",
		DstPort:  4444, // Metasploit default
		Protocol: 6,    // TCP
	}

	result, err := classifier.Classify(ctx, flow)
	if err != nil {
		t.Fatalf("Classification failed: %v", err)
	}

	if !result.IsThreat {
		t.Error("Expected threat to be detected for port 4444")
	}

	if result.Severity == "" {
		t.Error("Expected severity to be set")
	}
}

func TestMLPipeline_StartStop(t *testing.T) {
	config := DefaultPipelineConfig()
	config.WorkerCount = 2

	pipeline, err := NewMLPipeline(config)
	if err != nil {
		t.Fatalf("Failed to create pipeline: %v", err)
	}

	ctx := context.Background()

	// Start pipeline
	if err := pipeline.Start(ctx); err != nil {
		t.Fatalf("Failed to start pipeline: %v", err)
	}

	// Verify running
	stats := pipeline.GetStatistics()
	if stats.FlowsProcessed != 0 {
		t.Error("Expected 0 flows processed initially")
	}

	// Stop pipeline
	if err := pipeline.Stop(); err != nil {
		t.Fatalf("Failed to stop pipeline: %v", err)
	}
}

func TestMLPipeline_ProcessFlow(t *testing.T) {
	config := DefaultPipelineConfig()
	config.WorkerCount = 2
	config.EnableAnomalyDetection = true
	config.EnableTrafficClassification = true
	config.EnableThreatDetection = true

	pipeline, err := NewMLPipeline(config)
	if err != nil {
		t.Fatalf("Failed to create pipeline: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := pipeline.Start(ctx); err != nil {
		t.Fatalf("Failed to start pipeline: %v", err)
	}
	defer pipeline.Stop()

	// Process a flow
	flow := &models.Flow{
		ID:           "test-flow",
		SrcIP:        net.ParseIP("192.168.1.100"),
		DstIP:        net.ParseIP("10.0.0.1"),
		SrcPort:      45678,
		DstPort:      443,
		Protocol:     6, // TCP
		ProtocolName: "TCP",
		StartTime:    time.Now().Add(-1 * time.Second),
		EndTime:      time.Now(),
		Packets:      10,
		Bytes:        1000,
		PacketCount:  10,
		ByteCount:    1000,
	}

	if err := pipeline.ProcessFlow(flow); err != nil {
		t.Fatalf("Failed to process flow: %v", err)
	}

	// Wait for result
	select {
	case result := <-pipeline.Results():
		if result.FlowID != flow.ID {
			t.Errorf("Expected flow ID %s, got %s", flow.ID, result.FlowID)
		}
	case <-time.After(2 * time.Second):
		t.Error("Timeout waiting for result")
	}
}

func TestONNXEngine_Initialize(t *testing.T) {
	config := &ONNXConfig{
		ModelPath:  "/nonexistent/model.onnx",
		UseGPU:     false,
		NumThreads: 4,
	}

	engine, err := NewONNXEngine(config)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Initialize should fail for nonexistent model
	err = engine.Initialize()
	if err == nil {
		t.Error("Expected error for nonexistent model")
	}
}

func TestModelRegistry_RegisterUnregister(t *testing.T) {
	registry := NewModelRegistry()

	config := &ONNXConfig{
		ModelPath:  "/test/model.onnx",
		NumThreads: 4,
	}

	engine, err := NewONNXEngine(config)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Register model
	if err := registry.Register("test-model", engine); err != nil {
		t.Fatalf("Failed to register model: %v", err)
	}

	// Get model
	retrieved, err := registry.Get("test-model")
	if err != nil {
		t.Fatalf("Failed to get model: %v", err)
	}

	if retrieved != engine {
		t.Error("Retrieved model does not match registered model")
	}

	// Unregister model
	if err := registry.Unregister("test-model"); err != nil {
		t.Fatalf("Failed to unregister model: %v", err)
	}

	// Get should fail after unregister
	_, err = registry.Get("test-model")
	if err == nil {
		t.Error("Expected error getting unregistered model")
	}
}

func TestEWMADetector(t *testing.T) {
	detector := NewEWMADetector(0.3, 3.0)

	// Update with normal values
	for i := 0; i < 100; i++ {
		detector.Update("test_metric", 10.0)
	}

	// Test normal value
	isAnomaly, _ := detector.Detect("test_metric", 10.0)
	if isAnomaly {
		t.Error("Normal value should not be detected as anomaly")
	}

	// Test anomalous value
	isAnomaly, _ = detector.Detect("test_metric", 1000.0)
	if !isAnomaly {
		t.Error("Anomalous value should be detected")
	}
}

func TestDNSAnalyzer(t *testing.T) {
	analyzer := NewDNSAnalyzer()

	// Test normal domain
	result := analyzer.Analyze("query1", "google.com")
	if result.IsTunneling || result.IsDGA {
		t.Error("Normal domain should not be suspicious")
	}

	// Test suspicious domain
	result = analyzer.Analyze("query2", "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q.tunnel.example.com")
	if !result.IsTunneling {
		t.Error("Tunneling domain should be detected")
	}
}

func TestTimeSeriesAnomalyDetector(t *testing.T) {
	config := DefaultAnomalyConfig()
	detector := NewTimeSeriesAnomalyDetector(config, 24) // 24-hour period

	// Add some data points
	now := time.Now()
	for i := 0; i < 100; i++ {
		detector.Update(now.Add(time.Duration(i)*time.Hour), float64(i%24))
	}

	// Test detection
	ctx := context.Background()
	result, err := detector.Detect(ctx)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}
}

func TestMLSidecarClient_Creation(t *testing.T) {
	config := &GRPCClientConfig{
		Address:    "localhost:50051",
		Timeout:    5 * time.Second,
		MaxRetries: 3,
	}

	client := NewMLSidecarClient(config)
	if client == nil {
		t.Fatal("Expected non-nil client")
	}

	// Verify config was set
	if client.config.Address != "localhost:50051" {
		t.Errorf("Expected address localhost:50051, got %s", client.config.Address)
	}
}

func TestSidecarPool_Creation(t *testing.T) {
	addresses := []string{"localhost:50051", "localhost:50052"}
	config := &GRPCClientConfig{
		Timeout:    5 * time.Second,
		MaxRetries: 3,
	}

	pool := NewSidecarPool(addresses, config)
	if pool == nil {
		t.Fatal("Expected non-nil pool")
	}

	if len(pool.clients) != 2 {
		t.Errorf("Expected 2 clients, got %d", len(pool.clients))
	}
}
