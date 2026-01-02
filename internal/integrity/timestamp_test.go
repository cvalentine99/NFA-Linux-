package integrity

import (
	"bytes"
	"crypto"
	"os"
	"testing"
	"time"
)

func TestDefaultTSAConfig(t *testing.T) {
	cfg := DefaultTSAConfig()

	if cfg.TSAURL == "" {
		t.Error("TSA URL should not be empty")
	}

	if cfg.HashAlgorithm != crypto.SHA256 {
		t.Error("Default hash algorithm should be SHA-256")
	}

	if cfg.Timeout == 0 {
		t.Error("Timeout should not be zero")
	}
}

func TestNewTimestampClient(t *testing.T) {
	cfg := DefaultTSAConfig()

	client, err := NewTimestampClient(cfg)
	if err != nil {
		t.Fatalf("Failed to create timestamp client: %v", err)
	}

	if client == nil {
		t.Fatal("Timestamp client is nil")
	}

	if client.config.TSAURL != cfg.TSAURL {
		t.Error("TSA URL not set correctly")
	}
}

func TestTimestampClientHashData(t *testing.T) {
	cfg := DefaultTSAConfig()
	client, _ := NewTimestampClient(cfg)

	data := []byte("Test data for hashing")
	hash := client.hashData(data)

	if len(hash) != 32 {
		t.Errorf("Expected 32-byte SHA-256 hash, got %d bytes", len(hash))
	}

	// Hash should be deterministic
	hash2 := client.hashData(data)
	if !bytes.Equal(hash, hash2) {
		t.Error("Hash is not deterministic")
	}
}

func TestTimestampClientGetHashOID(t *testing.T) {
	tests := []struct {
		algorithm crypto.Hash
		expected  string
	}{
		{crypto.SHA256, "2.16.840.1.101.3.4.2.1"},
		{crypto.SHA384, "2.16.840.1.101.3.4.2.2"},
		{crypto.SHA512, "2.16.840.1.101.3.4.2.3"},
	}

	for _, tt := range tests {
		cfg := &TSAConfig{
			TSAURL:        FreeTSAURL,
			HashAlgorithm: tt.algorithm,
			Timeout:       30 * time.Second,
		}
		client, _ := NewTimestampClient(cfg)

		oid := client.getHashOID()
		oidStr := oid.String()

		if oidStr != tt.expected {
			t.Errorf("For %v, expected OID %s, got %s", tt.algorithm, tt.expected, oidStr)
		}
	}
}

func TestTimestampClientGetHashAlgorithmName(t *testing.T) {
	tests := []struct {
		algorithm crypto.Hash
		expected  string
	}{
		{crypto.SHA256, "SHA-256"},
		{crypto.SHA384, "SHA-384"},
		{crypto.SHA512, "SHA-512"},
	}

	for _, tt := range tests {
		cfg := &TSAConfig{
			TSAURL:        FreeTSAURL,
			HashAlgorithm: tt.algorithm,
			Timeout:       30 * time.Second,
		}
		client, _ := NewTimestampClient(cfg)

		name := client.getHashAlgorithmName()

		if name != tt.expected {
			t.Errorf("For %v, expected name %s, got %s", tt.algorithm, tt.expected, name)
		}
	}
}

func TestTimestampClientBuildRequest(t *testing.T) {
	cfg := DefaultTSAConfig()
	cfg.UseNonce = true
	cfg.CertReq = true

	client, _ := NewTimestampClient(cfg)

	hash := []byte("test hash data 32 bytes long!!")
	req := client.buildRequest(hash)

	if req.Version != 1 {
		t.Errorf("Expected version 1, got %d", req.Version)
	}

	if !bytes.Equal(req.MessageImprint.HashedMessage, hash) {
		t.Error("Hash not set correctly in request")
	}

	if req.CertReq != true {
		t.Error("CertReq should be true")
	}

	if req.Nonce == nil {
		t.Error("Nonce should be set when UseNonce is true")
	}
}

func TestTimestampClientBuildRequestNoNonce(t *testing.T) {
	cfg := DefaultTSAConfig()
	cfg.UseNonce = false

	client, _ := NewTimestampClient(cfg)

	hash := []byte("test hash data 32 bytes long!!")
	req := client.buildRequest(hash)

	if req.Nonce != nil {
		t.Error("Nonce should be nil when UseNonce is false")
	}
}

func TestGenerateNonce(t *testing.T) {
	nonce1, err := generateNonce()
	if err != nil {
		t.Fatalf("Failed to generate nonce: %v", err)
	}

	if nonce1 == nil {
		t.Fatal("Nonce is nil")
	}

	// Generate another nonce
	time.Sleep(time.Nanosecond)
	nonce2, _ := generateNonce()

	// Nonces should be different (based on time)
	if nonce1.Cmp(nonce2) == 0 {
		t.Error("Nonces should be different")
	}
}

func TestNewTimestampStore(t *testing.T) {
	cfg := DefaultTSAConfig()

	store, err := NewTimestampStore(cfg)
	if err != nil {
		t.Fatalf("Failed to create timestamp store: %v", err)
	}

	if store == nil {
		t.Fatal("Timestamp store is nil")
	}

	if store.client == nil {
		t.Error("Store client is nil")
	}
}

func TestTimestampStoreGetTimestamp(t *testing.T) {
	cfg := DefaultTSAConfig()
	store, _ := NewTimestampStore(cfg)

	// Try to get non-existent timestamp
	ts, ok := store.GetTimestamp("nonexistent")
	if ok {
		t.Error("Should not find non-existent timestamp")
	}
	if ts != nil {
		t.Error("Timestamp should be nil for non-existent ID")
	}
}

func TestTimestampStoreExportTimestamps(t *testing.T) {
	cfg := DefaultTSAConfig()
	store, _ := NewTimestampStore(cfg)

	// Add a mock timestamp directly
	store.mu.Lock()
	store.timestamps["test1"] = &Timestamp{
		Time:          time.Now(),
		TimeNano:      time.Now().UnixNano(),
		HashAlgorithm: "SHA-256",
		HashedMessage: "abc123",
		TSAURL:        FreeTSAURL,
	}
	store.mu.Unlock()

	exported := store.ExportTimestamps()

	if len(exported) != 1 {
		t.Errorf("Expected 1 timestamp, got %d", len(exported))
	}

	if _, ok := exported["test1"]; !ok {
		t.Error("Expected test1 timestamp in export")
	}
}

func TestTimestampVerification(t *testing.T) {
	cfg := DefaultTSAConfig()
	client, _ := NewTimestampClient(cfg)

	data := []byte("Test data for verification")
	hash := client.hashData(data)

	// Create a mock timestamp
	ts := &Timestamp{
		Time:          time.Now(),
		TimeNano:      time.Now().UnixNano(),
		HashAlgorithm: "SHA-256",
		HashedMessage: bytesToHex(hash),
		TSAURL:        FreeTSAURL,
		Verified:      true,
	}

	// Verify with original data
	valid, err := client.VerifyTimestamp(ts, data)
	if err != nil {
		t.Fatalf("Verification error: %v", err)
	}
	if !valid {
		t.Error("Original data should verify")
	}

	// Verify with modified data
	modifiedData := []byte("Modified data")
	valid, err = client.VerifyTimestamp(ts, modifiedData)
	if err == nil {
		t.Error("Modified data should produce error")
	}
	if valid {
		t.Error("Modified data should not verify")
	}
}

func TestTimestampStoreVerifyEvidence(t *testing.T) {
	cfg := DefaultTSAConfig()
	store, _ := NewTimestampStore(cfg)

	// Try to verify non-existent evidence
	_, err := store.VerifyEvidence("nonexistent", []byte("data"))
	if err == nil {
		t.Error("Should error for non-existent evidence")
	}
}

// Helper function to convert bytes to hex
func bytesToHex(b []byte) string {
	const hexChars = "0123456789abcdef"
	result := make([]byte, len(b)*2)
	for i, v := range b {
		result[i*2] = hexChars[v>>4]
		result[i*2+1] = hexChars[v&0x0f]
	}
	return string(result)
}

// Integration test - only run if network is available
func TestTimestampDataIntegration(t *testing.T) {
	if os.Getenv("RUN_INTEGRATION_TESTS") != "1" {
		t.Skip("Skipping integration test (set RUN_INTEGRATION_TESTS=1 to run)")
	}

	cfg := DefaultTSAConfig()
	cfg.Timeout = 60 * time.Second

	client, err := NewTimestampClient(cfg)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	data := []byte("Test data for timestamping " + time.Now().String())

	ts, err := client.TimestampData(data)
	if err != nil {
		t.Fatalf("Failed to timestamp data: %v", err)
	}

	if ts == nil {
		t.Fatal("Timestamp is nil")
	}

	if ts.Token == "" {
		t.Error("Timestamp token is empty")
	}

	if ts.HashedMessage == "" {
		t.Error("Hashed message is empty")
	}

	t.Logf("Timestamp: %+v", ts)
}

func TestTimestampFileIntegration(t *testing.T) {
	if os.Getenv("RUN_INTEGRATION_TESTS") != "1" {
		t.Skip("Skipping integration test (set RUN_INTEGRATION_TESTS=1 to run)")
	}

	// Create temp file
	f, err := os.CreateTemp("", "tstest")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(f.Name())

	data := []byte("Test file content for timestamping")
	f.Write(data)
	f.Close()

	cfg := DefaultTSAConfig()
	cfg.Timeout = 60 * time.Second

	client, _ := NewTimestampClient(cfg)

	ts, err := client.TimestampFile(f.Name())
	if err != nil {
		t.Fatalf("Failed to timestamp file: %v", err)
	}

	if ts == nil {
		t.Fatal("Timestamp is nil")
	}

	t.Logf("File timestamp: %+v", ts)
}

func BenchmarkHashData(b *testing.B) {
	cfg := DefaultTSAConfig()
	client, _ := NewTimestampClient(cfg)

	data := bytes.Repeat([]byte("X"), 1024*1024) // 1MB

	b.ResetTimer()
	b.SetBytes(int64(len(data)))

	for i := 0; i < b.N; i++ {
		client.hashData(data)
	}
}

func BenchmarkBuildRequest(b *testing.B) {
	cfg := DefaultTSAConfig()
	client, _ := NewTimestampClient(cfg)

	hash := make([]byte, 32)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		client.buildRequest(hash)
	}
}
