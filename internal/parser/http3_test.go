package parser

import (
	"testing"
	"time"
)

func TestHTTP3Parser_ParseFrame(t *testing.T) {
	parser := NewHTTP3Parser()
	
	// Create a simple DATA frame
	// Type: 0x00 (DATA), Length: 5, Payload: "hello"
	data := []byte{
		0x00,       // Frame type: DATA
		0x05,       // Length: 5
		'h', 'e', 'l', 'l', 'o', // Payload
	}
	
	err := parser.ParseStreamData(0, data, time.Now().UnixNano())
	if err != nil {
		t.Fatalf("Failed to parse stream data: %v", err)
	}
}

func TestHTTP3Parser_ParseSettingsFrame(t *testing.T) {
	parser := NewHTTP3Parser()
	
	// SETTINGS frame with QPACK_MAX_TABLE_CAPACITY = 4096
	// QUIC varint encoding: 4096 = 0x1000, needs 2-byte encoding (prefix 01)
	// 2-byte format: 01xxxxxx xxxxxxxx where value = (first & 0x3F) << 8 | second
	// 4096 = 0x1000, so first byte = 0x40 | 0x10 = 0x50, second = 0x00
	// Setting ID 0x01 is a 1-byte varint
	// Total payload: 1 (setting ID) + 2 (value) = 3 bytes
	data := []byte{
		0x04,       // Frame type: SETTINGS (1-byte varint)
		0x03,       // Length: 3 bytes (1-byte varint)
		0x01,       // Setting ID: QPACK_MAX_TABLE_CAPACITY (1-byte varint)
		0x50, 0x00, // Value: 4096 (2-byte varint: 0x50 = 01|010000, 0x00)
	}
	
	err := parser.ParseStreamData(2, data, time.Now().UnixNano()) // Control stream
	if err != nil {
		t.Fatalf("Failed to parse settings frame: %v", err)
	}
}

func TestQPACKDecoder_DecodeInteger(t *testing.T) {
	decoder := NewQPACKDecoder(4096)
	
	tests := []struct {
		name      string
		data      []byte
		prefixLen int
		expected  uint64
		length    int
	}{
		{"Small value (5-bit prefix)", []byte{0x0A}, 5, 10, 1},
		{"Max prefix value (5-bit)", []byte{0x1F, 0x00}, 5, 31, 2},
		{"Multi-byte (5-bit prefix)", []byte{0x1F, 0x9A, 0x0A}, 5, 1337, 3},
		{"6-bit prefix", []byte{0x3F, 0x00}, 6, 63, 2},
		{"7-bit prefix", []byte{0x7F, 0x00}, 7, 127, 2},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, length := decoder.decodeInteger(tt.data, tt.prefixLen)
			if value != tt.expected {
				t.Errorf("Expected value %d, got %d", tt.expected, value)
			}
			if length != tt.length {
				t.Errorf("Expected length %d, got %d", tt.length, length)
			}
		})
	}
}

func TestQPACKDecoder_StaticTable(t *testing.T) {
	// QPACK static table indices (RFC 9204 Appendix A)
	// Based on the actual qpackStaticTable in http3.go:
	// Index 0: :authority
	// Index 1: :path /
	// Index 15: :method CONNECT
	// Index 16: :method DELETE  
	// Index 17: :method GET
	// Index 18: :method HEAD
	// Index 19: :method OPTIONS
	// Index 20: :method POST
	// Index 21: :method PUT
	// Index 22: :scheme http
	// Index 23: :scheme https
	// Index 24: :status 103
	// Index 25: :status 200
	tests := []struct {
		index    int
		name     string
		value    string
	}{
		{0, ":authority", ""},
		{1, ":path", "/"},
		{17, ":method", "GET"},
		{20, ":method", "POST"},  // Fixed: POST is at index 20, not 21
		{23, ":scheme", "https"},
		{25, ":status", "200"},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, value := getStaticTableEntry(tt.index)
			if name != tt.name {
				t.Errorf("Expected name %s, got %s", tt.name, name)
			}
			if value != tt.value {
				t.Errorf("Expected value %s, got %s", tt.value, value)
			}
		})
	}
}

func TestQPACKDecoder_DynamicTable(t *testing.T) {
	decoder := NewQPACKDecoder(4096)
	
	// Insert entries
	decoder.InsertEntry("custom-header", "custom-value")
	decoder.InsertEntry("another-header", "another-value")
	
	// Check table size
	decoder.mu.RLock()
	if len(decoder.dynamicTable) != 2 {
		t.Errorf("Expected 2 entries in dynamic table, got %d", len(decoder.dynamicTable))
	}
	
	// Check entries (newest first)
	if decoder.dynamicTable[0].Name != "another-header" {
		t.Errorf("Expected newest entry to be 'another-header', got %s", decoder.dynamicTable[0].Name)
	}
	decoder.mu.RUnlock()
}

func TestQPACKDecoder_TableEviction(t *testing.T) {
	decoder := NewQPACKDecoder(100) // Small table
	
	// Insert entries that exceed table size
	decoder.InsertEntry("header1", "value1")
	decoder.InsertEntry("header2", "value2")
	decoder.InsertEntry("header3", "value3")
	
	decoder.mu.RLock()
	// Table should have evicted oldest entries
	if decoder.currentSize > 100 {
		t.Errorf("Table size %d exceeds max %d", decoder.currentSize, 100)
	}
	decoder.mu.RUnlock()
}

func TestHTTP3Parser_BuildRequest(t *testing.T) {
	parser := NewHTTP3Parser()
	
	headers := map[string][]string{
		":method":    {"GET"},
		":scheme":    {"https"},
		":authority": {"example.com"},
		":path":      {"/api/test"},
		"user-agent": {"test-agent"},
	}
	
	req := parser.buildRequest(4, headers, time.Now().UnixNano())
	
	if req.Method != "GET" {
		t.Errorf("Expected method GET, got %s", req.Method)
	}
	if req.Scheme != "https" {
		t.Errorf("Expected scheme https, got %s", req.Scheme)
	}
	if req.Authority != "example.com" {
		t.Errorf("Expected authority example.com, got %s", req.Authority)
	}
	if req.Path != "/api/test" {
		t.Errorf("Expected path /api/test, got %s", req.Path)
	}
	if req.StreamID != 4 {
		t.Errorf("Expected stream ID 4, got %d", req.StreamID)
	}
}

func TestHTTP3Parser_BuildResponse(t *testing.T) {
	parser := NewHTTP3Parser()
	
	headers := map[string][]string{
		":status":      {"200"},
		"content-type": {"application/json"},
	}
	
	resp := parser.buildResponse(4, headers, time.Now().UnixNano())
	
	if resp.Status != 200 {
		t.Errorf("Expected status 200, got %d", resp.Status)
	}
	if resp.StreamID != 4 {
		t.Errorf("Expected stream ID 4, got %d", resp.StreamID)
	}
}

func TestIsClientInitiatedBidirectional(t *testing.T) {
	tests := []struct {
		streamID uint64
		expected bool
	}{
		{0, true},   // Client-initiated bidirectional
		{4, true},   // Client-initiated bidirectional
		{8, true},   // Client-initiated bidirectional
		{1, false},  // Server-initiated bidirectional
		{2, false},  // Client-initiated unidirectional
		{3, false},  // Server-initiated unidirectional
	}
	
	for _, tt := range tests {
		result := isClientInitiatedBidirectional(tt.streamID)
		if result != tt.expected {
			t.Errorf("Stream %d: expected %v, got %v", tt.streamID, tt.expected, result)
		}
	}
}

func TestHTTP3Parser_GetStats(t *testing.T) {
	parser := NewHTTP3Parser()
	
	stats := parser.GetStats()
	if stats.TotalRequests != 0 {
		t.Errorf("Expected 0 requests, got %d", stats.TotalRequests)
	}
	if stats.ActiveStreams != 0 {
		t.Errorf("Expected 0 active streams, got %d", stats.ActiveStreams)
	}
}

func TestGenerateHTTP3Fingerprint(t *testing.T) {
	req := &HTTP3Request{
		Method:    "GET",
		Scheme:    "https",
		Authority: "example.com",
		Path:      "/",
		Headers: map[string][]string{
			":method":      {"GET"},
			":scheme":      {"https"},
			":authority":   {"example.com"},
			":path":        {"/"},
			"user-agent":   {"Mozilla/5.0"},
			"accept":       {"*/*"},
		},
	}
	
	fp := GenerateHTTP3Fingerprint(req)
	
	if len(fp.PseudoHeaders) != 4 {
		t.Errorf("Expected 4 pseudo headers, got %d", len(fp.PseudoHeaders))
	}
	
	if len(fp.HeaderOrder) != 2 {
		t.Errorf("Expected 2 regular headers, got %d", len(fp.HeaderOrder))
	}
}

func BenchmarkQPACKDecoder_DecodeInteger(b *testing.B) {
	decoder := NewQPACKDecoder(4096)
	data := []byte{0x1F, 0x9A, 0x0A}
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		_, _ = decoder.decodeInteger(data, 5)
	}
}

func BenchmarkHTTP3Parser_ParseStreamData(b *testing.B) {
	parser := NewHTTP3Parser()
	
	// Simple DATA frame
	data := []byte{
		0x00, 0x40, 0x64, // DATA frame, length 100
	}
	data = append(data, make([]byte, 100)...)
	
	timestamp := time.Now().UnixNano()
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		_ = parser.ParseStreamData(uint64(i*4), data, timestamp)
	}
}
