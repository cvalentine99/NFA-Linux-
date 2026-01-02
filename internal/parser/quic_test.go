package parser

import (
	"encoding/hex"
	"testing"
	"time"
)

func TestQUICParser_ParseHeader_LongHeader(t *testing.T) {
	parser := NewQUICParser(nil)
	
	// QUIC v1 Initial packet (Long Header)
	// Format: 1 byte header + 4 bytes version + 1 byte DCID len + DCID + 1 byte SCID len + SCID
	packet := []byte{
		0xC0,                   // Long header, Initial packet type
		0x00, 0x00, 0x00, 0x01, // Version 1
		0x08,                   // DCID length = 8
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DCID
		0x08,                   // SCID length = 8
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, // SCID
		0x00,                   // Token length = 0
		0x40, 0x50,             // Packet length (variable int)
		// ... payload would follow
	}
	
	// Pad to minimum size
	packet = append(packet, make([]byte, 100)...)
	
	qp, err := parser.ParsePacket(packet, "192.168.1.1", "192.168.1.2", 12345, 443, time.Now().UnixNano())
	if err != nil {
		t.Fatalf("Failed to parse QUIC packet: %v", err)
	}
	
	if !qp.Header.IsLongHeader {
		t.Error("Expected Long Header")
	}
	
	if qp.Header.Version != QUICVersion1 {
		t.Errorf("Expected version 0x00000001, got 0x%08X", qp.Header.Version)
	}
	
	if qp.Header.PacketType != PacketTypeInitial {
		t.Errorf("Expected Initial packet type, got %d", qp.Header.PacketType)
	}
	
	if qp.Header.DCIDLen != 8 {
		t.Errorf("Expected DCID length 8, got %d", qp.Header.DCIDLen)
	}
	
	expectedDCID := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	for i, b := range expectedDCID {
		if qp.Header.DCID[i] != b {
			t.Errorf("DCID mismatch at position %d", i)
		}
	}
}

func TestQUICParser_ParseHeader_ShortHeader(t *testing.T) {
	parser := NewQUICParser(nil)
	
	// QUIC Short Header
	packet := []byte{
		0x40,                   // Short header (bit 7 = 0, fixed bit = 1)
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DCID (8 bytes default)
		// ... encrypted payload would follow
	}
	
	// Pad to minimum size
	packet = append(packet, make([]byte, 50)...)
	
	qp, err := parser.ParsePacket(packet, "192.168.1.1", "192.168.1.2", 12345, 443, time.Now().UnixNano())
	if err != nil {
		t.Fatalf("Failed to parse QUIC packet: %v", err)
	}
	
	if qp.Header.IsLongHeader {
		t.Error("Expected Short Header")
	}
}

func TestQUICParser_ConnectionTracking(t *testing.T) {
	parser := NewQUICParser(nil)
	
	// Simulate Initial packet
	packet := []byte{
		0xC0,                   // Long header, Initial
		0x00, 0x00, 0x00, 0x01, // Version 1
		0x08,                   // DCID length
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, // DCID
		0x08,                   // SCID length
		0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, // SCID
		0x00,                   // Token length
		0x40, 0x20,             // Packet length
	}
	packet = append(packet, make([]byte, 100)...)
	
	_, err := parser.ParsePacket(packet, "10.0.0.1", "10.0.0.2", 54321, 443, time.Now().UnixNano())
	if err != nil {
		t.Fatalf("Failed to parse packet: %v", err)
	}
	
	// Check connection was tracked
	conns := parser.GetConnections()
	if len(conns) != 1 {
		t.Fatalf("Expected 1 connection, got %d", len(conns))
	}
	
	conn := conns[0]
	if conn.SrcIP != "10.0.0.1" {
		t.Errorf("Expected SrcIP 10.0.0.1, got %s", conn.SrcIP)
	}
	
	if conn.DstIP != "10.0.0.2" {
		t.Errorf("Expected DstIP 10.0.0.2, got %s", conn.DstIP)
	}
	
	if conn.Version != QUICVersion1 {
		t.Errorf("Expected version 1, got %d", conn.Version)
	}
}

func TestQUICParser_VarintDecoding(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected uint64
		length   int
	}{
		{"1-byte", []byte{0x25}, 37, 1},
		{"2-byte", []byte{0x7B, 0xBD}, 15293, 2},
		{"4-byte", []byte{0x9D, 0x7F, 0x3E, 0x7D}, 494878333, 4},
		{"8-byte", []byte{0xC2, 0x19, 0x7C, 0x5E, 0xFF, 0x14, 0xE8, 0x8C}, 151288809941952652, 8},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, length := decodeVarint(tt.data)
			if value != tt.expected {
				t.Errorf("Expected value %d, got %d", tt.expected, value)
			}
			if length != tt.length {
				t.Errorf("Expected length %d, got %d", tt.length, length)
			}
		})
	}
}

func TestIsQUICPacket(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "Valid Long Header v1",
			data:     []byte{0xC0, 0x00, 0x00, 0x00, 0x01, 0x08},
			expected: true,
		},
		{
			name:     "Valid Long Header v2",
			data:     []byte{0xC0, 0x6b, 0x33, 0x43, 0xcf, 0x08},
			expected: true,
		},
		{
			name:     "Valid Short Header",
			data:     []byte{0x40, 0x01, 0x02, 0x03, 0x04, 0x05},
			expected: true,
		},
		{
			name:     "Invalid - Fixed bit not set",
			data:     []byte{0x80, 0x00, 0x00, 0x00, 0x01},
			expected: false,
		},
		{
			name:     "Too short",
			data:     []byte{0xC0, 0x00},
			expected: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsQUICPacket(tt.data)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestGetVersionString(t *testing.T) {
	tests := []struct {
		version  uint32
		expected string
	}{
		{QUICVersion1, "QUIC v1"},
		{QUICVersion2, "QUIC v2"},
		{0, "Version Negotiation"},
		{0xff00001d, "Draft-29"},
	}
	
	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := GetVersionString(tt.version)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestQUICParser_CleanupExpired(t *testing.T) {
	cfg := &QUICParserConfig{
		MaxConnections:    100,
		ConnectionTimeout: 1 * time.Millisecond,
	}
	parser := NewQUICParser(cfg)
	
	// Add a connection
	packet := []byte{
		0xC0, 0x00, 0x00, 0x00, 0x01,
		0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x00, 0x40, 0x20,
	}
	packet = append(packet, make([]byte, 100)...)
	
	_, _ = parser.ParsePacket(packet, "1.1.1.1", "2.2.2.2", 1234, 443, time.Now().Add(-1*time.Second).UnixNano())
	
	// Wait for expiration
	time.Sleep(5 * time.Millisecond)
	
	// Cleanup
	removed := parser.CleanupExpired()
	if removed != 1 {
		t.Errorf("Expected 1 connection removed, got %d", removed)
	}
	
	conns := parser.GetConnections()
	if len(conns) != 0 {
		t.Errorf("Expected 0 connections after cleanup, got %d", len(conns))
	}
}

func BenchmarkQUICParser_ParsePacket(b *testing.B) {
	parser := NewQUICParser(nil)
	
	packet := []byte{
		0xC0, 0x00, 0x00, 0x00, 0x01,
		0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x00, 0x40, 0x20,
	}
	packet = append(packet, make([]byte, 1200)...)
	
	timestamp := time.Now().UnixNano()
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		_, _ = parser.ParsePacket(packet, "1.1.1.1", "2.2.2.2", 1234, 443, timestamp)
	}
}

func BenchmarkVarintDecode(b *testing.B) {
	data := []byte{0x9D, 0x7F, 0x3E, 0x7D}
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		_, _ = decodeVarint(data)
	}
}

// Test helper to create hex-encoded test data
func hexDecode(s string) []byte {
	data, _ := hex.DecodeString(s)
	return data
}
