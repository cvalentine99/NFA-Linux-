package parser

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func TestSMBParser_ParseHeader(t *testing.T) {
	parser := NewSMBParser(nil)
	
	// Create a valid SMB2 header
	header := make([]byte, 64)
	copy(header[0:4], []byte{0xFE, 'S', 'M', 'B'}) // Protocol ID
	binary.LittleEndian.PutUint16(header[4:6], 64)  // Structure size
	binary.LittleEndian.PutUint16(header[6:8], 1)   // Credit charge
	binary.LittleEndian.PutUint32(header[8:12], 0)  // Status
	binary.LittleEndian.PutUint16(header[12:14], SMB2CommandNegotiate) // Command
	binary.LittleEndian.PutUint16(header[14:16], 1) // Credit request
	binary.LittleEndian.PutUint32(header[16:20], 0) // Flags
	binary.LittleEndian.PutUint32(header[20:24], 0) // Next command
	binary.LittleEndian.PutUint64(header[24:32], 1) // Message ID
	binary.LittleEndian.PutUint32(header[32:36], 0) // Reserved
	binary.LittleEndian.PutUint32(header[36:40], 0) // Tree ID
	binary.LittleEndian.PutUint64(header[40:48], 0) // Session ID
	// Signature (16 bytes) at 48:64
	
	parsedHeader, err := parser.parseHeader(header)
	if err != nil {
		t.Fatalf("Failed to parse header: %v", err)
	}
	
	if !bytes.Equal(parsedHeader.ProtocolID[:], []byte{0xFE, 'S', 'M', 'B'}) {
		t.Error("Protocol ID mismatch")
	}
	
	if parsedHeader.Command != SMB2CommandNegotiate {
		t.Errorf("Expected command Negotiate, got %d", parsedHeader.Command)
	}
	
	if parsedHeader.MessageID != 1 {
		t.Errorf("Expected message ID 1, got %d", parsedHeader.MessageID)
	}
}

func TestSMBParser_ParsePacket(t *testing.T) {
	parser := NewSMBParser(nil)
	
	// Create packet with NetBIOS header + SMB2 header
	packet := make([]byte, 4+64+36) // NetBIOS + SMB2 header + Negotiate request
	
	// NetBIOS header
	packet[0] = 0x00                                      // Message type
	packet[1] = 0x00                                      // Length (high byte)
	binary.BigEndian.PutUint16(packet[2:4], uint16(64+36)) // Length
	
	// SMB2 header
	copy(packet[4:8], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(packet[8:10], 64)
	binary.LittleEndian.PutUint16(packet[16:18], SMB2CommandNegotiate)
	
	// Negotiate request structure
	binary.LittleEndian.PutUint16(packet[68:70], 36) // Structure size
	binary.LittleEndian.PutUint16(packet[70:72], 2)  // Dialect count
	binary.LittleEndian.PutUint16(packet[72:74], SMB2NegotiateSigningEnabled) // Security mode
	
	smbPacket, err := parser.ParsePacket(packet, "192.168.1.100", "192.168.1.1", 49152, 445, time.Now().UnixNano())
	if err != nil {
		t.Fatalf("Failed to parse packet: %v", err)
	}
	
	if smbPacket.Header.Command != SMB2CommandNegotiate {
		t.Errorf("Expected Negotiate command, got %d", smbPacket.Header.Command)
	}
	
	if !smbPacket.IsRequest {
		t.Error("Expected request, got response")
	}
}

func TestIsSMB2Packet(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "Valid SMB2 with NetBIOS",
			data:     []byte{0x00, 0x00, 0x00, 0x40, 0xFE, 'S', 'M', 'B'},
			expected: true,
		},
		{
			name:     "Valid SMB2 direct",
			data:     []byte{0xFE, 'S', 'M', 'B'},
			expected: true,
		},
		{
			name:     "Invalid - SMB1",
			data:     []byte{0xFF, 'S', 'M', 'B'},
			expected: false,
		},
		{
			name:     "Invalid - too short",
			data:     []byte{0xFE, 'S'},
			expected: false,
		},
		{
			name:     "Invalid - wrong signature",
			data:     []byte{0xFE, 'X', 'Y', 'Z'},
			expected: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsSMB2Packet(tt.data)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestGetDialectString(t *testing.T) {
	tests := []struct {
		dialect  uint16
		expected string
	}{
		{SMB2Dialect202, "SMB 2.0.2"},
		{SMB2Dialect210, "SMB 2.1"},
		{SMB2Dialect300, "SMB 3.0"},
		{SMB2Dialect302, "SMB 3.0.2"},
		{SMB2Dialect311, "SMB 3.1.1"},
		{0x9999, "Unknown (0x9999)"},
	}
	
	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := GetDialectString(tt.dialect)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestGetCommandString(t *testing.T) {
	tests := []struct {
		cmd      uint16
		expected string
	}{
		{SMB2CommandNegotiate, "Negotiate"},
		{SMB2CommandSessionSetup, "SessionSetup"},
		{SMB2CommandTreeConnect, "TreeConnect"},
		{SMB2CommandCreate, "Create"},
		{SMB2CommandRead, "Read"},
		{SMB2CommandWrite, "Write"},
		{SMB2CommandClose, "Close"},
		{0xFFFF, "Unknown (0xFFFF)"},
	}
	
	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := GetCommandString(tt.cmd)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestDecodeUTF16LE(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected string
	}{
		{
			name:     "Simple ASCII",
			data:     []byte{'H', 0, 'e', 0, 'l', 0, 'l', 0, 'o', 0},
			expected: "Hello",
		},
		{
			name:     "Empty",
			data:     []byte{},
			expected: "",
		},
		{
			name:     "Single char",
			data:     []byte{'A', 0},
			expected: "A",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := decodeUTF16LE(tt.data)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestSMBParser_SessionTracking(t *testing.T) {
	parser := NewSMBParser(nil)
	
	// Simulate Negotiate request
	negotiateReq := createSMBPacket(SMB2CommandNegotiate, 0, 0, true)
	_, _ = parser.ParsePacket(negotiateReq, "10.0.0.100", "10.0.0.1", 49152, 445, time.Now().UnixNano())
	
	// Check session was created
	parser.mu.RLock()
	if len(parser.sessionsByConn) != 1 {
		t.Errorf("Expected 1 session by connection, got %d", len(parser.sessionsByConn))
	}
	parser.mu.RUnlock()
}

func TestSMBParser_CleanupExpired(t *testing.T) {
	cfg := &SMBParserConfig{
		MaxSessions:    100,
		SessionTimeout: 1 * time.Millisecond,
	}
	parser := NewSMBParser(cfg)
	
	// Add a session directly
	parser.mu.Lock()
	parser.sessions[12345] = &SMBSession{
		SessionID:    12345,
		LastSeenNano: time.Now().Add(-1 * time.Second).UnixNano(),
	}
	parser.mu.Unlock()
	
	// Wait for expiration
	time.Sleep(5 * time.Millisecond)
	
	// Cleanup
	removed := parser.CleanupExpired()
	if removed != 1 {
		t.Errorf("Expected 1 session removed, got %d", removed)
	}
}

func TestSMBParser_LateralMovementDetection(t *testing.T) {
	parser := NewSMBParser(nil)
	
	var detectedMove string
	parser.SetLateralMovementHandler(func(session *SMBSession, indicator string) {
		detectedMove = indicator
	})
	
	// Add a session
	parser.mu.Lock()
	parser.sessions[12345] = &SMBSession{
		SessionID: 12345,
		UserName:  "admin",
		Trees:     make(map[uint32]*SMBTree),
	}
	parser.mu.Unlock()
	
	// Check admin share detection
	parser.checkLateralMovement(12345, "\\\\server\\ADMIN$")
	
	// Give callback time to execute
	time.Sleep(10 * time.Millisecond)
	
	if detectedMove == "" {
		t.Error("Expected lateral movement detection for ADMIN$ share")
	}
}

// Helper function to create SMB packets for testing
func createSMBPacket(command uint16, sessionID uint64, treeID uint32, isRequest bool) []byte {
	packet := make([]byte, 4+64+36)
	
	// NetBIOS header
	packet[0] = 0x00
	binary.BigEndian.PutUint16(packet[2:4], uint16(64+36))
	
	// SMB2 header
	copy(packet[4:8], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(packet[8:10], 64)
	binary.LittleEndian.PutUint16(packet[16:18], command)
	
	flags := uint32(0)
	if !isRequest {
		flags |= SMB2FlagsServerToRedir
	}
	binary.LittleEndian.PutUint32(packet[20:24], flags)
	binary.LittleEndian.PutUint32(packet[40:44], treeID)
	binary.LittleEndian.PutUint64(packet[44:52], sessionID)
	
	return packet
}

func BenchmarkSMBParser_ParsePacket(b *testing.B) {
	parser := NewSMBParser(nil)
	
	packet := createSMBPacket(SMB2CommandNegotiate, 0, 0, true)
	timestamp := time.Now().UnixNano()
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		_, _ = parser.ParsePacket(packet, "10.0.0.100", "10.0.0.1", 49152, 445, timestamp)
	}
}

func BenchmarkSMBParser_ParseHeader(b *testing.B) {
	parser := NewSMBParser(nil)
	
	header := make([]byte, 64)
	copy(header[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(header[4:6], 64)
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		_, _ = parser.parseHeader(header)
	}
}

func BenchmarkDecodeUTF16LE(b *testing.B) {
	data := []byte{'T', 0, 'e', 0, 's', 0, 't', 0, ' ', 0, 'S', 0, 't', 0, 'r', 0, 'i', 0, 'n', 0, 'g', 0}
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		_ = decodeUTF16LE(data)
	}
}
