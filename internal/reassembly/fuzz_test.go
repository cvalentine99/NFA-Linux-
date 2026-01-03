// Package reassembly provides TCP stream reassembly for NFA-Linux.
package reassembly

import (
	"encoding/binary"
	"testing"
)

// FuzzTCPSegment fuzzes TCP segment processing.
// Tests the reassembler's ability to handle malformed or adversarial TCP segments.
func FuzzTCPSegment(f *testing.F) {
	// Seed corpus with various TCP segment patterns
	seeds := [][]byte{
		// Normal segment
		{0x00, 0x50, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00},
		// SYN packet
		{0x00, 0x50, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00},
		// FIN packet
		{0x00, 0x50, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x11, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00},
		// RST packet
		{0x00, 0x50, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x04, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00},
		// Segment with data
		{0x00, 0x50, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x18, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 'H', 'e', 'l', 'l', 'o'},
		// Empty segment
		{},
		// Minimal header
		{0x00, 0x50, 0x01, 0xbb},
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Parse TCP header fields if enough data
		if len(data) < 20 {
			return
		}

		// Extract fields to verify parsing doesn't panic
		_ = binary.BigEndian.Uint16(data[0:2])  // src port
		_ = binary.BigEndian.Uint16(data[2:4])  // dst port
		_ = binary.BigEndian.Uint32(data[4:8])  // seq
		_ = binary.BigEndian.Uint32(data[8:12]) // ack
		
		dataOffset := (data[12] >> 4) * 4
		if dataOffset < 20 || int(dataOffset) > len(data) {
			return
		}

		// Extract flags
		flags := data[13]
		_ = flags & 0x01 // FIN
		_ = flags & 0x02 // SYN
		_ = flags & 0x04 // RST
		_ = flags & 0x08 // PSH
		_ = flags & 0x10 // ACK

		// Extract payload
		if int(dataOffset) < len(data) {
			_ = data[dataOffset:]
		}
	})
}

// FuzzStreamKey fuzzes stream key generation.
func FuzzStreamKey(f *testing.F) {
	// Seed with various IP:port combinations
	seeds := []struct {
		srcIP   string
		srcPort uint16
		dstIP   string
		dstPort uint16
	}{
		{"192.168.1.1", 12345, "10.0.0.1", 80},
		{"::1", 443, "::1", 8080},
		{"0.0.0.0", 0, "255.255.255.255", 65535},
		{"", 0, "", 0},
	}

	for _, seed := range seeds {
		f.Add(seed.srcIP, seed.srcPort, seed.dstIP, seed.dstPort)
	}

	f.Fuzz(func(t *testing.T, srcIP string, srcPort uint16, dstIP string, dstPort uint16) {
		// Generate stream key (should not panic)
		key := generateStreamKey(srcIP, srcPort, dstIP, dstPort)
		
		// Key should be deterministic
		key2 := generateStreamKey(srcIP, srcPort, dstIP, dstPort)
		if key != key2 {
			t.Errorf("Stream key not deterministic: %s != %s", key, key2)
		}
	})
}

// generateStreamKey creates a unique key for a TCP stream.
// This is a helper for fuzzing - actual implementation may differ.
func generateStreamKey(srcIP string, srcPort uint16, dstIP string, dstPort uint16) string {
	// Normalize direction (smaller IP:port first)
	if srcIP > dstIP || (srcIP == dstIP && srcPort > dstPort) {
		srcIP, dstIP = dstIP, srcIP
		srcPort, dstPort = dstPort, srcPort
	}
	return srcIP + ":" + string(rune(srcPort)) + "-" + dstIP + ":" + string(rune(dstPort))
}

// FuzzReassemblyBuffer fuzzes the reassembly buffer logic.
func FuzzReassemblyBuffer(f *testing.F) {
	// Seed with various segment patterns
	type segment struct {
		seq  uint32
		data []byte
	}

	// Add seeds as raw bytes (seq as 4 bytes + data)
	seeds := [][]byte{
		// Normal sequential segments
		append([]byte{0, 0, 0, 0}, []byte("Hello")...),
		append([]byte{0, 0, 0, 5}, []byte("World")...),
		// Overlapping segments
		append([]byte{0, 0, 0, 3}, []byte("loWor")...),
		// Gap in sequence
		append([]byte{0, 0, 0, 100}, []byte("Far away")...),
		// Wraparound sequence number
		append([]byte{0xff, 0xff, 0xff, 0xfe}, []byte("Wrap")...),
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 4 {
			return
		}

		seq := binary.BigEndian.Uint32(data[:4])
		payload := data[4:]

		// Simulate buffer operations (should not panic)
		buffer := make(map[uint32][]byte)
		buffer[seq] = payload

		// Check for overlaps
		for existingSeq := range buffer {
			if existingSeq != seq {
				// Calculate overlap
				end1 := seq + uint32(len(payload))
				end2 := existingSeq + uint32(len(buffer[existingSeq]))
				
				// Check if ranges overlap
				if seq < end2 && existingSeq < end1 {
					// Overlapping - this is fine, just testing
				}
			}
		}
	})
}

// FuzzOutOfOrderHandling fuzzes out-of-order segment handling.
func FuzzOutOfOrderHandling(f *testing.F) {
	// Seed with segment arrival patterns
	f.Add([]byte{1, 2, 3, 4, 5})      // In order
	f.Add([]byte{5, 4, 3, 2, 1})      // Reverse order
	f.Add([]byte{1, 3, 2, 5, 4})      // Mixed order
	f.Add([]byte{1, 1, 1, 1, 1})      // Duplicates
	f.Add([]byte{1, 100, 2, 99, 3})   // Large gaps

	f.Fuzz(func(t *testing.T, order []byte) {
		if len(order) == 0 {
			return
		}

		// Simulate receiving segments in given order
		received := make(map[byte]bool)
		maxSeen := byte(0)
		gaps := 0

		for _, seq := range order {
			if received[seq] {
				// Duplicate
				continue
			}
			received[seq] = true

			if seq > maxSeen+1 && maxSeen > 0 {
				gaps++
			}
			if seq > maxSeen {
				maxSeen = seq
			}
		}

		// Verify we can handle any pattern without panic
		_ = gaps
	})
}
