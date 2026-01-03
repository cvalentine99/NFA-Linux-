// Package parser provides fuzz tests for protocol parsers.
// Run with: go test -fuzz=FuzzDNS -fuzztime=60s ./internal/parser/
package parser

import (
	"bytes"
	"testing"
)

// =============================================================================
// DNS Parser Fuzzing
// =============================================================================

// FuzzDNSRawParse fuzzes the raw DNS packet parser.
func FuzzDNSRawParse(f *testing.F) {
	// Add seed corpus
	f.Add([]byte{
		// Valid DNS query for example.com
		0x12, 0x34, // Transaction ID
		0x01, 0x00, // Flags: standard query
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answers: 0
		0x00, 0x00, // Authority: 0
		0x00, 0x00, // Additional: 0
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', // "example"
		0x03, 'c', 'o', 'm', // "com"
		0x00,       // Root label
		0x00, 0x01, // Type: A
		0x00, 0x01, // Class: IN
	})
	
	// DNS response with compression pointer
	f.Add([]byte{
		0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x07, 'e', 'x', 'a',
		'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm',
		0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, // Compression pointer
		0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10,
		0x00, 0x04, 0x5d, 0xb8, 0xd8, 0x22,
	})
	
	// Malformed: compression pointer loop
	f.Add([]byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0xc0, 0x0c, // Self-referencing pointer
		0x00, 0x01, 0x00, 0x01,
	})
	
	// Empty packet
	f.Add([]byte{})
	
	// Minimal valid header
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	
	parser := NewDNSParser()
	
	f.Fuzz(func(t *testing.T, data []byte) {
		// Should not panic
		_, _ = parser.ParseRawDNS(data)
	})
}

// =============================================================================
// HTTP/2 Parser Fuzzing
// =============================================================================

// FuzzHTTP2Frame fuzzes the HTTP/2 frame parser.
func FuzzHTTP2Frame(f *testing.F) {
	// Valid HEADERS frame
	f.Add([]byte{
		0x00, 0x00, 0x05, // Length: 5
		0x01,             // Type: HEADERS
		0x04,             // Flags: END_HEADERS
		0x00, 0x00, 0x00, 0x01, // Stream ID: 1
		0x82, 0x86, 0x84, 0x41, 0x8a, // HPACK encoded headers
	})
	
	// Valid DATA frame
	f.Add([]byte{
		0x00, 0x00, 0x0d, // Length: 13
		0x00,             // Type: DATA
		0x01,             // Flags: END_STREAM
		0x00, 0x00, 0x00, 0x01, // Stream ID: 1
		'H', 'e', 'l', 'l', 'o', ',', ' ', 'W', 'o', 'r', 'l', 'd', '!',
	})
	
	// SETTINGS frame
	f.Add([]byte{
		0x00, 0x00, 0x06, // Length: 6
		0x04,             // Type: SETTINGS
		0x00,             // Flags
		0x00, 0x00, 0x00, 0x00, // Stream ID: 0
		0x00, 0x01, 0x00, 0x00, 0x10, 0x00, // HEADER_TABLE_SIZE = 4096
	})
	
	// Empty
	f.Add([]byte{})
	
	// Minimal frame header
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0})
	
	parser := NewHTTP2Parser()
	
	f.Fuzz(func(t *testing.T, data []byte) {
		frame, _, err := parser.ParseFrame(data)
		if err == nil && frame != nil {
			// Try to process the frame
			_ = parser.ProcessFrame(frame)
		}
	})
}

// FuzzHPACKDecode fuzzes the HPACK decoder.
func FuzzHPACKDecode(f *testing.F) {
	// Indexed header field
	f.Add([]byte{0x82}) // :method: GET
	
	// Literal header with indexing
	f.Add([]byte{
		0x40, 0x0a, 'c', 'u', 's', 't', 'o', 'm', '-', 'k', 'e', 'y',
		0x0d, 'c', 'u', 's', 't', 'o', 'm', '-', 'h', 'e', 'a', 'd', 'e', 'r',
	})
	
	// Dynamic table size update
	f.Add([]byte{0x3f, 0xe1, 0x1f}) // Size update to 4096
	
	// Empty
	f.Add([]byte{})
	
	parser := NewHTTP2Parser()
	
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parser.DecodeHPACK(data)
	})
}

// =============================================================================
// QUIC Parser Fuzzing
// =============================================================================

// FuzzQUICHeader fuzzes the QUIC header parser.
func FuzzQUICHeader(f *testing.F) {
	// Long header (Initial packet)
	f.Add([]byte{
		0xc0,                   // Long header, Initial
		0x00, 0x00, 0x00, 0x01, // Version 1
		0x08,                   // DCID length
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DCID
		0x00, // SCID length
		0x00, // Token length (varint)
		0x40, 0x75, // Packet length (varint)
	})
	
	// Version Negotiation packet
	f.Add([]byte{
		0x80,                   // Long header
		0x00, 0x00, 0x00, 0x00, // Version 0 (negotiation)
		0x08,                   // DCID length
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x08, // SCID length
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x00, 0x00, 0x00, 0x01, // Supported version 1
		0x6b, 0x33, 0x43, 0xcf, // Supported version 2
	})
	
	// Short header
	f.Add([]byte{
		0x40, // Short header
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DCID
	})
	
	// Empty
	f.Add([]byte{})
	
	parser := NewQUICParser(nil)
	
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parser.ParsePacket(data, "192.168.1.1", "192.168.1.2", 12345, 443, 0)
	})
}

// =============================================================================
// SMB Parser Fuzzing
// =============================================================================

// FuzzSMB2Header fuzzes the SMB2 header parser.
func FuzzSMB2Header(f *testing.F) {
	// Valid SMB2 Negotiate request
	f.Add([]byte{
		0xfe, 'S', 'M', 'B', // Protocol ID
		0x40, 0x00, // Structure size
		0x00, 0x00, // Credit charge
		0x00, 0x00, 0x00, 0x00, // Status
		0x00, 0x00, // Command: Negotiate
		0x00, 0x00, // Credit request
		0x00, 0x00, 0x00, 0x00, // Flags
		0x00, 0x00, 0x00, 0x00, // Next command
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Message ID
		0x00, 0x00, 0x00, 0x00, // Reserved
		0x00, 0x00, 0x00, 0x00, // Tree ID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Session ID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature (16 bytes)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	})
	
	// SMB3 Transform header (encrypted)
	f.Add([]byte{
		0xfd, 'S', 'M', 'B', // Transform Protocol ID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature (16 bytes)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Nonce (16 bytes)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x40, 0x00, 0x00, 0x00, // Original message size
		0x00, 0x00, // Reserved
		0x01, 0x00, // Flags: encrypted
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Session ID
	})
	
	// With NetBIOS header
	f.Add(append([]byte{0x00, 0x00, 0x00, 0x44}, bytes.Repeat([]byte{0x00}, 68)...))
	
	// Empty
	f.Add([]byte{})
	
	parser := NewSMBParser(nil)
	
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parser.ParsePacket(data, "192.168.1.1", "192.168.1.2", 12345, 445, 0)
	})
}

// =============================================================================
// TLS Parser Fuzzing
// =============================================================================

// FuzzTLSClientHello fuzzes the TLS ClientHello parser.
func FuzzTLSClientHello(f *testing.F) {
	// Minimal TLS 1.2 ClientHello
	f.Add([]byte{
		0x16,       // Content type: Handshake
		0x03, 0x01, // Version: TLS 1.0
		0x00, 0x45, // Length
		0x01,             // Handshake type: ClientHello
		0x00, 0x00, 0x41, // Length
		0x03, 0x03, // Version: TLS 1.2
		// Random (32 bytes)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, // Session ID length
		0x00, 0x02, // Cipher suites length
		0x00, 0x2f, // TLS_RSA_WITH_AES_128_CBC_SHA
		0x01, 0x00, // Compression methods
		0x00, 0x16, // Extensions length
		// SNI extension
		0x00, 0x00, 0x00, 0x0f, 0x00, 0x0d, 0x00, 0x00,
		0x0a, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
	})
	
	// Empty
	f.Add([]byte{})
	
	// Just record header
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x00})
	
	parser := NewTLSParser()
	
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parser.ParseClientHello(data, 0)
	})
}

// =============================================================================
// HTTP Parser Fuzzing
// =============================================================================

// FuzzHTTPRequest fuzzes the HTTP request parser.
func FuzzHTTPRequest(f *testing.F) {
	// Simple GET request
	f.Add([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	
	// POST with body
	f.Add([]byte("POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 13\r\n\r\nHello, World!"))
	
	// With various headers
	f.Add([]byte("GET /path HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Test\r\nAccept: */*\r\nCookie: session=abc123\r\n\r\n"))
	
	// Chunked encoding
	f.Add([]byte("POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello\r\n0\r\n\r\n"))
	
	// Empty
	f.Add([]byte{})
	
	// Partial
	f.Add([]byte("GET"))
	
	parser := NewHTTPParser()
	
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parser.ParseRequest(data, 0)
	})
}

// FuzzHTTPGzipDecompress fuzzes gzip decompression.
func FuzzHTTPGzipDecompress(f *testing.F) {
	// Valid gzip data (empty content)
	f.Add([]byte{
		0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	})
	
	// Empty
	f.Add([]byte{})
	
	// Invalid gzip header
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})
	
	f.Fuzz(func(t *testing.T, data []byte) {
		// decompressGzip is not exported, so we test via ParseResponse
		// which handles gzip internally
		parser := NewHTTPParser()
		response := "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: " +
			string(rune(len(data))) + "\r\n\r\n" + string(data)
		_, _ = parser.ParseResponse([]byte(response), 0)
	})
}

// =============================================================================
// Additional Edge Case Fuzzing
// =============================================================================

// FuzzDNSCompressionPointer specifically targets compression pointer attacks.
func FuzzDNSCompressionPointer(f *testing.F) {
	// Self-referencing pointer at offset 12
	f.Add([]byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0xc0, 0x0c,
	})
	
	// Forward pointer (invalid)
	f.Add([]byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0xc0, 0xff,
	})
	
	// Nested pointers
	f.Add([]byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x03, 'w', 'w', 'w', 0xc0, 0x10, // Points to next
		0x03, 'c', 'o', 'm', 0x00,
	})
	
	parser := NewDNSParser()
	
	f.Fuzz(func(t *testing.T, data []byte) {
		// Should handle any compression pointer pattern without panic or infinite loop
		_, _ = parser.ParseRawDNS(data)
	})
}

// FuzzHTTPChunkedEncoding specifically targets chunked transfer encoding.
func FuzzHTTPChunkedEncoding(f *testing.F) {
	// Valid chunked
	f.Add([]byte("5\r\nhello\r\n0\r\n\r\n"))
	
	// Invalid chunk size
	f.Add([]byte("ffffffff\r\ndata\r\n"))
	
	// Missing CRLF
	f.Add([]byte("5\nhello\n0\n\n"))
	
	// Negative-looking size
	f.Add([]byte("-1\r\n\r\n"))
	
	// Chunk extensions
	f.Add([]byte("5;ext=value\r\nhello\r\n0\r\n\r\n"))
	
	parser := NewHTTPParser()
	
	f.Fuzz(func(t *testing.T, data []byte) {
		request := "POST / HTTP/1.1\r\nHost: test\r\nTransfer-Encoding: chunked\r\n\r\n" + string(data)
		_, _ = parser.ParseRequest([]byte(request), 0)
	})
}

// FuzzTLSExtensions specifically targets TLS extension parsing.
func FuzzTLSExtensions(f *testing.F) {
	// SNI extension
	f.Add([]byte{0x00, 0x00, 0x00, 0x0e, 0x00, 0x0c, 0x00, 0x00, 0x09, 't', 'e', 's', 't', '.', 'c', 'o', 'm'})
	
	// Supported versions extension
	f.Add([]byte{0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04})
	
	// ALPN extension
	f.Add([]byte{0x00, 0x10, 0x00, 0x0b, 0x00, 0x09, 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'})
	
	// Key share extension (large)
	f.Add(append([]byte{0x00, 0x33, 0x00, 0x45, 0x00, 0x43, 0x00, 0x1d, 0x00, 0x20}, make([]byte, 32)...))
	
	// Empty extension
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})
	
	// Oversized extension length
	f.Add([]byte{0x00, 0x00, 0xff, 0xff})
	
	parser := NewTLSParser()
	
	f.Fuzz(func(t *testing.T, data []byte) {
		// Build a ClientHello with the fuzzed extensions
		clientHello := buildClientHelloWithExtensions(data)
		_, _ = parser.ParseClientHello(clientHello, 0)
	})
}

// buildClientHelloWithExtensions creates a ClientHello with given extensions.
func buildClientHelloWithExtensions(extensions []byte) []byte {
	var buf bytes.Buffer
	
	// Record header
	buf.WriteByte(0x16)       // Handshake
	buf.Write([]byte{0x03, 0x01}) // TLS 1.0
	
	// Calculate lengths
	handshakeLen := 38 + 2 + len(extensions) // Fixed fields + extensions length + extensions
	buf.WriteByte(byte(handshakeLen >> 8))
	buf.WriteByte(byte(handshakeLen))
	
	// Handshake header
	buf.WriteByte(0x01) // ClientHello
	buf.WriteByte(0x00)
	buf.WriteByte(byte((handshakeLen - 4) >> 8))
	buf.WriteByte(byte(handshakeLen - 4))
	
	// ClientHello
	buf.Write([]byte{0x03, 0x03}) // TLS 1.2
	buf.Write(make([]byte, 32))   // Random
	buf.WriteByte(0x00)           // Session ID length
	buf.Write([]byte{0x00, 0x02, 0x00, 0x2f}) // Cipher suites
	buf.Write([]byte{0x01, 0x00}) // Compression
	
	// Extensions
	buf.WriteByte(byte(len(extensions) >> 8))
	buf.WriteByte(byte(len(extensions)))
	buf.Write(extensions)
	
	return buf.Bytes()
}

// FuzzQUICVarint specifically targets QUIC variable-length integer parsing.
func FuzzQUICVarint(f *testing.F) {
	// 1-byte varint
	f.Add([]byte{0x00})
	f.Add([]byte{0x3f})
	
	// 2-byte varint
	f.Add([]byte{0x40, 0x00})
	f.Add([]byte{0x7f, 0xff})
	
	// 4-byte varint
	f.Add([]byte{0x80, 0x00, 0x00, 0x00})
	f.Add([]byte{0xbf, 0xff, 0xff, 0xff})
	
	// 8-byte varint
	f.Add([]byte{0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	
	// Truncated
	f.Add([]byte{0x40})
	f.Add([]byte{0x80, 0x00})
	
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = decodeQUICVarintFuzz(data)
	})
}

// decodeQUICVarintFuzz decodes a QUIC variable-length integer (fuzz test version).
func decodeQUICVarintFuzz(data []byte) (uint64, int) {
	if len(data) == 0 {
		return 0, 0
	}
	
	prefix := data[0] >> 6
	var length int
	switch prefix {
	case 0:
		length = 1
	case 1:
		length = 2
	case 2:
		length = 4
	case 3:
		length = 8
	}
	
	if len(data) < length {
		return 0, 0
	}
	
	var value uint64
	switch length {
	case 1:
		value = uint64(data[0] & 0x3f)
	case 2:
		value = uint64(data[0]&0x3f)<<8 | uint64(data[1])
	case 4:
		value = uint64(data[0]&0x3f)<<24 | uint64(data[1])<<16 | uint64(data[2])<<8 | uint64(data[3])
	case 8:
		value = uint64(data[0]&0x3f)<<56 | uint64(data[1])<<48 | uint64(data[2])<<40 | uint64(data[3])<<32 |
			uint64(data[4])<<24 | uint64(data[5])<<16 | uint64(data[6])<<8 | uint64(data[7])
	}
	
	return value, length
}

// =============================================================================
// Corpus Generation Helpers
// =============================================================================

// GenerateDNSCorpus generates a corpus of DNS packets for fuzzing.
func GenerateDNSCorpus() [][]byte {
	var corpus [][]byte
	
	// Various query types
	queryTypes := []uint16{1, 2, 5, 6, 12, 15, 16, 28, 33, 255}
	for _, qtype := range queryTypes {
		pkt := makeDNSQuery("test.example.com", qtype)
		corpus = append(corpus, pkt)
	}
	
	// Long domain names
	longDomain := bytes.Repeat([]byte{'a'}, 63)
	corpus = append(corpus, makeDNSQuery(string(longDomain)+".com", 1))
	
	// Many labels
	manyLabels := "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.example.com"
	corpus = append(corpus, makeDNSQuery(manyLabels, 1))
	
	return corpus
}

func makeDNSQuery(domain string, qtype uint16) []byte {
	var buf bytes.Buffer
	
	// Header
	buf.Write([]byte{0x12, 0x34}) // Transaction ID
	buf.Write([]byte{0x01, 0x00}) // Flags
	buf.Write([]byte{0x00, 0x01}) // Questions
	buf.Write([]byte{0x00, 0x00}) // Answers
	buf.Write([]byte{0x00, 0x00}) // Authority
	buf.Write([]byte{0x00, 0x00}) // Additional
	
	// Question
	labels := bytes.Split([]byte(domain), []byte{'.'})
	for _, label := range labels {
		buf.WriteByte(byte(len(label)))
		buf.Write(label)
	}
	buf.WriteByte(0) // Root label
	
	buf.WriteByte(byte(qtype >> 8))
	buf.WriteByte(byte(qtype))
	buf.Write([]byte{0x00, 0x01}) // Class IN
	
	return buf.Bytes()
}
