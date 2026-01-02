// Package fixtures provides test fixtures and mock data generators for NFA-Linux
package fixtures

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"net"
	"time"

	"github.com/cvalentine99/nfa-linux/internal/models"
)

// =============================================================================
// Packet Fixtures
// =============================================================================

// PacketFixture generates test packets
type PacketFixture struct {
	baseTime time.Time
	counter  int
}

// NewPacketFixture creates a new packet fixture generator
func NewPacketFixture() *PacketFixture {
	return &PacketFixture{
		baseTime: time.Now(),
	}
}

// TCPPacket generates a TCP packet fixture
func (pf *PacketFixture) TCPPacket(srcIP, dstIP string, srcPort, dstPort uint16, payload []byte) *models.Packet {
	pf.counter++
	return &models.Packet{
		ID:            fmt.Sprintf("pkt-%06d", pf.counter),
		Timestamp:     pf.baseTime.Add(time.Duration(pf.counter) * time.Millisecond),
		TimestampNano: pf.baseTime.Add(time.Duration(pf.counter) * time.Millisecond).UnixNano(),
		Length:        uint32(len(payload) + 40), // TCP/IP header
		CaptureLength: uint32(len(payload) + 40),
		SrcIP:         net.ParseIP(srcIP),
		DstIP:         net.ParseIP(dstIP),
		SrcPort:       srcPort,
		DstPort:       dstPort,
		Protocol:      "TCP",
		Payload:       payload,
	}
}

// UDPPacket generates a UDP packet fixture
func (pf *PacketFixture) UDPPacket(srcIP, dstIP string, srcPort, dstPort uint16, payload []byte) *models.Packet {
	pf.counter++
	return &models.Packet{
		ID:            fmt.Sprintf("pkt-%06d", pf.counter),
		Timestamp:     pf.baseTime.Add(time.Duration(pf.counter) * time.Millisecond),
		TimestampNano: pf.baseTime.Add(time.Duration(pf.counter) * time.Millisecond).UnixNano(),
		Length:        uint32(len(payload) + 28), // UDP/IP header
		CaptureLength: uint32(len(payload) + 28),
		SrcIP:         net.ParseIP(srcIP),
		DstIP:         net.ParseIP(dstIP),
		SrcPort:       srcPort,
		DstPort:       dstPort,
		Protocol:      "UDP",
		Payload:       payload,
	}
}

// ICMPPacket generates an ICMP packet fixture
func (pf *PacketFixture) ICMPPacket(srcIP, dstIP string, icmpType, icmpCode uint8) *models.Packet {
	pf.counter++
	payload := []byte{icmpType, icmpCode, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01}
	return &models.Packet{
		ID:            fmt.Sprintf("pkt-%06d", pf.counter),
		Timestamp:     pf.baseTime.Add(time.Duration(pf.counter) * time.Millisecond),
		TimestampNano: pf.baseTime.Add(time.Duration(pf.counter) * time.Millisecond).UnixNano(),
		Length:        uint32(len(payload) + 20),
		CaptureLength: uint32(len(payload) + 20),
		SrcIP:         net.ParseIP(srcIP),
		DstIP:         net.ParseIP(dstIP),
		Protocol:      "ICMP",
		Payload:       payload,
	}
}

// =============================================================================
// Flow Fixtures
// =============================================================================

// FlowFixture generates test flows
type FlowFixture struct {
	baseTime time.Time
	counter  int
}

// NewFlowFixture creates a new flow fixture generator
func NewFlowFixture() *FlowFixture {
	return &FlowFixture{
		baseTime: time.Now(),
	}
}

// TCPFlow generates a TCP flow fixture
func (ff *FlowFixture) TCPFlow(srcIP, dstIP string, srcPort, dstPort uint16) *models.Flow {
	ff.counter++
	return &models.Flow{
		ID:           fmt.Sprintf("flow-%06d", ff.counter),
		SrcIP:        net.ParseIP(srcIP),
		DstIP:        net.ParseIP(dstIP),
		SrcPort:      srcPort,
		DstPort:      dstPort,
		Protocol:     6, // TCP
		ProtocolName: "TCP",
		StartTime:    ff.baseTime,
		EndTime:      ff.baseTime.Add(5 * time.Second),
		Packets:      250,
		Bytes:        163840,
		PacketCount:  250,
		ByteCount:    163840,
	}
}

// HTTPFlow generates an HTTP flow fixture
func (ff *FlowFixture) HTTPFlow(srcIP, dstIP string) *models.Flow {
	flow := ff.TCPFlow(srcIP, dstIP, uint16(40000+ff.counter), 80)
	flow.Metadata = models.FlowMetadata{
		Protocol:  "HTTP",
		UserAgent: "Mozilla/5.0",
	}
	return flow
}

// TLSFlow generates a TLS flow fixture
func (ff *FlowFixture) TLSFlow(srcIP, dstIP string, sni string) *models.Flow {
	flow := ff.TCPFlow(srcIP, dstIP, uint16(40000+ff.counter), 443)
	flow.Metadata = models.FlowMetadata{
		Protocol:   "TLS",
		ServerName: sni,
		JA3:        "e7d705a3286e19ea42f587b344ee6865",
		JA4:        "t13d1516h2_8daaf6152771_b0da82dd1658",
	}
	return flow
}

// DNSFlow generates a DNS flow fixture
func (ff *FlowFixture) DNSFlow(srcIP, dstIP string) *models.Flow {
	ff.counter++
	return &models.Flow{
		ID:           fmt.Sprintf("flow-%06d", ff.counter),
		SrcIP:        net.ParseIP(srcIP),
		DstIP:        net.ParseIP(dstIP),
		SrcPort:      uint16(50000 + ff.counter),
		DstPort:      53,
		Protocol:     17, // UDP
		ProtocolName: "UDP",
		StartTime:    ff.baseTime,
		EndTime:      ff.baseTime.Add(100 * time.Millisecond),
		Packets:      2,
		Bytes:        150,
		PacketCount:  2,
		ByteCount:    150,
		Metadata: models.FlowMetadata{
			Protocol: "DNS",
		},
	}
}

// =============================================================================
// Protocol Payload Fixtures
// =============================================================================

// DNSQueryPayload generates a DNS query payload
func DNSQueryPayload(domain string) []byte {
	var buf bytes.Buffer

	// Transaction ID
	buf.Write([]byte{0x12, 0x34})
	// Flags: standard query
	buf.Write([]byte{0x01, 0x00})
	// Questions: 1
	buf.Write([]byte{0x00, 0x01})
	// Answer RRs: 0
	buf.Write([]byte{0x00, 0x00})
	// Authority RRs: 0
	buf.Write([]byte{0x00, 0x00})
	// Additional RRs: 0
	buf.Write([]byte{0x00, 0x00})

	// Question section
	parts := splitDomain(domain)
	for _, part := range parts {
		buf.WriteByte(byte(len(part)))
		buf.WriteString(part)
	}
	buf.WriteByte(0x00) // Null terminator

	// Type: A
	buf.Write([]byte{0x00, 0x01})
	// Class: IN
	buf.Write([]byte{0x00, 0x01})

	return buf.Bytes()
}

// DNSResponsePayload generates a DNS response payload
func DNSResponsePayload(domain string, ip net.IP) []byte {
	var buf bytes.Buffer

	// Transaction ID
	buf.Write([]byte{0x12, 0x34})
	// Flags: standard response
	buf.Write([]byte{0x81, 0x80})
	// Questions: 1
	buf.Write([]byte{0x00, 0x01})
	// Answer RRs: 1
	buf.Write([]byte{0x00, 0x01})
	// Authority RRs: 0
	buf.Write([]byte{0x00, 0x00})
	// Additional RRs: 0
	buf.Write([]byte{0x00, 0x00})

	// Question section
	parts := splitDomain(domain)
	for _, part := range parts {
		buf.WriteByte(byte(len(part)))
		buf.WriteString(part)
	}
	buf.WriteByte(0x00)
	buf.Write([]byte{0x00, 0x01}) // Type A
	buf.Write([]byte{0x00, 0x01}) // Class IN

	// Answer section
	buf.Write([]byte{0xc0, 0x0c}) // Pointer to domain name
	buf.Write([]byte{0x00, 0x01}) // Type A
	buf.Write([]byte{0x00, 0x01}) // Class IN
	buf.Write([]byte{0x00, 0x00, 0x01, 0x2c}) // TTL: 300
	buf.Write([]byte{0x00, 0x04}) // Data length: 4
	buf.Write(ip.To4())           // IP address

	return buf.Bytes()
}

// HTTPRequestPayload generates an HTTP request payload
func HTTPRequestPayload(method, path, host string) []byte {
	return []byte(fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n", method, path, host))
}

// HTTPResponsePayload generates an HTTP response payload
func HTTPResponsePayload(statusCode int, body string) []byte {
	return []byte(fmt.Sprintf("HTTP/1.1 %d OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n%s", statusCode, len(body), body))
}

// TLSClientHelloPayload generates a TLS ClientHello payload
func TLSClientHelloPayload(sni string) []byte {
	var buf bytes.Buffer

	// Record layer
	buf.WriteByte(0x16) // Handshake
	buf.Write([]byte{0x03, 0x01}) // TLS 1.0 (for compatibility)

	// Placeholder for length (will be filled later)
	lengthPos := buf.Len()
	buf.Write([]byte{0x00, 0x00})

	// Handshake header
	buf.WriteByte(0x01) // ClientHello
	// Placeholder for handshake length
	hsLengthPos := buf.Len()
	buf.Write([]byte{0x00, 0x00, 0x00})

	// ClientHello body
	buf.Write([]byte{0x03, 0x03}) // TLS 1.2

	// Random (32 bytes)
	random := make([]byte, 32)
	rand.Read(random)
	buf.Write(random)

	// Session ID length: 0
	buf.WriteByte(0x00)

	// Cipher suites
	cipherSuites := []uint16{
		0x1301, 0x1302, 0x1303, // TLS 1.3 suites
		0xc02c, 0xc02b, 0xc030, // ECDHE suites
		0x009f, 0x009e, 0x006b, // DHE suites
	}
	binary.Write(&buf, binary.BigEndian, uint16(len(cipherSuites)*2))
	for _, suite := range cipherSuites {
		binary.Write(&buf, binary.BigEndian, suite)
	}

	// Compression methods
	buf.WriteByte(0x01) // Length
	buf.WriteByte(0x00) // null compression

	// Extensions
	var extBuf bytes.Buffer

	// SNI extension
	extBuf.Write([]byte{0x00, 0x00}) // Extension type: server_name
	sniLen := len(sni) + 5
	binary.Write(&extBuf, binary.BigEndian, uint16(sniLen))
	binary.Write(&extBuf, binary.BigEndian, uint16(sniLen-2))
	extBuf.WriteByte(0x00) // Host name type
	binary.Write(&extBuf, binary.BigEndian, uint16(len(sni)))
	extBuf.WriteString(sni)

	// Supported versions extension
	extBuf.Write([]byte{0x00, 0x2b}) // Extension type: supported_versions
	extBuf.Write([]byte{0x00, 0x05}) // Length
	extBuf.WriteByte(0x04)           // Versions length
	extBuf.Write([]byte{0x03, 0x04}) // TLS 1.3
	extBuf.Write([]byte{0x03, 0x03}) // TLS 1.2

	// Write extensions length and data
	binary.Write(&buf, binary.BigEndian, uint16(extBuf.Len()))
	buf.Write(extBuf.Bytes())

	// Fix lengths
	data := buf.Bytes()
	hsLen := len(data) - hsLengthPos - 3
	data[hsLengthPos] = byte(hsLen >> 16)
	data[hsLengthPos+1] = byte(hsLen >> 8)
	data[hsLengthPos+2] = byte(hsLen)

	recordLen := len(data) - lengthPos - 2
	data[lengthPos] = byte(recordLen >> 8)
	data[lengthPos+1] = byte(recordLen)

	return data
}

// QUICInitialPayload generates a QUIC Initial packet payload
func QUICInitialPayload(dcid, scid []byte, version uint32) []byte {
	var buf bytes.Buffer

	// Header byte: Long header, Initial packet type
	buf.WriteByte(0xc0 | 0x00) // Long header + Initial

	// Version
	binary.Write(&buf, binary.BigEndian, version)

	// DCID
	buf.WriteByte(byte(len(dcid)))
	buf.Write(dcid)

	// SCID
	buf.WriteByte(byte(len(scid)))
	buf.Write(scid)

	// Token length: 0
	buf.WriteByte(0x00)

	// Length (variable-length integer encoding for 16 bytes)
	// Using 1-byte encoding: values 0-63 use single byte
	buf.WriteByte(0x10) // 16 bytes payload length

	// Encrypted payload (random)
	payload := make([]byte, 16)
	rand.Read(payload)
	buf.Write(payload)

	return buf.Bytes()
}

// SMB2NegotiatePayload generates an SMB2 Negotiate request payload
func SMB2NegotiatePayload(dialects []uint16) []byte {
	var buf bytes.Buffer

	// SMB2 header
	buf.Write([]byte{0xfe, 'S', 'M', 'B'}) // Protocol ID
	binary.Write(&buf, binary.LittleEndian, uint16(64)) // Structure size
	buf.Write(make([]byte, 2)) // Credit charge
	buf.Write(make([]byte, 4)) // Status
	binary.Write(&buf, binary.LittleEndian, uint16(0)) // Command: Negotiate
	buf.Write(make([]byte, 2)) // Credit request
	buf.Write(make([]byte, 4)) // Flags
	buf.Write(make([]byte, 4)) // Next command
	buf.Write(make([]byte, 8)) // Message ID
	buf.Write(make([]byte, 4)) // Process ID
	buf.Write(make([]byte, 4)) // Tree ID
	buf.Write(make([]byte, 8)) // Session ID
	buf.Write(make([]byte, 16)) // Signature

	// Negotiate request
	binary.Write(&buf, binary.LittleEndian, uint16(36)) // Structure size
	binary.Write(&buf, binary.LittleEndian, uint16(len(dialects))) // Dialect count
	buf.Write(make([]byte, 2)) // Security mode
	buf.Write(make([]byte, 2)) // Reserved
	buf.Write(make([]byte, 4)) // Capabilities
	buf.Write(make([]byte, 16)) // Client GUID
	buf.Write(make([]byte, 4)) // Negotiate context offset
	buf.Write(make([]byte, 2)) // Negotiate context count
	buf.Write(make([]byte, 2)) // Reserved2

	// Dialects
	for _, dialect := range dialects {
		binary.Write(&buf, binary.LittleEndian, dialect)
	}

	return buf.Bytes()
}

// =============================================================================
// File Fixtures
// =============================================================================

// PNGFileFixture generates a minimal PNG file
func PNGFileFixture(width, height int) []byte {
	var buf bytes.Buffer

	// PNG signature
	buf.Write([]byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a})

	// IHDR chunk
	var ihdr bytes.Buffer
	binary.Write(&ihdr, binary.BigEndian, uint32(width))
	binary.Write(&ihdr, binary.BigEndian, uint32(height))
	ihdr.WriteByte(8)  // Bit depth
	ihdr.WriteByte(2)  // Color type (RGB)
	ihdr.WriteByte(0)  // Compression
	ihdr.WriteByte(0)  // Filter
	ihdr.WriteByte(0)  // Interlace
	writeChunk(&buf, "IHDR", ihdr.Bytes())

	// IDAT chunk (minimal compressed data)
	idat := []byte{0x78, 0x9c, 0x62, 0x60, 0x60, 0x60, 0x00, 0x00, 0x00, 0x04, 0x00, 0x01}
	writeChunk(&buf, "IDAT", idat)

	// IEND chunk
	writeChunk(&buf, "IEND", nil)

	return buf.Bytes()
}

// PDFFileFixture generates a minimal PDF file
func PDFFileFixture() []byte {
	return []byte(`%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
xref
0 4
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
trailer
<< /Size 4 /Root 1 0 R >>
startxref
190
%%EOF
`)
}

// ZIPFileFixture generates a minimal ZIP file
func ZIPFileFixture(filename string, content []byte) []byte {
	var buf bytes.Buffer

	// Calculate CRC32 of content
	crc := crc32.ChecksumIEEE(content)

	// Local file header
	buf.Write([]byte{0x50, 0x4b, 0x03, 0x04}) // Signature
	buf.Write([]byte{0x14, 0x00}) // Version needed
	buf.Write([]byte{0x00, 0x00}) // Flags
	buf.Write([]byte{0x00, 0x00}) // Compression: none
	buf.Write([]byte{0x00, 0x00}) // Mod time
	buf.Write([]byte{0x00, 0x00}) // Mod date
	binary.Write(&buf, binary.LittleEndian, crc) // CRC32
	binary.Write(&buf, binary.LittleEndian, uint32(len(content))) // Compressed size
	binary.Write(&buf, binary.LittleEndian, uint32(len(content))) // Uncompressed size
	binary.Write(&buf, binary.LittleEndian, uint16(len(filename))) // Filename length
	buf.Write([]byte{0x00, 0x00}) // Extra field length
	buf.WriteString(filename)
	buf.Write(content)

	// Central directory
	cdOffset := buf.Len()
	buf.Write([]byte{0x50, 0x4b, 0x01, 0x02}) // Signature
	buf.Write([]byte{0x14, 0x00}) // Version made by
	buf.Write([]byte{0x14, 0x00}) // Version needed
	buf.Write([]byte{0x00, 0x00}) // Flags
	buf.Write([]byte{0x00, 0x00}) // Compression
	buf.Write([]byte{0x00, 0x00}) // Mod time
	buf.Write([]byte{0x00, 0x00}) // Mod date
	binary.Write(&buf, binary.LittleEndian, crc) // CRC32
	binary.Write(&buf, binary.LittleEndian, uint32(len(content)))
	binary.Write(&buf, binary.LittleEndian, uint32(len(content)))
	binary.Write(&buf, binary.LittleEndian, uint16(len(filename)))
	buf.Write([]byte{0x00, 0x00}) // Extra field length
	buf.Write([]byte{0x00, 0x00}) // Comment length
	buf.Write([]byte{0x00, 0x00}) // Disk number
	buf.Write([]byte{0x00, 0x00}) // Internal attributes
	buf.Write(make([]byte, 4)) // External attributes
	buf.Write(make([]byte, 4)) // Offset
	buf.WriteString(filename)

	// End of central directory
	cdSize := buf.Len() - cdOffset
	buf.Write([]byte{0x50, 0x4b, 0x05, 0x06}) // Signature
	buf.Write([]byte{0x00, 0x00}) // Disk number
	buf.Write([]byte{0x00, 0x00}) // CD disk number
	binary.Write(&buf, binary.LittleEndian, uint16(1)) // Entries on disk
	binary.Write(&buf, binary.LittleEndian, uint16(1)) // Total entries
	binary.Write(&buf, binary.LittleEndian, uint32(cdSize)) // CD size
	binary.Write(&buf, binary.LittleEndian, uint32(cdOffset)) // CD offset
	buf.Write([]byte{0x00, 0x00}) // Comment length

	return buf.Bytes()
}

// =============================================================================
// Helper Functions
// =============================================================================

func splitDomain(domain string) []string {
	var parts []string
	current := ""
	for _, c := range domain {
		if c == '.' {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

func writeChunk(buf *bytes.Buffer, chunkType string, data []byte) {
	// Length
	binary.Write(buf, binary.BigEndian, uint32(len(data)))
	// Type
	buf.WriteString(chunkType)
	// Data
	buf.Write(data)
	// CRC (calculated over type + data)
	crcData := append([]byte(chunkType), data...)
	crc := crc32.ChecksumIEEE(crcData)
	binary.Write(buf, binary.BigEndian, crc)
}

// RandomBytes generates random bytes
func RandomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// RandomIP generates a random IP address
func RandomIP() net.IP {
	return net.IPv4(
		byte(randInt(1, 254)),
		byte(randInt(0, 255)),
		byte(randInt(0, 255)),
		byte(randInt(1, 254)),
	)
}

// RandomPort generates a random port number
func RandomPort() uint16 {
	return uint16(randInt(1024, 65535))
}

func randInt(min, max int) int {
	b := make([]byte, 4)
	rand.Read(b)
	n := int(binary.BigEndian.Uint32(b))
	if n < 0 {
		n = -n
	}
	return min + n%(max-min+1)
}
