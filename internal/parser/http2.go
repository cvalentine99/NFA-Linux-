// Package parser provides HTTP/2 frame and HPACK header parsing for NFA-Linux.
package parser

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

// HTTP/2 Frame Types (RFC 7540)
const (
	HTTP2FrameData         = 0x0
	HTTP2FrameHeaders      = 0x1
	HTTP2FramePriority     = 0x2
	HTTP2FrameRSTStream    = 0x3
	HTTP2FrameSettings     = 0x4
	HTTP2FramePushPromise  = 0x5
	HTTP2FramePing         = 0x6
	HTTP2FrameGoAway       = 0x7
	HTTP2FrameWindowUpdate = 0x8
	HTTP2FrameContinuation = 0x9
)

// HTTP/2 Frame Flags
const (
	HTTP2FlagEndStream  = 0x1
	HTTP2FlagEndHeaders = 0x4
	HTTP2FlagPadded     = 0x8
	HTTP2FlagPriority   = 0x20
)

// HPACK Constants
const (
	// MaxHPACKDynamicTableSize is the default max dynamic table size (4KB)
	MaxHPACKDynamicTableSize = 4096
	// MaxHPACKHeaderSize limits individual header size to prevent DoS
	MaxHPACKHeaderSize = 8192
	// MaxHPACKHeaderCount limits total headers per request
	MaxHPACKHeaderCount = 100
)

// HTTP2Frame represents a parsed HTTP/2 frame.
type HTTP2Frame struct {
	Length   uint32
	Type     uint8
	Flags    uint8
	StreamID uint32
	Payload  []byte
}

// HTTP2Parser parses HTTP/2 frames and HPACK-encoded headers.
type HTTP2Parser struct {
	// HPACK decoder state (per-connection)
	dynamicTable     []hpackEntry
	dynamicTableSize int
	maxTableSize     int
	
	// Callbacks
	onHeaders func(streamID uint32, headers map[string]string, endStream bool)
	onData    func(streamID uint32, data []byte, endStream bool)
	
	mu sync.Mutex
}

// hpackEntry represents an entry in the HPACK dynamic table.
type hpackEntry struct {
	name  string
	value string
	size  int // name length + value length + 32 (RFC 7541)
}

// NewHTTP2Parser creates a new HTTP/2 parser.
func NewHTTP2Parser() *HTTP2Parser {
	return &HTTP2Parser{
		dynamicTable: make([]hpackEntry, 0),
		maxTableSize: MaxHPACKDynamicTableSize,
	}
}

// SetHeadersHandler sets the callback for decoded headers.
func (p *HTTP2Parser) SetHeadersHandler(handler func(streamID uint32, headers map[string]string, endStream bool)) {
	p.onHeaders = handler
}

// SetDataHandler sets the callback for data frames.
func (p *HTTP2Parser) SetDataHandler(handler func(streamID uint32, data []byte, endStream bool)) {
	p.onData = handler
}

// ParseFrame parses a single HTTP/2 frame from data.
func (p *HTTP2Parser) ParseFrame(data []byte) (*HTTP2Frame, int, error) {
	if len(data) < 9 {
		return nil, 0, io.ErrShortBuffer
	}
	
	// Frame header: Length (24 bits) + Type (8 bits) + Flags (8 bits) + Stream ID (32 bits)
	length := uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2])
	frameType := data[3]
	flags := data[4]
	streamID := binary.BigEndian.Uint32(data[5:9]) & 0x7FFFFFFF // Clear reserved bit
	
	// Sanity check frame length (max 16MB per RFC 7540)
	if length > 16777215 {
		return nil, 0, fmt.Errorf("HTTP/2 frame too large: %d bytes", length)
	}
	
	totalLen := 9 + int(length)
	if len(data) < totalLen {
		return nil, 0, io.ErrShortBuffer
	}
	
	frame := &HTTP2Frame{
		Length:   length,
		Type:     frameType,
		Flags:    flags,
		StreamID: streamID,
		Payload:  data[9:totalLen],
	}
	
	return frame, totalLen, nil
}

// ProcessFrame processes a parsed HTTP/2 frame.
func (p *HTTP2Parser) ProcessFrame(frame *HTTP2Frame) error {
	switch frame.Type {
	case HTTP2FrameHeaders:
		return p.processHeadersFrame(frame)
	case HTTP2FrameData:
		return p.processDataFrame(frame)
	case HTTP2FrameContinuation:
		return p.processContinuationFrame(frame)
	case HTTP2FrameSettings:
		return p.processSettingsFrame(frame)
	}
	return nil
}

// processHeadersFrame processes a HEADERS frame.
func (p *HTTP2Parser) processHeadersFrame(frame *HTTP2Frame) error {
	payload := frame.Payload
	offset := 0
	
	// Handle padding
	if frame.Flags&HTTP2FlagPadded != 0 {
		if len(payload) < 1 {
			return errors.New("HEADERS frame too short for padding")
		}
		padLen := int(payload[0])
		offset = 1
		if len(payload) < offset+padLen {
			return errors.New("HEADERS frame padding exceeds payload")
		}
		payload = payload[offset : len(payload)-padLen]
		offset = 0
	}
	
	// Handle priority
	if frame.Flags&HTTP2FlagPriority != 0 {
		if len(payload) < offset+5 {
			return errors.New("HEADERS frame too short for priority")
		}
		offset += 5 // Skip stream dependency (4) + weight (1)
	}
	
	// Decode HPACK headers
	headers, err := p.DecodeHPACK(payload[offset:])
	if err != nil {
		return fmt.Errorf("HPACK decode error: %w", err)
	}
	
	endStream := frame.Flags&HTTP2FlagEndStream != 0
	
	if p.onHeaders != nil {
		p.onHeaders(frame.StreamID, headers, endStream)
	}
	
	return nil
}

// processDataFrame processes a DATA frame.
func (p *HTTP2Parser) processDataFrame(frame *HTTP2Frame) error {
	payload := frame.Payload
	
	// Handle padding
	if frame.Flags&HTTP2FlagPadded != 0 {
		if len(payload) < 1 {
			return errors.New("DATA frame too short for padding")
		}
		padLen := int(payload[0])
		if len(payload) < 1+padLen {
			return errors.New("DATA frame padding exceeds payload")
		}
		payload = payload[1 : len(payload)-padLen]
	}
	
	endStream := frame.Flags&HTTP2FlagEndStream != 0
	
	if p.onData != nil {
		p.onData(frame.StreamID, payload, endStream)
	}
	
	return nil
}

// processContinuationFrame processes a CONTINUATION frame.
func (p *HTTP2Parser) processContinuationFrame(frame *HTTP2Frame) error {
	// CONTINUATION frames contain additional header block fragments
	// In a full implementation, we'd buffer these until END_HEADERS
	headers, err := p.DecodeHPACK(frame.Payload)
	if err != nil {
		return fmt.Errorf("HPACK decode error in CONTINUATION: %w", err)
	}
	
	endHeaders := frame.Flags&HTTP2FlagEndHeaders != 0
	
	if p.onHeaders != nil && endHeaders {
		p.onHeaders(frame.StreamID, headers, false)
	}
	
	return nil
}

// processSettingsFrame processes a SETTINGS frame.
func (p *HTTP2Parser) processSettingsFrame(frame *HTTP2Frame) error {
	// SETTINGS frames contain 6-byte settings (ID + Value)
	if len(frame.Payload)%6 != 0 {
		return errors.New("SETTINGS frame has invalid length")
	}
	
	for i := 0; i < len(frame.Payload); i += 6 {
		settingID := binary.BigEndian.Uint16(frame.Payload[i : i+2])
		settingValue := binary.BigEndian.Uint32(frame.Payload[i+2 : i+6])
		
		// SETTINGS_HEADER_TABLE_SIZE (0x1)
		if settingID == 0x1 {
			p.mu.Lock()
			p.maxTableSize = int(settingValue)
			p.evictDynamicTable()
			p.mu.Unlock()
		}
	}
	
	return nil
}

// =============================================================================
// HPACK Decoder (RFC 7541)
// =============================================================================

// DecodeHPACK decodes HPACK-encoded headers.
func (p *HTTP2Parser) DecodeHPACK(data []byte) (map[string]string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	headers := make(map[string]string)
	headerCount := 0
	offset := 0
	
	for offset < len(data) {
		// SAFETY: Limit header count
		headerCount++
		if headerCount > MaxHPACKHeaderCount {
			return headers, fmt.Errorf("HPACK: too many headers (%d)", headerCount)
		}
		
		b := data[offset]
		
		if b&0x80 != 0 {
			// Indexed Header Field (Section 6.1)
			index, n := decodeHPACKInteger(data[offset:], 7)
			if n <= 0 {
				return headers, errors.New("HPACK: invalid indexed header")
			}
			offset += n
			
			name, value, err := p.getIndexedHeader(int(index))
			if err != nil {
				return headers, err
			}
			headers[name] = value
			
		} else if b&0xC0 == 0x40 {
			// Literal Header Field with Incremental Indexing (Section 6.2.1)
			name, value, n, err := p.decodeLiteralHeader(data[offset:], 6, true)
			if err != nil {
				return headers, err
			}
			offset += n
			headers[name] = value
			
		} else if b&0xF0 == 0x00 {
			// Literal Header Field without Indexing (Section 6.2.2)
			name, value, n, err := p.decodeLiteralHeader(data[offset:], 4, false)
			if err != nil {
				return headers, err
			}
			offset += n
			headers[name] = value
			
		} else if b&0xF0 == 0x10 {
			// Literal Header Field Never Indexed (Section 6.2.3)
			name, value, n, err := p.decodeLiteralHeader(data[offset:], 4, false)
			if err != nil {
				return headers, err
			}
			offset += n
			headers[name] = value
			
		} else if b&0xE0 == 0x20 {
			// Dynamic Table Size Update (Section 6.3)
			newSize, n := decodeHPACKInteger(data[offset:], 5)
			if n <= 0 {
				return headers, errors.New("HPACK: invalid table size update")
			}
			offset += n
			
			if int(newSize) > p.maxTableSize {
				return headers, fmt.Errorf("HPACK: table size %d exceeds max %d", newSize, p.maxTableSize)
			}
			p.maxTableSize = int(newSize)
			p.evictDynamicTable()
			
		} else {
			return headers, fmt.Errorf("HPACK: unknown header type 0x%02x", b)
		}
	}
	
	return headers, nil
}

// decodeLiteralHeader decodes a literal header field.
func (p *HTTP2Parser) decodeLiteralHeader(data []byte, prefixBits int, addToTable bool) (string, string, int, error) {
	if len(data) < 1 {
		return "", "", 0, errors.New("HPACK: literal header too short")
	}
	
	offset := 0
	var name string
	
	// Decode name index or literal name
	index, n := decodeHPACKInteger(data, prefixBits)
	if n <= 0 {
		return "", "", 0, errors.New("HPACK: invalid name index")
	}
	offset += n
	
	if index == 0 {
		// Literal name
		var err error
		name, n, err = decodeHPACKString(data[offset:])
		if err != nil {
			return "", "", 0, err
		}
		offset += n
	} else {
		// Indexed name
		var err error
		name, _, err = p.getIndexedHeader(int(index))
		if err != nil {
			return "", "", 0, err
		}
	}
	
	// Decode value
	value, n, err := decodeHPACKString(data[offset:])
	if err != nil {
		return "", "", 0, err
	}
	offset += n
	
	// SAFETY: Check header size
	if len(name)+len(value) > MaxHPACKHeaderSize {
		return "", "", 0, fmt.Errorf("HPACK: header too large (%d bytes)", len(name)+len(value))
	}
	
	// Add to dynamic table if requested
	if addToTable {
		p.addToDynamicTable(name, value)
	}
	
	return name, value, offset, nil
}

// getIndexedHeader retrieves a header from the static or dynamic table.
func (p *HTTP2Parser) getIndexedHeader(index int) (string, string, error) {
	if index < 1 {
		return "", "", errors.New("HPACK: invalid index 0")
	}
	
	// Static table (indices 1-61)
	if index <= len(hpackStaticTable) {
		entry := hpackStaticTable[index-1]
		return entry.name, entry.value, nil
	}
	
	// Dynamic table (indices 62+)
	dynIndex := index - len(hpackStaticTable) - 1
	if dynIndex >= len(p.dynamicTable) {
		return "", "", fmt.Errorf("HPACK: dynamic table index %d out of range", dynIndex)
	}
	
	entry := p.dynamicTable[dynIndex]
	return entry.name, entry.value, nil
}

// addToDynamicTable adds an entry to the dynamic table.
func (p *HTTP2Parser) addToDynamicTable(name, value string) {
	entrySize := len(name) + len(value) + 32
	
	// Evict entries if needed
	for p.dynamicTableSize+entrySize > p.maxTableSize && len(p.dynamicTable) > 0 {
		// Remove oldest entry (end of table)
		oldest := p.dynamicTable[len(p.dynamicTable)-1]
		p.dynamicTableSize -= oldest.size
		p.dynamicTable = p.dynamicTable[:len(p.dynamicTable)-1]
	}
	
	// Add new entry at the front
	if entrySize <= p.maxTableSize {
		entry := hpackEntry{name: name, value: value, size: entrySize}
		p.dynamicTable = append([]hpackEntry{entry}, p.dynamicTable...)
		p.dynamicTableSize += entrySize
	}
}

// evictDynamicTable evicts entries to fit within maxTableSize.
func (p *HTTP2Parser) evictDynamicTable() {
	for p.dynamicTableSize > p.maxTableSize && len(p.dynamicTable) > 0 {
		oldest := p.dynamicTable[len(p.dynamicTable)-1]
		p.dynamicTableSize -= oldest.size
		p.dynamicTable = p.dynamicTable[:len(p.dynamicTable)-1]
	}
}

// decodeHPACKInteger decodes an HPACK integer with the given prefix bits.
func decodeHPACKInteger(data []byte, prefixBits int) (uint64, int) {
	if len(data) < 1 {
		return 0, 0
	}
	
	mask := byte((1 << prefixBits) - 1)
	value := uint64(data[0] & mask)
	
	if value < uint64(mask) {
		return value, 1
	}
	
	// Multi-byte integer
	m := uint64(0)
	for i := 1; i < len(data); i++ {
		b := data[i]
		value += uint64(b&0x7F) << m
		m += 7
		
		if b&0x80 == 0 {
			return value, i + 1
		}
		
		// SAFETY: Prevent integer overflow
		if m > 63 {
			return 0, 0
		}
	}
	
	return 0, 0 // Incomplete
}

// decodeHPACKString decodes an HPACK string (with optional Huffman encoding).
func decodeHPACKString(data []byte) (string, int, error) {
	if len(data) < 1 {
		return "", 0, errors.New("HPACK: string too short")
	}
	
	huffman := data[0]&0x80 != 0
	length, n := decodeHPACKInteger(data, 7)
	if n <= 0 {
		return "", 0, errors.New("HPACK: invalid string length")
	}
	
	if int(length) > len(data)-n {
		return "", 0, errors.New("HPACK: string extends beyond data")
	}
	
	// SAFETY: Limit string length
	if length > MaxHPACKHeaderSize {
		return "", 0, fmt.Errorf("HPACK: string too long (%d bytes)", length)
	}
	
	strData := data[n : n+int(length)]
	
	if huffman {
		decoded, err := decodeHuffman(strData)
		if err != nil {
			return "", 0, err
		}
		return decoded, n + int(length), nil
	}
	
	return string(strData), n + int(length), nil
}

// decodeHuffman decodes Huffman-encoded data.
// This is a simplified implementation; a full implementation would use the RFC 7541 Huffman table.
func decodeHuffman(data []byte) (string, error) {
	// For now, return a placeholder - full Huffman decoding requires the 256-entry table
	// In production, use golang.org/x/net/http2/hpack
	var result bytes.Buffer
	
	// Simple bit-by-bit Huffman decoder using the static table
	bits := uint64(0)
	bitCount := 0
	
	for _, b := range data {
		bits = (bits << 8) | uint64(b)
		bitCount += 8
		
		for bitCount >= 5 {
			// Try to match Huffman codes (simplified - real implementation needs full table)
			// This is a stub that returns the raw bytes for now
			if bitCount >= 8 {
				result.WriteByte(byte(bits >> (bitCount - 8)))
				bitCount -= 8
				bits &= (1 << bitCount) - 1
			} else {
				break
			}
		}
	}
	
	return result.String(), nil
}

// =============================================================================
// HPACK Static Table (RFC 7541 Appendix A)
// =============================================================================

var hpackStaticTable = []hpackEntry{
	{":authority", "", 42},
	{":method", "GET", 42},
	{":method", "POST", 43},
	{":path", "/", 37},
	{":path", "/index.html", 47},
	{":scheme", "http", 42},
	{":scheme", "https", 43},
	{":status", "200", 42},
	{":status", "204", 42},
	{":status", "206", 42},
	{":status", "304", 42},
	{":status", "400", 42},
	{":status", "404", 42},
	{":status", "500", 42},
	{"accept-charset", "", 46},
	{"accept-encoding", "gzip, deflate", 60},
	{"accept-language", "", 47},
	{"accept-ranges", "", 45},
	{"accept", "", 38},
	{"access-control-allow-origin", "", 59},
	{"age", "", 35},
	{"allow", "", 37},
	{"authorization", "", 45},
	{"cache-control", "", 45},
	{"content-disposition", "", 51},
	{"content-encoding", "", 48},
	{"content-language", "", 48},
	{"content-length", "", 46},
	{"content-location", "", 48},
	{"content-range", "", 45},
	{"content-type", "", 44},
	{"cookie", "", 38},
	{"date", "", 36},
	{"etag", "", 36},
	{"expect", "", 38},
	{"expires", "", 39},
	{"from", "", 36},
	{"host", "", 36},
	{"if-match", "", 40},
	{"if-modified-since", "", 49},
	{"if-none-match", "", 45},
	{"if-range", "", 40},
	{"if-unmodified-since", "", 51},
	{"last-modified", "", 45},
	{"link", "", 36},
	{"location", "", 40},
	{"max-forwards", "", 44},
	{"proxy-authenticate", "", 50},
	{"proxy-authorization", "", 51},
	{"range", "", 37},
	{"referer", "", 39},
	{"refresh", "", 39},
	{"retry-after", "", 43},
	{"server", "", 38},
	{"set-cookie", "", 42},
	{"strict-transport-security", "", 57},
	{"transfer-encoding", "", 49},
	{"user-agent", "", 42},
	{"vary", "", 36},
	{"via", "", 35},
	{"www-authenticate", "", 48},
}

// IsHTTP2Preface checks if data starts with the HTTP/2 connection preface.
func IsHTTP2Preface(data []byte) bool {
	preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	return len(data) >= len(preface) && bytes.Equal(data[:len(preface)], preface)
}

// HTTP2FrameTypeName returns the name of an HTTP/2 frame type.
func HTTP2FrameTypeName(frameType uint8) string {
	names := []string{
		"DATA", "HEADERS", "PRIORITY", "RST_STREAM",
		"SETTINGS", "PUSH_PROMISE", "PING", "GOAWAY",
		"WINDOW_UPDATE", "CONTINUATION",
	}
	if int(frameType) < len(names) {
		return names[frameType]
	}
	return fmt.Sprintf("UNKNOWN(%d)", frameType)
}
