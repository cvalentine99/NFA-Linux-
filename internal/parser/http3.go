// Package parser provides HTTP/3 protocol parsing for network forensics.
// This implementation handles HTTP/3 frame parsing, QPACK header decompression,
// and request/response extraction from QUIC streams.
package parser

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// HTTP/3 frame type constants (RFC 9114)
const (
	HTTP3FrameData         uint64 = 0x00
	HTTP3FrameHeaders      uint64 = 0x01
	HTTP3FrameCancelPush   uint64 = 0x03
	HTTP3FrameSettings     uint64 = 0x04
	HTTP3FramePushPromise  uint64 = 0x05
	HTTP3FrameGoaway       uint64 = 0x07
	HTTP3FrameMaxPushID    uint64 = 0x0d
)

// HTTP/3 settings identifiers
const (
	HTTP3SettingsQPACKMaxTableCapacity uint64 = 0x01
	HTTP3SettingsMaxFieldSectionSize   uint64 = 0x06
	HTTP3SettingsQPACKBlockedStreams   uint64 = 0x07
)

// QPACK instruction types
const (
	QPACKInsertWithNameRef    byte = 0x80
	QPACKInsertWithoutNameRef byte = 0x40
	QPACKDuplicate            byte = 0x00
	QPACKSetDynamicTableCap   byte = 0x20
)

// Errors
var (
	ErrInvalidHTTP3Frame   = errors.New("invalid HTTP/3 frame")
	ErrInvalidQPACK        = errors.New("invalid QPACK encoding")
	ErrQPACKTableOverflow  = errors.New("QPACK dynamic table overflow")
	ErrStreamNotFound      = errors.New("stream not found")
)

// HTTP3Frame represents a parsed HTTP/3 frame.
type HTTP3Frame struct {
	Type    uint64
	Length  uint64
	Payload []byte
}

// HTTP3Request represents a parsed HTTP/3 request.
type HTTP3Request struct {
	Method      string
	Scheme      string
	Authority   string
	Path        string
	Headers     map[string][]string
	Body        []byte
	StreamID    uint64
	TimestampNano int64
}

// HTTP3Response represents a parsed HTTP/3 response.
type HTTP3Response struct {
	Status      int
	Headers     map[string][]string
	Body        []byte
	StreamID    uint64
	TimestampNano int64
}

// HTTP3Settings represents HTTP/3 settings.
type HTTP3Settings struct {
	QPACKMaxTableCapacity uint64
	MaxFieldSectionSize   uint64
	QPACKBlockedStreams   uint64
}

// HTTP3Transaction represents a complete HTTP/3 request/response pair.
type HTTP3Transaction struct {
	Request      *HTTP3Request
	Response     *HTTP3Response
	ConnectionID string
	StartNano    int64
	EndNano      int64
}

// QPACKDecoder handles QPACK header decompression.
type QPACKDecoder struct {
	dynamicTable    []QPACKEntry
	maxTableSize    uint64
	currentSize     uint64
	insertCount     uint64
	knownReceived   uint64
	mu              sync.RWMutex
}

// QPACKEntry represents an entry in the QPACK dynamic table.
type QPACKEntry struct {
	Name  string
	Value string
	Size  uint64
}

// HTTP3Parser handles HTTP/3 parsing and transaction tracking.
type HTTP3Parser struct {
	transactions map[string]*HTTP3Transaction
	streams      map[uint64]*http3Stream
	decoder      *QPACKDecoder
	settings     *HTTP3Settings
	
	// Callbacks
	onRequest    func(*HTTP3Request)
	onResponse   func(*HTTP3Response)
	onTransaction func(*HTTP3Transaction)
	
	mu sync.RWMutex
}

// http3Stream tracks state for an HTTP/3 stream.
type http3Stream struct {
	streamID     uint64
	headerData   []byte
	bodyData     []byte
	headersComplete bool
	isRequest    bool
}

// NewHTTP3Parser creates a new HTTP/3 parser.
func NewHTTP3Parser() *HTTP3Parser {
	return &HTTP3Parser{
		transactions: make(map[string]*HTTP3Transaction),
		streams:      make(map[uint64]*http3Stream),
		decoder:      NewQPACKDecoder(4096),
		settings: &HTTP3Settings{
			QPACKMaxTableCapacity: 4096,
			MaxFieldSectionSize:   16384,
			QPACKBlockedStreams:   100,
		},
	}
}

// SetRequestHandler sets the callback for parsed requests.
func (p *HTTP3Parser) SetRequestHandler(handler func(*HTTP3Request)) {
	p.onRequest = handler
}

// SetResponseHandler sets the callback for parsed responses.
func (p *HTTP3Parser) SetResponseHandler(handler func(*HTTP3Response)) {
	p.onResponse = handler
}

// SetTransactionHandler sets the callback for complete transactions.
func (p *HTTP3Parser) SetTransactionHandler(handler func(*HTTP3Transaction)) {
	p.onTransaction = handler
}

// ParseStreamData parses HTTP/3 frames from QUIC stream data.
func (p *HTTP3Parser) ParseStreamData(streamID uint64, data []byte, timestampNano int64) error {
	p.mu.Lock()
	stream, ok := p.streams[streamID]
	if !ok {
		stream = &http3Stream{
			streamID:  streamID,
			isRequest: isClientInitiatedBidirectional(streamID),
		}
		p.streams[streamID] = stream
	}
	p.mu.Unlock()
	
	// Parse frames from data
	offset := 0
	for offset < len(data) {
		frame, n, err := p.parseFrame(data[offset:])
		if err != nil {
			return err
		}
		offset += n
		
		// Process frame
		p.processFrame(stream, frame, timestampNano)
	}
	
	return nil
}

// parseFrame parses a single HTTP/3 frame.
func (p *HTTP3Parser) parseFrame(data []byte) (*HTTP3Frame, int, error) {
	if len(data) < 2 {
		return nil, 0, ErrInvalidHTTP3Frame
	}
	
	offset := 0
	
	// Frame type (variable-length integer)
	frameType, n := decodeVarint(data[offset:])
	if n == 0 {
		return nil, 0, ErrInvalidHTTP3Frame
	}
	offset += n
	
	// Frame length (variable-length integer)
	frameLen, n := decodeVarint(data[offset:])
	if n == 0 {
		return nil, 0, ErrInvalidHTTP3Frame
	}
	offset += n
	
	if len(data) < offset+int(frameLen) {
		return nil, 0, ErrInvalidHTTP3Frame
	}
	
	frame := &HTTP3Frame{
		Type:    frameType,
		Length:  frameLen,
		Payload: data[offset : offset+int(frameLen)],
	}
	
	return frame, offset + int(frameLen), nil
}

// processFrame processes a parsed HTTP/3 frame.
func (p *HTTP3Parser) processFrame(stream *http3Stream, frame *HTTP3Frame, timestampNano int64) {
	switch frame.Type {
	case HTTP3FrameHeaders:
		stream.headerData = append(stream.headerData, frame.Payload...)
		stream.headersComplete = true
		
		// Decode headers using QPACK
		headers, err := p.decoder.DecodeHeaderBlock(frame.Payload)
		if err != nil {
			return
		}
		
		if stream.isRequest {
			req := p.buildRequest(stream.streamID, headers, timestampNano)
			if p.onRequest != nil {
				go p.onRequest(req)
			}
		} else {
			resp := p.buildResponse(stream.streamID, headers, timestampNano)
			if p.onResponse != nil {
				go p.onResponse(resp)
			}
		}
		
	case HTTP3FrameData:
		stream.bodyData = append(stream.bodyData, frame.Payload...)
		
	case HTTP3FrameSettings:
		p.parseSettings(frame.Payload)
		
	case HTTP3FrameGoaway:
		// Connection is closing
		
	case HTTP3FramePushPromise:
		// Server push (rarely used)
	}
}

// buildRequest builds an HTTP3Request from decoded headers.
func (p *HTTP3Parser) buildRequest(streamID uint64, headers map[string][]string, timestampNano int64) *HTTP3Request {
	req := &HTTP3Request{
		Headers:       headers,
		StreamID:      streamID,
		TimestampNano: timestampNano,
	}
	
	// Extract pseudo-headers
	if method, ok := headers[":method"]; ok && len(method) > 0 {
		req.Method = method[0]
	}
	if scheme, ok := headers[":scheme"]; ok && len(scheme) > 0 {
		req.Scheme = scheme[0]
	}
	if authority, ok := headers[":authority"]; ok && len(authority) > 0 {
		req.Authority = authority[0]
	}
	if path, ok := headers[":path"]; ok && len(path) > 0 {
		req.Path = path[0]
	}
	
	return req
}

// buildResponse builds an HTTP3Response from decoded headers.
func (p *HTTP3Parser) buildResponse(streamID uint64, headers map[string][]string, timestampNano int64) *HTTP3Response {
	resp := &HTTP3Response{
		Headers:       headers,
		StreamID:      streamID,
		TimestampNano: timestampNano,
	}
	
	// Extract status
	if status, ok := headers[":status"]; ok && len(status) > 0 {
		fmt.Sscanf(status[0], "%d", &resp.Status)
	}
	
	return resp
}

// parseSettings parses HTTP/3 SETTINGS frame.
func (p *HTTP3Parser) parseSettings(data []byte) {
	offset := 0
	for offset < len(data) {
		id, n := decodeVarint(data[offset:])
		if n == 0 {
			break
		}
		offset += n
		
		value, n := decodeVarint(data[offset:])
		if n == 0 {
			break
		}
		offset += n
		
		switch id {
		case HTTP3SettingsQPACKMaxTableCapacity:
			p.settings.QPACKMaxTableCapacity = value
			p.decoder.SetMaxTableSize(value)
		case HTTP3SettingsMaxFieldSectionSize:
			p.settings.MaxFieldSectionSize = value
		case HTTP3SettingsQPACKBlockedStreams:
			p.settings.QPACKBlockedStreams = value
		}
	}
}

// GetTransaction retrieves a transaction by ID.
func (p *HTTP3Parser) GetTransaction(id string) (*HTTP3Transaction, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	
	tx, ok := p.transactions[id]
	return tx, ok
}

// isClientInitiatedBidirectional checks if a stream ID is client-initiated bidirectional.
func isClientInitiatedBidirectional(streamID uint64) bool {
	// Client-initiated bidirectional streams have the two least significant bits as 0b00
	return (streamID & 0x03) == 0
}

// NewQPACKDecoder creates a new QPACK decoder.
func NewQPACKDecoder(maxTableSize uint64) *QPACKDecoder {
	return &QPACKDecoder{
		dynamicTable: make([]QPACKEntry, 0),
		maxTableSize: maxTableSize,
	}
}

// SetMaxTableSize sets the maximum dynamic table size.
func (d *QPACKDecoder) SetMaxTableSize(size uint64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	
	d.maxTableSize = size
	d.evictEntries()
}

// DecodeHeaderBlock decodes a QPACK-encoded header block.
func (d *QPACKDecoder) DecodeHeaderBlock(data []byte) (map[string][]string, error) {
	if len(data) < 2 {
		return nil, ErrInvalidQPACK
	}
	
	headers := make(map[string][]string)
	offset := 0
	
	// Required Insert Count (variable-length integer with prefix)
	requiredInsertCount, n := d.decodeInteger(data[offset:], 8)
	if n == 0 {
		return nil, ErrInvalidQPACK
	}
	offset += n
	
	// Delta Base (variable-length integer with sign bit)
	_, n = d.decodeInteger(data[offset:], 7)
	if n == 0 {
		return nil, ErrInvalidQPACK
	}
	offset += n
	
	// Decode header field lines
	for offset < len(data) {
		name, value, n, err := d.decodeHeaderLine(data[offset:])
		if err != nil {
			return nil, err
		}
		if n == 0 {
			break
		}
		offset += n
		
		headers[name] = append(headers[name], value)
	}
	
	// Handle required insert count
	_ = requiredInsertCount
	
	return headers, nil
}

// decodeHeaderLine decodes a single header field line.
func (d *QPACKDecoder) decodeHeaderLine(data []byte) (string, string, int, error) {
	if len(data) == 0 {
		return "", "", 0, nil
	}
	
	firstByte := data[0]
	
	// Indexed Header Field (starts with 1)
	if (firstByte & 0x80) != 0 {
		return d.decodeIndexedField(data)
	}
	
	// Literal Header Field With Name Reference (starts with 01)
	if (firstByte & 0x40) != 0 {
		return d.decodeLiteralWithNameRef(data)
	}
	
	// Literal Header Field Without Name Reference (starts with 001)
	if (firstByte & 0x20) != 0 {
		return d.decodeLiteralWithoutNameRef(data)
	}
	
	// Indexed Header Field With Post-Base Index (starts with 0001)
	if (firstByte & 0x10) != 0 {
		return d.decodeIndexedPostBase(data)
	}
	
	return "", "", 0, ErrInvalidQPACK
}

// decodeIndexedField decodes an indexed header field.
func (d *QPACKDecoder) decodeIndexedField(data []byte) (string, string, int, error) {
	// Check static table bit
	isStatic := (data[0] & 0x40) != 0
	
	index, n := d.decodeInteger(data, 6)
	if n == 0 {
		return "", "", 0, ErrInvalidQPACK
	}
	
	var name, value string
	if isStatic {
		name, value = getStaticTableEntry(int(index))
	} else {
		d.mu.RLock()
		if int(index) < len(d.dynamicTable) {
			entry := d.dynamicTable[index]
			name, value = entry.Name, entry.Value
		}
		d.mu.RUnlock()
	}
	
	return name, value, n, nil
}

// decodeLiteralWithNameRef decodes a literal header with name reference.
func (d *QPACKDecoder) decodeLiteralWithNameRef(data []byte) (string, string, int, error) {
	offset := 0
	
	// Check static table bit
	isStatic := (data[0] & 0x10) != 0
	
	// Name index
	index, n := d.decodeInteger(data, 4)
	if n == 0 {
		return "", "", 0, ErrInvalidQPACK
	}
	offset += n
	
	// Get name from table
	var name string
	if isStatic {
		name, _ = getStaticTableEntry(int(index))
	} else {
		d.mu.RLock()
		if int(index) < len(d.dynamicTable) {
			name = d.dynamicTable[index].Name
		}
		d.mu.RUnlock()
	}
	
	// Decode value
	value, n, err := d.decodeString(data[offset:])
	if err != nil {
		return "", "", 0, err
	}
	offset += n
	
	return name, value, offset, nil
}

// decodeLiteralWithoutNameRef decodes a literal header without name reference.
func (d *QPACKDecoder) decodeLiteralWithoutNameRef(data []byte) (string, string, int, error) {
	offset := 0
	
	// Skip first byte prefix
	offset++
	
	// Decode name
	name, n, err := d.decodeString(data[offset:])
	if err != nil {
		return "", "", 0, err
	}
	offset += n
	
	// Decode value
	value, n, err := d.decodeString(data[offset:])
	if err != nil {
		return "", "", 0, err
	}
	offset += n
	
	return name, value, offset, nil
}

// decodeIndexedPostBase decodes an indexed field with post-base index.
func (d *QPACKDecoder) decodeIndexedPostBase(data []byte) (string, string, int, error) {
	index, n := d.decodeInteger(data, 4)
	if n == 0 {
		return "", "", 0, ErrInvalidQPACK
	}
	
	d.mu.RLock()
	defer d.mu.RUnlock()
	
	// Post-base index is relative to the base
	absIndex := int(index)
	if absIndex < len(d.dynamicTable) {
		entry := d.dynamicTable[absIndex]
		return entry.Name, entry.Value, n, nil
	}
	
	return "", "", n, nil
}

// decodeInteger decodes a QPACK integer with the given prefix length.
func (d *QPACKDecoder) decodeInteger(data []byte, prefixLen int) (uint64, int) {
	if len(data) == 0 {
		return 0, 0
	}
	
	mask := byte((1 << prefixLen) - 1)
	value := uint64(data[0] & mask)
	
	if value < uint64(mask) {
		return value, 1
	}
	
	// Multi-byte encoding
	offset := 1
	m := uint64(0)
	for offset < len(data) {
		b := data[offset]
		value += uint64(b&0x7f) << m
		offset++
		m += 7
		
		if (b & 0x80) == 0 {
			break
		}
	}
	
	return value, offset
}

// decodeString decodes a QPACK string.
func (d *QPACKDecoder) decodeString(data []byte) (string, int, error) {
	if len(data) == 0 {
		return "", 0, ErrInvalidQPACK
	}
	
	// Check Huffman encoding bit
	huffman := (data[0] & 0x80) != 0
	
	// Decode length
	length, n := d.decodeInteger(data, 7)
	if n == 0 {
		return "", 0, ErrInvalidQPACK
	}
	
	if len(data) < n+int(length) {
		return "", 0, ErrInvalidQPACK
	}
	
	strData := data[n : n+int(length)]
	
	var result string
	if huffman {
		decoded, err := huffmanDecode(strData)
		if err != nil {
			return "", 0, err
		}
		result = string(decoded)
	} else {
		result = string(strData)
	}
	
	return result, n + int(length), nil
}

// InsertEntry inserts an entry into the dynamic table.
func (d *QPACKDecoder) InsertEntry(name, value string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	
	entrySize := uint64(len(name) + len(value) + 32) // 32 bytes overhead per RFC
	
	// Evict entries if necessary
	for d.currentSize+entrySize > d.maxTableSize && len(d.dynamicTable) > 0 {
		oldest := d.dynamicTable[len(d.dynamicTable)-1]
		d.dynamicTable = d.dynamicTable[:len(d.dynamicTable)-1]
		d.currentSize -= oldest.Size
	}
	
	if entrySize <= d.maxTableSize {
		entry := QPACKEntry{
			Name:  name,
			Value: value,
			Size:  entrySize,
		}
		d.dynamicTable = append([]QPACKEntry{entry}, d.dynamicTable...)
		d.currentSize += entrySize
		d.insertCount++
	}
}

// evictEntries evicts entries to fit within max table size.
func (d *QPACKDecoder) evictEntries() {
	for d.currentSize > d.maxTableSize && len(d.dynamicTable) > 0 {
		oldest := d.dynamicTable[len(d.dynamicTable)-1]
		d.dynamicTable = d.dynamicTable[:len(d.dynamicTable)-1]
		d.currentSize -= oldest.Size
	}
}

// QPACK Static Table (RFC 9204 Appendix A)
var qpackStaticTable = []QPACKEntry{
	{Name: ":authority", Value: ""},
	{Name: ":path", Value: "/"},
	{Name: "age", Value: "0"},
	{Name: "content-disposition", Value: ""},
	{Name: "content-length", Value: "0"},
	{Name: "cookie", Value: ""},
	{Name: "date", Value: ""},
	{Name: "etag", Value: ""},
	{Name: "if-modified-since", Value: ""},
	{Name: "if-none-match", Value: ""},
	{Name: "last-modified", Value: ""},
	{Name: "link", Value: ""},
	{Name: "location", Value: ""},
	{Name: "referer", Value: ""},
	{Name: "set-cookie", Value: ""},
	{Name: ":method", Value: "CONNECT"},
	{Name: ":method", Value: "DELETE"},
	{Name: ":method", Value: "GET"},
	{Name: ":method", Value: "HEAD"},
	{Name: ":method", Value: "OPTIONS"},
	{Name: ":method", Value: "POST"},
	{Name: ":method", Value: "PUT"},
	{Name: ":scheme", Value: "http"},
	{Name: ":scheme", Value: "https"},
	{Name: ":status", Value: "103"},
	{Name: ":status", Value: "200"},
	{Name: ":status", Value: "304"},
	{Name: ":status", Value: "404"},
	{Name: ":status", Value: "503"},
	{Name: "accept", Value: "*/*"},
	{Name: "accept", Value: "application/dns-message"},
	{Name: "accept-encoding", Value: "gzip, deflate, br"},
	{Name: "accept-ranges", Value: "bytes"},
	{Name: "access-control-allow-headers", Value: "cache-control"},
	{Name: "access-control-allow-headers", Value: "content-type"},
	{Name: "access-control-allow-origin", Value: "*"},
	{Name: "cache-control", Value: "max-age=0"},
	{Name: "cache-control", Value: "max-age=2592000"},
	{Name: "cache-control", Value: "max-age=604800"},
	{Name: "cache-control", Value: "no-cache"},
	{Name: "cache-control", Value: "no-store"},
	{Name: "cache-control", Value: "public, max-age=31536000"},
	{Name: "content-encoding", Value: "br"},
	{Name: "content-encoding", Value: "gzip"},
	{Name: "content-type", Value: "application/dns-message"},
	{Name: "content-type", Value: "application/javascript"},
	{Name: "content-type", Value: "application/json"},
	{Name: "content-type", Value: "application/x-www-form-urlencoded"},
	{Name: "content-type", Value: "image/gif"},
	{Name: "content-type", Value: "image/jpeg"},
	{Name: "content-type", Value: "image/png"},
	{Name: "content-type", Value: "text/css"},
	{Name: "content-type", Value: "text/html; charset=utf-8"},
	{Name: "content-type", Value: "text/plain"},
	{Name: "content-type", Value: "text/plain;charset=utf-8"},
	{Name: "range", Value: "bytes=0-"},
	{Name: "strict-transport-security", Value: "max-age=31536000"},
	{Name: "strict-transport-security", Value: "max-age=31536000; includesubdomains"},
	{Name: "strict-transport-security", Value: "max-age=31536000; includesubdomains; preload"},
	{Name: "vary", Value: "accept-encoding"},
	{Name: "vary", Value: "origin"},
	{Name: "x-content-type-options", Value: "nosniff"},
	{Name: "x-xss-protection", Value: "1; mode=block"},
	{Name: ":status", Value: "100"},
	{Name: ":status", Value: "204"},
	{Name: ":status", Value: "206"},
	{Name: ":status", Value: "302"},
	{Name: ":status", Value: "400"},
	{Name: ":status", Value: "403"},
	{Name: ":status", Value: "421"},
	{Name: ":status", Value: "425"},
	{Name: ":status", Value: "500"},
	{Name: "accept-language", Value: ""},
	{Name: "access-control-allow-credentials", Value: "FALSE"},
	{Name: "access-control-allow-credentials", Value: "TRUE"},
	{Name: "access-control-allow-methods", Value: "get"},
	{Name: "access-control-allow-methods", Value: "get, post, options"},
	{Name: "access-control-allow-methods", Value: "options"},
	{Name: "access-control-expose-headers", Value: "content-length"},
	{Name: "access-control-request-headers", Value: "content-type"},
	{Name: "access-control-request-method", Value: "get"},
	{Name: "access-control-request-method", Value: "post"},
	{Name: "alt-svc", Value: "clear"},
	{Name: "authorization", Value: ""},
	{Name: "content-security-policy", Value: "script-src 'none'; object-src 'none'; base-uri 'none'"},
	{Name: "early-data", Value: "1"},
	{Name: "expect-ct", Value: ""},
	{Name: "forwarded", Value: ""},
	{Name: "if-range", Value: ""},
	{Name: "origin", Value: ""},
	{Name: "purpose", Value: "prefetch"},
	{Name: "server", Value: ""},
	{Name: "timing-allow-origin", Value: "*"},
	{Name: "upgrade-insecure-requests", Value: "1"},
	{Name: "user-agent", Value: ""},
	{Name: "x-forwarded-for", Value: ""},
	{Name: "x-frame-options", Value: "deny"},
	{Name: "x-frame-options", Value: "sameorigin"},
}

// getStaticTableEntry returns the entry at the given index in the static table.
func getStaticTableEntry(index int) (string, string) {
	if index >= 0 && index < len(qpackStaticTable) {
		return qpackStaticTable[index].Name, qpackStaticTable[index].Value
	}
	return "", ""
}

// Huffman decoding (simplified - uses static Huffman table from HPACK/QPACK)
func huffmanDecode(data []byte) ([]byte, error) {
	// Simplified Huffman decoding
	// In production, use a proper Huffman decoder with the HPACK table
	var result bytes.Buffer
	
	bits := uint64(0)
	numBits := 0
	
	for _, b := range data {
		bits = (bits << 8) | uint64(b)
		numBits += 8
		
		for numBits >= 5 {
			// Extract 5-8 bits and decode
			// This is a simplified version - real implementation needs full Huffman tree
			symbol := byte((bits >> (numBits - 8)) & 0xff)
			result.WriteByte(symbol)
			numBits -= 8
		}
	}
	
	return result.Bytes(), nil
}

// HTTP3ConnectionStats holds statistics for an HTTP/3 connection.
type HTTP3ConnectionStats struct {
	TotalRequests    uint64
	TotalResponses   uint64
	TotalBytes       uint64
	ActiveStreams    int
	CompletedStreams int
}

// GetStats returns statistics for the parser.
func (p *HTTP3Parser) GetStats() *HTTP3ConnectionStats {
	p.mu.RLock()
	defer p.mu.RUnlock()
	
	stats := &HTTP3ConnectionStats{
		TotalRequests:    uint64(len(p.transactions)),
		ActiveStreams:    len(p.streams),
	}
	
	for _, stream := range p.streams {
		if stream.headersComplete {
			stats.CompletedStreams++
		}
	}
	
	return stats
}

// ExtractURLs extracts all URLs from parsed requests.
func (p *HTTP3Parser) ExtractURLs() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	
	urls := make([]string, 0)
	
	for _, tx := range p.transactions {
		if tx.Request != nil {
			url := fmt.Sprintf("%s://%s%s",
				tx.Request.Scheme,
				tx.Request.Authority,
				tx.Request.Path)
			urls = append(urls, url)
		}
	}
	
	return urls
}

// GetRequestByStreamID retrieves a request by stream ID.
func (p *HTTP3Parser) GetRequestByStreamID(streamID uint64) *HTTP3Request {
	p.mu.RLock()
	defer p.mu.RUnlock()
	
	for _, tx := range p.transactions {
		if tx.Request != nil && tx.Request.StreamID == streamID {
			return tx.Request
		}
	}
	
	return nil
}

// HTTP3Fingerprint generates a fingerprint for HTTP/3 traffic.
type HTTP3Fingerprint struct {
	SettingsHash    string
	HeaderOrder     []string
	PseudoHeaders   []string
	CommonHeaders   map[string]int
}

// GenerateFingerprint generates an HTTP/3 fingerprint from a request.
func GenerateHTTP3Fingerprint(req *HTTP3Request) *HTTP3Fingerprint {
	fp := &HTTP3Fingerprint{
		HeaderOrder:   make([]string, 0),
		PseudoHeaders: make([]string, 0),
		CommonHeaders: make(map[string]int),
	}
	
	// Extract header order
	for name := range req.Headers {
		if strings.HasPrefix(name, ":") {
			fp.PseudoHeaders = append(fp.PseudoHeaders, name)
		} else {
			fp.HeaderOrder = append(fp.HeaderOrder, name)
		}
	}
	
	return fp
}
