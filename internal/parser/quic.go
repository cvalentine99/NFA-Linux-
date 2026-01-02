// Package parser provides QUIC protocol parsing for network forensics.
// This implementation handles QUIC packet header parsing, connection tracking,
// and TLS 1.3 ClientHello extraction from Initial packets.
package parser

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

// QUIC version constants
const (
	QUICVersion1       uint32 = 0x00000001
	QUICVersion2       uint32 = 0x6b3343cf
	QUICVersionDraft29 uint32 = 0xff00001d
	QUICVersionDraft32 uint32 = 0xff000020
)

// QUIC packet type constants (for Long Header)
const (
	PacketTypeInitial   byte = 0x00
	PacketType0RTT      byte = 0x01
	PacketTypeHandshake byte = 0x02
	PacketTypeRetry     byte = 0x03
)

// QUIC frame type constants
const (
	FrameTypePadding          uint64 = 0x00
	FrameTypePing             uint64 = 0x01
	FrameTypeAck              uint64 = 0x02
	FrameTypeResetStream      uint64 = 0x04
	FrameTypeStopSending      uint64 = 0x05
	FrameTypeCrypto           uint64 = 0x06
	FrameTypeNewToken         uint64 = 0x07
	FrameTypeStream           uint64 = 0x08 // 0x08 - 0x0f
	FrameTypeMaxData          uint64 = 0x10
	FrameTypeMaxStreamData    uint64 = 0x11
	FrameTypeMaxStreams       uint64 = 0x12
	FrameTypeDataBlocked      uint64 = 0x14
	FrameTypeStreamDataBlocked uint64 = 0x15
	FrameTypeStreamsBlocked   uint64 = 0x16
	FrameTypeNewConnectionID  uint64 = 0x18
	FrameTypeRetireConnectionID uint64 = 0x19
	FrameTypePathChallenge    uint64 = 0x1a
	FrameTypePathResponse     uint64 = 0x1b
	FrameTypeConnectionClose  uint64 = 0x1c
	FrameTypeHandshakeDone    uint64 = 0x1e
)

// Errors
var (
	ErrInvalidQUICPacket    = errors.New("invalid QUIC packet")
	ErrUnsupportedVersion   = errors.New("unsupported QUIC version")
	ErrPacketTooShort       = errors.New("packet too short")
	ErrDecryptionFailed     = errors.New("decryption failed")
	ErrConnectionNotFound   = errors.New("connection not found")
)

// QUICHeader represents a parsed QUIC packet header.
type QUICHeader struct {
	// Common fields
	IsLongHeader bool
	Version      uint32
	
	// Long header fields
	PacketType   byte
	DCIDLen      uint8
	DCID         []byte
	SCIDLen      uint8
	SCID         []byte
	TokenLen     uint64
	Token        []byte
	PacketLength uint64
	
	// Short header fields
	SpinBit      bool
	KeyPhase     bool
	
	// Packet number (decoded after header protection removal)
	PacketNumber uint64
	PacketNumberLen int
}

// QUICPacket represents a parsed QUIC packet.
type QUICPacket struct {
	Header        *QUICHeader
	Payload       []byte
	DecryptedPayload []byte
	Frames        []*QUICFrame
	TimestampNano int64
	SrcIP         string
	DstIP         string
	SrcPort       uint16
	DstPort       uint16
}

// QUICFrame represents a parsed QUIC frame.
type QUICFrame struct {
	Type    uint64
	Payload []byte
	
	// Stream frame specific
	StreamID uint64
	Offset   uint64
	Length   uint64
	Fin      bool
	
	// Crypto frame specific
	CryptoOffset uint64
	CryptoLength uint64
	CryptoData   []byte
}

// QUICConnection represents a tracked QUIC connection.
type QUICConnection struct {
	ID              string // Unique connection identifier
	DCID            []byte
	SCID            []byte
	Version         uint32
	State           QUICConnectionState
	
	// TLS information extracted from ClientHello
	SNI             string
	ALPN            []string
	SupportedVersions []uint16
	CipherSuites    []uint16
	
	// JA4 fingerprint
	JA4Fingerprint  string
	
	// Connection metadata
	SrcIP           string
	DstIP           string
	SrcPort         uint16
	DstPort         uint16
	StartTimeNano   int64
	LastSeenNano    int64
	
	// Packet statistics
	PacketsSent     uint64
	PacketsRecv     uint64
	BytesSent       uint64
	BytesRecv       uint64
	
	// Stream tracking
	Streams         map[uint64]*QUICStream
	
	// Crypto data accumulator for ClientHello reassembly
	CryptoData      []byte
	
	mu sync.RWMutex
}

// QUICConnectionState represents the state of a QUIC connection.
type QUICConnectionState int

const (
	QUICStateInitial QUICConnectionState = iota
	QUICStateHandshake
	QUICState1RTT
	QUICStateClosed
)

// QUICStream represents a QUIC stream within a connection.
type QUICStream struct {
	StreamID      uint64
	Data          []byte
	Offset        uint64
	Fin           bool
	Bidirectional bool
	ClientInitiated bool
}

// QUICParser handles QUIC packet parsing and connection tracking.
type QUICParser struct {
	connections map[string]*QUICConnection
	connByDCID  map[string]*QUICConnection
	
	// Callbacks
	onConnection    func(*QUICConnection)
	onClientHello   func(*QUICConnection, *TLSClientHello)
	onStream        func(*QUICConnection, *QUICStream)
	
	// Configuration
	maxConnections  int
	connectionTimeout time.Duration
	
	mu sync.RWMutex
}

// QUICParserConfig holds configuration for the QUIC parser.
type QUICParserConfig struct {
	MaxConnections    int
	ConnectionTimeout time.Duration
}

// DefaultQUICParserConfig returns default configuration.
func DefaultQUICParserConfig() *QUICParserConfig {
	return &QUICParserConfig{
		MaxConnections:    100000,
		ConnectionTimeout: 30 * time.Second,
	}
}

// NewQUICParser creates a new QUIC parser.
func NewQUICParser(cfg *QUICParserConfig) *QUICParser {
	if cfg == nil {
		cfg = DefaultQUICParserConfig()
	}
	
	return &QUICParser{
		connections:       make(map[string]*QUICConnection),
		connByDCID:        make(map[string]*QUICConnection),
		maxConnections:    cfg.MaxConnections,
		connectionTimeout: cfg.ConnectionTimeout,
	}
}

// SetConnectionHandler sets the callback for new connections.
func (p *QUICParser) SetConnectionHandler(handler func(*QUICConnection)) {
	p.onConnection = handler
}

// SetClientHelloHandler sets the callback for extracted ClientHello.
func (p *QUICParser) SetClientHelloHandler(handler func(*QUICConnection, *TLSClientHello)) {
	p.onClientHello = handler
}

// SetStreamHandler sets the callback for stream data.
func (p *QUICParser) SetStreamHandler(handler func(*QUICConnection, *QUICStream)) {
	p.onStream = handler
}

// ParsePacket parses a QUIC packet from raw UDP payload.
func (p *QUICParser) ParsePacket(data []byte, srcIP, dstIP string, srcPort, dstPort uint16, timestampNano int64) (*QUICPacket, error) {
	if len(data) < 1 {
		return nil, ErrPacketTooShort
	}
	
	packet := &QUICPacket{
		TimestampNano: timestampNano,
		SrcIP:         srcIP,
		DstIP:         dstIP,
		SrcPort:       srcPort,
		DstPort:       dstPort,
	}
	
	// Parse header
	header, headerLen, err := p.parseHeader(data)
	if err != nil {
		return nil, err
	}
	
	packet.Header = header
	packet.Payload = data[headerLen:]
	
	// Track connection
	conn := p.trackConnection(packet)
	
	// For Initial packets, try to extract ClientHello
	if header.IsLongHeader && header.PacketType == PacketTypeInitial {
		p.processInitialPacket(packet, conn)
	}
	
	return packet, nil
}

// parseHeader parses the QUIC packet header.
func (p *QUICParser) parseHeader(data []byte) (*QUICHeader, int, error) {
	if len(data) < 1 {
		return nil, 0, ErrPacketTooShort
	}
	
	header := &QUICHeader{}
	offset := 0
	
	firstByte := data[0]
	offset++
	
	// Check if Long Header (bit 7 set)
	header.IsLongHeader = (firstByte & 0x80) != 0
	
	if header.IsLongHeader {
		return p.parseLongHeader(data, firstByte)
	}
	
	return p.parseShortHeader(data, firstByte)
}

// parseLongHeader parses a QUIC Long Header.
func (p *QUICParser) parseLongHeader(data []byte, firstByte byte) (*QUICHeader, int, error) {
	if len(data) < 7 {
		return nil, 0, ErrPacketTooShort
	}
	
	header := &QUICHeader{
		IsLongHeader: true,
	}
	offset := 1
	
	// Version (4 bytes)
	header.Version = binary.BigEndian.Uint32(data[offset:])
	offset += 4
	
	// Packet type (bits 4-5 of first byte)
	header.PacketType = (firstByte & 0x30) >> 4
	
	// DCID Length (1 byte)
	header.DCIDLen = data[offset]
	offset++
	
	if len(data) < offset+int(header.DCIDLen) {
		return nil, 0, ErrPacketTooShort
	}
	
	// DCID
	header.DCID = make([]byte, header.DCIDLen)
	copy(header.DCID, data[offset:offset+int(header.DCIDLen)])
	offset += int(header.DCIDLen)
	
	// SCID Length (1 byte)
	if len(data) < offset+1 {
		return nil, 0, ErrPacketTooShort
	}
	header.SCIDLen = data[offset]
	offset++
	
	if len(data) < offset+int(header.SCIDLen) {
		return nil, 0, ErrPacketTooShort
	}
	
	// SCID
	header.SCID = make([]byte, header.SCIDLen)
	copy(header.SCID, data[offset:offset+int(header.SCIDLen)])
	offset += int(header.SCIDLen)
	
	// For Initial packets, parse Token
	if header.PacketType == PacketTypeInitial {
		tokenLen, n := decodeVarint(data[offset:])
		if n == 0 {
			return nil, 0, ErrPacketTooShort
		}
		header.TokenLen = tokenLen
		offset += n
		
		if len(data) < offset+int(tokenLen) {
			return nil, 0, ErrPacketTooShort
		}
		
		header.Token = make([]byte, tokenLen)
		copy(header.Token, data[offset:offset+int(tokenLen)])
		offset += int(tokenLen)
	}
	
	// Packet Length (variable-length integer)
	packetLen, n := decodeVarint(data[offset:])
	if n == 0 {
		return nil, 0, ErrPacketTooShort
	}
	header.PacketLength = packetLen
	offset += n
	
	return header, offset, nil
}

// parseShortHeader parses a QUIC Short Header.
func (p *QUICParser) parseShortHeader(data []byte, firstByte byte) (*QUICHeader, int, error) {
	header := &QUICHeader{
		IsLongHeader: false,
		SpinBit:      (firstByte & 0x20) != 0,
		KeyPhase:     (firstByte & 0x04) != 0,
	}
	
	// For short headers, we need to know the DCID length from connection state
	// Default to 8 bytes if unknown
	dcidLen := 8
	
	if len(data) < 1+dcidLen {
		return nil, 0, ErrPacketTooShort
	}
	
	header.DCIDLen = uint8(dcidLen)
	header.DCID = make([]byte, dcidLen)
	copy(header.DCID, data[1:1+dcidLen])
	
	return header, 1 + dcidLen, nil
}

// trackConnection tracks or retrieves a QUIC connection.
func (p *QUICParser) trackConnection(packet *QUICPacket) *QUICConnection {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	// Generate connection key
	dcidHex := hex.EncodeToString(packet.Header.DCID)
	
	// Check if connection exists by DCID
	if conn, ok := p.connByDCID[dcidHex]; ok {
		conn.mu.Lock()
		conn.LastSeenNano = packet.TimestampNano
		conn.PacketsRecv++
		conn.BytesRecv += uint64(len(packet.Payload))
		conn.mu.Unlock()
		return conn
	}
	
	// Create new connection for Initial packets
	if packet.Header.IsLongHeader && packet.Header.PacketType == PacketTypeInitial {
		connID := fmt.Sprintf("%s:%d-%s:%d-%s",
			packet.SrcIP, packet.SrcPort,
			packet.DstIP, packet.DstPort,
			dcidHex)
		
		conn := &QUICConnection{
			ID:            connID,
			DCID:          packet.Header.DCID,
			SCID:          packet.Header.SCID,
			Version:       packet.Header.Version,
			State:         QUICStateInitial,
			SrcIP:         packet.SrcIP,
			DstIP:         packet.DstIP,
			SrcPort:       packet.SrcPort,
			DstPort:       packet.DstPort,
			StartTimeNano: packet.TimestampNano,
			LastSeenNano:  packet.TimestampNano,
			PacketsRecv:   1,
			BytesRecv:     uint64(len(packet.Payload)),
			Streams:       make(map[uint64]*QUICStream),
			CryptoData:    make([]byte, 0),
		}
		
		p.connections[connID] = conn
		p.connByDCID[dcidHex] = conn
		
		// Also index by SCID
		if len(packet.Header.SCID) > 0 {
			scidHex := hex.EncodeToString(packet.Header.SCID)
			p.connByDCID[scidHex] = conn
		}
		
		if p.onConnection != nil {
			go p.onConnection(conn)
		}
		
		return conn
	}
	
	return nil
}

// processInitialPacket processes a QUIC Initial packet to extract ClientHello.
func (p *QUICParser) processInitialPacket(packet *QUICPacket, conn *QUICConnection) {
	if conn == nil {
		return
	}
	
	// Try to decrypt the Initial packet
	decrypted, err := p.decryptInitialPacket(packet)
	if err != nil {
		return
	}
	
	// Parse frames from decrypted payload
	frames := p.parseFrames(decrypted)
	
	// Look for CRYPTO frames
	for _, frame := range frames {
		if frame.Type == FrameTypeCrypto {
			conn.mu.Lock()
			// Accumulate crypto data
			if frame.CryptoOffset == uint64(len(conn.CryptoData)) {
				conn.CryptoData = append(conn.CryptoData, frame.CryptoData...)
			}
			conn.mu.Unlock()
			
			// Try to parse ClientHello
			p.tryParseClientHello(conn)
		}
	}
}

// decryptInitialPacket attempts to decrypt a QUIC Initial packet.
func (p *QUICParser) decryptInitialPacket(packet *QUICPacket) ([]byte, error) {
	if len(packet.Header.DCID) == 0 {
		return nil, ErrDecryptionFailed
	}
	
	// Derive initial secrets from DCID
	// This follows RFC 9001 Section 5.2
	initialSalt := getInitialSalt(packet.Header.Version)
	if initialSalt == nil {
		return nil, ErrUnsupportedVersion
	}
	
	// Derive initial secret
	initialSecret := hkdfExtract(initialSalt, packet.Header.DCID)
	
	// Derive client initial secret
	clientInitialSecret := hkdfExpandLabel(initialSecret, "client in", nil, 32)
	
	// Derive key and IV
	key := hkdfExpandLabel(clientInitialSecret, "quic key", nil, 16)
	iv := hkdfExpandLabel(clientInitialSecret, "quic iv", nil, 12)
	hp := hkdfExpandLabel(clientInitialSecret, "quic hp", nil, 16)
	
	// Remove header protection and decrypt
	return p.decryptPacket(packet.Payload, key, iv, hp)
}

// decryptPacket decrypts a QUIC packet payload.
func (p *QUICParser) decryptPacket(payload, key, iv, hp []byte) ([]byte, error) {
	if len(payload) < 20 {
		return nil, ErrPacketTooShort
	}
	
	// Create AES cipher for header protection
	hpCipher, err := aes.NewCipher(hp)
	if err != nil {
		return nil, err
	}
	
	// Sample for header protection (16 bytes starting at offset 4)
	sampleOffset := 4
	if len(payload) < sampleOffset+16 {
		return nil, ErrPacketTooShort
	}
	sample := payload[sampleOffset : sampleOffset+16]
	
	// Generate mask
	mask := make([]byte, 16)
	hpCipher.Encrypt(mask, sample)
	
	// The packet number is at the beginning of the payload
	// We need to determine its length from the first byte
	pnLen := int(payload[0]&0x03) + 1
	
	// Decrypt packet number
	pn := make([]byte, 4)
	copy(pn, payload[1:1+pnLen])
	for i := 0; i < pnLen; i++ {
		pn[i] ^= mask[i+1]
	}
	
	// Construct nonce
	nonce := make([]byte, 12)
	copy(nonce, iv)
	for i := 0; i < pnLen; i++ {
		nonce[12-pnLen+i] ^= pn[i]
	}
	
	// Create AEAD cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	
	// Decrypt payload
	ciphertext := payload[1+pnLen:]
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	
	return plaintext, nil
}

// parseFrames parses QUIC frames from decrypted payload.
func (p *QUICParser) parseFrames(data []byte) []*QUICFrame {
	frames := make([]*QUICFrame, 0)
	offset := 0
	
	for offset < len(data) {
		frameType, n := decodeVarint(data[offset:])
		if n == 0 {
			break
		}
		offset += n
		
		frame := &QUICFrame{Type: frameType}
		
		switch frameType {
		case FrameTypePadding:
			// Skip padding
			continue
			
		case FrameTypeCrypto:
			// Parse CRYPTO frame
			cryptoOffset, n := decodeVarint(data[offset:])
			if n == 0 {
				break
			}
			frame.CryptoOffset = cryptoOffset
			offset += n
			
			cryptoLen, n := decodeVarint(data[offset:])
			if n == 0 {
				break
			}
			frame.CryptoLength = cryptoLen
			offset += n
			
			if offset+int(cryptoLen) > len(data) {
				break
			}
			
			frame.CryptoData = make([]byte, cryptoLen)
			copy(frame.CryptoData, data[offset:offset+int(cryptoLen)])
			offset += int(cryptoLen)
			
		default:
			// Skip unknown frames
			break
		}
		
		frames = append(frames, frame)
	}
	
	return frames
}

// tryParseClientHello attempts to parse a TLS ClientHello from accumulated crypto data.
func (p *QUICParser) tryParseClientHello(conn *QUICConnection) {
	conn.mu.RLock()
	data := conn.CryptoData
	conn.mu.RUnlock()
	
	if len(data) < 5 {
		return
	}
	
	// Check for TLS Handshake record (type 0x16)
	// In QUIC, the record layer is stripped, so we look for ClientHello directly
	// ClientHello message type is 0x01
	if data[0] != 0x01 {
		return
	}
	
	// Parse ClientHello length (3 bytes)
	length := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) < 4+length {
		return // Not enough data yet
	}
	
	// Parse ClientHello
	clientHello, err := ParseTLSClientHello(data[4:])
	if err != nil {
		return
	}
	
	// Update connection with extracted info
	conn.mu.Lock()
	conn.SNI = clientHello.ServerName
	conn.ALPN = clientHello.ALPNProtocols
	conn.SupportedVersions = clientHello.SupportedVersions
	conn.CipherSuites = clientHello.CipherSuites
	conn.JA4Fingerprint = ComputeJA4Fingerprint(clientHello)
	conn.mu.Unlock()
	
	if p.onClientHello != nil {
		go p.onClientHello(conn, clientHello)
	}
}

// GetConnection retrieves a connection by ID.
func (p *QUICParser) GetConnection(id string) (*QUICConnection, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	
	conn, ok := p.connections[id]
	return conn, ok
}

// GetConnectionByDCID retrieves a connection by DCID.
func (p *QUICParser) GetConnectionByDCID(dcid []byte) (*QUICConnection, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	
	dcidHex := hex.EncodeToString(dcid)
	conn, ok := p.connByDCID[dcidHex]
	return conn, ok
}

// GetConnections returns all tracked connections.
func (p *QUICParser) GetConnections() []*QUICConnection {
	p.mu.RLock()
	defer p.mu.RUnlock()
	
	conns := make([]*QUICConnection, 0, len(p.connections))
	for _, conn := range p.connections {
		conns = append(conns, conn)
	}
	return conns
}

// CleanupExpired removes expired connections.
func (p *QUICParser) CleanupExpired() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	now := time.Now().UnixNano()
	timeout := p.connectionTimeout.Nanoseconds()
	removed := 0
	
	for id, conn := range p.connections {
		conn.mu.RLock()
		lastSeen := conn.LastSeenNano
		dcid := conn.DCID
		scid := conn.SCID
		conn.mu.RUnlock()
		
		if now-lastSeen > timeout {
			delete(p.connections, id)
			delete(p.connByDCID, hex.EncodeToString(dcid))
			if len(scid) > 0 {
				delete(p.connByDCID, hex.EncodeToString(scid))
			}
			removed++
		}
	}
	
	return removed
}

// Helper functions

// decodeVarint decodes a QUIC variable-length integer.
func decodeVarint(data []byte) (uint64, int) {
	if len(data) == 0 {
		return 0, 0
	}
	
	prefix := data[0] >> 6
	length := 1 << prefix
	
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

// getInitialSalt returns the initial salt for the given QUIC version.
func getInitialSalt(version uint32) []byte {
	switch version {
	case QUICVersion1:
		return []byte{
			0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
			0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
			0xcc, 0xbb, 0x7f, 0x0a,
		}
	case QUICVersion2:
		return []byte{
			0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb,
			0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
			0xf9, 0xbd, 0x2e, 0xd9,
		}
	default:
		// Draft versions
		return []byte{
			0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c,
			0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0,
			0x43, 0x90, 0xa8, 0x99,
		}
	}
}

// hkdfExtract performs HKDF-Extract.
func hkdfExtract(salt, ikm []byte) []byte {
	h := hkdf.Extract(sha256.New, ikm, salt)
	return h
}

// hkdfExpandLabel performs HKDF-Expand-Label for TLS 1.3.
func hkdfExpandLabel(secret []byte, label string, context []byte, length int) []byte {
	hkdfLabel := make([]byte, 0, 2+1+6+len(label)+1+len(context))
	hkdfLabel = append(hkdfLabel, byte(length>>8), byte(length))
	hkdfLabel = append(hkdfLabel, byte(6+len(label)))
	hkdfLabel = append(hkdfLabel, []byte("tls13 ")...)
	hkdfLabel = append(hkdfLabel, []byte(label)...)
	hkdfLabel = append(hkdfLabel, byte(len(context)))
	hkdfLabel = append(hkdfLabel, context...)
	
	reader := hkdf.Expand(sha256.New, secret, hkdfLabel)
	out := make([]byte, length)
	reader.Read(out)
	return out
}

// IsQUICPacket checks if data looks like a QUIC packet.
func IsQUICPacket(data []byte) bool {
	if len(data) < 5 {
		return false
	}
	
	firstByte := data[0]
	
	// Long header check
	if (firstByte & 0x80) != 0 {
		// Fixed bit should be set
		if (firstByte & 0x40) == 0 {
			return false
		}
		
		// Check version
		version := binary.BigEndian.Uint32(data[1:5])
		return version == QUICVersion1 || version == QUICVersion2 ||
			(version >= 0xff000000 && version <= 0xffffffff) // Draft versions
	}
	
	// Short header - fixed bit should be set
	return (firstByte & 0x40) != 0
}

// GetVersionString returns a human-readable version string.
func GetVersionString(version uint32) string {
	switch version {
	case QUICVersion1:
		return "QUIC v1"
	case QUICVersion2:
		return "QUIC v2"
	case 0:
		return "Version Negotiation"
	default:
		if version >= 0xff000000 {
			return fmt.Sprintf("Draft-%d", version&0xff)
		}
		return fmt.Sprintf("Unknown (0x%08x)", version)
	}
}
