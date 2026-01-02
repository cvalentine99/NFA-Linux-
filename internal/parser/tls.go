// Package parser provides TLS protocol parsing and fingerprinting for NFA-Linux.
package parser

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// TLSParser parses TLS handshakes and generates fingerprints.
type TLSParser struct {
	// Callbacks
	onClientHello func(*TLSClientHello)
	onServerHello func(*TLSServerHello)
}

// TLSClientHello represents a parsed TLS Client Hello message.
type TLSClientHello struct {
	Version           uint16
	CipherSuites      []uint16
	Extensions        []uint16
	SupportedGroups   []uint16
	ECPointFormats    []uint8
	SignatureAlgs     []uint16
	ALPNProtocols     []string
	SNI               string
	ServerName        string   // Alias for SNI (for QUIC compatibility)
	SupportedVersions []uint16 // TLS supported versions extension
	JA3               string
	JA3Hash           string
	JA4               string
	TimestampNano     int64
	Raw               []byte
}

// TLSServerHello represents a parsed TLS Server Hello message.
type TLSServerHello struct {
	Version         uint16
	CipherSuite     uint16
	Extensions      []uint16
	JA3S            string
	JA3SHash        string
	TimestampNano   int64
	Raw             []byte
}

// TLS extension types
const (
	ExtServerName          uint16 = 0
	ExtSupportedGroups     uint16 = 10
	ExtECPointFormats      uint16 = 11
	ExtSignatureAlgorithms uint16 = 13
	ExtALPN                uint16 = 16
	ExtSupportedVersions   uint16 = 43
)

// NewTLSParser creates a new TLS parser.
func NewTLSParser() *TLSParser {
	return &TLSParser{}
}

// SetClientHelloHandler sets the callback for Client Hello messages.
func (p *TLSParser) SetClientHelloHandler(handler func(*TLSClientHello)) {
	p.onClientHello = handler
}

// SetServerHelloHandler sets the callback for Server Hello messages.
func (p *TLSParser) SetServerHelloHandler(handler func(*TLSServerHello)) {
	p.onServerHello = handler
}

// Parse parses a TLS packet.
func (p *TLSParser) Parse(packet gopacket.Packet) error {
	tlsLayer := packet.Layer(layers.LayerTypeTLS)
	if tlsLayer == nil {
		return nil
	}

	tls, _ := tlsLayer.(*layers.TLS)
	if tls == nil {
		return nil
	}

	timestamp := packet.Metadata().Timestamp.UnixNano()

	// Process TLS records from the Contents byte slice
	record := tls.Contents
	if len(record) < 5 {
		return nil
	}

	// Check for handshake record (type 22)
	if record[0] != 22 {
		return nil
	}

	// Parse handshake message
	if len(record) < 6 {
		return nil
	}

	handshakeType := record[5]
	switch handshakeType {
	case 1: // Client Hello
		ch, err := p.parseClientHello(record[5:], timestamp)
		if err == nil && p.onClientHello != nil {
			p.onClientHello(ch)
		}
	case 2: // Server Hello
		sh, err := p.parseServerHello(record[5:], timestamp)
		if err == nil && p.onServerHello != nil {
			p.onServerHello(sh)
		}
	}

	return nil
}

// ParseClientHello parses a TLS Client Hello from raw data.
func (p *TLSParser) ParseClientHello(data []byte, timestampNano int64) (*TLSClientHello, error) {
	return p.parseClientHello(data, timestampNano)
}

// parseClientHello parses a Client Hello message.
func (p *TLSParser) parseClientHello(data []byte, timestampNano int64) (*TLSClientHello, error) {
	if len(data) < 38 {
		return nil, fmt.Errorf("client hello too short")
	}

	ch := &TLSClientHello{
		TimestampNano: timestampNano,
		Raw:           data,
	}

	// Skip handshake type (1 byte) and length (3 bytes)
	pos := 4

	// Client version
	ch.Version = uint16(data[pos])<<8 | uint16(data[pos+1])
	pos += 2

	// Skip random (32 bytes)
	pos += 32

	// Session ID length and data
	if pos >= len(data) {
		return nil, fmt.Errorf("truncated client hello")
	}
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen

	// Cipher suites
	if pos+2 > len(data) {
		return nil, fmt.Errorf("truncated client hello")
	}
	cipherSuitesLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2

	if pos+cipherSuitesLen > len(data) {
		return nil, fmt.Errorf("truncated client hello")
	}

	for i := 0; i < cipherSuitesLen; i += 2 {
		suite := uint16(data[pos+i])<<8 | uint16(data[pos+i+1])
		// Skip GREASE values
		if !isGREASE(suite) {
			ch.CipherSuites = append(ch.CipherSuites, suite)
		}
	}
	pos += cipherSuitesLen

	// Compression methods
	if pos >= len(data) {
		return nil, fmt.Errorf("truncated client hello")
	}
	compressionLen := int(data[pos])
	pos += 1 + compressionLen

	// Extensions
	if pos+2 > len(data) {
		// No extensions
		ch.JA3, ch.JA3Hash = p.computeJA3(ch)
		ch.JA4 = p.computeJA4(ch)
		return ch, nil
	}

	extensionsLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2

	extensionsEnd := pos + extensionsLen
	if extensionsEnd > len(data) {
		extensionsEnd = len(data)
	}

	for pos < extensionsEnd {
		if pos+4 > extensionsEnd {
			break
		}

		extType := uint16(data[pos])<<8 | uint16(data[pos+1])
		extLen := int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4

		if pos+extLen > extensionsEnd {
			break
		}

		extData := data[pos : pos+extLen]

		// Skip GREASE extensions
		if !isGREASE(extType) {
			ch.Extensions = append(ch.Extensions, extType)
		}

		// Parse specific extensions
		switch extType {
		case ExtServerName:
			ch.SNI = p.parseSNI(extData)
		case ExtSupportedGroups:
			ch.SupportedGroups = p.parseSupportedGroups(extData)
		case ExtECPointFormats:
			ch.ECPointFormats = p.parseECPointFormats(extData)
		case ExtSignatureAlgorithms:
			ch.SignatureAlgs = p.parseSignatureAlgorithms(extData)
		case ExtALPN:
			ch.ALPNProtocols = p.parseALPN(extData)
		}

		pos += extLen
	}

	// Compute fingerprints
	ch.JA3, ch.JA3Hash = p.computeJA3(ch)
	ch.JA4 = p.computeJA4(ch)

	return ch, nil
}

// parseServerHello parses a Server Hello message.
func (p *TLSParser) parseServerHello(data []byte, timestampNano int64) (*TLSServerHello, error) {
	if len(data) < 38 {
		return nil, fmt.Errorf("server hello too short")
	}

	sh := &TLSServerHello{
		TimestampNano: timestampNano,
		Raw:           data,
	}

	// Skip handshake type (1 byte) and length (3 bytes)
	pos := 4

	// Server version
	sh.Version = uint16(data[pos])<<8 | uint16(data[pos+1])
	pos += 2

	// Skip random (32 bytes)
	pos += 32

	// Session ID length and data
	if pos >= len(data) {
		return nil, fmt.Errorf("truncated server hello")
	}
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen

	// Cipher suite
	if pos+2 > len(data) {
		return nil, fmt.Errorf("truncated server hello")
	}
	sh.CipherSuite = uint16(data[pos])<<8 | uint16(data[pos+1])
	pos += 2

	// Compression method
	pos += 1

	// Extensions
	if pos+2 > len(data) {
		sh.JA3S, sh.JA3SHash = p.computeJA3S(sh)
		return sh, nil
	}

	extensionsLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2

	extensionsEnd := pos + extensionsLen
	if extensionsEnd > len(data) {
		extensionsEnd = len(data)
	}

	for pos < extensionsEnd {
		if pos+4 > extensionsEnd {
			break
		}

		extType := uint16(data[pos])<<8 | uint16(data[pos+1])
		extLen := int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4

		if !isGREASE(extType) {
			sh.Extensions = append(sh.Extensions, extType)
		}

		pos += extLen
	}

	sh.JA3S, sh.JA3SHash = p.computeJA3S(sh)

	return sh, nil
}

// parseSNI parses the Server Name Indication extension.
func (p *TLSParser) parseSNI(data []byte) string {
	if len(data) < 5 {
		return ""
	}

	// Skip list length (2 bytes)
	pos := 2

	// Name type (should be 0 for hostname)
	if data[pos] != 0 {
		return ""
	}
	pos++

	// Name length
	nameLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2

	if pos+nameLen > len(data) {
		return ""
	}

	return string(data[pos : pos+nameLen])
}

// parseSupportedGroups parses the Supported Groups extension.
func (p *TLSParser) parseSupportedGroups(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}

	listLen := int(data[0])<<8 | int(data[1])
	if listLen+2 > len(data) {
		listLen = len(data) - 2
	}

	var groups []uint16
	for i := 2; i < listLen+2; i += 2 {
		group := uint16(data[i])<<8 | uint16(data[i+1])
		if !isGREASE(group) {
			groups = append(groups, group)
		}
	}

	return groups
}

// parseECPointFormats parses the EC Point Formats extension.
func (p *TLSParser) parseECPointFormats(data []byte) []uint8 {
	if len(data) < 1 {
		return nil
	}

	listLen := int(data[0])
	if listLen+1 > len(data) {
		listLen = len(data) - 1
	}

	formats := make([]uint8, listLen)
	copy(formats, data[1:1+listLen])

	return formats
}

// parseSignatureAlgorithms parses the Signature Algorithms extension.
func (p *TLSParser) parseSignatureAlgorithms(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}

	listLen := int(data[0])<<8 | int(data[1])
	if listLen+2 > len(data) {
		listLen = len(data) - 2
	}

	var algs []uint16
	for i := 2; i < listLen+2; i += 2 {
		alg := uint16(data[i])<<8 | uint16(data[i+1])
		algs = append(algs, alg)
	}

	return algs
}

// parseALPN parses the Application-Layer Protocol Negotiation extension.
func (p *TLSParser) parseALPN(data []byte) []string {
	if len(data) < 2 {
		return nil
	}

	listLen := int(data[0])<<8 | int(data[1])
	if listLen+2 > len(data) {
		listLen = len(data) - 2
	}

	var protocols []string
	pos := 2
	for pos < listLen+2 {
		protoLen := int(data[pos])
		pos++
		if pos+protoLen > len(data) {
			break
		}
		protocols = append(protocols, string(data[pos:pos+protoLen]))
		pos += protoLen
	}

	return protocols
}

// computeJA3 computes the JA3 fingerprint for a Client Hello.
func (p *TLSParser) computeJA3(ch *TLSClientHello) (string, string) {
	// JA3 = Version,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
	// Using strings.Builder for efficient string construction
	var sb strings.Builder
	sb.Grow(256) // Pre-allocate reasonable capacity

	// Version
	sb.WriteString(strconv.Itoa(int(ch.Version)))

	// Cipher suites
	sb.WriteByte(',')
	for i, c := range ch.CipherSuites {
		if i > 0 {
			sb.WriteByte('-')
		}
		sb.WriteString(strconv.Itoa(int(c)))
	}

	// Extensions
	sb.WriteByte(',')
	for i, e := range ch.Extensions {
		if i > 0 {
			sb.WriteByte('-')
		}
		sb.WriteString(strconv.Itoa(int(e)))
	}

	// Supported groups (elliptic curves)
	sb.WriteByte(',')
	for i, g := range ch.SupportedGroups {
		if i > 0 {
			sb.WriteByte('-')
		}
		sb.WriteString(strconv.Itoa(int(g)))
	}

	// EC point formats
	sb.WriteByte(',')
	for i, f := range ch.ECPointFormats {
		if i > 0 {
			sb.WriteByte('-')
		}
		sb.WriteString(strconv.Itoa(int(f)))
	}

	ja3 := sb.String()
	hash := md5.Sum([]byte(ja3))
	return ja3, hex.EncodeToString(hash[:])
}

// computeJA3S computes the JA3S fingerprint for a Server Hello.
func (p *TLSParser) computeJA3S(sh *TLSServerHello) (string, string) {
	// JA3S = Version,Cipher,Extensions
	// Using strings.Builder for efficient string construction
	var sb strings.Builder
	sb.Grow(128) // Pre-allocate reasonable capacity

	sb.WriteString(strconv.Itoa(int(sh.Version)))
	sb.WriteByte(',')
	sb.WriteString(strconv.Itoa(int(sh.CipherSuite)))
	sb.WriteByte(',')

	for i, e := range sh.Extensions {
		if i > 0 {
			sb.WriteByte('-')
		}
		sb.WriteString(strconv.Itoa(int(e)))
	}

	ja3s := sb.String()
	hash := md5.Sum([]byte(ja3s))
	return ja3s, hex.EncodeToString(hash[:])
}

// computeJA4 computes the JA4 fingerprint for a Client Hello.
// JA4 format: t13d1516h2_8daaf6152771_e5627efa2ab1
func (p *TLSParser) computeJA4(ch *TLSClientHello) string {
	// Part 1: Protocol info
	// t = TLS, q = QUIC, d = DTLS
	proto := "t"

	// TLS version (2 chars)
	version := "00"
	switch ch.Version {
	case 0x0301:
		version = "10"
	case 0x0302:
		version = "11"
	case 0x0303:
		version = "12"
	case 0x0304:
		version = "13"
	}

	// SNI present
	sni := "d"
	if ch.SNI != "" {
		sni = "i"
	}

	// Number of cipher suites (2 digits, capped at 99)
	numCiphers := len(ch.CipherSuites)
	if numCiphers > 99 {
		numCiphers = 99
	}

	// Number of extensions (2 digits, capped at 99)
	numExts := len(ch.Extensions)
	if numExts > 99 {
		numExts = 99
	}

	// ALPN first value
	alpn := "00"
	if len(ch.ALPNProtocols) > 0 {
		first := ch.ALPNProtocols[0]
		if len(first) >= 2 {
			alpn = first[:2]
		} else if len(first) == 1 {
			alpn = first + "0"
		}
	}

	part1 := fmt.Sprintf("%s%s%s%02d%02d%s", proto, version, sni, numCiphers, numExts, alpn)

	// Part 2: Sorted cipher suites hash (first 12 chars of SHA256)
	sortedCiphers := make([]uint16, len(ch.CipherSuites))
	copy(sortedCiphers, ch.CipherSuites)
	sort.Slice(sortedCiphers, func(i, j int) bool {
		return sortedCiphers[i] < sortedCiphers[j]
	})

	var cipherBuilder strings.Builder
	cipherBuilder.Grow(len(sortedCiphers) * 5) // 4 hex chars + comma
	for i, c := range sortedCiphers {
		if i > 0 {
			cipherBuilder.WriteByte(',')
		}
		fmt.Fprintf(&cipherBuilder, "%04x", c)
	}
	part2 := truncateHash(cipherBuilder.String(), 12)

	// Part 3: Sorted extensions hash (first 12 chars of SHA256)
	sortedExts := make([]uint16, len(ch.Extensions))
	copy(sortedExts, ch.Extensions)
	sort.Slice(sortedExts, func(i, j int) bool {
		return sortedExts[i] < sortedExts[j]
	})

	var extBuilder strings.Builder
	extBuilder.Grow(len(sortedExts) * 5) // 4 hex chars + comma
	for i, e := range sortedExts {
		if i > 0 {
			extBuilder.WriteByte(',')
		}
		fmt.Fprintf(&extBuilder, "%04x", e)
	}
	part3 := truncateHash(extBuilder.String(), 12)

	return fmt.Sprintf("%s_%s_%s", part1, part2, part3)
}

// isGREASE checks if a value is a GREASE value.
func isGREASE(val uint16) bool {
	// GREASE values are 0x0a0a, 0x1a1a, 0x2a2a, etc.
	return (val & 0x0f0f) == 0x0a0a
}

// truncateHash computes a hash and returns the first n characters.
func truncateHash(s string, n int) string {
	hash := md5.Sum([]byte(s))
	hexStr := hex.EncodeToString(hash[:])
	if len(hexStr) > n {
		return hexStr[:n]
	}
	return hexStr
}

// GetTLSVersionString returns a human-readable TLS version string.
func GetTLSVersionString(version uint16) string {
	switch version {
	case 0x0300:
		return "SSL 3.0"
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

// ParseTLSClientHello parses a TLS ClientHello from raw data (for use by QUIC parser).
// This is a standalone function that can be called without a TLSParser instance.
func ParseTLSClientHello(data []byte) (*TLSClientHello, error) {
	p := NewTLSParser()
	return p.parseClientHello(data, 0)
}

// ComputeJA4Fingerprint computes the JA4 fingerprint from a TLSClientHello.
// JA4 format: t13d1516h2_8daaf6152771_e5627efa2ab1
// - Protocol (t=TLS, q=QUIC)
// - TLS version (13=1.3, 12=1.2, etc.)
// - SNI (d=domain present, i=IP literal, empty=no SNI)
// - Number of cipher suites (2 digits)
// - Number of extensions (2 digits)
// - ALPN first value first char (h=http, empty if none)
// - First 12 chars of SHA256 of sorted cipher suites
// - First 12 chars of SHA256 of sorted extensions
func ComputeJA4Fingerprint(ch *TLSClientHello) string {
	if ch == nil {
		return ""
	}

	// Protocol indicator (t for TLS)
	protocol := "t"

	// TLS version
	var version string
	switch ch.Version {
	case 0x0304:
		version = "13"
	case 0x0303:
		version = "12"
	case 0x0302:
		version = "11"
	case 0x0301:
		version = "10"
	default:
		version = "00"
	}

	// SNI indicator
	var sni string
	if ch.SNI != "" {
		// Check if it's an IP literal
		if isIPAddress(ch.SNI) {
			sni = "i"
		} else {
			sni = "d"
		}
	}

	// Cipher suite count (2 digits, max 99)
	cipherCount := len(ch.CipherSuites)
	if cipherCount > 99 {
		cipherCount = 99
	}

	// Extension count (2 digits, max 99)
	extCount := len(ch.Extensions)
	if extCount > 99 {
		extCount = 99
	}

	// ALPN first char
	var alpn string
	if len(ch.ALPNProtocols) > 0 && len(ch.ALPNProtocols[0]) > 0 {
		alpn = string(ch.ALPNProtocols[0][0])
	}

	// Build first part
	part1 := fmt.Sprintf("%s%s%s%02d%02d%s", protocol, version, sni, cipherCount, extCount, alpn)

	// Sort and hash cipher suites (excluding GREASE values)
	var ciphers []uint16
	for _, cs := range ch.CipherSuites {
		if !isGREASE(cs) {
			ciphers = append(ciphers, cs)
		}
	}
	sort.Slice(ciphers, func(i, j int) bool { return ciphers[i] < ciphers[j] })

	var cipherStr strings.Builder
	for i, cs := range ciphers {
		if i > 0 {
			cipherStr.WriteString(",")
		}
		cipherStr.WriteString(fmt.Sprintf("%04x", cs))
	}
	cipherHash := sha256Hash(cipherStr.String())[:12]

	// Sort and hash extensions (excluding GREASE values and certain extensions)
	var exts []uint16
	for _, ext := range ch.Extensions {
		if !isGREASE(ext) && ext != 0 && ext != 16 { // Exclude SNI (0) and ALPN (16)
			exts = append(exts, ext)
		}
	}
	sort.Slice(exts, func(i, j int) bool { return exts[i] < exts[j] })

	var extStr strings.Builder
	for i, ext := range exts {
		if i > 0 {
			extStr.WriteString(",")
		}
		extStr.WriteString(fmt.Sprintf("%04x", ext))
	}
	extHash := sha256Hash(extStr.String())[:12]

	return fmt.Sprintf("%s_%s_%s", part1, cipherHash, extHash)
}

// isIPAddress checks if a string is an IP address.
func isIPAddress(s string) bool {
	for _, c := range s {
		if c != '.' && c != ':' && (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// sha256Hash computes SHA256 hash and returns first 12 bytes as hex string (JA4 spec).
func sha256Hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:12]) // JA4 uses truncated SHA256 (first 12 bytes = 24 hex chars)
}
