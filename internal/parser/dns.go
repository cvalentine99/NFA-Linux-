// Package parser provides protocol parsers for NFA-Linux.
package parser

import (
	"sync"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/cvalentine99/nfa-linux/internal/models"
	"github.com/cvalentine99/nfa-linux/internal/privacy"
)

const (
	// MaxDNSLabelDepth limits DNS label/compression pointer recursion to prevent DoS.
	// RFC 1035 allows up to 255 bytes total, with 63-byte max per label.
	// A depth of 128 is generous but prevents infinite loops from malformed packets.
	MaxDNSLabelDepth = 128

	// MaxDNSNameLength is the maximum length of a DNS name (RFC 1035).
	MaxDNSNameLength = 255
)

// DNSParser parses DNS packets and extracts query/response information.
type DNSParser struct {
	// Callback for DNS records
	onRecord func(*models.DNSRecord)
	// Callback for PII findings
	onPII func(*DNSPIIFinding)
	// MaxLabelDepth limits recursion for compression pointer following
	MaxLabelDepth int
	// PII detection
	piiDetector *privacy.Detector
	piiEnabled  bool
}

// DNSPIIFinding represents PII detected in DNS traffic.
type DNSPIIFinding struct {
	QueryName   string
	Matches     []privacy.PIIMatch
	Timestamp   int64
	SrcIP       net.IP
	DstIP       net.IP
}

// NewDNSParser creates a new DNS parser.
func NewDNSParser() *DNSParser {
	return &DNSParser{
		MaxLabelDepth: MaxDNSLabelDepth,
	}
}

// SetRecordHandler sets the callback for DNS records.
func (p *DNSParser) SetRecordHandler(handler func(*models.DNSRecord)) {
	p.onRecord = handler
}

// SetPIIHandler sets the callback for PII findings.
func (p *DNSParser) SetPIIHandler(handler func(*DNSPIIFinding)) {
	p.onPII = handler
}

// EnablePIIDetection enables PII scanning with the given detector.
func (p *DNSParser) EnablePIIDetection(detector *privacy.Detector) {
	p.piiDetector = detector
	p.piiEnabled = detector != nil
}

// Parse parses a DNS packet and extracts records.
func (p *DNSParser) Parse(packet gopacket.Packet) ([]*models.DNSRecord, error) {
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return nil, nil
	}

	dns, _ := dnsLayer.(*layers.DNS)
	if dns == nil {
		return nil, nil
	}

	// Get IP addresses
	var srcIP, dstIP net.IP
	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4, _ := ipv4Layer.(*layers.IPv4)
		srcIP = ipv4.SrcIP
		dstIP = ipv4.DstIP
	} else if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		ipv6, _ := ipv6Layer.(*layers.IPv6)
		srcIP = ipv6.SrcIP
		dstIP = ipv6.DstIP
	}

	timestamp := packet.Metadata().Timestamp.UnixNano()

	var records []*models.DNSRecord

	// Process queries
	for _, q := range dns.Questions {
		record := &models.DNSRecord{
			QueryName:     string(q.Name),
			QueryType:     q.Type.String(),
			ResponseCode:  dns.ResponseCode.String(),
			ClientIP:      srcIP,
			ServerIP:      dstIP,
			TimestampNano: timestamp,
		}

		// If this is a response, add answers
		if dns.QR {
			record.ClientIP = dstIP // Response goes to client
			record.ServerIP = srcIP
			record.Answers = p.extractAnswers(dns, q.Name)
			if len(dns.Answers) > 0 {
				record.TTL = dns.Answers[0].TTL
			}
		}

		records = append(records, record)

		// Scan for PII in query name (e.g., email in subdomain)
		if p.piiEnabled && p.piiDetector != nil {
			p.scanDNSForPII(string(q.Name), timestamp, srcIP, dstIP)
		}

		if p.onRecord != nil {
			p.onRecord(record)
		}
	}

	return records, nil
}

// scanDNSForPII scans DNS query names for PII.
// This detects data exfiltration via DNS tunneling (e.g., email.base64data.evil.com)
func (p *DNSParser) scanDNSForPII(queryName string, timestamp int64, srcIP, dstIP net.IP) {
	if p.onPII == nil {
		return
	}

	// Check the full query name
	matches := p.piiDetector.Detect(queryName)
	
	// Also check each subdomain label separately (for encoded data)
	labels := strings.Split(queryName, ".")
	for _, label := range labels {
		// Skip short labels and TLDs
		if len(label) < 10 {
			continue
		}
		labelMatches := p.piiDetector.Detect(label)
		matches = append(matches, labelMatches...)
	}

	if len(matches) > 0 {
		p.onPII(&DNSPIIFinding{
			QueryName: queryName,
			Matches:   matches,
			Timestamp: timestamp,
			SrcIP:     srcIP,
			DstIP:     dstIP,
		})
	}
}

// ParseFromLayers parses DNS from pre-decoded layers.
func (p *DNSParser) ParseFromLayers(
	dns *layers.DNS,
	srcIP, dstIP net.IP,
	timestampNano int64,
) ([]*models.DNSRecord, error) {
	if dns == nil {
		return nil, nil
	}

	var records []*models.DNSRecord

	for _, q := range dns.Questions {
		record := &models.DNSRecord{
			QueryName:     string(q.Name),
			QueryType:     q.Type.String(),
			ResponseCode:  dns.ResponseCode.String(),
			ClientIP:      srcIP,
			ServerIP:      dstIP,
			TimestampNano: timestampNano,
		}

		if dns.QR {
			record.ClientIP = dstIP
			record.ServerIP = srcIP
			record.Answers = p.extractAnswers(dns, q.Name)
			if len(dns.Answers) > 0 {
				record.TTL = dns.Answers[0].TTL
			}
		}

		records = append(records, record)

		if p.onRecord != nil {
			p.onRecord(record)
		}
	}

	return records, nil
}

// extractAnswers extracts answer records from a DNS response.
// Validates name lengths to prevent DoS from malformed packets.
func (p *DNSParser) extractAnswers(dns *layers.DNS, queryName []byte) []string {
	var answers []string

	// Limit total answers to prevent memory exhaustion
	maxAnswers := 256
	if len(dns.Answers) > maxAnswers {
		return nil // Suspicious packet, skip
	}

	for _, ans := range dns.Answers {
		// Validate name length (RFC 1035: max 255 bytes)
		if len(ans.Name) > MaxDNSNameLength {
			continue // Skip malformed answer
		}
		if !strings.EqualFold(string(ans.Name), string(queryName)) {
			continue
		}

		switch ans.Type {
		case layers.DNSTypeA:
			if len(ans.IP) == 4 {
				answers = append(answers, ans.IP.String())
			}
		case layers.DNSTypeAAAA:
			if len(ans.IP) == 16 {
				answers = append(answers, ans.IP.String())
			}
		case layers.DNSTypeCNAME:
			answers = append(answers, string(ans.CNAME))
		case layers.DNSTypeMX:
			answers = append(answers, fmt.Sprintf("%d %s", ans.MX.Preference, string(ans.MX.Name)))
		case layers.DNSTypeTXT:
			for _, txt := range ans.TXTs {
				answers = append(answers, string(txt))
			}
		case layers.DNSTypeNS:
			answers = append(answers, string(ans.NS))
		case layers.DNSTypePTR:
			answers = append(answers, string(ans.PTR))
		case layers.DNSTypeSOA:
			answers = append(answers, fmt.Sprintf("%s %s", string(ans.SOA.MName), string(ans.SOA.RName)))
		}
	}

	return answers
}

// DNSCache provides a simple cache for DNS lookups.
type DNSCache struct {
	cache map[string]*dnsCacheEntry
	mu    sync.RWMutex
	ttl   time.Duration
}

type dnsCacheEntry struct {
	record    *models.DNSRecord
	expiresAt time.Time
}

// NewDNSCache creates a new DNS cache.
func NewDNSCache(ttl time.Duration) *DNSCache {
	return &DNSCache{
		cache: make(map[string]*dnsCacheEntry),
		mu:    sync.RWMutex{},
		ttl:   ttl,
	}
}

// Add adds a DNS record to the cache.
func (c *DNSCache) Add(record *models.DNSRecord) {
	key := record.QueryName + ":" + record.QueryType
	c.mu.Lock()
	c.cache[key] = &dnsCacheEntry{
		record:    record,
		expiresAt: time.Now().Add(c.ttl),
	}
	c.mu.Unlock()
}

// Lookup looks up a DNS record in the cache.
func (c *DNSCache) Lookup(name, queryType string) *models.DNSRecord {
	key := name + ":" + queryType
	c.mu.RLock()
	entry, ok := c.cache[key]
	c.mu.RUnlock()
	if !ok {
		return nil
	}

	if time.Now().After(entry.expiresAt) {
		c.mu.Lock()
		delete(c.cache, key)
		c.mu.Unlock()
		return nil
	}

	return entry.record
}

// ReverseLookup looks up a hostname by IP address.
func (c *DNSCache) ReverseLookup(ip net.IP) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, entry := range c.cache {
		if time.Now().After(entry.expiresAt) {
			continue
		}
		for _, ans := range entry.record.Answers {
			if ans == ip.String() {
				return entry.record.QueryName
			}
		}
	}
	return ""
}

// Cleanup removes expired entries from the cache.
func (c *DNSCache) Cleanup() {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, entry := range c.cache {
		if now.After(entry.expiresAt) {
			delete(c.cache, key)
		}
	}
}

// =============================================================================
// Raw DNS Packet Parsing with Compression Loop Protection
// =============================================================================

// ParseRawDNS parses raw DNS packet bytes with compression pointer protection.
// This is used when gopacket's DNS layer is not available or for deep inspection.
func (p *DNSParser) ParseRawDNS(data []byte) (*RawDNSPacket, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("DNS packet too short: %d bytes", len(data))
	}
	
	pkt := &RawDNSPacket{
		ID:            uint16(data[0])<<8 | uint16(data[1]),
		Flags:         uint16(data[2])<<8 | uint16(data[3]),
		QuestionCount: uint16(data[4])<<8 | uint16(data[5]),
		AnswerCount:   uint16(data[6])<<8 | uint16(data[7]),
		NSCount:       uint16(data[8])<<8 | uint16(data[9]),
		ARCount:       uint16(data[10])<<8 | uint16(data[11]),
	}
	
	// Sanity check counts to prevent DoS
	if pkt.QuestionCount > 256 || pkt.AnswerCount > 256 || pkt.NSCount > 256 || pkt.ARCount > 256 {
		return nil, fmt.Errorf("DNS packet has suspicious record counts")
	}
	
	offset := 12
	
	// Parse questions
	for i := uint16(0); i < pkt.QuestionCount && offset < len(data); i++ {
		name, newOffset, err := p.decodeDNSName(data, offset, 0)
		if err != nil {
			return nil, fmt.Errorf("failed to decode question name: %w", err)
		}
		offset = newOffset
		
		if offset+4 > len(data) {
			return nil, fmt.Errorf("DNS question truncated")
		}
		
		qtype := uint16(data[offset])<<8 | uint16(data[offset+1])
		qclass := uint16(data[offset+2])<<8 | uint16(data[offset+3])
		offset += 4
		
		pkt.Questions = append(pkt.Questions, RawDNSQuestion{
			Name:  name,
			Type:  qtype,
			Class: qclass,
		})
	}
	
	// Parse answers
	for i := uint16(0); i < pkt.AnswerCount && offset < len(data); i++ {
		rr, newOffset, err := p.decodeDNSResourceRecord(data, offset)
		if err != nil {
			// Don't fail on malformed answers, just stop parsing
			break
		}
		offset = newOffset
		pkt.Answers = append(pkt.Answers, rr)
	}
	
	return pkt, nil
}

// decodeDNSName decodes a DNS name with compression pointer loop protection.
// depth tracks recursion to prevent infinite loops from malicious packets.
func (p *DNSParser) decodeDNSName(data []byte, offset int, depth int) (string, int, error) {
	// SAFETY: Prevent compression pointer loops
	if depth > p.MaxLabelDepth {
		return "", 0, fmt.Errorf("DNS compression pointer depth exceeded (%d)", p.MaxLabelDepth)
	}
	
	if offset >= len(data) {
		return "", 0, fmt.Errorf("DNS name offset out of bounds")
	}
	
	var name strings.Builder
	_ = offset // originalOffset used for debugging
	jumped := false
	jumpOffset := 0
	totalLength := 0
	
	// Track visited offsets to detect pointer loops
	visited := make(map[int]bool)
	
	for {
		if offset >= len(data) {
			return "", 0, fmt.Errorf("DNS name truncated")
		}
		
		// SAFETY: Detect pointer loops - check BEFORE any processing
		if visited[offset] {
			return "", 0, fmt.Errorf("DNS compression pointer loop detected at offset %d", offset)
		}
		// Mark as visited BEFORE processing to prevent infinite loop on first iteration
		visited[offset] = true
		
		labelLen := int(data[offset])
		
		// Check for compression pointer (top 2 bits set = 0xC0)
		if labelLen&0xC0 == 0xC0 {
			if offset+1 >= len(data) {
				return "", 0, fmt.Errorf("DNS compression pointer truncated")
			}
			
				// Calculate pointer target
				pointer := int(data[offset]&0x3F)<<8 | int(data[offset+1])
				
				// SAFETY: Pointer must point to valid DNS name data (after 12-byte header)
				// and must point backwards (not forward into unprocessed data)
				const minValidPointer = 12 // DNS header is 12 bytes
				if pointer < minValidPointer {
					return "", 0, fmt.Errorf("DNS compression pointer targets header: %d < %d", pointer, minValidPointer)
				}
				if pointer >= offset {
					return "", 0, fmt.Errorf("DNS compression pointer points forward: %d >= %d", pointer, offset)
				}
				// SAFETY: Pointer must not have been visited (prevents mutual pointer loops)
				if visited[pointer] {
					return "", 0, fmt.Errorf("DNS compression pointer creates loop to offset %d", pointer)
				}
			
			if !jumped {
				jumpOffset = offset + 2
				jumped = true
			}
			
			// Recursively decode from pointer target
			subName, _, err := p.decodeDNSName(data, pointer, depth+1)
			if err != nil {
				return "", 0, err
			}
			
			if name.Len() > 0 {
				name.WriteByte('.')
			}
			name.WriteString(subName)
			break
		}
		
		// End of name
		if labelLen == 0 {
			offset++
			break
		}
		
		// SAFETY: Label length check (max 63 bytes per RFC 1035)
		if labelLen > 63 {
			return "", 0, fmt.Errorf("DNS label too long: %d bytes", labelLen)
		}
		
		// SAFETY: Total name length check
		totalLength += labelLen + 1
		if totalLength > MaxDNSNameLength {
			return "", 0, fmt.Errorf("DNS name too long: %d bytes", totalLength)
		}
		
		offset++
		if offset+labelLen > len(data) {
			return "", 0, fmt.Errorf("DNS label extends beyond packet")
		}
		
		if name.Len() > 0 {
			name.WriteByte('.')
		}
		name.Write(data[offset : offset+labelLen])
		offset += labelLen
	}
	
	if jumped {
		return name.String(), jumpOffset, nil
	}
	return name.String(), offset, nil
}

// decodeDNSResourceRecord decodes a DNS resource record.
func (p *DNSParser) decodeDNSResourceRecord(data []byte, offset int) (RawDNSResourceRecord, int, error) {
	var rr RawDNSResourceRecord
	
	// Decode name
	name, newOffset, err := p.decodeDNSName(data, offset, 0)
	if err != nil {
		return rr, 0, err
	}
	rr.Name = name
	offset = newOffset
	
	// Need at least 10 bytes for type, class, TTL, rdlength
	if offset+10 > len(data) {
		return rr, 0, fmt.Errorf("DNS RR truncated")
	}
	
	rr.Type = uint16(data[offset])<<8 | uint16(data[offset+1])
	rr.Class = uint16(data[offset+2])<<8 | uint16(data[offset+3])
	rr.TTL = uint32(data[offset+4])<<24 | uint32(data[offset+5])<<16 | uint32(data[offset+6])<<8 | uint32(data[offset+7])
	rdLength := uint16(data[offset+8])<<8 | uint16(data[offset+9])
	offset += 10
	
	// SAFETY: Validate rdLength
	if int(rdLength) > len(data)-offset {
		return rr, 0, fmt.Errorf("DNS RR data length exceeds packet")
	}
	
	rr.RData = data[offset : offset+int(rdLength)]
	offset += int(rdLength)
	
	return rr, offset, nil
}

// RawDNSPacket represents a parsed DNS packet.
type RawDNSPacket struct {
	ID            uint16
	Flags         uint16
	QuestionCount uint16
	AnswerCount   uint16
	NSCount       uint16
	ARCount       uint16
	Questions     []RawDNSQuestion
	Answers       []RawDNSResourceRecord
}

// RawDNSQuestion represents a DNS question.
type RawDNSQuestion struct {
	Name  string
	Type  uint16
	Class uint16
}

// RawDNSResourceRecord represents a DNS resource record.
type RawDNSResourceRecord struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	RData []byte
}

// IsResponse returns true if this is a DNS response.
func (p *RawDNSPacket) IsResponse() bool {
	return p.Flags&0x8000 != 0
}

// =============================================================================
// Integrated Parsing with Compression Protection
// =============================================================================

// ParseWithProtection parses DNS from raw bytes with full compression protection.
// This should be used for untrusted input where gopacket's parsing might be bypassed.
func (p *DNSParser) ParseWithProtection(data []byte, srcIP, dstIP net.IP, timestampNano int64) ([]*models.DNSRecord, error) {
	// First, validate the raw packet structure with our protected parser
	rawPkt, err := p.ParseRawDNS(data)
	if err != nil {
		return nil, fmt.Errorf("DNS validation failed: %w", err)
	}
	
	// Convert raw packet to models
	var records []*models.DNSRecord
	
	for _, q := range rawPkt.Questions {
		record := &models.DNSRecord{
			QueryName:     q.Name,
			QueryType:     dnsTypeName(q.Type),
			ResponseCode:  dnsRcodeName(rawPkt.ResponseCode()),
			ClientIP:      srcIP,
			ServerIP:      dstIP,
			TimestampNano: timestampNano,
		}
		
		// If response, extract answers
		if rawPkt.IsResponse() {
			record.ClientIP = dstIP
			record.ServerIP = srcIP
			record.Answers = p.extractRawAnswers(rawPkt.Answers, q.Name, q.Type)
			if len(rawPkt.Answers) > 0 {
				record.TTL = rawPkt.Answers[0].TTL
			}
		}
		
		records = append(records, record)
		
		// PII scanning
		if p.piiEnabled && p.piiDetector != nil {
			p.scanDNSForPII(q.Name, timestampNano, srcIP, dstIP)
		}
		
		if p.onRecord != nil {
			p.onRecord(record)
		}
	}
	
	return records, nil
}

// extractRawAnswers extracts answer strings from raw DNS resource records.
func (p *DNSParser) extractRawAnswers(answers []RawDNSResourceRecord, queryName string, queryType uint16) []string {
	var result []string
	
	for _, ans := range answers {
		// Match query name (case-insensitive)
		if !strings.EqualFold(ans.Name, queryName) {
			continue
		}
		
		switch ans.Type {
		case 1: // A record
			if len(ans.RData) == 4 {
				ip := net.IP(ans.RData)
				result = append(result, ip.String())
			}
		case 28: // AAAA record
			if len(ans.RData) == 16 {
				ip := net.IP(ans.RData)
				result = append(result, ip.String())
			}
		case 5: // CNAME
			// CNAME rdata is a compressed name, need to decode
			// For safety, just use the raw bytes as string if short enough
			if len(ans.RData) > 0 && len(ans.RData) <= MaxDNSNameLength {
				result = append(result, string(ans.RData))
			}
		case 16: // TXT
			// TXT records have length-prefixed strings
			offset := 0
			for offset < len(ans.RData) {
				if offset >= len(ans.RData) {
					break
				}
				txtLen := int(ans.RData[offset])
				offset++
				if offset+txtLen > len(ans.RData) {
					break
				}
				result = append(result, string(ans.RData[offset:offset+txtLen]))
				offset += txtLen
			}
		case 15: // MX
			if len(ans.RData) >= 3 {
				pref := uint16(ans.RData[0])<<8 | uint16(ans.RData[1])
				result = append(result, fmt.Sprintf("%d %s", pref, string(ans.RData[2:])))
			}
		}
	}
	
	return result
}

// dnsTypeName returns the string name for a DNS type.
func dnsTypeName(t uint16) string {
	names := map[uint16]string{
		1:   "A",
		2:   "NS",
		5:   "CNAME",
		6:   "SOA",
		12:  "PTR",
		15:  "MX",
		16:  "TXT",
		28:  "AAAA",
		33:  "SRV",
		35:  "NAPTR",
		43:  "DS",
		46:  "RRSIG",
		47:  "NSEC",
		48:  "DNSKEY",
		50:  "NSEC3",
		52:  "TLSA",
		65:  "HTTPS",
		99:  "SPF",
		255: "ANY",
		256: "URI",
		257: "CAA",
	}
	if name, ok := names[t]; ok {
		return name
	}
	return fmt.Sprintf("TYPE%d", t)
}

// dnsRcodeName returns the string name for a DNS response code.
func dnsRcodeName(rcode int) string {
	names := map[int]string{
		0: "NoError",
		1: "FormErr",
		2: "ServFail",
		3: "NXDomain",
		4: "NotImp",
		5: "Refused",
		6: "YXDomain",
		7: "YXRRSet",
		8: "NXRRSet",
		9: "NotAuth",
	}
	if name, ok := names[rcode]; ok {
		return name
	}
	return fmt.Sprintf("RCODE%d", rcode)
}

// ResponseCode returns the DNS response code.
func (p *RawDNSPacket) ResponseCode() int {
	return int(p.Flags & 0x000F)
}
