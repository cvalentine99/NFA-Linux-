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
)

// DNSParser parses DNS packets and extracts query/response information.
type DNSParser struct {
	// Callback for DNS records
	onRecord func(*models.DNSRecord)
}

// NewDNSParser creates a new DNS parser.
func NewDNSParser() *DNSParser {
	return &DNSParser{}
}

// SetRecordHandler sets the callback for DNS records.
func (p *DNSParser) SetRecordHandler(handler func(*models.DNSRecord)) {
	p.onRecord = handler
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

		if p.onRecord != nil {
			p.onRecord(record)
		}
	}

	return records, nil
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
func (p *DNSParser) extractAnswers(dns *layers.DNS, queryName []byte) []string {
	var answers []string

	for _, ans := range dns.Answers {
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
