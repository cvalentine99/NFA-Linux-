// Package ml provides machine learning inference capabilities for network forensics
package ml

import (
	"math"
	"sort"

	"github.com/cvalentine99/nfa-linux/internal/models"
)

// FlowFeatures represents extracted features from a network flow
type FlowFeatures struct {
	// Basic flow statistics
	Duration        float32 // Flow duration in seconds
	TotalPackets    float32 // Total number of packets
	TotalBytes      float32 // Total bytes transferred
	PacketsPerSec   float32 // Packets per second
	BytesPerSec     float32 // Bytes per second
	
	// Directional statistics
	FwdPackets      float32 // Forward direction packets
	BwdPackets      float32 // Backward direction packets
	FwdBytes        float32 // Forward direction bytes
	BwdBytes        float32 // Backward direction bytes
	FwdBwdRatio     float32 // Forward/backward packet ratio
	
	// Packet size statistics
	MinPacketLen    float32 // Minimum packet length
	MaxPacketLen    float32 // Maximum packet length
	MeanPacketLen   float32 // Mean packet length
	StdPacketLen    float32 // Standard deviation of packet length
	
	// Inter-arrival time statistics
	MinIAT          float32 // Minimum inter-arrival time
	MaxIAT          float32 // Maximum inter-arrival time
	MeanIAT         float32 // Mean inter-arrival time
	StdIAT          float32 // Standard deviation of IAT
	
	// TCP flags (if applicable)
	SYNCount        float32 // Number of SYN flags
	ACKCount        float32 // Number of ACK flags
	FINCount        float32 // Number of FIN flags
	RSTCount        float32 // Number of RST flags
	PSHCount        float32 // Number of PSH flags
	URGCount        float32 // Number of URG flags
	
	// Payload statistics
	PayloadEntropy  float32 // Shannon entropy of payload
	PayloadMean     float32 // Mean byte value of payload
	PayloadStd      float32 // Standard deviation of payload bytes
	
	// Protocol indicators
	IsTCP           float32 // 1 if TCP, 0 otherwise
	IsUDP           float32 // 1 if UDP, 0 otherwise
	IsHTTP          float32 // 1 if HTTP detected
	IsHTTPS         float32 // 1 if HTTPS/TLS detected
	IsDNS           float32 // 1 if DNS detected
	IsSMB           float32 // 1 if SMB detected
	IsQUIC          float32 // 1 if QUIC detected
	
	// Port features
	SrcPortNorm     float32 // Normalized source port (0-1)
	DstPortNorm     float32 // Normalized destination port (0-1)
	IsWellKnownPort float32 // 1 if destination is well-known port
	IsEphemeralPort float32 // 1 if source is ephemeral port
}

// ToSlice converts FlowFeatures to a float32 slice for model input
func (f *FlowFeatures) ToSlice() []float32 {
	return []float32{
		f.Duration,
		f.TotalPackets,
		f.TotalBytes,
		f.PacketsPerSec,
		f.BytesPerSec,
		f.FwdPackets,
		f.BwdPackets,
		f.FwdBytes,
		f.BwdBytes,
		f.FwdBwdRatio,
		f.MinPacketLen,
		f.MaxPacketLen,
		f.MeanPacketLen,
		f.StdPacketLen,
		f.MinIAT,
		f.MaxIAT,
		f.MeanIAT,
		f.StdIAT,
		f.SYNCount,
		f.ACKCount,
		f.FINCount,
		f.RSTCount,
		f.PSHCount,
		f.URGCount,
		f.PayloadEntropy,
		f.PayloadMean,
		f.PayloadStd,
		f.IsTCP,
		f.IsUDP,
		f.IsHTTP,
		f.IsHTTPS,
		f.IsDNS,
		f.IsSMB,
		f.IsQUIC,
		f.SrcPortNorm,
		f.DstPortNorm,
		f.IsWellKnownPort,
		f.IsEphemeralPort,
	}
}

// FeatureCount returns the number of features
func (f *FlowFeatures) FeatureCount() int {
	return 38
}

// PacketFeatures represents extracted features from a single packet
type PacketFeatures struct {
	// Basic packet info
	Length          float32 // Packet length
	PayloadLength   float32 // Payload length
	HeaderLength    float32 // Header length
	
	// Protocol indicators
	IsTCP           float32
	IsUDP           float32
	IsICMP          float32
	
	// TCP flags
	SYN             float32
	ACK             float32
	FIN             float32
	RST             float32
	PSH             float32
	URG             float32
	
	// Port features
	SrcPort         float32
	DstPort         float32
	
	// Payload features
	PayloadEntropy  float32
	FirstBytesMean  float32 // Mean of first N bytes
	FirstBytesStd   float32 // Std of first N bytes
	
	// Timing
	TimeDelta       float32 // Time since last packet in flow
}

// ToSlice converts PacketFeatures to a float32 slice
func (p *PacketFeatures) ToSlice() []float32 {
	return []float32{
		p.Length,
		p.PayloadLength,
		p.HeaderLength,
		p.IsTCP,
		p.IsUDP,
		p.IsICMP,
		p.SYN,
		p.ACK,
		p.FIN,
		p.RST,
		p.PSH,
		p.URG,
		p.SrcPort,
		p.DstPort,
		p.PayloadEntropy,
		p.FirstBytesMean,
		p.FirstBytesStd,
		p.TimeDelta,
	}
}

// DNSFeatures represents features extracted from DNS queries
type DNSFeatures struct {
	// Domain name features
	DomainLength    float32 // Length of domain name
	SubdomainCount  float32 // Number of subdomains
	MaxLabelLength  float32 // Maximum label length
	AvgLabelLength  float32 // Average label length
	
	// Character distribution
	NumericRatio    float32 // Ratio of numeric characters
	AlphaRatio      float32 // Ratio of alphabetic characters
	SpecialRatio    float32 // Ratio of special characters
	ConsonantRatio  float32 // Ratio of consonants
	VowelRatio      float32 // Ratio of vowels
	
	// Entropy features
	DomainEntropy   float32 // Shannon entropy of domain
	LabelEntropy    float32 // Average entropy per label
	
	// N-gram features
	BigramEntropy   float32 // Entropy of character bigrams
	TrigramEntropy  float32 // Entropy of character trigrams
	
	// Query features
	QueryType       float32 // DNS query type (normalized)
	IsReverseLookup float32 // 1 if reverse DNS lookup
	HasDigits       float32 // 1 if domain contains digits
	HasHyphens      float32 // 1 if domain contains hyphens
	
	// TLD features
	TLDLength       float32 // Length of TLD
	IsCommonTLD     float32 // 1 if common TLD (.com, .org, etc.)
}

// ToSlice converts DNSFeatures to a float32 slice
func (d *DNSFeatures) ToSlice() []float32 {
	return []float32{
		d.DomainLength,
		d.SubdomainCount,
		d.MaxLabelLength,
		d.AvgLabelLength,
		d.NumericRatio,
		d.AlphaRatio,
		d.SpecialRatio,
		d.ConsonantRatio,
		d.VowelRatio,
		d.DomainEntropy,
		d.LabelEntropy,
		d.BigramEntropy,
		d.TrigramEntropy,
		d.QueryType,
		d.IsReverseLookup,
		d.HasDigits,
		d.HasHyphens,
		d.TLDLength,
		d.IsCommonTLD,
	}
}

// TLSFeatures represents features extracted from TLS handshakes
type TLSFeatures struct {
	// ClientHello features
	CipherSuiteCount     float32 // Number of cipher suites
	ExtensionCount       float32 // Number of extensions
	SupportedVersions    float32 // Number of supported versions
	SignatureAlgCount    float32 // Number of signature algorithms
	SupportedGroupCount  float32 // Number of supported groups
	
	// JA3/JA4 derived features
	JA3HashEntropy       float32 // Entropy of JA3 hash
	JA4HashEntropy       float32 // Entropy of JA4 hash
	
	// Version indicators
	IsTLS10              float32
	IsTLS11              float32
	IsTLS12              float32
	IsTLS13              float32
	
	// ALPN features
	HasALPN              float32
	ALPNProtocolCount    float32
	SupportsHTTP2        float32
	SupportsHTTP3        float32
	
	// SNI features
	SNILength            float32
	SNIEntropy           float32
	SNIHasDigits         float32
}

// ToSlice converts TLSFeatures to a float32 slice
func (t *TLSFeatures) ToSlice() []float32 {
	return []float32{
		t.CipherSuiteCount,
		t.ExtensionCount,
		t.SupportedVersions,
		t.SignatureAlgCount,
		t.SupportedGroupCount,
		t.JA3HashEntropy,
		t.JA4HashEntropy,
		t.IsTLS10,
		t.IsTLS11,
		t.IsTLS12,
		t.IsTLS13,
		t.HasALPN,
		t.ALPNProtocolCount,
		t.SupportsHTTP2,
		t.SupportsHTTP3,
		t.SNILength,
		t.SNIEntropy,
		t.SNIHasDigits,
	}
}

// FeatureExtractor extracts ML features from network data
type FeatureExtractor struct {
	// Configuration
	maxPayloadBytes int
	entropyBins     int
}

// NewFeatureExtractor creates a new feature extractor
func NewFeatureExtractor() *FeatureExtractor {
	return &FeatureExtractor{
		maxPayloadBytes: 256,
		entropyBins:     256,
	}
}

// ExtractFlowFeatures extracts features from a Flow
func (fe *FeatureExtractor) ExtractFlowFeatures(flow *models.Flow) *FlowFeatures {
	features := &FlowFeatures{}
	
	// Calculate duration from timestamps
	duration := flow.EndTime.Sub(flow.StartTime).Seconds()
	if duration < 0 {
		duration = 0
	}
	
	// Basic statistics
	features.Duration = float32(duration)
	features.TotalPackets = float32(flow.Packets)
	features.TotalBytes = float32(flow.Bytes)
	
	if features.Duration > 0 {
		features.PacketsPerSec = features.TotalPackets / features.Duration
		features.BytesPerSec = features.TotalBytes / features.Duration
	}
	
	// Protocol indicators (Protocol is uint8, ProtocolName is string)
	switch flow.ProtocolName {
	case "TCP":
		features.IsTCP = 1.0
	case "UDP":
		features.IsUDP = 1.0
	}
	
	// Port features
	features.SrcPortNorm = float32(flow.SrcPort) / 65535.0
	features.DstPortNorm = float32(flow.DstPort) / 65535.0
	features.IsWellKnownPort = boolToFloat32(flow.DstPort < 1024)
	features.IsEphemeralPort = boolToFloat32(flow.SrcPort >= 49152)
	
	// Application protocol detection
	if flow.Metadata.ServerName != "" {
		features.IsHTTPS = 1.0
	}
	
	return features
}

// ExtractPacketFeatures extracts features from a Packet
func (fe *FeatureExtractor) ExtractPacketFeatures(packet *models.Packet) *PacketFeatures {
	features := &PacketFeatures{}
	
	features.Length = float32(packet.Length)
	features.PayloadLength = float32(len(packet.Payload))
	features.HeaderLength = float32(packet.Length) - float32(len(packet.Payload))
	
	// Protocol indicators
	switch packet.Protocol {
	case "TCP":
		features.IsTCP = 1.0
	case "UDP":
		features.IsUDP = 1.0
	case "ICMP":
		features.IsICMP = 1.0
	}
	
	// TCP flags (TCPFlags is uint8 bitmask)
	if packet.TCPFlags != 0 {
		features.SYN = boolToFloat32(packet.TCPFlags&0x02 != 0) // SYN
		features.ACK = boolToFloat32(packet.TCPFlags&0x10 != 0) // ACK
		features.FIN = boolToFloat32(packet.TCPFlags&0x01 != 0) // FIN
		features.RST = boolToFloat32(packet.TCPFlags&0x04 != 0) // RST
		features.PSH = boolToFloat32(packet.TCPFlags&0x08 != 0) // PSH
		features.URG = boolToFloat32(packet.TCPFlags&0x20 != 0) // URG
	}
	
	// Port features (normalized)
	features.SrcPort = float32(packet.SrcPort) / 65535.0
	features.DstPort = float32(packet.DstPort) / 65535.0
	
	// Payload features
	if len(packet.Payload) > 0 {
		features.PayloadEntropy = fe.calculateEntropy(packet.Payload)
		mean, std := fe.calculateByteStats(packet.Payload[:min(fe.maxPayloadBytes, len(packet.Payload))])
		features.FirstBytesMean = mean
		features.FirstBytesStd = std
	}
	
	return features
}

// ExtractDNSFeatures extracts features from a DNS query domain
func (fe *FeatureExtractor) ExtractDNSFeatures(domain string, queryType uint16) *DNSFeatures {
	features := &DNSFeatures{}
	
	if domain == "" {
		return features
	}
	
	// Domain length
	features.DomainLength = float32(len(domain))
	
	// Parse labels
	labels := splitDomain(domain)
	features.SubdomainCount = float32(len(labels) - 1) // Exclude TLD
	
	if len(labels) > 0 {
		maxLen := 0
		totalLen := 0
		for _, label := range labels {
			if len(label) > maxLen {
				maxLen = len(label)
			}
			totalLen += len(label)
		}
		features.MaxLabelLength = float32(maxLen)
		features.AvgLabelLength = float32(totalLen) / float32(len(labels))
	}
	
	// Character distribution
	var numeric, alpha, special, consonant, vowel int
	vowels := "aeiouAEIOU"
	for _, c := range domain {
		if c >= '0' && c <= '9' {
			numeric++
		} else if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			alpha++
			if containsRune(vowels, c) {
				vowel++
			} else {
				consonant++
			}
		} else if c != '.' {
			special++
		}
	}
	
	total := float32(len(domain))
	if total > 0 {
		features.NumericRatio = float32(numeric) / total
		features.AlphaRatio = float32(alpha) / total
		features.SpecialRatio = float32(special) / total
		features.ConsonantRatio = float32(consonant) / total
		features.VowelRatio = float32(vowel) / total
	}
	
	// Entropy
	features.DomainEntropy = fe.calculateStringEntropy(domain)
	
	// Label entropy (average)
	if len(labels) > 0 {
		var totalEntropy float32
		for _, label := range labels {
			totalEntropy += fe.calculateStringEntropy(label)
		}
		features.LabelEntropy = totalEntropy / float32(len(labels))
	}
	
	// N-gram entropy
	features.BigramEntropy = fe.calculateNgramEntropy(domain, 2)
	features.TrigramEntropy = fe.calculateNgramEntropy(domain, 3)
	
	// Query type (normalized)
	features.QueryType = float32(queryType) / 255.0
	
	// Reverse lookup detection
	features.IsReverseLookup = boolToFloat32(isReverseDNS(domain))
	
	// Character presence
	features.HasDigits = boolToFloat32(numeric > 0)
	features.HasHyphens = boolToFloat32(containsRune(domain, '-'))
	
	// TLD features
	if len(labels) > 0 {
		tld := labels[len(labels)-1]
		features.TLDLength = float32(len(tld))
		features.IsCommonTLD = boolToFloat32(isCommonTLD(tld))
	}
	
	return features
}

// calculateEntropy calculates Shannon entropy of byte data
func (fe *FeatureExtractor) calculateEntropy(data []byte) float32 {
	if len(data) == 0 {
		return 0
	}
	
	// Count byte frequencies
	freq := make([]int, 256)
	for _, b := range data {
		freq[b]++
	}
	
	// Calculate entropy
	var entropy float64
	total := float64(len(data))
	for _, count := range freq {
		if count > 0 {
			p := float64(count) / total
			entropy -= p * math.Log2(p)
		}
	}
	
	return float32(entropy)
}

// calculateStringEntropy calculates Shannon entropy of a string
func (fe *FeatureExtractor) calculateStringEntropy(s string) float32 {
	if len(s) == 0 {
		return 0
	}
	
	// Count character frequencies
	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}
	
	// Calculate entropy
	var entropy float64
	total := float64(len(s))
	for _, count := range freq {
		p := float64(count) / total
		entropy -= p * math.Log2(p)
	}
	
	return float32(entropy)
}

// calculateNgramEntropy calculates entropy of character n-grams
func (fe *FeatureExtractor) calculateNgramEntropy(s string, n int) float32 {
	if len(s) < n {
		return 0
	}
	
	// Count n-gram frequencies
	freq := make(map[string]int)
	for i := 0; i <= len(s)-n; i++ {
		ngram := s[i : i+n]
		freq[ngram]++
	}
	
	// Calculate entropy
	var entropy float64
	total := float64(len(s) - n + 1)
	for _, count := range freq {
		p := float64(count) / total
		entropy -= p * math.Log2(p)
	}
	
	return float32(entropy)
}

// calculateByteStats calculates mean and standard deviation of byte values
func (fe *FeatureExtractor) calculateByteStats(data []byte) (mean, std float32) {
	if len(data) == 0 {
		return 0, 0
	}
	
	// Calculate mean
	var sum float64
	for _, b := range data {
		sum += float64(b)
	}
	meanVal := sum / float64(len(data))
	
	// Calculate standard deviation
	var variance float64
	for _, b := range data {
		diff := float64(b) - meanVal
		variance += diff * diff
	}
	variance /= float64(len(data))
	
	return float32(meanVal) / 255.0, float32(math.Sqrt(variance)) / 255.0
}

// Helper functions

func boolToFloat32(b bool) float32 {
	if b {
		return 1.0
	}
	return 0.0
}

func containsFlag(flags string, flag string) bool {
	for _, f := range flags {
		if string(f) == flag {
			return true
		}
	}
	return false
}

func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}


func isReverseDNS(domain string) bool {
	labels := splitDomain(domain)
	if len(labels) >= 2 {
		lastTwo := labels[len(labels)-2:]
		return lastTwo[0] == "in-addr" && lastTwo[1] == "arpa"
	}
	return false
}

func isCommonTLD(tld string) bool {
	commonTLDs := map[string]bool{
		"com": true, "org": true, "net": true, "edu": true,
		"gov": true, "mil": true, "int": true, "io": true,
		"co": true, "us": true, "uk": true, "de": true,
		"fr": true, "jp": true, "cn": true, "ru": true,
	}
	return commonTLDs[tld]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Normalize normalizes a slice of float32 values to [0, 1] range
func Normalize(data []float32) []float32 {
	if len(data) == 0 {
		return data
	}
	
	minVal := data[0]
	maxVal := data[0]
	for _, v := range data {
		if v < minVal {
			minVal = v
		}
		if v > maxVal {
			maxVal = v
		}
	}
	
	rangeVal := maxVal - minVal
	if rangeVal == 0 {
		return make([]float32, len(data))
	}
	
	result := make([]float32, len(data))
	for i, v := range data {
		result[i] = (v - minVal) / rangeVal
	}
	return result
}

// Standardize standardizes a slice of float32 values (z-score normalization)
func Standardize(data []float32) []float32 {
	if len(data) == 0 {
		return data
	}
	
	// Calculate mean
	var sum float64
	for _, v := range data {
		sum += float64(v)
	}
	mean := sum / float64(len(data))
	
	// Calculate standard deviation
	var variance float64
	for _, v := range data {
		diff := float64(v) - mean
		variance += diff * diff
	}
	variance /= float64(len(data))
	std := math.Sqrt(variance)
	
	if std == 0 {
		return make([]float32, len(data))
	}
	
	result := make([]float32, len(data))
	for i, v := range data {
		result[i] = float32((float64(v) - mean) / std)
	}
	return result
}

// Percentile calculates the p-th percentile of a slice
func Percentile(data []float32, p float64) float32 {
	if len(data) == 0 {
		return 0
	}
	
	sorted := make([]float32, len(data))
	copy(sorted, data)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	
	index := (p / 100.0) * float64(len(sorted)-1)
	lower := int(index)
	upper := lower + 1
	if upper >= len(sorted) {
		return sorted[len(sorted)-1]
	}
	
	weight := float32(index - float64(lower))
	return sorted[lower]*(1-weight) + sorted[upper]*weight
}
