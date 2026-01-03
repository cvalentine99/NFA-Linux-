// Package ml provides machine learning inference capabilities for network forensics
package ml

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cvalentine99/nfa-linux/internal/models"
)

// TrafficCategory represents a category of network traffic
type TrafficCategory string

const (
	CategoryWeb         TrafficCategory = "web"
	CategoryStreaming   TrafficCategory = "streaming"
	CategoryGaming      TrafficCategory = "gaming"
	CategoryVoIP        TrafficCategory = "voip"
	CategoryFileTransfer TrafficCategory = "file_transfer"
	CategoryEmail       TrafficCategory = "email"
	CategoryDatabase    TrafficCategory = "database"
	CategoryVPN         TrafficCategory = "vpn"
	CategoryMalware     TrafficCategory = "malware"
	CategoryP2P         TrafficCategory = "p2p"
	CategoryIoT         TrafficCategory = "iot"
	CategoryCloud       TrafficCategory = "cloud"
	CategoryUnknown     TrafficCategory = "unknown"
)

// ClassificationResult holds the result of traffic classification
type ClassificationResult struct {
	FlowID         string
	Application    string
	Category       TrafficCategory
	Confidence     float64
	TopPredictions []ClassPrediction
	Method         string
	Timestamp      time.Time
}

// ClassPrediction represents a single class prediction with probability
type ClassPrediction struct {
	Class       string
	Probability float64
}

// TrafficClassifierConfig holds configuration for traffic classification
type TrafficClassifierConfig struct {
	// EnableDPI enables deep packet inspection for classification
	EnableDPI bool
	// EnableML enables ML-based classification
	EnableML bool
	// MinConfidence is the minimum confidence threshold
	MinConfidence float64
	// MaxPayloadBytes is the maximum payload bytes to analyze
	MaxPayloadBytes int
}

// DefaultClassifierConfig returns default classifier configuration
func DefaultClassifierConfig() *TrafficClassifierConfig {
	return &TrafficClassifierConfig{
		EnableDPI:       true,
		EnableML:        true,
		MinConfidence:   0.5,
		MaxPayloadBytes: 1024,
	}
}

// TrafficClassifier classifies network traffic
type TrafficClassifier struct {
	config           *TrafficClassifierConfig
	mu               sync.RWMutex
	onnxEngine       *ONNXEngine
	featureExtractor *FeatureExtractor
	
	// Port-based classification
	portApps map[uint16]string
	
	// Protocol signatures for DPI
	signatures []protocolSignature
	
	// Application to category mapping
	appCategories map[string]TrafficCategory
	
	// Statistics (use atomic for lock-free updates)
	classificationCount atomic.Int64
	totalLatencyNanos   atomic.Int64
}

// protocolSignature defines a signature for protocol detection
type protocolSignature struct {
	Name       string
	Category   TrafficCategory
	Offset     int
	Pattern    []byte
	Mask       []byte // Optional mask for partial matching
	MinLength  int
}

// NewTrafficClassifier creates a new traffic classifier
func NewTrafficClassifier(config *TrafficClassifierConfig) *TrafficClassifier {
	if config == nil {
		config = DefaultClassifierConfig()
	}

	classifier := &TrafficClassifier{
		config:           config,
		featureExtractor: NewFeatureExtractor(),
		portApps:         make(map[uint16]string),
		appCategories:    make(map[string]TrafficCategory),
	}

	classifier.initPortMappings()
	classifier.initSignatures()
	classifier.initCategoryMappings()

	return classifier
}

// initPortMappings initializes well-known port to application mappings
func (c *TrafficClassifier) initPortMappings() {
	c.portApps = map[uint16]string{
		// Web
		80:   "http",
		443:  "https",
		8080: "http_proxy",
		8443: "https_alt",
		
		// Email
		25:   "smtp",
		465:  "smtps",
		587:  "smtp_submission",
		110:  "pop3",
		995:  "pop3s",
		143:  "imap",
		993:  "imaps",
		
		// File Transfer
		20:   "ftp_data",
		21:   "ftp",
		22:   "ssh",
		69:   "tftp",
		115:  "sftp",
		445:  "smb",
		2049: "nfs",
		
		// Database
		1433:  "mssql",
		1521:  "oracle",
		3306:  "mysql",
		5432:  "postgres",
		6379:  "redis",
		27017: "mongodb",
		9042:  "cassandra",
		
		// DNS/Network
		53:   "dns",
		67:   "dhcp_server",
		68:   "dhcp_client",
		123:  "ntp",
		161:  "snmp",
		162:  "snmp_trap",
		
		// VPN
		500:  "ipsec_ike",
		1194: "openvpn",
		1701: "l2tp",
		1723: "pptp",
		4500: "ipsec_nat",
		51820: "wireguard",
		
		// VoIP
		5060: "sip",
		5061: "sips",
		
		// Remote Access
		23:   "telnet",
		3389: "rdp",
		5900: "vnc",
		
		// Messaging
		5222: "xmpp",
		6667: "irc",
		
		// Gaming
		3074:  "xbox_live",
		3478:  "playstation",
		3479:  "playstation",
		3480:  "playstation",
		27015: "steam",
		
		// Streaming
		554:  "rtsp",
		1935: "rtmp",
	}
}

// initSignatures initializes protocol signatures for DPI
func (c *TrafficClassifier) initSignatures() {
	c.signatures = []protocolSignature{
		// HTTP
		{Name: "http_get", Category: CategoryWeb, Offset: 0, Pattern: []byte("GET "), MinLength: 4},
		{Name: "http_post", Category: CategoryWeb, Offset: 0, Pattern: []byte("POST "), MinLength: 5},
		{Name: "http_put", Category: CategoryWeb, Offset: 0, Pattern: []byte("PUT "), MinLength: 4},
		{Name: "http_head", Category: CategoryWeb, Offset: 0, Pattern: []byte("HEAD "), MinLength: 5},
		{Name: "http_response", Category: CategoryWeb, Offset: 0, Pattern: []byte("HTTP/"), MinLength: 5},
		
		// TLS/SSL
		{Name: "tls_handshake", Category: CategoryWeb, Offset: 0, Pattern: []byte{0x16, 0x03}, MinLength: 2},
		
		// SSH
		{Name: "ssh", Category: CategoryFileTransfer, Offset: 0, Pattern: []byte("SSH-"), MinLength: 4},
		
		// DNS
		{Name: "dns_query", Category: CategoryWeb, Offset: 2, Pattern: []byte{0x01, 0x00}, MinLength: 12},
		
		// SMTP
		{Name: "smtp_ehlo", Category: CategoryEmail, Offset: 0, Pattern: []byte("EHLO "), MinLength: 5},
		{Name: "smtp_helo", Category: CategoryEmail, Offset: 0, Pattern: []byte("HELO "), MinLength: 5},
		{Name: "smtp_mail", Category: CategoryEmail, Offset: 0, Pattern: []byte("MAIL FROM:"), MinLength: 10},
		{Name: "smtp_220", Category: CategoryEmail, Offset: 0, Pattern: []byte("220 "), MinLength: 4},
		
		// FTP
		{Name: "ftp_user", Category: CategoryFileTransfer, Offset: 0, Pattern: []byte("USER "), MinLength: 5},
		{Name: "ftp_220", Category: CategoryFileTransfer, Offset: 0, Pattern: []byte("220 "), MinLength: 4},
		
		// SMB
		{Name: "smb2", Category: CategoryFileTransfer, Offset: 0, Pattern: []byte{0xFE, 'S', 'M', 'B'}, MinLength: 4},
		{Name: "smb1", Category: CategoryFileTransfer, Offset: 0, Pattern: []byte{0xFF, 'S', 'M', 'B'}, MinLength: 4},
		
		// MySQL
		{Name: "mysql", Category: CategoryDatabase, Offset: 4, Pattern: []byte{0x0a}, MinLength: 5},
		
		// Redis
		{Name: "redis_ping", Category: CategoryDatabase, Offset: 0, Pattern: []byte("*1\r\n$4\r\nPING"), MinLength: 14},
		{Name: "redis_cmd", Category: CategoryDatabase, Offset: 0, Pattern: []byte("*"), MinLength: 1},
		
		// BitTorrent
		{Name: "bittorrent", Category: CategoryP2P, Offset: 0, Pattern: []byte{0x13, 'B', 'i', 't', 'T', 'o', 'r', 'r', 'e', 'n', 't'}, MinLength: 11},
		
		// RTMP (Streaming)
		{Name: "rtmp", Category: CategoryStreaming, Offset: 0, Pattern: []byte{0x03}, MinLength: 1},
		
		// SIP
		{Name: "sip_invite", Category: CategoryVoIP, Offset: 0, Pattern: []byte("INVITE "), MinLength: 7},
		{Name: "sip_register", Category: CategoryVoIP, Offset: 0, Pattern: []byte("REGISTER "), MinLength: 9},
		{Name: "sip_200", Category: CategoryVoIP, Offset: 0, Pattern: []byte("SIP/2.0 200"), MinLength: 11},
		
		// RTP (VoIP)
		{Name: "rtp", Category: CategoryVoIP, Offset: 0, Pattern: []byte{0x80}, MinLength: 12},
		
		// QUIC
		{Name: "quic_initial", Category: CategoryWeb, Offset: 0, Pattern: []byte{0xc0}, MinLength: 1},
	}
}

// initCategoryMappings initializes application to category mappings
func (c *TrafficClassifier) initCategoryMappings() {
	c.appCategories = map[string]TrafficCategory{
		// Web
		"http": CategoryWeb, "https": CategoryWeb, "http_proxy": CategoryWeb,
		"https_alt": CategoryWeb, "dns": CategoryWeb, "quic": CategoryWeb,
		
		// Email
		"smtp": CategoryEmail, "smtps": CategoryEmail, "smtp_submission": CategoryEmail,
		"pop3": CategoryEmail, "pop3s": CategoryEmail, "imap": CategoryEmail, "imaps": CategoryEmail,
		
		// File Transfer
		"ftp": CategoryFileTransfer, "ftp_data": CategoryFileTransfer, "sftp": CategoryFileTransfer,
		"ssh": CategoryFileTransfer, "tftp": CategoryFileTransfer, "smb": CategoryFileTransfer,
		"nfs": CategoryFileTransfer, "scp": CategoryFileTransfer,
		
		// Database
		"mysql": CategoryDatabase, "postgres": CategoryDatabase, "mssql": CategoryDatabase,
		"oracle": CategoryDatabase, "mongodb": CategoryDatabase, "redis": CategoryDatabase,
		"cassandra": CategoryDatabase, "elasticsearch": CategoryDatabase,
		
		// VPN
		"openvpn": CategoryVPN, "wireguard": CategoryVPN, "ipsec_ike": CategoryVPN,
		"ipsec_nat": CategoryVPN, "l2tp": CategoryVPN, "pptp": CategoryVPN,
		
		// VoIP
		"sip": CategoryVoIP, "sips": CategoryVoIP, "rtp": CategoryVoIP,
		"rtcp": CategoryVoIP, "h323": CategoryVoIP,
		
		// Streaming
		"rtsp": CategoryStreaming, "rtmp": CategoryStreaming, "hls": CategoryStreaming,
		"dash": CategoryStreaming,
		
		// Gaming
		"xbox_live": CategoryGaming, "playstation": CategoryGaming, "steam": CategoryGaming,
		"discord": CategoryGaming,
		
		// P2P
		"bittorrent": CategoryP2P, "ed2k": CategoryP2P,
		
		// Cloud
		"aws": CategoryCloud, "azure": CategoryCloud, "gcp": CategoryCloud,
		"s3": CategoryCloud, "cloudflare": CategoryCloud,
	}
}

// SetONNXEngine sets the ONNX engine for ML-based classification
func (c *TrafficClassifier) SetONNXEngine(engine *ONNXEngine) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onnxEngine = engine
}

// Classify classifies a network flow
func (c *TrafficClassifier) Classify(ctx context.Context, flow *models.Flow) (*ClassificationResult, error) {
	start := time.Now()
	defer func() {
		// Use atomic operations for lock-free statistics updates
		c.classificationCount.Add(1)
		c.totalLatencyNanos.Add(time.Since(start).Nanoseconds())
	}()

	result := &ClassificationResult{
		FlowID:    flow.ID,
		Timestamp: time.Now(),
	}

	// Try port-based classification first
	if app, ok := c.classifyByPort(flow.DstPort); ok {
		result.Application = app
		result.Category = c.getCategory(app)
		result.Confidence = 0.7
		result.Method = "port"
		return result, nil
	}

	// Try DPI if enabled and we have payload
	if c.config.EnableDPI && len(flow.Metadata.ServerName) > 0 {
		if app, category, conf := c.classifyByDPI([]byte(flow.Metadata.ServerName)); conf > 0 {
			result.Application = app
			result.Category = category
			result.Confidence = conf
			result.Method = "dpi"
			return result, nil
		}
	}

	// Try ML-based classification if enabled
	if c.config.EnableML && c.onnxEngine != nil {
		if mlResult, err := c.classifyByML(ctx, flow); err == nil && mlResult.Confidence >= c.config.MinConfidence {
			return mlResult, nil
		}
	}

	// Heuristic-based classification
	result = c.classifyByHeuristics(flow)
	return result, nil
}

// classifyByPort classifies traffic based on destination port
func (c *TrafficClassifier) classifyByPort(port uint16) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	app, ok := c.portApps[port]
	return app, ok
}

// classifyByDPI classifies traffic using deep packet inspection
func (c *TrafficClassifier) classifyByDPI(payload []byte) (string, TrafficCategory, float64) {
	if len(payload) == 0 {
		return "", CategoryUnknown, 0
	}

	for _, sig := range c.signatures {
		if len(payload) < sig.MinLength {
			continue
		}

		if sig.Offset+len(sig.Pattern) > len(payload) {
			continue
		}

		// Check pattern match
		match := true
		for i, b := range sig.Pattern {
			if sig.Mask != nil && i < len(sig.Mask) {
				if payload[sig.Offset+i]&sig.Mask[i] != b&sig.Mask[i] {
					match = false
					break
				}
			} else {
				if payload[sig.Offset+i] != b {
					match = false
					break
				}
			}
		}

		if match {
			return sig.Name, sig.Category, 0.9
		}
	}

	return "", CategoryUnknown, 0
}

// classifyByML classifies traffic using ML model
func (c *TrafficClassifier) classifyByML(ctx context.Context, flow *models.Flow) (*ClassificationResult, error) {
	c.mu.RLock()
	engine := c.onnxEngine
	c.mu.RUnlock()

	if engine == nil {
		return nil, fmt.Errorf("ONNX engine not initialized")
	}

	// Extract features
	features := c.featureExtractor.ExtractFlowFeatures(flow)
	featureSlice := features.ToSlice()

	// Run inference
	output, err := engine.Predict(ctx, featureSlice)
	if err != nil {
		return nil, fmt.Errorf("inference failed: %w", err)
	}

	// Parse output
	result := &ClassificationResult{
		FlowID:    flow.ID,
		Method:    "ml",
		Timestamp: time.Now(),
	}

	// Find top predictions
	type indexedProb struct {
		index int
		prob  float64
	}
	probs := make([]indexedProb, len(output))
	for i, p := range output {
		probs[i] = indexedProb{index: i, prob: float64(p)}
	}
	sort.Slice(probs, func(i, j int) bool {
		return probs[i].prob > probs[j].prob
	})

	// Get class labels (would come from model metadata)
	classLabels := []string{
		"web", "streaming", "gaming", "voip", "file_transfer",
		"email", "database", "vpn", "malware", "p2p", "unknown",
	}

	if len(probs) > 0 && probs[0].index < len(classLabels) {
		result.Application = classLabels[probs[0].index]
		result.Category = TrafficCategory(classLabels[probs[0].index])
		result.Confidence = probs[0].prob
	}

	// Top 3 predictions
	for i := 0; i < 3 && i < len(probs); i++ {
		if probs[i].index < len(classLabels) {
			result.TopPredictions = append(result.TopPredictions, ClassPrediction{
				Class:       classLabels[probs[i].index],
				Probability: probs[i].prob,
			})
		}
	}

	return result, nil
}

// classifyByHeuristics classifies traffic using heuristics
func (c *TrafficClassifier) classifyByHeuristics(flow *models.Flow) *ClassificationResult {
	result := &ClassificationResult{
		FlowID:    flow.ID,
		Method:    "heuristic",
		Timestamp: time.Now(),
	}

	// Check for encrypted traffic
	if flow.Metadata.JA3 != "" || flow.Metadata.JA4 != "" {
		result.Application = "tls"
		result.Category = CategoryWeb
		result.Confidence = 0.6
		
		// Check SNI for more specific classification
		if flow.Metadata.ServerName != "" {
			sni := strings.ToLower(flow.Metadata.ServerName)
			
			// Streaming services
			streamingDomains := []string{"netflix", "youtube", "twitch", "spotify", "hulu", "disney"}
			for _, domain := range streamingDomains {
				if strings.Contains(sni, domain) {
					result.Application = domain
					result.Category = CategoryStreaming
					result.Confidence = 0.85
					return result
				}
			}
			
			// Gaming services
			gamingDomains := []string{"steam", "xbox", "playstation", "epicgames", "riot", "blizzard"}
			for _, domain := range gamingDomains {
				if strings.Contains(sni, domain) {
					result.Application = domain
					result.Category = CategoryGaming
					result.Confidence = 0.85
					return result
				}
			}
			
			// Cloud services
			cloudDomains := []string{"amazonaws", "azure", "googleapis", "cloudflare", "akamai"}
			for _, domain := range cloudDomains {
				if strings.Contains(sni, domain) {
					result.Application = domain
					result.Category = CategoryCloud
					result.Confidence = 0.85
					return result
				}
			}
		}
		
		return result
	}

	// Check protocol
	switch flow.ProtocolName {
	case "TCP":
		// High port to high port often indicates P2P
		if flow.SrcPort > 1024 && flow.DstPort > 1024 {
			result.Application = "unknown_tcp"
			result.Category = CategoryUnknown
			result.Confidence = 0.3
		}
	case "UDP":
		// Check for common UDP patterns
		if flow.DstPort >= 16384 && flow.DstPort <= 32767 {
			result.Application = "rtp"
			result.Category = CategoryVoIP
			result.Confidence = 0.5
		} else if flow.DstPort == 3074 || flow.DstPort == 3478 {
			result.Application = "gaming"
			result.Category = CategoryGaming
			result.Confidence = 0.6
		}
	}

	if result.Application == "" {
		result.Application = "unknown"
		result.Category = CategoryUnknown
		result.Confidence = 0.1
	}

	return result
}

// getCategory returns the category for an application
func (c *TrafficClassifier) getCategory(app string) TrafficCategory {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	if cat, ok := c.appCategories[app]; ok {
		return cat
	}
	return CategoryUnknown
}

// GetStatistics returns classification statistics
func (c *TrafficClassifier) GetStatistics() ClassifierStats {
	// Atomic reads - no lock needed
	count := c.classificationCount.Load()
	totalNanos := c.totalLatencyNanos.Load()
	totalLatency := time.Duration(totalNanos)

	var avgLatency time.Duration
	if count > 0 {
		avgLatency = totalLatency / time.Duration(count)
	}

	return ClassifierStats{
		ClassificationCount: count,
		TotalLatency:        totalLatency,
		AverageLatency:      avgLatency,
	}
}

// ClassifierStats holds classifier statistics
type ClassifierStats struct {
	ClassificationCount int64
	TotalLatency        time.Duration
	AverageLatency      time.Duration
}

// ThreatClassifier classifies traffic for potential threats
type ThreatClassifier struct {
	config           *TrafficClassifierConfig
	mu               sync.RWMutex
	featureExtractor *FeatureExtractor
	
	// Known malicious indicators
	maliciousPorts    map[uint16]string
	maliciousPatterns []threatPattern
	
	// C2 detection
	c2Indicators []c2Indicator
}

// threatPattern defines a pattern for threat detection
type threatPattern struct {
	Name        string
	ThreatType  string
	Severity    string
	Pattern     []byte
	Description string
}

// c2Indicator defines indicators for C2 detection
type c2Indicator struct {
	Name        string
	Type        string // beacon, exfiltration, lateral_movement
	Condition   func(*models.Flow) bool
	Description string
}

// NewThreatClassifier creates a new threat classifier
func NewThreatClassifier(config *TrafficClassifierConfig) *ThreatClassifier {
	if config == nil {
		config = DefaultClassifierConfig()
	}

	classifier := &ThreatClassifier{
		config:           config,
		featureExtractor: NewFeatureExtractor(),
		maliciousPorts:   make(map[uint16]string),
	}

	classifier.initMaliciousPorts()
	classifier.initThreatPatterns()
	classifier.initC2Indicators()

	return classifier
}

// initMaliciousPorts initializes known malicious ports
func (c *ThreatClassifier) initMaliciousPorts() {
	c.maliciousPorts = map[uint16]string{
		4444:  "metasploit_default",
		5555:  "android_adb",
		6666:  "irc_backdoor",
		6667:  "irc_backdoor",
		31337: "back_orifice",
		12345: "netbus",
		27374: "subseven",
		1234:  "generic_backdoor",
		9001:  "tor_relay",
		9050:  "tor_socks",
	}
}

// initThreatPatterns initializes threat detection patterns
func (c *ThreatClassifier) initThreatPatterns() {
	c.maliciousPatterns = []threatPattern{
		{
			Name:        "cobalt_strike_beacon",
			ThreatType:  "c2",
			Severity:    "critical",
			Pattern:     []byte{0x00, 0x00, 0xBE, 0xEF},
			Description: "Potential Cobalt Strike beacon",
		},
		{
			Name:        "metasploit_shell",
			ThreatType:  "reverse_shell",
			Severity:    "critical",
			Pattern:     []byte("/bin/sh"),
			Description: "Potential reverse shell command",
		},
		{
			Name:        "powershell_encoded",
			ThreatType:  "malware",
			Severity:    "high",
			Pattern:     []byte("powershell -e"),
			Description: "Encoded PowerShell execution",
		},
	}
}

// initC2Indicators initializes C2 detection indicators
func (c *ThreatClassifier) initC2Indicators() {
	c.c2Indicators = []c2Indicator{
		{
			Name: "periodic_beacon",
			Type: "beacon",
			Condition: func(flow *models.Flow) bool {
				// Check for periodic connections (would need flow history)
				return false
			},
			Description: "Periodic beacon pattern detected",
		},
		{
			Name: "dns_tunneling",
			Type: "exfiltration",
			Condition: func(flow *models.Flow) bool {
				// Check for DNS tunneling indicators
				return flow.DstPort == 53 && flow.ByteCount > 10000
			},
			Description: "Potential DNS tunneling detected",
		},
		{
			Name: "admin_share_access",
			Type: "lateral_movement",
			Condition: func(flow *models.Flow) bool {
				// Check for admin share access
				return flow.DstPort == 445
			},
			Description: "Admin share access detected",
		},
	}
}

// ThreatResult holds the result of threat classification
type ThreatResult struct {
	FlowID      string
	IsThreat    bool
	ThreatType  string
	Severity    string
	Confidence  float64
	Indicators  []string
	Description string
	Timestamp   time.Time
}

// Classify classifies a flow for potential threats
func (c *ThreatClassifier) Classify(ctx context.Context, flow *models.Flow) (*ThreatResult, error) {
	result := &ThreatResult{
		FlowID:    flow.ID,
		Timestamp: time.Now(),
	}

	// Check malicious ports
	if threat, ok := c.maliciousPorts[flow.DstPort]; ok {
		result.IsThreat = true
		result.ThreatType = "suspicious_port"
		result.Severity = "medium"
		result.Confidence = 0.6
		result.Indicators = append(result.Indicators, fmt.Sprintf("port_%d_%s", flow.DstPort, threat))
		result.Description = fmt.Sprintf("Connection to known suspicious port %d (%s)", flow.DstPort, threat)
	}

	// Check C2 indicators
	for _, indicator := range c.c2Indicators {
		if indicator.Condition(flow) {
			result.IsThreat = true
			result.ThreatType = indicator.Type
			result.Severity = "high"
			result.Confidence = 0.7
			result.Indicators = append(result.Indicators, indicator.Name)
			result.Description = indicator.Description
		}
	}

	return result, nil
}
