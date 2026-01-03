// Package privacy provides PII (Personally Identifiable Information) detection
// and redaction capabilities for NFA-Linux forensic data.
package privacy

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"sync"
)

// =============================================================================
// PII Types and Configuration
// =============================================================================

// PIIType represents a type of personally identifiable information.
type PIIType int

const (
	PIITypeUnknown PIIType = iota
	PIITypeEmail
	PIITypePhone
	PIITypeSSN
	PIITypeCreditCard
	PIITypeIPAddress
	PIITypeMACAddress
	PIITypePassword
	PIITypeAPIKey
	PIITypeJWT
	PIITypeName
	PIITypeAddress
)

// PIIMatch represents a detected PII instance.
type PIIMatch struct {
	Type       PIIType
	Value      string
	Redacted   string
	StartIndex int
	EndIndex   int
	Confidence float64
}

// RedactionMode determines how PII is redacted.
type RedactionMode int

const (
	// RedactMask replaces PII with asterisks
	RedactMask RedactionMode = iota
	// RedactHash replaces PII with a SHA-256 hash (preserves uniqueness)
	RedactHash
	// RedactRemove completely removes PII
	RedactRemove
	// RedactTypeLabel replaces PII with type label (e.g., "[EMAIL]")
	RedactTypeLabel
)

// Config holds PII detector configuration.
type Config struct {
	// Enabled types of PII to detect
	EnabledTypes map[PIIType]bool
	
	// Redaction mode
	Mode RedactionMode
	
	// Custom patterns (regex string -> PIIType)
	CustomPatterns map[string]PIIType
	
	// Whitelist patterns that should not be redacted
	Whitelist []string
	
	// Whether to detect PII in binary data
	ScanBinary bool
	
	// Minimum confidence threshold (0.0 - 1.0)
	MinConfidence float64
}

// DefaultConfig returns default PII detection configuration.
func DefaultConfig() *Config {
	return &Config{
		EnabledTypes: map[PIIType]bool{
			PIITypeEmail:      true,
			PIITypePhone:      true,
			PIITypeSSN:        true,
			PIITypeCreditCard: true,
			PIITypeIPAddress:  false, // Often needed for forensics
			PIITypeMACAddress: false,
			PIITypePassword:   true,
			PIITypeAPIKey:     true,
			PIITypeJWT:        true,
		},
		Mode:          RedactMask,
		MinConfidence: 0.7,
	}
}

// =============================================================================
// PII Detector
// =============================================================================

// Detector detects and redacts PII in text and binary data.
type Detector struct {
	config   *Config
	patterns map[PIIType]*regexp.Regexp
	custom   map[*regexp.Regexp]PIIType
	whitelist []*regexp.Regexp
	mu       sync.RWMutex
}

// NewDetector creates a new PII detector.
func NewDetector(cfg *Config) *Detector {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	
	d := &Detector{
		config:   cfg,
		patterns: make(map[PIIType]*regexp.Regexp),
		custom:   make(map[*regexp.Regexp]PIIType),
	}
	
	// Compile built-in patterns
	d.compilePatterns()
	
	// Compile custom patterns
	for pattern, piiType := range cfg.CustomPatterns {
		if re, err := regexp.Compile(pattern); err == nil {
			d.custom[re] = piiType
		}
	}
	
	// Compile whitelist
	for _, pattern := range cfg.Whitelist {
		if re, err := regexp.Compile(pattern); err == nil {
			d.whitelist = append(d.whitelist, re)
		}
	}
	
	return d
}

func (d *Detector) compilePatterns() {
	// Email pattern
	d.patterns[PIITypeEmail] = regexp.MustCompile(
		`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	
	// Phone patterns (US and international)
	d.patterns[PIITypePhone] = regexp.MustCompile(
		`(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}`)
	
	// SSN pattern (US)
	d.patterns[PIITypeSSN] = regexp.MustCompile(
		`\b[0-9]{3}[-\s]?[0-9]{2}[-\s]?[0-9]{4}\b`)
	
	// Credit card patterns (major card types)
	d.patterns[PIITypeCreditCard] = regexp.MustCompile(
		`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b`)
	
	// IPv4 address
	d.patterns[PIITypeIPAddress] = regexp.MustCompile(
		`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)
	
	// MAC address
	d.patterns[PIITypeMACAddress] = regexp.MustCompile(
		`\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b`)
	
	// Password patterns (common formats in logs/configs)
	d.patterns[PIITypePassword] = regexp.MustCompile(
		`(?i)(?:password|passwd|pwd|secret|token)[\s]*[=:]\s*["']?([^\s"']+)["']?`)
	
	// API key patterns (common formats)
	d.patterns[PIITypeAPIKey] = regexp.MustCompile(
		`(?i)(?:api[_-]?key|apikey|api[_-]?secret|access[_-]?token)[\s]*[=:]\s*["']?([a-zA-Z0-9_-]{20,})["']?`)
	
	// JWT pattern
	d.patterns[PIITypeJWT] = regexp.MustCompile(
		`eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*`)
}

// Detect finds all PII in the given text.
func (d *Detector) Detect(text string) []PIIMatch {
	d.mu.RLock()
	defer d.mu.RUnlock()
	
	var matches []PIIMatch
	
	// Check built-in patterns
	for piiType, pattern := range d.patterns {
		if !d.config.EnabledTypes[piiType] {
			continue
		}
		
		for _, loc := range pattern.FindAllStringIndex(text, -1) {
			value := text[loc[0]:loc[1]]
			
			// Check whitelist
			if d.isWhitelisted(value) {
				continue
			}
			
			confidence := d.calculateConfidence(piiType, value)
			if confidence < d.config.MinConfidence {
				continue
			}
			
			matches = append(matches, PIIMatch{
				Type:       piiType,
				Value:      value,
				Redacted:   d.redact(piiType, value),
				StartIndex: loc[0],
				EndIndex:   loc[1],
				Confidence: confidence,
			})
		}
	}
	
	// Check custom patterns
	for pattern, piiType := range d.custom {
		for _, loc := range pattern.FindAllStringIndex(text, -1) {
			value := text[loc[0]:loc[1]]
			
			if d.isWhitelisted(value) {
				continue
			}
			
			matches = append(matches, PIIMatch{
				Type:       piiType,
				Value:      value,
				Redacted:   d.redact(piiType, value),
				StartIndex: loc[0],
				EndIndex:   loc[1],
				Confidence: 0.8, // Custom patterns get fixed confidence
			})
		}
	}
	
	return matches
}

// Redact replaces all detected PII in the text.
func (d *Detector) Redact(text string) string {
	matches := d.Detect(text)
	if len(matches) == 0 {
		return text
	}
	
	// Sort matches by start index (descending) to replace from end
	for i := 0; i < len(matches)-1; i++ {
		for j := i + 1; j < len(matches); j++ {
			if matches[i].StartIndex < matches[j].StartIndex {
				matches[i], matches[j] = matches[j], matches[i]
			}
		}
	}
	
	result := text
	for _, match := range matches {
		result = result[:match.StartIndex] + match.Redacted + result[match.EndIndex:]
	}
	
	return result
}

// RedactBytes redacts PII from byte data.
func (d *Detector) RedactBytes(data []byte) []byte {
	return []byte(d.Redact(string(data)))
}

func (d *Detector) isWhitelisted(value string) bool {
	for _, pattern := range d.whitelist {
		if pattern.MatchString(value) {
			return true
		}
	}
	return false
}

func (d *Detector) calculateConfidence(piiType PIIType, value string) float64 {
	switch piiType {
	case PIITypeEmail:
		// Higher confidence for common domains
		if strings.Contains(value, "@gmail.") || 
		   strings.Contains(value, "@yahoo.") ||
		   strings.Contains(value, "@outlook.") {
			return 0.95
		}
		return 0.85
		
	case PIITypeSSN:
		// Check for valid SSN format (not all zeros, etc.)
		if strings.ReplaceAll(strings.ReplaceAll(value, "-", ""), " ", "") == "000000000" {
			return 0.1
		}
		return 0.9
		
	case PIITypeCreditCard:
		// Luhn algorithm check
		if luhnValid(value) {
			return 0.95
		}
		return 0.5
		
	case PIITypeJWT:
		// JWTs are very distinctive
		return 0.99
		
	case PIITypeAPIKey:
		// API keys have high entropy
		if len(value) >= 32 {
			return 0.9
		}
		return 0.7
		
	default:
		return 0.8
	}
}

func (d *Detector) redact(piiType PIIType, value string) string {
	switch d.config.Mode {
	case RedactMask:
		// Keep first and last character, mask the rest
		if len(value) <= 4 {
			return strings.Repeat("*", len(value))
		}
		return string(value[0]) + strings.Repeat("*", len(value)-2) + string(value[len(value)-1])
		
	case RedactHash:
		hash := sha256.Sum256([]byte(value))
		return "[SHA256:" + hex.EncodeToString(hash[:8]) + "]"
		
	case RedactRemove:
		return ""
		
	case RedactTypeLabel:
		return "[" + piiTypeName(piiType) + "]"
		
	default:
		return strings.Repeat("*", len(value))
	}
}

func piiTypeName(t PIIType) string {
	names := map[PIIType]string{
		PIITypeEmail:      "EMAIL",
		PIITypePhone:      "PHONE",
		PIITypeSSN:        "SSN",
		PIITypeCreditCard: "CREDIT_CARD",
		PIITypeIPAddress:  "IP_ADDRESS",
		PIITypeMACAddress: "MAC_ADDRESS",
		PIITypePassword:   "PASSWORD",
		PIITypeAPIKey:     "API_KEY",
		PIITypeJWT:        "JWT",
		PIITypeName:       "NAME",
		PIITypeAddress:    "ADDRESS",
	}
	if name, ok := names[t]; ok {
		return name
	}
	return "PII"
}

// luhnValid checks if a credit card number passes the Luhn algorithm.
func luhnValid(number string) bool {
	// Remove non-digits
	digits := ""
	for _, c := range number {
		if c >= '0' && c <= '9' {
			digits += string(c)
		}
	}
	
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	
	sum := 0
	alt := false
	
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	
	return sum%10 == 0
}

// =============================================================================
// HTTP Header PII Detection
// =============================================================================

// SensitiveHeaders is a list of HTTP headers that may contain PII.
var SensitiveHeaders = []string{
	"authorization",
	"cookie",
	"set-cookie",
	"x-api-key",
	"x-auth-token",
	"x-access-token",
	"x-forwarded-for",
	"x-real-ip",
	"proxy-authorization",
}

// RedactHeaders redacts sensitive HTTP headers.
func (d *Detector) RedactHeaders(headers map[string]string) map[string]string {
	result := make(map[string]string, len(headers))
	
	for key, value := range headers {
		lowerKey := strings.ToLower(key)
		
		// Check if it's a sensitive header
		isSensitive := false
		for _, sensitive := range SensitiveHeaders {
			if lowerKey == sensitive {
				isSensitive = true
				break
			}
		}
		
		if isSensitive {
			result[key] = d.redact(PIITypeAPIKey, value)
		} else {
			// Still check for PII in the value
			result[key] = d.Redact(value)
		}
	}
	
	return result
}

// =============================================================================
// DNS Query PII Detection
// =============================================================================

// RedactDNSQuery redacts potential PII from DNS queries.
// Some DNS queries may contain user identifiers or tracking data.
func (d *Detector) RedactDNSQuery(query string) string {
	// Check for email-like patterns in DNS queries
	if d.config.EnabledTypes[PIITypeEmail] {
		if d.patterns[PIITypeEmail].MatchString(query) {
			return d.Redact(query)
		}
	}
	
	// Check for UUID-like patterns (often user IDs)
	uuidPattern := regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	if uuidPattern.MatchString(query) {
		return uuidPattern.ReplaceAllString(query, "[UUID]")
	}
	
	return query
}

// =============================================================================
// Credential Detection
// =============================================================================

// CredentialPattern represents a pattern for detecting credentials.
type CredentialPattern struct {
	Name    string
	Pattern *regexp.Regexp
	Type    string
}

// CommonCredentialPatterns contains patterns for common credential formats.
var CommonCredentialPatterns = []CredentialPattern{
	{
		Name:    "AWS Access Key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Type:    "aws_access_key",
	},
	{
		Name:    "AWS Secret Key",
		Pattern: regexp.MustCompile(`(?i)aws_secret_access_key\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?`),
		Type:    "aws_secret_key",
	},
	{
		Name:    "GitHub Token",
		Pattern: regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
		Type:    "github_token",
	},
	{
		Name:    "Slack Token",
		Pattern: regexp.MustCompile(`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}`),
		Type:    "slack_token",
	},
	{
		Name:    "Google API Key",
		Pattern: regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),
		Type:    "google_api_key",
	},
	{
		Name:    "Private Key",
		Pattern: regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
		Type:    "private_key",
	},
}

// DetectCredentials detects potential credentials in text.
func (d *Detector) DetectCredentials(text string) []PIIMatch {
	var matches []PIIMatch
	
	for _, cp := range CommonCredentialPatterns {
		for _, loc := range cp.Pattern.FindAllStringIndex(text, -1) {
			value := text[loc[0]:loc[1]]
			matches = append(matches, PIIMatch{
				Type:       PIITypeAPIKey,
				Value:      value,
				Redacted:   d.redact(PIITypeAPIKey, value),
				StartIndex: loc[0],
				EndIndex:   loc[1],
				Confidence: 0.95,
			})
		}
	}
	
	return matches
}
