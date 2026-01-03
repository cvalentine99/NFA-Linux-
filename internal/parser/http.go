// Package parser provides HTTP protocol parsing for NFA-Linux.
package parser

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cvalentine99/nfa-linux/internal/models"
	"github.com/cvalentine99/nfa-linux/internal/privacy"
)

// BUG-3 FIX: Constants for pending request management
const (
	// MaxPendingHTTPRequests is the maximum number of unmatched requests to keep
	MaxPendingHTTPRequests = 1000
	// PendingRequestTimeout is how long to keep unmatched requests (5 minutes)
	PendingRequestTimeout = 5 * time.Minute
)

// HTTPParser parses HTTP/1.x traffic from TCP streams.
type HTTPParser struct {
	// Callbacks
	onRequest     func(*HTTPRequest)
	onResponse    func(*HTTPResponse)
	onCredential  func(*models.Credential)
	onFile        func(*HTTPFile)
	onPII         func(*PIIFinding) // PII detection callback

	// State
	buffer        bytes.Buffer
	pendingReqs   []*HTTPRequest
	
	// BUG-3 FIX: Track pending request count for memory management
	lastCleanup   time.Time
	
	// PII detection
	piiDetector   *privacy.Detector
	piiEnabled    bool
}

// PIIFinding represents PII detected in HTTP traffic.
type PIIFinding struct {
	Source      string           // "header", "body", "url", "cookie"
	Field       string           // Header name, URL parameter, etc.
	Matches     []privacy.PIIMatch
	Timestamp   int64
}

// HTTPRequest represents a parsed HTTP request.
type HTTPRequest struct {
	Method        string
	URL           *url.URL
	Host          string
	UserAgent     string
	ContentType   string
	ContentLength int64
	Headers       http.Header
	Body          []byte
	TimestampNano int64
	Raw           []byte
}

// HTTPResponse represents a parsed HTTP response.
type HTTPResponse struct {
	StatusCode    int
	Status        string
	ContentType   string
	ContentLength int64
	Headers       http.Header
	Body          []byte
	TimestampNano int64
	Request       *HTTPRequest
	Raw           []byte
}

// HTTPFile represents a file extracted from HTTP traffic.
type HTTPFile struct {
	Filename      string
	ContentType   string
	Data          []byte
	URL           string
	TimestampNano int64
}

// NewHTTPParser creates a new HTTP parser.
func NewHTTPParser() *HTTPParser {
	return &HTTPParser{}
}

// SetRequestHandler sets the callback for HTTP requests.
func (p *HTTPParser) SetRequestHandler(handler func(*HTTPRequest)) {
	p.onRequest = handler
}

// SetResponseHandler sets the callback for HTTP responses.
func (p *HTTPParser) SetResponseHandler(handler func(*HTTPResponse)) {
	p.onResponse = handler
}

// SetPIIHandler sets the callback for PII findings.
func (p *HTTPParser) SetPIIHandler(handler func(*PIIFinding)) {
	p.onPII = handler
}

// EnablePIIDetection enables PII scanning with the given detector.
func (p *HTTPParser) EnablePIIDetection(detector *privacy.Detector) {
	p.piiDetector = detector
	p.piiEnabled = detector != nil
}

// SetCredentialHandler sets the callback for extracted credentials.
func (p *HTTPParser) SetCredentialHandler(handler func(*models.Credential)) {
	p.onCredential = handler
}

// SetFileHandler sets the callback for extracted files.
func (p *HTTPParser) SetFileHandler(handler func(*HTTPFile)) {
	p.onFile = handler
}

// ParseRequest parses an HTTP request from raw data.
func (p *HTTPParser) ParseRequest(data []byte, timestampNano int64) (*HTTPRequest, error) {
	reader := bufio.NewReader(bytes.NewReader(data))
	req, err := http.ReadRequest(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTTP request: %w", err)
	}
	defer req.Body.Close()

	// Read body
	var body []byte
	if req.ContentLength > 0 && req.ContentLength < 10*1024*1024 { // Limit to 10MB
		body, _ = io.ReadAll(io.LimitReader(req.Body, req.ContentLength))
	}

	httpReq := &HTTPRequest{
		Method:        req.Method,
		URL:           req.URL,
		Host:          req.Host,
		UserAgent:     req.UserAgent(),
		ContentType:   req.Header.Get("Content-Type"),
		ContentLength: req.ContentLength,
		Headers:       req.Header,
		Body:          body,
		TimestampNano: timestampNano,
		Raw:           data,
	}

	// Extract credentials from Authorization header
	if auth := req.Header.Get("Authorization"); auth != "" {
		p.extractCredentials(auth, req.URL.String(), timestampNano)
	}

	// BUG-3 FIX: Enforce limit on pending requests to prevent memory leak
	// Clean up old requests periodically
	now := time.Now()
	if now.Sub(p.lastCleanup) > time.Minute {
		p.cleanupOldPendingRequests(now)
		p.lastCleanup = now
	}
	
	// Only store if under limit
	if len(p.pendingReqs) < MaxPendingHTTPRequests {
		p.pendingReqs = append(p.pendingReqs, httpReq)
	} else {
		// Drop oldest request to make room (FIFO eviction)
		p.pendingReqs = append(p.pendingReqs[1:], httpReq)
	}

	// Scan for PII if enabled
	if p.piiEnabled && p.piiDetector != nil {
		p.scanRequestForPII(httpReq)
	}

	if p.onRequest != nil {
		p.onRequest(httpReq)
	}

	return httpReq, nil
}

// scanRequestForPII scans HTTP request for PII.
func (p *HTTPParser) scanRequestForPII(req *HTTPRequest) {
	if p.onPII == nil {
		return
	}

	// Scan URL query parameters
	if req.URL != nil && req.URL.RawQuery != "" {
		matches := p.piiDetector.Detect(req.URL.RawQuery)
		if len(matches) > 0 {
			p.onPII(&PIIFinding{
				Source:    "url",
				Field:     "query",
				Matches:   matches,
				Timestamp: req.TimestampNano,
			})
		}
	}

	// Scan sensitive headers
	sensitiveHeaders := []string{
		"Authorization", "Cookie", "X-Api-Key", "X-Auth-Token",
		"X-Access-Token", "X-Forwarded-For", "X-Real-IP",
	}
	for _, header := range sensitiveHeaders {
		if val := req.Headers.Get(header); val != "" {
			matches := p.piiDetector.Detect(val)
			if len(matches) > 0 {
				p.onPII(&PIIFinding{
					Source:    "header",
					Field:     header,
					Matches:   matches,
					Timestamp: req.TimestampNano,
				})
			}
		}
	}

	// Scan body for PII (only text content types)
	if len(req.Body) > 0 && isTextContentType(req.ContentType) {
		matches := p.piiDetector.Detect(string(req.Body))
		if len(matches) > 0 {
			p.onPII(&PIIFinding{
				Source:    "body",
				Field:     req.ContentType,
				Matches:   matches,
				Timestamp: req.TimestampNano,
			})
		}
	}
}

// isTextContentType checks if content type is text-based.
func isTextContentType(ct string) bool {
	textTypes := []string{
		"text/", "application/json", "application/xml",
		"application/x-www-form-urlencoded", "multipart/form-data",
	}
	for _, t := range textTypes {
		if strings.Contains(ct, t) {
			return true
		}
	}
	return false
}

// cleanupOldPendingRequests removes requests older than PendingRequestTimeout
// BUG-3 FIX: Prevents unbounded growth of pending requests
func (p *HTTPParser) cleanupOldPendingRequests(now time.Time) {
	cutoff := now.Add(-PendingRequestTimeout).UnixNano()
	
	// Find first non-expired request
	firstValid := 0
	for i, req := range p.pendingReqs {
		if req.TimestampNano >= cutoff {
			firstValid = i
			break
		}
		firstValid = i + 1
	}
	
	// Remove expired requests
	if firstValid > 0 {
		p.pendingReqs = p.pendingReqs[firstValid:]
	}
}

// ParseResponse parses an HTTP response from raw data.
func (p *HTTPParser) ParseResponse(data []byte, timestampNano int64) (*HTTPResponse, error) {
	reader := bufio.NewReader(bytes.NewReader(data))
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTTP response: %w", err)
	}
	defer resp.Body.Close()

	// Read body
	var body []byte
	if resp.ContentLength > 0 && resp.ContentLength < 100*1024*1024 { // Limit to 100MB
		body, _ = io.ReadAll(io.LimitReader(resp.Body, resp.ContentLength))
	} else if resp.ContentLength == -1 {
		// Chunked encoding or unknown length
		body, _ = io.ReadAll(io.LimitReader(resp.Body, 100*1024*1024))
	}

	// Decompress if gzipped
	if resp.Header.Get("Content-Encoding") == "gzip" && len(body) > 0 {
		if decompressed, err := p.decompressGzip(body); err == nil {
			body = decompressed
		}
	}

	httpResp := &HTTPResponse{
		StatusCode:    resp.StatusCode,
		Status:        resp.Status,
		ContentType:   resp.Header.Get("Content-Type"),
		ContentLength: resp.ContentLength,
		Headers:       resp.Header,
		Body:          body,
		TimestampNano: timestampNano,
		Raw:           data,
	}

	// Match with pending request
	if len(p.pendingReqs) > 0 {
		httpResp.Request = p.pendingReqs[0]
		p.pendingReqs = p.pendingReqs[1:]
	}

	// Extract file if applicable
	if len(body) > 0 {
		p.extractFile(httpResp)
	}

	if p.onResponse != nil {
		p.onResponse(httpResp)
	}

	return httpResp, nil
}

// extractCredentials extracts credentials from HTTP Authorization header.
func (p *HTTPParser) extractCredentials(auth, urlStr string, timestampNano int64) {
	if p.onCredential == nil {
		return
	}

	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 {
		return
	}

	authType := strings.ToLower(parts[0])
	authData := parts[1]

	switch authType {
	case "basic":
		decoded, err := base64.StdEncoding.DecodeString(authData)
		if err != nil {
			return
		}
		creds := strings.SplitN(string(decoded), ":", 2)
		if len(creds) != 2 {
			return
		}
		p.onCredential(&models.Credential{
			Protocol:      "HTTP-Basic",
			Username:      creds[0],
			Password:      creds[1],
			URL:           urlStr,
			TimestampNano: timestampNano,
		})

	case "digest":
		// Parse digest auth parameters
		params := p.parseDigestAuth(authData)
		if username, ok := params["username"]; ok {
			p.onCredential(&models.Credential{
				Protocol:      "HTTP-Digest",
				Username:      username,
				URL:           urlStr,
				TimestampNano: timestampNano,
			})
		}

	case "bearer":
		// Bearer tokens are sensitive but not credentials per se
		// Log them for analysis
		p.onCredential(&models.Credential{
			Protocol:      "HTTP-Bearer",
			Password:      authData[:min(50, len(authData))] + "...", // Truncate
			URL:           urlStr,
			TimestampNano: timestampNano,
		})
	}
}

// parseDigestAuth parses HTTP Digest authentication parameters.
func (p *HTTPParser) parseDigestAuth(data string) map[string]string {
	params := make(map[string]string)
	for _, part := range strings.Split(data, ",") {
		part = strings.TrimSpace(part)
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			key := strings.TrimSpace(kv[0])
			value := strings.Trim(strings.TrimSpace(kv[1]), "\"")
			params[key] = value
		}
	}
	return params
}

// extractFile extracts a file from an HTTP response.
func (p *HTTPParser) extractFile(resp *HTTPResponse) {
	if p.onFile == nil || len(resp.Body) == 0 {
		return
	}

	// Determine filename
	filename := ""
	if cd := resp.Headers.Get("Content-Disposition"); cd != "" {
		if idx := strings.Index(cd, "filename="); idx != -1 {
			filename = strings.Trim(cd[idx+9:], "\"")
		}
	}

	// If no filename from header, try to get from URL
	if filename == "" && resp.Request != nil && resp.Request.URL != nil {
		path := resp.Request.URL.Path
		if idx := strings.LastIndex(path, "/"); idx != -1 {
			filename = path[idx+1:]
		}
	}

	// Generate filename if still empty
	if filename == "" {
		ext := p.guessExtension(resp.ContentType)
		filename = fmt.Sprintf("file_%d%s", time.Now().UnixNano(), ext)
	}

	urlStr := ""
	if resp.Request != nil && resp.Request.URL != nil {
		urlStr = resp.Request.URL.String()
	}

	p.onFile(&HTTPFile{
		Filename:      filename,
		ContentType:   resp.ContentType,
		Data:          resp.Body,
		URL:           urlStr,
		TimestampNano: resp.TimestampNano,
	})
}

// guessExtension guesses a file extension from content type.
func (p *HTTPParser) guessExtension(contentType string) string {
	contentType = strings.ToLower(strings.Split(contentType, ";")[0])
	
	extensions := map[string]string{
		"text/html":                ".html",
		"text/plain":               ".txt",
		"text/css":                 ".css",
		"text/javascript":          ".js",
		"application/javascript":   ".js",
		"application/json":         ".json",
		"application/xml":          ".xml",
		"application/pdf":          ".pdf",
		"application/zip":          ".zip",
		"application/gzip":         ".gz",
		"application/x-tar":        ".tar",
		"application/octet-stream": ".bin",
		"image/jpeg":               ".jpg",
		"image/png":                ".png",
		"image/gif":                ".gif",
		"image/webp":               ".webp",
		"image/svg+xml":            ".svg",
		"audio/mpeg":               ".mp3",
		"audio/wav":                ".wav",
		"video/mp4":                ".mp4",
		"video/webm":               ".webm",
	}

	if ext, ok := extensions[contentType]; ok {
		return ext
	}
	return ".bin"
}

// SEC-5 FIX: Decompression bomb protection constants
const (
	// MaxDecompressedSize is the maximum allowed decompressed size (10MB)
	MaxDecompressedSize = 10 * 1024 * 1024
	// MaxCompressionRatio is the maximum allowed compression ratio (100:1)
	// Ratios above this indicate a potential decompression bomb
	MaxCompressionRatio = 100
	// DecompressChunkSize is the size of chunks read during decompression
	DecompressChunkSize = 64 * 1024
)

// ErrDecompressionBomb is returned when a decompression bomb is detected
var ErrDecompressionBomb = errors.New("decompression bomb detected: ratio exceeds safe threshold")

// decompressGzip decompresses gzip-encoded data with bomb detection.
// SEC-5 FIX: Implements ratio-based detection to prevent decompression bombs.
func (p *HTTPParser) decompressGzip(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	compressedSize := int64(len(data))
	if compressedSize == 0 {
		return nil, errors.New("empty compressed data")
	}

	// Read in chunks and check ratio progressively
	var result bytes.Buffer
	buf := make([]byte, DecompressChunkSize)
	var totalRead int64

	for {
		n, err := reader.Read(buf)
		if n > 0 {
			totalRead += int64(n)
			
			// Check absolute size limit
			if totalRead > MaxDecompressedSize {
				return nil, fmt.Errorf("decompressed size exceeds limit: %d > %d", totalRead, MaxDecompressedSize)
			}
			
			// Check compression ratio (bomb detection)
			ratio := totalRead / compressedSize
			if ratio > MaxCompressionRatio {
				return nil, ErrDecompressionBomb
			}
			
			result.Write(buf[:n])
		}
		
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("decompression error: %w", err)
		}
	}

	return result.Bytes(), nil
}

// IsHTTPRequest checks if data looks like an HTTP request.
func IsHTTPRequest(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	
	methods := []string{"GET ", "POST", "PUT ", "HEAD", "DELE", "OPTI", "PATC", "CONN", "TRAC"}
	prefix := string(data[:4])
	
	for _, m := range methods {
		if prefix == m {
			return true
		}
	}
	return false
}

// IsHTTPResponse checks if data looks like an HTTP response.
func IsHTTPResponse(data []byte) bool {
	if len(data) < 5 {
		return false
	}
	return string(data[:5]) == "HTTP/"
}

// ExtractUserAgent extracts the User-Agent from HTTP headers.
func ExtractUserAgent(headers http.Header) string {
	return headers.Get("User-Agent")
}

// ExtractHost extracts the Host from HTTP headers.
func ExtractHost(headers http.Header) string {
	return headers.Get("Host")
}

// ParseContentLength parses the Content-Length header.
func ParseContentLength(headers http.Header) int64 {
	cl := headers.Get("Content-Length")
	if cl == "" {
		return -1
	}
	length, err := strconv.ParseInt(cl, 10, 64)
	if err != nil {
		return -1
	}
	return length
}
