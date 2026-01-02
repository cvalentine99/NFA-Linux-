// Package parser provides HTTP protocol parsing for NFA-Linux.
package parser

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cvalentine99/nfa-linux/internal/models"
)

// HTTPParser parses HTTP/1.x traffic from TCP streams.
type HTTPParser struct {
	// Callbacks
	onRequest     func(*HTTPRequest)
	onResponse    func(*HTTPResponse)
	onCredential  func(*models.Credential)
	onFile        func(*HTTPFile)

	// State
	buffer        bytes.Buffer
	pendingReqs   []*HTTPRequest
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

	// Store pending request for response matching
	p.pendingReqs = append(p.pendingReqs, httpReq)

	if p.onRequest != nil {
		p.onRequest(httpReq)
	}

	return httpReq, nil
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

// decompressGzip decompresses gzip-encoded data.
func (p *HTTPParser) decompressGzip(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	return io.ReadAll(io.LimitReader(reader, 100*1024*1024)) // 100MB limit
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
