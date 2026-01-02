package parser

import (
	"net"
	"testing"
	"time"

	"github.com/cvalentine99/nfa-linux/internal/models"
)

func TestDNSParserCreation(t *testing.T) {
	parser := NewDNSParser()
	if parser == nil {
		t.Fatal("expected non-nil parser")
	}
}

func TestDNSParserHandler(t *testing.T) {
	parser := NewDNSParser()

	handlerCalled := false
	parser.SetRecordHandler(func(record *models.DNSRecord) {
		handlerCalled = true
	})

	// Handler should be set but not called yet
	if handlerCalled {
		t.Error("handler should not be called before parsing")
	}
}

func TestDNSCache(t *testing.T) {
	cache := NewDNSCache(5 * time.Minute)

	record := &models.DNSRecord{
		QueryName:     "example.com",
		QueryType:     "A",
		ResponseCode:  "NOERROR",
		Answers:       []string{"93.184.216.34"},
		TTL:           300,
		ClientIP:      net.ParseIP("192.168.1.1"),
		ServerIP:      net.ParseIP("8.8.8.8"),
		TimestampNano: time.Now().UnixNano(),
	}

	cache.Add(record)

	// Test lookup
	found := cache.Lookup("example.com", "A")
	if found == nil {
		t.Fatal("expected to find record in cache")
	}

	if found.QueryName != "example.com" {
		t.Errorf("expected query name 'example.com', got '%s'", found.QueryName)
	}

	// Test reverse lookup
	hostname := cache.ReverseLookup(net.ParseIP("93.184.216.34"))
	if hostname != "example.com" {
		t.Errorf("expected hostname 'example.com', got '%s'", hostname)
	}

	// Test lookup miss
	notFound := cache.Lookup("notfound.com", "A")
	if notFound != nil {
		t.Error("expected nil for non-existent record")
	}
}

func TestDNSCacheCleanup(t *testing.T) {
	cache := NewDNSCache(1 * time.Millisecond)

	record := &models.DNSRecord{
		QueryName:     "example.com",
		QueryType:     "A",
		ResponseCode:  "NOERROR",
		TimestampNano: time.Now().UnixNano(),
	}

	cache.Add(record)

	// Wait for expiration
	time.Sleep(5 * time.Millisecond)

	// Cleanup should remove expired entries
	cache.Cleanup()

	found := cache.Lookup("example.com", "A")
	if found != nil {
		t.Error("expected expired record to be removed")
	}
}

func TestHTTPParserCreation(t *testing.T) {
	parser := NewHTTPParser()
	if parser == nil {
		t.Fatal("expected non-nil parser")
	}
}

func TestHTTPParserHandlers(t *testing.T) {
	parser := NewHTTPParser()

	requestHandlerCalled := false
	responseHandlerCalled := false
	credentialHandlerCalled := false
	fileHandlerCalled := false

	parser.SetRequestHandler(func(req *HTTPRequest) {
		requestHandlerCalled = true
	})

	parser.SetResponseHandler(func(resp *HTTPResponse) {
		responseHandlerCalled = true
	})

	parser.SetCredentialHandler(func(cred *models.Credential) {
		credentialHandlerCalled = true
	})

	parser.SetFileHandler(func(file *HTTPFile) {
		fileHandlerCalled = true
	})

	// Handlers should be set but not called yet
	if requestHandlerCalled || responseHandlerCalled || credentialHandlerCalled || fileHandlerCalled {
		t.Error("handlers should not be called before parsing")
	}
}

func TestHTTPParseRequest(t *testing.T) {
	parser := NewHTTPParser()

	requestData := []byte("GET /index.html HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"User-Agent: TestAgent/1.0\r\n" +
		"Accept: */*\r\n" +
		"\r\n")

	req, err := parser.ParseRequest(requestData, time.Now().UnixNano())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if req.Method != "GET" {
		t.Errorf("expected method GET, got %s", req.Method)
	}

	if req.URL.Path != "/index.html" {
		t.Errorf("expected path /index.html, got %s", req.URL.Path)
	}

	if req.Host != "example.com" {
		t.Errorf("expected host example.com, got %s", req.Host)
	}

	if req.UserAgent != "TestAgent/1.0" {
		t.Errorf("expected user agent TestAgent/1.0, got %s", req.UserAgent)
	}
}

func TestHTTPParseResponse(t *testing.T) {
	parser := NewHTTPParser()

	responseData := []byte("HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/html\r\n" +
		"Content-Length: 13\r\n" +
		"\r\n" +
		"Hello, World!")

	resp, err := parser.ParseResponse(responseData, time.Now().UnixNano())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("expected status code 200, got %d", resp.StatusCode)
	}

	if resp.ContentType != "text/html" {
		t.Errorf("expected content type text/html, got %s", resp.ContentType)
	}

	if string(resp.Body) != "Hello, World!" {
		t.Errorf("expected body 'Hello, World!', got '%s'", string(resp.Body))
	}
}

func TestIsHTTPRequest(t *testing.T) {
	tests := []struct {
		data     []byte
		expected bool
	}{
		{[]byte("GET /"), true},
		{[]byte("POST /"), true},
		{[]byte("PUT /"), true},
		{[]byte("HEAD /"), true},
		{[]byte("DELETE /"), true},
		{[]byte("OPTIONS /"), true},
		{[]byte("PATCH /"), true},
		{[]byte("CONNECT /"), true},
		{[]byte("HTTP/1.1"), false},
		{[]byte("random data"), false},
		{[]byte("GE"), false},
	}

	for _, test := range tests {
		result := IsHTTPRequest(test.data)
		if result != test.expected {
			t.Errorf("IsHTTPRequest(%q) = %v, expected %v", test.data, result, test.expected)
		}
	}
}

func TestIsHTTPResponse(t *testing.T) {
	tests := []struct {
		data     []byte
		expected bool
	}{
		{[]byte("HTTP/1.1 200 OK"), true},
		{[]byte("HTTP/1.0 404 Not Found"), true},
		{[]byte("GET /"), false},
		{[]byte("random data"), false},
		{[]byte("HTTP"), false},
	}

	for _, test := range tests {
		result := IsHTTPResponse(test.data)
		if result != test.expected {
			t.Errorf("IsHTTPResponse(%q) = %v, expected %v", test.data, result, test.expected)
		}
	}
}

func TestTLSParserCreation(t *testing.T) {
	parser := NewTLSParser()
	if parser == nil {
		t.Fatal("expected non-nil parser")
	}
}

func TestTLSParserHandlers(t *testing.T) {
	parser := NewTLSParser()

	clientHelloHandlerCalled := false
	serverHelloHandlerCalled := false

	parser.SetClientHelloHandler(func(ch *TLSClientHello) {
		clientHelloHandlerCalled = true
	})

	parser.SetServerHelloHandler(func(sh *TLSServerHello) {
		serverHelloHandlerCalled = true
	})

	// Handlers should be set but not called yet
	if clientHelloHandlerCalled || serverHelloHandlerCalled {
		t.Error("handlers should not be called before parsing")
	}
}

func TestGetTLSVersionString(t *testing.T) {
	tests := []struct {
		version  uint16
		expected string
	}{
		{0x0300, "SSL 3.0"},
		{0x0301, "TLS 1.0"},
		{0x0302, "TLS 1.1"},
		{0x0303, "TLS 1.2"},
		{0x0304, "TLS 1.3"},
		{0x0305, "Unknown (0x0305)"},
	}

	for _, test := range tests {
		result := GetTLSVersionString(test.version)
		if result != test.expected {
			t.Errorf("GetTLSVersionString(0x%04x) = %s, expected %s", test.version, result, test.expected)
		}
	}
}

func TestIsGREASE(t *testing.T) {
	greaseValues := []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}

	for _, v := range greaseValues {
		if !isGREASE(v) {
			t.Errorf("expected 0x%04x to be GREASE", v)
		}
	}

	nonGreaseValues := []uint16{0x0001, 0x0035, 0x009c, 0x1301, 0x1302, 0x1303}

	for _, v := range nonGreaseValues {
		if isGREASE(v) {
			t.Errorf("expected 0x%04x to NOT be GREASE", v)
		}
	}
}

func BenchmarkHTTPParseRequest(b *testing.B) {
	parser := NewHTTPParser()

	requestData := []byte("GET /index.html HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"User-Agent: TestAgent/1.0\r\n" +
		"Accept: */*\r\n" +
		"Accept-Language: en-US,en;q=0.9\r\n" +
		"Accept-Encoding: gzip, deflate\r\n" +
		"Connection: keep-alive\r\n" +
		"\r\n")

	timestamp := time.Now().UnixNano()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parser.ParseRequest(requestData, timestamp)
	}
}

func BenchmarkHTTPParseResponse(b *testing.B) {
	parser := NewHTTPParser()

	responseData := []byte("HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"Content-Length: 1024\r\n" +
		"Server: Apache/2.4\r\n" +
		"Date: Mon, 01 Jan 2024 00:00:00 GMT\r\n" +
		"\r\n" +
		string(make([]byte, 1024)))

	timestamp := time.Now().UnixNano()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parser.ParseResponse(responseData, timestamp)
	}
}
