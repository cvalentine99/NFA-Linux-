# NFA-Linux Testing Strategy

## Executive Summary

This document outlines the comprehensive testing strategy for NFA-Linux, a next-generation network forensics application. The strategy encompasses unit testing, integration testing, performance benchmarking, and continuous profiling to ensure reliability, correctness, and high performance under demanding network capture scenarios.

## Testing Philosophy

### Core Principles

1. **Forensic Accuracy First**: All tests must verify that data integrity is maintained throughout the capture and analysis pipeline
2. **Performance Under Load**: Tests must validate behavior at 10Gbps+ capture rates
3. **Memory Safety**: Continuous monitoring for memory leaks and buffer overflows
4. **Deterministic Results**: Tests must produce reproducible results for forensic validation

### Test Pyramid

```
                    ╱╲
                   ╱  ╲
                  ╱ E2E╲
                 ╱──────╲
                ╱        ╲
               ╱Integration╲
              ╱────────────╲
             ╱              ╲
            ╱   Unit Tests   ╲
           ╱──────────────────╲
```

| Layer | Coverage Target | Execution Time |
|-------|-----------------|----------------|
| Unit Tests | 80%+ | < 5 minutes |
| Integration Tests | Critical paths | < 15 minutes |
| E2E Tests | User workflows | < 30 minutes |

---

## Unit Testing

### Coverage Requirements

| Package | Minimum Coverage | Critical Functions |
|---------|------------------|-------------------|
| `internal/capture` | 85% | AF_XDP, AF_PACKET, PCAP engines |
| `internal/parser` | 90% | DNS, HTTP, TLS, QUIC, SMB parsers |
| `internal/reassembly` | 85% | TCP reassembly, memory limits |
| `internal/carver` | 80% | Magic byte detection, file extraction |
| `internal/integrity` | 95% | BLAKE3, Merkle trees, timestamps |
| `internal/evidence` | 90% | CASE/UCO serialization |
| `internal/ml` | 75% | Anomaly detection, classification |

### Test File Organization

```
nfa-linux/
├── internal/
│   ├── capture/
│   │   ├── capture.go
│   │   └── capture_test.go          # Unit tests
│   ├── parser/
│   │   ├── dns.go
│   │   ├── dns_test.go
│   │   ├── parser_comprehensive_test.go  # Cross-parser tests
│   │   └── ...
│   └── ...
├── test/
│   ├── integration/
│   │   └── integration_test.go      # Integration tests
│   ├── benchmark/
│   │   └── benchmark_test.go        # Performance benchmarks
│   ├── fixtures/
│   │   └── fixtures.go              # Test data generators
│   └── mocks/
│       └── mocks.go                 # Mock implementations
```

### Running Unit Tests

```bash
# Run all unit tests
go test ./internal/... -v

# Run with coverage
go test ./internal/... -coverprofile=coverage.out
go tool cover -html=coverage.out -o coverage.html

# Run specific package tests
go test ./internal/parser/... -v

# Run with race detector
go test ./internal/... -race

# Run short tests only (skip long-running tests)
go test ./internal/... -short
```

---

## Integration Testing

### Test Scenarios

#### 1. Packet Capture Pipeline
```go
// Test: Full capture pipeline from raw packets to parsed flows
func TestCaptureToFlowPipeline(t *testing.T)
```
- Validates packet capture → parsing → flow creation
- Verifies timestamp preservation (nanosecond precision)
- Checks protocol detection accuracy

#### 2. File Carving Pipeline
```go
// Test: File extraction from reassembled streams
func TestFileCarving(t *testing.T)
```
- Tests magic byte detection across protocols
- Validates hash computation (BLAKE3, SHA256)
- Verifies MIME type accuracy

#### 3. Evidence Packaging
```go
// Test: CASE/UCO evidence export
func TestEvidenceExport(t *testing.T)
```
- Validates JSON-LD structure
- Tests RFC 3161 timestamp integration
- Verifies chain of custody metadata

#### 4. ML Pipeline
```go
// Test: Anomaly detection and classification
func TestMLPipeline(t *testing.T)
```
- Tests feature extraction
- Validates model inference
- Checks alert generation

### Running Integration Tests

```bash
# Run integration tests
go test ./test/integration/... -v

# Run with timeout
go test ./test/integration/... -timeout 15m

# Run specific integration test
go test ./test/integration/... -run TestCaptureToFlowPipeline
```

---

## Performance Benchmarking

### Benchmark Categories

#### 1. Packet Processing Throughput
```go
func BenchmarkPacketThroughput(b *testing.B)
```
- Measures packets per second
- Tests various packet sizes (64B to 9000B)
- Validates memory allocation patterns

#### 2. Parser Performance
```go
func BenchmarkDNSParser(b *testing.B)
func BenchmarkHTTPParser(b *testing.B)
func BenchmarkTLSParser(b *testing.B)
func BenchmarkQUICParser(b *testing.B)
func BenchmarkSMBParser(b *testing.B)
```
- Measures parsing latency
- Tests with realistic payloads
- Validates zero-allocation parsing

#### 3. Hashing Performance
```go
func BenchmarkBLAKE3Hashing(b *testing.B)
func BenchmarkMerkleTreeCreation(b *testing.B)
```
- Measures hash throughput (GB/s)
- Tests various data sizes
- Validates Merkle proof generation

#### 4. Concurrency Performance
```go
func BenchmarkWorkerPoolThroughput(b *testing.B)
func BenchmarkAtomicOperations(b *testing.B)
func BenchmarkChannelThroughput(b *testing.B)
```
- Measures parallel processing efficiency
- Tests lock contention
- Validates channel throughput

### Performance Targets

| Metric | Target | Measurement |
|--------|--------|-------------|
| Packet capture rate | 10 Gbps | Sustained throughput |
| Packet parsing latency | < 1 μs | P99 latency |
| DNS parsing | > 5M queries/sec | Single core |
| TLS fingerprinting | > 2M/sec | JA3/JA4 computation |
| BLAKE3 hashing | > 10 GB/s | Large files |
| Memory per flow | < 2 KB | Average |
| GC pause time | < 1 ms | P99 |

### Running Benchmarks

```bash
# Run all benchmarks
go test ./test/benchmark/... -bench=. -benchmem

# Run specific benchmark
go test ./test/benchmark/... -bench=BenchmarkPacketThroughput -benchmem

# Run with CPU profiling
go test ./test/benchmark/... -bench=. -cpuprofile=cpu.prof

# Run with memory profiling
go test ./test/benchmark/... -bench=. -memprofile=mem.prof

# Analyze profiles
go tool pprof cpu.prof
go tool pprof mem.prof
```

---

## Profiling Infrastructure

### Runtime Profiling

The `internal/profiling` package provides comprehensive runtime profiling:

```go
import "github.com/cvalentine99/nfa-linux/internal/profiling"

// Create profiler
cfg := profiling.DefaultConfig()
cfg.EnableHTTP = true
cfg.HTTPAddr = "localhost:6060"

profiler, _ := profiling.New(cfg)
profiler.Start(ctx)
defer profiler.Stop()
```

### Available Profiles

| Profile | Endpoint | Description |
|---------|----------|-------------|
| CPU | `/debug/pprof/profile` | CPU usage |
| Heap | `/debug/pprof/heap` | Memory allocation |
| Goroutine | `/debug/pprof/goroutine` | Goroutine stacks |
| Block | `/debug/pprof/block` | Blocking operations |
| Mutex | `/debug/pprof/mutex` | Mutex contention |
| Trace | `/debug/pprof/trace` | Execution trace |

### Profiling Commands

```bash
# CPU profile (30 seconds)
go tool pprof http://localhost:6060/debug/pprof/profile?seconds=30

# Heap profile
go tool pprof http://localhost:6060/debug/pprof/heap

# Goroutine profile
go tool pprof http://localhost:6060/debug/pprof/goroutine

# Generate flame graph
go tool pprof -http=:8080 cpu.prof
```

---

## Optimization Utilities

### Buffer Pools

```go
import "github.com/cvalentine99/nfa-linux/internal/optimization"

// Create buffer pool
pool := optimization.NewBufferPool(1500)

// Use buffer
buf := pool.Get()
defer pool.Put(buf)

// Check hit rate
fmt.Printf("Pool hit rate: %.2f%%\n", pool.HitRate())
```

### Batch Processing

```go
// Create batch processor
processor := optimization.NewBatchProcessor(
    64,                    // Batch size
    100*time.Millisecond,  // Flush timeout
    func(batch []interface{}) {
        // Process batch
    },
)

// Add items
processor.Add(item)
```

### Object Cache

```go
// Create cache
cache := optimization.NewObjectCache(
    5*time.Minute,  // TTL
    10000,          // Max items
)

// Use cache
cache.Set("key", value)
value, ok := cache.Get("key")
```

---

## Test Fixtures

### Packet Fixtures

```go
import "github.com/cvalentine99/nfa-linux/test/fixtures"

pf := fixtures.NewPacketFixture()

// Generate TCP packet
tcpPkt := pf.TCPPacket("192.168.1.1", "192.168.1.2", 12345, 80, payload)

// Generate UDP packet
udpPkt := pf.UDPPacket("192.168.1.1", "8.8.8.8", 54321, 53, dnsQuery)
```

### Protocol Payloads

```go
// DNS query
dnsPayload := fixtures.DNSQueryPayload("example.com", 1)

// HTTP request
httpPayload := fixtures.HTTPRequestPayload("GET", "/", "example.com", nil)

// TLS ClientHello
tlsPayload := fixtures.TLSClientHelloPayload("example.com", cipherSuites, extensions)

// QUIC Initial
quicPayload := fixtures.QUICInitialPayload(dcid, scid, 0x00000001)
```

### File Fixtures

```go
// PNG file
pngData := fixtures.PNGFileFixture(100, 100)

// PDF file
pdfData := fixtures.PDFFileFixture()

// ZIP file
zipData := fixtures.ZIPFileFixture("test.txt", []byte("content"))
```

---

## Mock Implementations

### Mock Capture Engine

```go
import "github.com/cvalentine99/nfa-linux/test/mocks"

engine := mocks.NewMockCaptureEngine()
engine.SetPackets(testPackets)
engine.SetDelay(time.Millisecond)

engine.Start(ctx)
defer engine.Stop()
```

### Mock Event Emitter

```go
emitter := mocks.NewMockEventEmitter()
emitter.On("packet", func(data interface{}) {
    // Handle event
})

emitter.Emit("packet", packetData)
events := emitter.GetEvents("packet")
```

### Mock Flow Store

```go
store := mocks.NewMockFlowStore()
store.Add(flow)

flow, ok := store.Get(flowID)
allFlows := store.GetAll()
```

---

## Continuous Integration

### CI Pipeline

```yaml
# .github/workflows/test.yml
name: Test

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.22'
      
      - name: Install dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y libpcap-dev
      
      - name: Run unit tests
        run: go test ./internal/... -v -race -coverprofile=coverage.out
      
      - name: Run integration tests
        run: go test ./test/integration/... -v -timeout 15m
      
      - name: Run benchmarks
        run: go test ./test/benchmark/... -bench=. -benchmem -run=^$
      
      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./coverage.out
```

### Pre-commit Hooks

```bash
#!/bin/bash
# .git/hooks/pre-commit

# Run tests
go test ./internal/... -short
if [ $? -ne 0 ]; then
    echo "Tests failed"
    exit 1
fi

# Run linter
golangci-lint run
if [ $? -ne 0 ]; then
    echo "Linting failed"
    exit 1
fi
```

---

## Test Data Management

### PCAP Test Files

Test PCAP files should be stored in `test/data/pcap/`:

| File | Description | Size |
|------|-------------|------|
| `http_simple.pcap` | Basic HTTP traffic | ~1 MB |
| `tls_handshake.pcap` | TLS 1.3 handshakes | ~500 KB |
| `dns_queries.pcap` | DNS query/response | ~200 KB |
| `smb_session.pcap` | SMB2/3 file transfer | ~5 MB |
| `quic_traffic.pcap` | QUIC/HTTP3 traffic | ~2 MB |
| `mixed_protocols.pcap` | Mixed traffic | ~10 MB |

### Generating Test Data

```bash
# Generate synthetic PCAP
tcpreplay --intf1=lo --pps=10000 test.pcap

# Capture live traffic
tcpdump -i eth0 -w capture.pcap -c 10000
```

---

## Appendix: Test Commands Reference

```bash
# Full test suite
make test

# Unit tests only
make test-unit

# Integration tests only
make test-integration

# Benchmarks only
make benchmark

# Coverage report
make coverage

# Profile analysis
make profile

# Race detection
make test-race
```

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-01-02 | Initial testing strategy |
