# NFA-Linux Security Audit Report

**Application:** NFA-Linux v0.2.1 - Next-Generation Network Forensic Analyzer
**Architecture:** Go + Wails v2 desktop (WebKit) + React frontend + optional Python ML sidecar
**Audit Date:** 2026-02-15
**Scope:** All files in the repository; 8 audit dimensions (A-H)

---

## 1. Executive Summary

NFA-Linux is a desktop-first network forensics tool at **early-beta maturity**. The core packet pipeline (capture, reassembly, carving, evidence export) is architecturally sound with deliberate memory safety controls. The ML subsystem is split between functional Go-native statistical inference and scaffolded gRPC sidecar integration. The Wails desktop bridge is used correctly (no HTTP middleware surface). The codebase shows evidence of prior bug-fix passes (RACE-1, RACE-4, BUG-4, SEC-3 annotations) that have addressed several concurrency and memory issues.

**Top 5 risks, ordered by impact:**

1. **Dockerfile build target references nonexistent file** (`main_app.go` vs `main.go`) -- Docker builds will fail (Dimension H)
2. **AF_PACKET BPF filter is a no-op stub** -- filters specified by users are silently ignored in AF_PACKET mode (Dimension B)
3. **PCAP NoCopy=true leaks unsafe buffer references to GUI handler** -- potential data corruption under PCAP load in GUI mode (Dimension B)
4. **Isolation Forest RNG uses unsynchronized global mutable state** -- data race during concurrent training (Dimension D)
5. **host network mode breaks ML sidecar DNS resolution** -- `nfa-ml:50051` is unreachable when main container uses `network_mode: host` (Dimension H)

---

## 2. Confirmed Design Strengths

### S1. Memory-bounded packet storage (Dimensions A, B)
Both headless (`main.go:231-240`) and GUI (`gui_app.go:278-279`) modes use ring buffers with explicit size caps (1M packets / 1GB headless; 100K packets GUI). The headless handler includes a memory pressure eviction loop (`main.go:433-444`) that drops oldest packets before accepting new ones. This prevents unbounded growth under sustained capture.

### S2. AF_XDP with graceful fallback chain (Dimension B)
`afxdp.go:959-979` attempts native/driver XDP mode first, falls back to generic XDP, and the top-level `capture.go` engine falls back from AF_XDP to AF_PACKET entirely if XDP initialization fails. The multi-tier strategy maximizes capture performance without hard-failing on unsupported hardware.

### S3. File carver safety defaults (Dimension C)
`carver.go:113-129`: `MetadataOnly=true`, `ExtractExecutables=false`, `QuarantineExecutables=true` by default. Hard limits on files per stream (100), total files (10,000), and total bytes (10GB) in `carver.go:48-57`. Filenames use `crypto/rand` with regex validation for extensions. Executable signatures are marked `Dangerous=true` in `signatures.go`.

### S4. TCP reassembly memory controls (Dimension B)
`tcp_reassembly.go:57-66`: Defaults of 4000 pages/connection (~7.6MB), 150K pages total (~285MB), 100K max connections. The assembler mutex (`assemblerMu`) correctly serializes all assembler operations since gopacket's assembler is not thread-safe. Periodic flushing at half the `FlushOlderThan` interval prevents stale connection accumulation.

### S5. Evidence chain integrity (Dimension C)
BLAKE3 hashing by default for carved files. UCO/CASE evidence format export with investigation metadata, tool provenance, and host/flow/file records. The evidence packager is used consistently in both headless (`main.go:388-396`) and GUI (`gui_app.go:865-900`) modes.

### S6. Frontend event throttling (Dimensions E, F)
Backend throttles Wails events at 100ms intervals (`gui_app.go:267`, `gui_app.go:1250-1263`). Frontend applies RAF-based throttling at ~60fps (`useWailsEvents.ts` with `THROTTLE_MS=16`). Combined with bounded Zustand stores (100K packets, 50K flows, 10K alerts) and version-counter memoization, this prevents UI saturation during high-rate capture.

### S7. Non-root Docker container (Dimension H)
`Dockerfile:91-92`: Dedicated `nfa-linux` user (UID 1000). Capabilities (`NET_RAW`, `NET_ADMIN`) are granted at runtime via `cap_add` rather than embedded. Resource limits in compose (4 CPU, 8GB RAM) provide containment.

### S8. XDP kernel stats delta tracking (Dimension B)
`afxdp.go:314-351`: The `collectKernelStats` goroutine correctly computes deltas from cumulative kernel counters per worker (`BUG-4 FIX`), preventing the counter explosion bug that would otherwise inflate drop counts on every poll cycle.

### S9. Worker cleanup with sync.Once (Dimension A)
`afxdp.go:575-594`: Worker `cleanup()` uses `sync.Once` to prevent double-free of mmapped memory and socket FDs when both the deferred cleanup and `stopWorkers()` run.

---

## 3. Verified Issues & Risks

### I1. Dockerfile build target references nonexistent file
- **Severity:** High
- **Dimension:** H (Packaging)
- **Component:** `Dockerfile:67`
- **Evidence:** `go build ... -o /app/nfa-linux ./main_app.go` -- actual entry point is `main.go`
- **Impact:** Docker production builds fail. CI/CD pipelines break.
- **Fix:** Change `./main_app.go` to `.` or `./main.go`

### I2. AF_PACKET BPF filter is a no-op stub
- **Severity:** High
- **Dimension:** B (Capture Pipeline)
- **Component:** `afpacket.go:228-239`
- **Evidence:** `setBPFFilterInternal()` returns `nil` without calling any filter compilation or socket attachment. The comment says "we'll skip this and implement it later."
- **Impact:** Users who specify `-filter "tcp port 443"` in AF_PACKET mode (the default for headless and GUI) get unfiltered capture. This is a silent failure -- no error, no warning. Forensic analysts may believe they are capturing a subset when they are capturing everything.
- **Fix:** Use `gopacket/pcap`'s `CompileBPFFilter` or the `go-pcap/filter` package as noted in the comment, or at minimum log a warning that the filter is not applied.

### I3. PCAP NoCopy buffer aliasing in GUI mode
- **Severity:** Medium
- **Dimension:** B (Capture Pipeline)
- **Component:** `pcap.go:166` and `gui_app.go:1049`
- **Evidence:** `packetSource.DecodeOptions.NoCopy = true` means `packet.Data()` returns a slice aliasing an internal buffer that may be overwritten on the next read. Headless mode (`main.go:499-501`) explicitly copies data before passing to reassembly, but GUI mode's `handlePacketData` at `gui_app.go:1049` stores `data` directly as `Payload: data` in the packet struct without copying.
- **Impact:** Under PCAP playback in GUI mode, packet payloads stored in the ring buffer may be silently corrupted by subsequent reads. This affects forensic integrity of retained packet data.
- **Fix:** Copy `data` at the entry of `gui_app.go:handlePacketData` before storing, or set `NoCopy = false` in the PCAP engine.

### I4. Isolation Forest global mutable RNG state
- **Severity:** Medium
- **Dimension:** D (ML Integration)
- **Component:** `anomaly.go:1440-1449`
- **Evidence:** `var ifoRandState uint64` is a package-level variable mutated by `ifoRandInt()` and `ifoRandFloat()` without any synchronization. These are called from `buildTree()` during `Train()`.
- **Impact:** If two `IsolationForest` instances are trained concurrently (e.g., the ensemble detector training multiple models), the RNG produces non-deterministic output and exhibits a data race detectable by `-race`. The `IsolationForest.mu` lock does not protect the global state since each instance has its own lock.
- **Fix:** Move the RNG state into the `IsolationForest` struct, or use `math/rand/v2` with per-instance sources.

### I5. host network mode breaks sidecar service discovery
- **Severity:** Medium
- **Dimension:** H (Deployment)
- **Component:** `docker-compose.yml:38` and `docker-compose.yml:45`
- **Evidence:** `network_mode: host` on the `nfa` service bypasses Docker's internal DNS. The environment variable `NFA_ML_ADDRESS=nfa-ml:50051` relies on Docker DNS to resolve `nfa-ml`, which only works on the `bridge` network.
- **Impact:** When the ML sidecar profile is activated, the main app cannot connect to it via hostname. The gRPC client will fail to connect.
- **Fix:** Either use `localhost:50051` with port mapping when in host mode, or use a bridge network with `CAP_NET_RAW` for both services.

### I6. GUI per-packet lock contention
- **Severity:** Medium
- **Dimension:** A (Architecture), E (Desktop Bridge)
- **Component:** `gui_app.go:1067-1135`
- **Evidence:** Each packet acquires and releases 7 separate mutexes sequentially: `packetsMu`, `statsMu`, `protoMu`, `protocolsMu`, `bytesDirMu`, `ipStatsMu`, `portStatsMu`, plus `flowsMu` via `updateFlow`. Under high packet rates (>100Kpps), the lock acquisition overhead becomes significant.
- **Impact:** Performance degradation in GUI mode at high packet rates. Not a correctness issue, but limits practical throughput of the GUI capture path.
- **Fix:** Consolidate related counters under fewer locks, or use atomic operations for simple counters (protocol counts, byte counters).

### I7. Metrics server missing timeouts
- **Severity:** Low
- **Dimension:** G (Observability)
- **Component:** `main.go:727-734`
- **Evidence:** The metrics server in `startMetricsServer()` creates an `http.Server` without `ReadTimeout` or `WriteTimeout`. The metrics package's own `Server` (`prometheus.go:530-537`) correctly sets both to 10s.
- **Impact:** The metrics endpoint is susceptible to slowloris-style connection exhaustion if exposed to untrusted networks. In typical desktop deployment this is localhost-only, limiting practical risk.
- **Fix:** Add `ReadTimeout` and `WriteTimeout` to the server in `startMetricsServer()`.

### I8. Packet ID race in GUI handler
- **Severity:** Low
- **Dimension:** A (Architecture)
- **Component:** `gui_app.go:1037`
- **Evidence:** `fmt.Sprintf("pkt-%d", a.packetIdx)` reads `a.packetIdx` before the `packetsMu` lock is acquired at line 1067. The value is used only for a display ID, not for indexing.
- **Impact:** Non-unique or misordered packet IDs under concurrent access. Cosmetic only -- does not affect data integrity.
- **Fix:** Move the ID generation inside the `packetsMu` lock scope.

### I9. currentMemory tracking without synchronization in GUI mode
- **Severity:** Low
- **Dimension:** A (Architecture)
- **Component:** `gui_app.go:1141`
- **Evidence:** `a.currentMemory += int64(pkt.Length) + 200` is executed outside any lock. This is an approximate counter used for display purposes only.
- **Impact:** Inaccurate memory usage reporting in the GUI stats. No safety implication since the value is advisory.
- **Fix:** Use `atomic.AddInt64` or place under an existing lock.

### I10. ML sidecar health check is superficial
- **Severity:** Low
- **Dimension:** H (Deployment)
- **Component:** `docker-compose.yml:130`
- **Evidence:** `test: ["CMD", "python", "-c", "import grpc; print('ok')"]` only verifies that the grpc Python package is importable, not that the service is running or responding.
- **Impact:** Docker will report the sidecar as healthy even if the gRPC server has crashed or failed to bind its port.
- **Fix:** Use a gRPC health check client (`grpc_health_probe`) or connect to `localhost:50051`.

---

## 4. Non-Issues (Confirmed Acceptable)

### N1. gRPC client uses insecure credentials
`grpc_client.go:96`: `insecure.NewCredentials()` is used for the sidecar connection. This is appropriate: the ML sidecar is a localhost co-process, not a remote service. The Docker compose exposes port 50051 only internally (`expose`, not `ports`). TLS would add complexity without meaningful security gain for local IPC.

### N2. AF_PACKET uses single capture goroutine
`afpacket.go:148-150`: Despite `NumWorkers` config, only one goroutine runs `captureLoop()`. This is correct for AF_PACKET with TPACKET_V3 -- the ring buffer is designed for single-reader access. Multi-reader would require `SO_ATTACH_FANOUT`, which is a separate feature.

### N3. Custom Prometheus implementation
`prometheus.go`: The metrics package implements Prometheus exposition format without depending on `prometheus/client_golang`. This reduces dependency surface area and is appropriate for a desktop tool that only needs basic counter/gauge/histogram support.

### N4. AF_XDP software BPF filter limited syntax
`afxdp.go:799-887`: Only supports `tcp`, `udp`, `icmp`, `port N`, `host IP`. This is supplemented by the eBPF hardware filter (`SetEBPFFilter` at `afxdp.go:731`), and the AF_XDP path is the high-performance path where full BPF compilation is less practical without libpcap. The limitation is documented in the error message.

### N5. resetState acquires 10 locks simultaneously
`gui_app.go:973-994`: This looks risky but is safe because: (a) it is only called from `StartCapture` and `LoadPCAP`, both of which hold `captureMu`, so only one call can be active; (b) locks are always acquired in the same fixed order; (c) no other code path acquires all 10 locks.

---

## 5. Maturity Gaps (Scaffolded, Not Defects)

### M1. gRPC client returns simulated responses
`grpc_client.go:180-185`, `226-231`, `271-279`, `321-326`, `357-364`: All `PredictFlow`, `DetectAnomaly`, `PredictDNS`, `ClassifyTraffic`, and `HealthCheck` methods return hardcoded stub data. The gRPC client is structurally complete (connection pooling, keepalive, retry logic, stats tracking) but does not issue actual RPCs.
**Status:** Scaffolded. Go-native ML inference (anomaly.go, pipeline.go) is functional and used in production paths.

### M2. ML sidecar proto servicer not registered
`ml_sidecar/server.py:39-41`: Comments indicate the gRPC servicer would be registered from generated protobuf modules, but the actual registration is not present. The server has complete `ModelManager`, `AnomalyDetector`, `DNSTunnelingDetector`, `DGADetector`, and `TrafficClassifier` classes implemented.
**Status:** Scaffolded. The Python implementations exist but are not wired to the gRPC server.

### M3. AF_PACKET BPF filter compilation not implemented
`afpacket.go:228-239`: As noted in I2, the filter stub needs implementation. This is a maturity gap that overlaps with the risk in I2 because users receive no error feedback.
**Status:** Stub with TODO comment.

### M4. No TLS/mTLS for sidecar communication
The gRPC channel uses `insecure.NewCredentials()`. For multi-host deployment or shared-network environments, mutual TLS would be needed.
**Status:** Not needed for current localhost architecture. Would be required if sidecar were deployed remotely.

### M5. Limited BPF filter language in AF_XDP
`afxdp.go:886`: The error message explicitly documents supported filters. More complex expressions (e.g., `tcp port 443 and not host 10.0.0.1`) are not supported.
**Status:** Functional within its documented scope.

### M6. ONNX Runtime Go integration not present
The ML pipeline references model loading and inference but does not import or use `onnxruntime-go`. The Go-native statistical methods are functional.
**Status:** Scaffolded architecture, not blocking.

---

## 6. Deployment Readiness Verdict

| Dimension | Rating | Notes |
|-----------|--------|-------|
| A. Architecture & Process Model | **Ready** | Sound process model, ring buffers, signal handling, memory limits |
| B. Capture & Packet Pipeline | **Conditional** | AF_XDP path is solid; AF_PACKET BPF stub (I2) and PCAP NoCopy (I3) need fixes |
| C. Analysis & Evidence Chain | **Ready** | Carver safety defaults, BLAKE3 integrity, UCO/CASE export functional |
| D. ML Integration Boundary | **Conditional** | Go-native inference works; IForest RNG race (I4) needs fix; sidecar is scaffolded |
| E. Desktop Bridge (Wails) | **Ready** | Correct use of Wails runtime, event throttling, no HTTP surface |
| F. Frontend Architecture | **Ready** | Bounded stores, memoized selectors, RAF throttling, payload validation |
| G. Observability & Metrics | **Ready** | Custom Prometheus works; minor timeout gap (I7) on metrics server |
| H. Packaging & Deployment | **Not Ready** | Dockerfile build fails (I1); host network breaks sidecar DNS (I5) |

**Overall:** The core forensic pipeline (capture -> reassembly -> carving -> evidence export) is deployment-ready for desktop use with AF_XDP or after fixing the AF_PACKET BPF stub. The Docker packaging requires the Dockerfile build target fix (I1) before any containerized deployment. The ML sidecar integration is scaffolded and should be documented as experimental.

**Blocking items for deployment:**
1. Fix `Dockerfile:67` build target (I1)
2. Fix or warn on AF_PACKET BPF filter no-op (I2)
3. Copy packet data in GUI PCAP handler (I3)

**Recommended but non-blocking:**
4. Fix IsolationForest RNG thread safety (I4)
5. Resolve host network vs sidecar DNS (I5)
6. Add timeouts to metrics server (I7)
