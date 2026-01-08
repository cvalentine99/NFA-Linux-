# NFA-Linux Defect Remediation Checklist

**Project:** NFA-Linux - Network Forensic Analyzer  
**Created:** January 8, 2026  
**Purpose:** Actionable fix checklist to remediate all audit defects  
**Contract Obligation:** Full end-to-end wiring, real data display, working forensic application

---

## Contract Deliverables

Per project requirements, the application must:
- [ ] Actually capture packets and display them
- [ ] Parse protocols and show parsed data
- [ ] Display real data (not zeros or placeholders)
- [ ] Work on WebKit2GTK 2.50.x (Ubuntu 24.04)
- [ ] Support sudo/root for packet capture
- [ ] Show accurate statistics (not false/misleading)
- [ ] Export valid forensic evidence
- [ ] Detect threats via ML pipeline

---

## CRITICAL FIXES (Must Complete)

### C1: Fix Statistics Contract Mismatch

**Problem:** Backend `StatsDTO` is flat, frontend `Statistics` expects nested structure with different field names.

**File:** `gui_app.go`

**Current StatsDTO:**
```go
type StatsDTO struct {
    PacketCount    int64   `json:"packet_count"`
    ByteCount      int64   `json:"byte_count"`
    FlowCount      int64   `json:"flow_count"`
    AlertCount     int64   `json:"alert_count"`
    FileCount      int64   `json:"file_count"`
    DroppedPackets int64   `json:"dropped_packets"`
    PacketsPerSec  float64 `json:"packets_per_sec"`
    BytesPerSec    float64 `json:"bytes_per_sec"`
    MemoryUsage    int64   `json:"memory_usage"`
    CaptureTime    int64   `json:"capture_time"`
    Interface      string  `json:"interface"`
    IsCapturing    bool    `json:"is_capturing"`
}
```

**Required StatsDTO (matching frontend expectations):**
```go
type StatsDTO struct {
    Packets struct {
        Total int64 `json:"total"`
        TCP   int64 `json:"tcp"`
        UDP   int64 `json:"udp"`
        ICMP  int64 `json:"icmp"`
        Other int64 `json:"other"`
    } `json:"packets"`
    Bytes struct {
        Total    int64 `json:"total"`
        Inbound  int64 `json:"inbound"`
        Outbound int64 `json:"outbound"`
    } `json:"bytes"`
    Flows struct {
        Total     int64 `json:"total"`
        Active    int64 `json:"active"`
        Completed int64 `json:"completed"`
    } `json:"flows"`
    Protocols  map[string]int64 `json:"protocols"`
    TopTalkers []TopTalkerDTO   `json:"topTalkers"`
    TopPorts   []TopPortDTO     `json:"topPorts"`
    
    // Additional fields
    AlertCount     int64   `json:"alertCount"`
    FileCount      int64   `json:"fileCount"`
    DroppedPackets int64   `json:"droppedPackets"`
    PacketsPerSec  float64 `json:"packetsPerSec"`
    BytesPerSec    float64 `json:"bytesPerSec"`
    MemoryUsage    int64   `json:"memoryUsage"`
    CaptureTime    int64   `json:"captureTime"`
    Interface      string  `json:"interface"`
    IsCapturing    bool    `json:"isCapturing"`
}

type TopTalkerDTO struct {
    IP      string `json:"ip"`
    Packets int64  `json:"packets"`
    Bytes   int64  `json:"bytes"`
}

type TopPortDTO struct {
    Port     uint16 `json:"port"`
    Protocol string `json:"protocol"`
    Count    int64  `json:"count"`
}
```

**Tasks:**
- [ ] Add `TopTalkerDTO` and `TopPortDTO` types to `gui_app.go`
- [ ] Rewrite `StatsDTO` to match frontend `Statistics` interface
- [ ] Add tracking fields to `App` struct:
  - [ ] `tcpCount`, `udpCount`, `icmpCount`, `otherCount` for protocol breakdown
  - [ ] `bytesInbound`, `bytesOutbound` for direction tracking
  - [ ] `flowsActive`, `flowsCompleted` for flow state
  - [ ] `protocols map[string]int64` for protocol distribution
  - [ ] `topTalkers map[string]*TalkerStats` for IP tracking
  - [ ] `topPorts map[uint16]*PortStats` for port tracking
- [ ] Update `GetStats()` to populate all fields
- [ ] Update `handlePacketData()` to increment protocol counters
- [ ] Update `updateFlow()` to track active/completed flows

**Verification:**
```bash
# Start capture, generate traffic, verify stats show real values
curl https://example.com
# Check dashboard shows TCP count > 0, bytes inbound/outbound > 0
```

---

### C2: Wire ML Pipeline

**Problem:** `internal/ml/` package exists but is never imported or instantiated. Alert detection is dead code.

**File:** `gui_app.go`

**Tasks:**
- [ ] Add import: `"github.com/cvalentine99/nfa-linux/internal/ml"`
- [ ] Add ML pipeline field to `App` struct:
```go
type App struct {
    // ... existing fields ...
    
    // ML pipeline
    mlPipeline *ml.MLPipeline
}
```
- [ ] Initialize ML pipeline in `NewApp()`:
```go
func NewApp() *App {
    app := &App{
        // ... existing initialization ...
    }
    
    // Initialize ML pipeline
    mlConfig := ml.DefaultPipelineConfig()
    mlConfig.EnableAnomalyDetection = true
    mlConfig.EnableThreatDetection = true
    mlConfig.EnableDNSAnalysis = true
    var err error
    app.mlPipeline, err = ml.NewMLPipeline(mlConfig)
    if err != nil {
        logging.Warnf("Failed to create ML pipeline: %v", err)
    }
    
    return app
}
```
- [ ] Start ML pipeline in `startup()`:
```go
func (a *App) startup(ctx context.Context) {
    // ... existing code ...
    
    // Start ML pipeline
    if a.mlPipeline != nil {
        if err := a.mlPipeline.Start(ctx); err != nil {
            logging.Warnf("Failed to start ML pipeline: %v", err)
        }
        
        // Start result consumer
        go a.consumeMLResults()
    }
}
```
- [ ] Add ML result consumer:
```go
func (a *App) consumeMLResults() {
    if a.mlPipeline == nil {
        return
    }
    
    for result := range a.mlPipeline.Results() {
        if result.AnomalyResult != nil && result.AnomalyResult.IsAnomaly {
            alert := &AlertDTO{
                ID:          fmt.Sprintf("alert-%d", time.Now().UnixNano()),
                Timestamp:   time.Now().UnixNano(),
                Severity:    "high",
                Category:    "anomaly",
                Title:       "Anomaly Detected",
                Description: fmt.Sprintf("Anomaly score: %.2f", result.AnomalyResult.Score),
                FlowID:      result.FlowID,
            }
            
            a.alertsMu.Lock()
            a.alerts = append(a.alerts, alert)
            a.alertsMu.Unlock()
            
            a.emitEvent("alert:new", map[string]interface{}{
                "alert":     alert,
                "timestamp": time.Now().UnixNano(),
            })
        }
    }
}
```
- [ ] Feed flows to ML pipeline in `updateFlow()`:
```go
func (a *App) updateFlow(packet *models.Packet) {
    // ... existing flow update code ...
    
    // Feed to ML pipeline
    if a.mlPipeline != nil && flow.PacketCount > 10 {
        a.mlPipeline.ProcessFlow(flow)
    }
}
```
- [ ] Stop ML pipeline in `shutdown()`:
```go
func (a *App) shutdown(ctx context.Context) {
    // ... existing code ...
    
    if a.mlPipeline != nil {
        a.mlPipeline.Stop()
    }
}
```

**Verification:**
```bash
# Generate suspicious traffic patterns
# Verify alerts appear in dashboard
```

---

### C3: Propagate Kernel Drop Stats

**Problem:** `AFPacketEngine.Stats()` correctly gets kernel drops, but `gui_app.go` never calls it.

**File:** `gui_app.go`

**Tasks:**
- [ ] Update `statsUpdater()` to fetch kernel stats:
```go
func (a *App) statsUpdater() {
    ticker := time.NewTicker(1 * time.Second)
    defer ticker.Stop()

    var lastPackets, lastBytes uint64
    lastTime := time.Now()

    for {
        select {
        case <-ticker.C:
            a.statsMu.Lock()
            now := time.Now()
            duration := now.Sub(lastTime).Seconds()
            if duration > 0 {
                currentPackets := a.stats.PacketsReceived
                currentBytes := a.stats.BytesReceived

                a.stats.PacketsPerSecond = float64(currentPackets-lastPackets) / duration
                a.stats.BytesPerSecond = float64(currentBytes-lastBytes) / duration

                lastPackets = currentPackets
                lastBytes = currentBytes
            }
            lastTime = now
            
            // CRITICAL FIX: Get kernel drop stats from capture engine
            if a.engine != nil {
                engineStats := a.engine.Stats()
                if engineStats != nil {
                    a.droppedPackets = int64(engineStats.PacketsDropped)
                }
            }
            
            a.statsMu.Unlock()

            // Emit stats update
            a.emitEvent("stats:update", map[string]interface{}{
                "stats":     a.GetStats(),
                "timestamp": time.Now().UnixNano(),
            })

        case <-a.ctx.Done():
            return
        }
    }
}
```

**Verification:**
```bash
# Generate high-rate traffic to cause drops
sudo tcpreplay -i eth0 --topspeed large_capture.pcap
# Verify drop rate > 0 in dashboard
```

---

### C4: Implement Real View Components

**Problem:** All view components (`DashboardView`, `PacketsView`, etc.) are empty placeholders.

**File:** `frontend/src/App.tsx`

**Tasks:**
- [ ] Implement `DashboardView` with real widgets:
```tsx
function DashboardView() {
  const stats = useAppStore(state => state.statistics)
  const capture = useCaptureState()
  
  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-bold">Dashboard</h1>
      
      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatsCard 
          title="Total Packets" 
          value={stats.packets.total.toLocaleString()}
          subtitle={`TCP: ${stats.packets.tcp} | UDP: ${stats.packets.udp}`}
        />
        <StatsCard 
          title="Data Processed" 
          value={formatBytes(stats.bytes.total)}
          subtitle={`↑ ${formatBytes(stats.bytes.outbound)} ↓ ${formatBytes(stats.bytes.inbound)}`}
        />
        <StatsCard 
          title="Active Flows" 
          value={stats.flows.active.toLocaleString()}
          subtitle={`Total: ${stats.flows.total} | Completed: ${stats.flows.completed}`}
        />
        <StatsCard 
          title="Drop Rate" 
          value={`${((capture.packetsDropped / Math.max(capture.packetsCaptured, 1)) * 100).toFixed(2)}%`}
          subtitle={`${capture.packetsDropped.toLocaleString()} dropped`}
          alert={capture.packetsDropped > 0}
        />
      </div>
      
      {/* Top Talkers */}
      <div className="bg-[#16161e] rounded-lg p-4">
        <h2 className="text-lg font-semibold mb-4">Top Talkers</h2>
        {stats.topTalkers.length > 0 ? (
          <table className="w-full">
            <thead>
              <tr className="text-left text-gray-400">
                <th>IP Address</th>
                <th>Packets</th>
                <th>Bytes</th>
              </tr>
            </thead>
            <tbody>
              {stats.topTalkers.slice(0, 10).map((talker, i) => (
                <tr key={i} className="border-t border-[#2a2a3a]">
                  <td className="py-2">{talker.ip}</td>
                  <td>{talker.packets.toLocaleString()}</td>
                  <td>{formatBytes(talker.bytes)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="text-gray-400">No traffic data yet. Start a capture to see top talkers.</p>
        )}
      </div>
      
      {/* Protocol Distribution */}
      <div className="bg-[#16161e] rounded-lg p-4">
        <h2 className="text-lg font-semibold mb-4">Protocol Distribution</h2>
        <div className="flex space-x-4">
          {Object.entries(stats.protocols).map(([proto, count]) => (
            <div key={proto} className="text-center">
              <div className="text-2xl font-bold">{count.toLocaleString()}</div>
              <div className="text-gray-400">{proto}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function StatsCard({ title, value, subtitle, alert }: { 
  title: string; value: string; subtitle?: string; alert?: boolean 
}) {
  return (
    <div className={`bg-[#16161e] rounded-lg p-4 ${alert ? 'border border-red-500' : ''}`}>
      <div className="text-gray-400 text-sm">{title}</div>
      <div className="text-2xl font-bold mt-1">{value}</div>
      {subtitle && <div className="text-gray-500 text-sm mt-1">{subtitle}</div>}
    </div>
  )
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}
```

- [ ] Implement `PacketsView` with real packet table:
```tsx
function PacketsView({ searchValue }: { searchValue: string }) {
  const packets = useFilteredPackets()
  
  return (
    <div className="p-6 h-full flex flex-col">
      <h1 className="text-2xl font-bold mb-4">Packets ({packets.length.toLocaleString()})</h1>
      
      <div className="flex-1 overflow-auto">
        <table className="w-full">
          <thead className="sticky top-0 bg-[#16161e]">
            <tr className="text-left text-gray-400">
              <th className="p-2">Time</th>
              <th className="p-2">Source</th>
              <th className="p-2">Destination</th>
              <th className="p-2">Protocol</th>
              <th className="p-2">Length</th>
              <th className="p-2">Info</th>
            </tr>
          </thead>
          <tbody>
            {packets.slice(0, 1000).map((pkt) => (
              <tr key={pkt.id} className="border-t border-[#2a2a3a] hover:bg-[#1a1a24]">
                <td className="p-2 text-sm">{new Date(pkt.timestampNano / 1000000).toISOString()}</td>
                <td className="p-2">{pkt.srcIP}:{pkt.srcPort}</td>
                <td className="p-2">{pkt.dstIP}:{pkt.dstPort}</td>
                <td className="p-2">{pkt.protocol}</td>
                <td className="p-2">{pkt.length}</td>
                <td className="p-2 text-gray-400">{pkt.info || '-'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
```

- [ ] Implement `FlowsView` with real flow table
- [ ] Implement `AlertsView` with real alert list
- [ ] Implement `FilesView` with real file list
- [ ] Implement `TopologyView` (or show "Not available" message)

**Verification:**
```bash
# Start capture, verify all views show real data
```

---

## HIGH PRIORITY FIXES

### H1: Track TopTalkers and TopPorts

**File:** `gui_app.go`

**Tasks:**
- [ ] Add tracking maps to `App` struct:
```go
type App struct {
    // ... existing fields ...
    
    // Traffic tracking
    ipStats   map[string]*IPStats
    ipStatsMu sync.RWMutex
    
    portStats   map[uint16]*PortStats
    portStatsMu sync.RWMutex
}

type IPStats struct {
    IP      string
    Packets int64
    Bytes   int64
}

type PortStats struct {
    Port     uint16
    Protocol string
    Count    int64
}
```

- [ ] Initialize maps in `NewApp()`:
```go
app := &App{
    // ... existing ...
    ipStats:   make(map[string]*IPStats),
    portStats: make(map[uint16]*PortStats),
}
```

- [ ] Update `handlePacketData()` to track IPs and ports:
```go
func (a *App) handlePacketData(data []byte, info *models.PacketInfo) {
    // ... existing code ...
    
    // Track IP stats
    a.ipStatsMu.Lock()
    srcIP := pkt.SrcIP.String()
    if _, exists := a.ipStats[srcIP]; !exists {
        a.ipStats[srcIP] = &IPStats{IP: srcIP}
    }
    a.ipStats[srcIP].Packets++
    a.ipStats[srcIP].Bytes += int64(pkt.Length)
    
    dstIP := pkt.DstIP.String()
    if _, exists := a.ipStats[dstIP]; !exists {
        a.ipStats[dstIP] = &IPStats{IP: dstIP}
    }
    a.ipStats[dstIP].Packets++
    a.ipStats[dstIP].Bytes += int64(pkt.Length)
    a.ipStatsMu.Unlock()
    
    // Track port stats
    a.portStatsMu.Lock()
    if pkt.DstPort > 0 {
        if _, exists := a.portStats[pkt.DstPort]; !exists {
            a.portStats[pkt.DstPort] = &PortStats{Port: pkt.DstPort, Protocol: pkt.Protocol}
        }
        a.portStats[pkt.DstPort].Count++
    }
    a.portStatsMu.Unlock()
    
    // ... rest of existing code ...
}
```

- [ ] Add helper to get top N talkers:
```go
func (a *App) getTopTalkers(n int) []TopTalkerDTO {
    a.ipStatsMu.RLock()
    defer a.ipStatsMu.RUnlock()
    
    // Convert to slice and sort
    talkers := make([]TopTalkerDTO, 0, len(a.ipStats))
    for _, stats := range a.ipStats {
        talkers = append(talkers, TopTalkerDTO{
            IP:      stats.IP,
            Packets: stats.Packets,
            Bytes:   stats.Bytes,
        })
    }
    
    sort.Slice(talkers, func(i, j int) bool {
        return talkers[i].Bytes > talkers[j].Bytes
    })
    
    if len(talkers) > n {
        talkers = talkers[:n]
    }
    return talkers
}
```

- [ ] Update `GetStats()` to include top talkers and ports

**Verification:**
```bash
# Capture traffic, verify TopTalkers shows real IPs
```

---

### H2: Track Inbound/Outbound Bytes

**File:** `gui_app.go`

**Tasks:**
- [ ] Add local network detection:
```go
type App struct {
    // ... existing fields ...
    localNetworks []*net.IPNet
}

func (a *App) initLocalNetworks(iface string) {
    netIface, err := net.InterfaceByName(iface)
    if err != nil {
        return
    }
    
    addrs, err := netIface.Addrs()
    if err != nil {
        return
    }
    
    a.localNetworks = make([]*net.IPNet, 0)
    for _, addr := range addrs {
        if ipnet, ok := addr.(*net.IPNet); ok {
            a.localNetworks = append(a.localNetworks, ipnet)
        }
    }
}

func (a *App) isLocalIP(ip net.IP) bool {
    for _, network := range a.localNetworks {
        if network.Contains(ip) {
            return true
        }
    }
    return false
}
```

- [ ] Call `initLocalNetworks()` in `StartCapture()`
- [ ] Track direction in `handlePacketData()`:
```go
// Determine direction
srcLocal := a.isLocalIP(pkt.SrcIP)
dstLocal := a.isLocalIP(pkt.DstIP)

a.statsMu.Lock()
if srcLocal && !dstLocal {
    a.bytesOutbound += int64(pkt.Length)
} else if !srcLocal && dstLocal {
    a.bytesInbound += int64(pkt.Length)
}
a.statsMu.Unlock()
```

**Verification:**
```bash
# Capture traffic, verify inbound/outbound bytes are non-zero
```

---

### H3: Add GetTopology Method

**File:** `gui_app.go`

**Tasks:**
- [ ] Add `GetTopology()` method:
```go
type TopologyDTO struct {
    Nodes []TopologyNodeDTO `json:"nodes"`
    Links []TopologyLinkDTO `json:"links"`
}

type TopologyNodeDTO struct {
    ID          string `json:"id"`
    IP          string `json:"ip"`
    Type        string `json:"type"`
    PacketCount int64  `json:"packetCount"`
    ByteCount   int64  `json:"byteCount"`
}

type TopologyLinkDTO struct {
    Source   string `json:"source"`
    Target   string `json:"target"`
    Protocol string `json:"protocol"`
    Packets  int64  `json:"packets"`
    Bytes    int64  `json:"bytes"`
}

func (a *App) GetTopology() *TopologyDTO {
    a.ipStatsMu.RLock()
    a.flowsMu.RLock()
    defer a.ipStatsMu.RUnlock()
    defer a.flowsMu.RUnlock()
    
    // Build nodes from IP stats
    nodes := make([]TopologyNodeDTO, 0)
    for ip, stats := range a.ipStats {
        nodeType := "external"
        if a.isLocalIP(net.ParseIP(ip)) {
            nodeType = "internal"
        }
        nodes = append(nodes, TopologyNodeDTO{
            ID:          ip,
            IP:          ip,
            Type:        nodeType,
            PacketCount: stats.Packets,
            ByteCount:   stats.Bytes,
        })
    }
    
    // Build links from flows
    links := make([]TopologyLinkDTO, 0)
    for _, flow := range a.flows {
        links = append(links, TopologyLinkDTO{
            Source:   flow.SrcIP.String(),
            Target:   flow.DstIP.String(),
            Protocol: flow.ProtocolName,
            Packets:  int64(flow.PacketCount),
            Bytes:    int64(flow.ByteCount),
        })
    }
    
    return &TopologyDTO{Nodes: nodes, Links: links}
}
```

**Verification:**
```bash
# Call GetTopology(), verify nodes and links returned
```

---

### H4: Add ExportEvidence Method

**File:** `gui_app.go`

**Tasks:**
- [ ] Add import: `"github.com/cvalentine99/nfa-linux/internal/evidence"`
- [ ] Add `ExportEvidence()` method:
```go
func (a *App) ExportEvidence(outputPath string) error {
    config := &evidence.EvidencePackagerConfig{
        InvestigationName:  "NFA-Linux Capture",
        InvestigationFocus: "Network Forensics",
        ToolName:           "NFA-Linux",
        ToolVersion:        Version,
        ToolCreator:        "NFA-Linux Team",
        OutputDir:          filepath.Dir(outputPath),
    }
    
    packager := evidence.NewEvidencePackager(config)
    
    // Add flows
    a.flowsMu.RLock()
    for _, flow := range a.flows {
        packager.AddFlow(flow)
    }
    a.flowsMu.RUnlock()
    
    // Add carved files
    a.filesMu.RLock()
    for _, file := range a.files {
        packager.AddCarvedFile(file)
    }
    a.filesMu.RUnlock()
    
    // Add hosts
    a.hostsMu.RLock()
    for _, host := range a.hosts {
        packager.AddHost(host)
    }
    a.hostsMu.RUnlock()
    
    // Export to file
    return packager.ExportJSONToFile(outputPath)
}
```

**Verification:**
```bash
# Capture traffic, export evidence, verify non-empty JSON-LD file
```

---

## MEDIUM PRIORITY FIXES

### M1: Add Event Payload Validation

**File:** `frontend/src/hooks/useWailsEvents.ts`

**Tasks:**
- [ ] Add validation functions:
```typescript
function isValidPacketBatch(data: unknown): data is PacketBatchPayload {
  if (typeof data !== 'object' || data === null) return false
  const d = data as Record<string, unknown>
  return 'packets' in d && Array.isArray(d.packets) && 'timestamp' in d
}

function isValidStatsUpdate(data: unknown): data is StatsUpdatePayload {
  if (typeof data !== 'object' || data === null) return false
  const d = data as Record<string, unknown>
  return 'stats' in d && typeof d.stats === 'object'
}
```

- [ ] Update handlers to validate:
```typescript
const handlePacketBatch = useCallback((data: unknown) => {
  if (!isValidPacketBatch(data)) {
    console.error('Invalid packet batch payload:', data)
    return
  }
  packetBufferRef.current.push(...data.packets)
  scheduleFlush()
}, [scheduleFlush])
```

---

### M2: Fix JSON Field Name Mismatches

**File:** `gui_app.go`

**Tasks:**
- [ ] Update all JSON tags to use camelCase:
```go
type FlowDTO struct {
    ID           string `json:"id"`
    SrcIP        string `json:"srcIP"`        // was src_ip
    DstIP        string `json:"dstIP"`        // was dst_ip
    SrcPort      uint16 `json:"srcPort"`      // was src_port
    DstPort      uint16 `json:"dstPort"`      // was dst_port
    Protocol     string `json:"protocol"`
    AppProtocol  string `json:"appProtocol"`  // was app_protocol
    State        string `json:"state"`
    PacketCount  uint64 `json:"packetCount"`  // was packet_count
    ByteCount    uint64 `json:"byteCount"`    // was byte_count
    StartTime    int64  `json:"startTime"`    // was start_time
    LastActivity int64  `json:"lastActivity"` // was last_activity
    Duration     int64  `json:"duration"`
}
```

- [ ] Update `PacketDTO`, `AlertDTO`, `FileDTO` similarly

---

### M3: Fix Dual Capture State Ownership

**File:** `frontend/src/App.tsx`

**Tasks:**
- [ ] Remove direct state setting in `handleCaptureToggle()`:
```typescript
const handleCaptureToggle = async () => {
  try {
    if (capture.isCapturing) {
      setCaptureStatus('Stopping capture...')
      await backendStopCapture()
      // REMOVED: updateCaptureState({ isCapturing: false })
      // Let backend event update state
      setCaptureStatus('')
    } else {
      if (!selectedInterface) {
        console.error('No interface selected')
        return
      }
      setCaptureStatus(`Starting capture on ${selectedInterface}...`)
      await backendStartCapture(selectedInterface)
      // REMOVED: updateCaptureState({ isCapturing: true, ... })
      // Let backend event update state
      setCaptureStatus(`Capturing on ${selectedInterface}`)
    }
  } catch (e) {
    console.error('Capture toggle failed:', e)
    setCaptureStatus('Capture failed')
    setTimeout(() => setCaptureStatus(''), 3000)
  }
}
```

---

### M4: Add Staleness Detection

**File:** `frontend/src/hooks/useWailsEvents.ts`

**Tasks:**
- [ ] Add staleness tracking:
```typescript
const lastUpdateRef = useRef<number>(Date.now())
const [isStale, setIsStale] = useState(false)

// Update timestamp in event handlers
const handleStatsUpdate = useCallback((data: unknown) => {
  lastUpdateRef.current = Date.now()
  setIsStale(false)
  // ... rest of handler
}, [updateStatistics])

// Check for staleness
useEffect(() => {
  const interval = setInterval(() => {
    const capture = useAppStore.getState().capture
    if (capture.isCapturing) {
      const timeSinceUpdate = Date.now() - lastUpdateRef.current
      if (timeSinceUpdate > 5000) {
        setIsStale(true)
        console.warn('No backend updates in 5 seconds - connection may be lost')
      }
    }
  }, 1000)
  return () => clearInterval(interval)
}, [])
```

- [ ] Export `isStale` for UI to display warning

---

## LOW PRIORITY FIXES

### L1: Add Empty State Messages

**Tasks:**
- [ ] Add meaningful empty states to all views:
  - "Start a capture to see packets"
  - "No flows detected yet"
  - "No alerts - ML analysis running"
  - "No files extracted from traffic"

### L2: Add Error Boundaries

**Tasks:**
- [ ] Wrap view components in error boundaries:
```tsx
class ViewErrorBoundary extends React.Component<{children: React.ReactNode}> {
  state = { hasError: false, error: null }
  
  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error }
  }
  
  render() {
    if (this.state.hasError) {
      return (
        <div className="p-6 text-red-400">
          <h2>Something went wrong</h2>
          <p>{this.state.error?.message}</p>
        </div>
      )
    }
    return this.props.children
  }
}
```

---

## Implementation Order

1. **C1: Statistics Contract** - Must fix first, everything depends on it
2. **C4: View Components** - Need real UI to verify other fixes
3. **C3: Kernel Drop Stats** - Critical for forensic accuracy
4. **H1: TopTalkers/TopPorts** - Required by dashboard
5. **H2: Inbound/Outbound** - Required by dashboard
6. **C2: ML Pipeline** - Enables alert detection
7. **H3: GetTopology** - Enables topology view
8. **H4: ExportEvidence** - Enables forensic export
9. **M1-M4: Medium fixes** - Data integrity improvements
10. **L1-L2: Low fixes** - UX polish

---

## Verification Checklist

After all fixes:

- [ ] Start capture on real interface
- [ ] Generate traffic: `curl https://example.com`
- [ ] Verify packet count > 0
- [ ] Verify flow count > 0
- [ ] Verify bytes inbound/outbound > 0
- [ ] Verify TopTalkers shows real IPs
- [ ] Verify protocol distribution shows TCP/UDP
- [ ] Verify drop rate reflects kernel stats (may be 0 if no drops)
- [ ] Generate suspicious traffic, verify alert fires
- [ ] Export evidence, verify non-empty CASE/UCO JSON
- [ ] Load PCAP file, verify parsing works
- [ ] Stop capture, verify state updates correctly
- [ ] Check no console errors in browser

---

## Build and Test Commands

```bash
# Build
cd /home/ubuntu/nfa-linux-github
wails build -tags webkit2_41

# Test
sudo ./build/bin/nfa-linux

# Package
VERSION="0.2.0"
cp build/bin/nfa-linux /home/ubuntu/nfa-linux-x86_64-v${VERSION}
tar -czvf /home/ubuntu/nfa-linux-x86_64-v${VERSION}.tar.gz -C /home/ubuntu nfa-linux-x86_64-v${VERSION}
```
