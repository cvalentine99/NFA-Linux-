# NFA-Linux Forensic Wiring Verification Audit

**Application:** NFA-Linux - Network Forensic Analyzer  
**Audit Date:** January 8, 2026  
**Auditor:** Systems Integration Engineer  
**Purpose:** Post-build truth audit per project instructions

---

## Executive Summary: What This Dashboard Lies About Today

The NFA-Linux dashboard presents as a functional network forensics tool while hiding fundamental disconnects between what it shows and what actually happens. This audit documents every break in the chain between **what the dashboard shows ↔ what the backend knows ↔ what the system is actually doing**.

---

## Phase 1: Widget-by-Widget Interrogation

### Header Stats Bar

| Widget | Location | Backend Source | Fetch Trigger | Verdict |
|--------|----------|----------------|---------------|---------|
| Packet Count | `App.tsx:226` | `packetIds.length` from Zustand store | Event-driven via `packet:batch` | ⚠️ CONDITIONAL - depends on events firing |
| Flow Count | `App.tsx:230` | `flowIds.length` from Zustand store | Event-driven via `flow:update` | ⚠️ CONDITIONAL - depends on events firing |
| Alert Count | `App.tsx:234` | `alertIds.length` from Zustand store | Event-driven via `alert:new` | ❌ DEAD - ML pipeline never instantiated |
| File Count | `App.tsx:238` | `files.size` from Zustand store | Event-driven via `file:extracted` | ⚠️ CONDITIONAL - depends on carver |

**Interrogation Results:**

**Packet Count Widget:**
- **Exact backend endpoint:** `gui_app.go:672` emits `packet:batch` event
- **Trigger:** Each packet processed in `handlePacketData()` emits throttled event
- **Empty data behavior:** Shows `0` - indistinguishable from "not started"
- **Stale data behavior:** No expiry, continues showing last value indefinitely
- **Error behavior:** No error handling, renders whatever is in state
- **DEFECT:** If events stop firing, count freezes with no indication

**Flow Count Widget:**
- **Exact backend endpoint:** `gui_app.go:712` emits `flow:update` event
- **Trigger:** Each flow update in `updateFlow()` emits throttled event
- **Empty data behavior:** Shows `0`
- **DEFECT:** Flow count is `flowIds.length` in frontend, not `stats.flows.active` from backend

**Alert Count Widget:**
- **Exact backend endpoint:** `gui_app.go` has `alerts` slice but NO code path populates it
- **Trigger:** NONE - ML pipeline (`internal/ml/`) is never imported or instantiated
- **VERDICT:** ❌ **DEAD CODE** - Alert count will ALWAYS be 0

**File Count Widget:**
- **Exact backend endpoint:** `gui_app.go:213` emits `file:extracted` event
- **Trigger:** `carverEngine.SetFileCarvedHandler()` callback
- **DEFECT:** Carver only triggers on specific file signatures in streams

---

### Interface Dropdown

| Element | Backend Source | Verification |
|---------|----------------|--------------|
| Interface list | `gui_app.go:271` `ListInterfaces()` | ✅ REAL - calls `net.Interfaces()` |
| IsUp indicator | `iface.Flags&net.FlagUp` | ✅ REAL |
| HasAddress indicator | `iface.Addrs()` | ✅ REAL |
| IsLoopback indicator | `iface.Flags&net.FlagLoopback` | ✅ REAL |

**Verdict:** ✅ Interface dropdown is correctly wired

---

### Capture Button

| State | Backend Source | Verification |
|-------|----------------|--------------|
| isCapturing | `gui_app.go:399` `IsCapturing()` | ⚠️ PARTIAL - returns `a.isCapturing` field |
| Start Capture | `gui_app.go:299` `StartCapture()` | ✅ REAL - creates capture engine |
| Stop Capture | `gui_app.go:366` `StopCapture()` | ✅ REAL - stops engine |

**DEFECT:** `isCapturing` is a boolean flag set by the app, NOT a verification that packets are actually being received. Capture can "start" but fail silently.

---

### DashboardView Component

| Widget | Backend Source | Actual Population | Verdict |
|--------|----------------|-------------------|---------|
| (Empty grid) | N/A | DashboardView renders empty `<div>` | ❌ PLACEHOLDER |

**CRITICAL:** `DashboardView()` at line 280-288 is a placeholder that renders nothing:
```tsx
function DashboardView() {
  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-4">Dashboard</h1>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Dashboard content */}
      </div>
    </div>
  )
}
```

**Verdict:** ❌ **Dashboard is an empty shell** - no actual widgets rendered

---

### Statistics Type (Frontend Expectations)

The frontend `Statistics` type expects these fields:

| Field | Expected Type | Backend Provides | Verdict |
|-------|---------------|------------------|---------|
| `packets.total` | number | ❌ NOT PROVIDED | ❌ MISSING |
| `packets.tcp` | number | ❌ NOT PROVIDED | ❌ MISSING |
| `packets.udp` | number | ❌ NOT PROVIDED | ❌ MISSING |
| `packets.icmp` | number | ❌ NOT PROVIDED | ❌ MISSING |
| `packets.other` | number | ❌ NOT PROVIDED | ❌ MISSING |
| `bytes.total` | number | ✅ `byte_count` | ⚠️ NAME MISMATCH |
| `bytes.inbound` | number | ❌ NOT TRACKED | ❌ NEVER SET |
| `bytes.outbound` | number | ❌ NOT TRACKED | ❌ NEVER SET |
| `flows.total` | number | ✅ `flow_count` | ⚠️ NAME MISMATCH |
| `flows.active` | number | ❌ NOT TRACKED | ❌ NEVER SET |
| `flows.completed` | number | ❌ NOT TRACKED | ❌ NEVER SET |
| `protocols` | Record<string, number> | ❌ NOT PROVIDED | ❌ MISSING |
| `topTalkers` | array | ❌ NOT PROVIDED | ❌ NEVER POPULATED |
| `topPorts` | array | ❌ NOT PROVIDED | ❌ NEVER POPULATED |

**Backend StatsDTO provides:**
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

**Verdict:** ❌ **MASSIVE CONTRACT MISMATCH** - Backend provides flat structure, frontend expects nested structure with fields that don't exist

---

## Phase 2: Contract Reality Check

### Event Payload Validation

All event handlers cast `unknown` to typed payloads **without validation**:

```typescript
// useWailsEvents.ts:125-126
const handlePacketBatch = useCallback((data: unknown) => {
    const payload = data as PacketBatchPayload  // NO VALIDATION
```

**Risk:** Malformed backend data silently corrupts frontend state.

### JSON Field Name Mismatches

| Go Backend Field | JSON Tag | TypeScript Expects | Result |
|------------------|----------|-------------------|--------|
| `PacketCount` | `packet_count` | `packets.total` | ❌ UNDEFINED |
| `ByteCount` | `byte_count` | `bytes.total` | ❌ UNDEFINED |
| `FlowCount` | `flow_count` | `flows.total` | ❌ UNDEFINED |
| `DroppedPackets` | `dropped_packets` | `packetsDropped` | ⚠️ MISMATCH |
| `PacketsPerSec` | `packets_per_sec` | N/A | ❌ NOT USED |
| `BytesPerSec` | `bytes_per_sec` | N/A | ❌ NOT USED |

### Flow DTO Mismatches

| Go Field | JSON Tag | TypeScript Expects | Result |
|----------|----------|-------------------|--------|
| `PacketCount` | `packet_count` | `packetCount` | ⚠️ CASE MISMATCH |
| `ByteCount` | `byte_count` | `byteCount` | ⚠️ CASE MISMATCH |
| `StartTime` | `start_time` | `startTimeNano` | ⚠️ NAME MISMATCH |
| `LastActivity` | `last_activity` | `endTimeNano` | ⚠️ NAME MISMATCH |

---

## Phase 3: State Ownership Autopsy

### State Classification

| State | Type | Owner | Issue |
|-------|------|-------|-------|
| `packets` Map | Authoritative | Backend via events | ✅ Correct |
| `flows` Map | Authoritative | Backend via events | ✅ Correct |
| `alerts` Map | Authoritative | Backend via events | ❌ Never populated |
| `statistics` | Authoritative | Backend via events | ❌ Contract mismatch |
| `capture.isCapturing` | Authoritative | Backend | ⚠️ Frontend also sets it |
| `packetIds.length` | Derived | Frontend | ⚠️ Used as packet count |
| `flowIds.length` | Derived | Frontend | ⚠️ Used as flow count |

### Violations Found

1. **Frontend calculating derived state it shouldn't:**
   - Packet count = `packetIds.length` (frontend array length)
   - Flow count = `flowIds.length` (frontend array length)
   - Backend provides `packet_count` and `flow_count` but they're ignored

2. **Dual ownership of capture state:**
   - Backend sets `isCapturing` via events
   - Frontend also sets it directly in `handleCaptureToggle()`:
   ```typescript
   updateCaptureState({ isCapturing: false })  // Frontend sets directly
   ```

3. **Backend defaulting values silently:**
   - `NewApp()` initializes `stats: &models.CaptureStats{}`
   - All fields default to zero with no indication these are defaults

---

## Phase 4: False Confidence Detection

### Green Indicators Without Positive Confirmation

| Indicator | Shows Green When | Actually Means |
|-----------|-----------------|----------------|
| Interface "Up" dot | `iface.Flags&net.FlagUp != 0` | Interface exists and is up |
| Capture button green | `!capture.isCapturing` | Ready to start (not verified) |
| No alerts badge | `alertCount === 0` | ML pipeline is dead code |

### "Healthy" States as Absence of Errors

The entire dashboard assumes:
- No errors = system working
- Zero alerts = no threats
- Zero drops = perfect capture

**None of these are proven by the code.**

### Charts/Widgets Rendering with Zero/Placeholder Data

- **DashboardView:** Renders empty grid - no actual content
- **PacketsView:** Renders placeholder text only
- **FlowsView:** Renders placeholder text only
- **FilesView:** Renders placeholder text only
- **AlertsView:** Renders placeholder text only
- **TopologyView:** Renders placeholder text only

**CRITICAL:** All view components are placeholders that render nothing useful.

---

## Phase 5: Temporal Truth

### Time Source Analysis

| Component | Time Source | Issue |
|-----------|-------------|-------|
| Packet timestamps | `info.TimestampNano` from kernel | ✅ Authoritative |
| Stats update | `time.Now().UnixNano()` Go | ✅ Server time |
| Frontend display | `Date.now()` JS | Browser time |
| Capture startTime | `Date.now()` in frontend | ⚠️ Browser time |
| Event timestamps | `time.Now().UnixNano()` Go | ✅ Server time |

### Freshness Problems

- **No heartbeat mechanism** - cannot detect backend death
- **No "last update received" indicator**
- **Cannot distinguish:**
  - "Nothing happened in last 5 seconds"
  - "Backend stopped sending events"
  - "WebSocket disconnected"

**OPERATIONALLY UNSAFE:** Silence is indistinguishable from success.

---

## Phase 6: Wiring Smell Inventory

### Critical Smells

1. **ML Pipeline Never Instantiated (CRITICAL)**
   - `internal/ml/` contains sophisticated detection code
   - Zero imports of `internal/ml` in `gui_app.go` or `main.go`
   - DGA, DNS tunneling, anomaly detection = dead code
   - Alert count will ALWAYS be 0

2. **Kernel Drop Stats Never Retrieved (CRITICAL)**
   - `AFPacketEngine.Stats()` correctly gets kernel drops
   - `gui_app.go` maintains separate `droppedPackets` field
   - No call to `engine.Stats()` anywhere in gui_app.go
   - `droppedPackets` is only incremented by memory pressure, not kernel drops

3. **Statistics Contract Mismatch (CRITICAL)**
   - Backend `StatsDTO` has flat structure
   - Frontend `Statistics` expects nested structure with different field names
   - `handleStatsUpdate` passes data directly without transformation
   - Result: All statistics fields are undefined

4. **View Components Are Placeholders (HIGH)**
   - `DashboardView`, `PacketsView`, `FlowsView`, `FilesView`, `AlertsView`, `TopologyView`
   - All render placeholder text with no actual data display

5. **Missing Backend Methods (HIGH)**
   - No `GetTopology()` method exists
   - No `ExportEvidence()` method exists
   - Frontend expects these but they don't exist

6. **Event Payload Validation Absent (MEDIUM)**
   - All handlers cast `unknown` to typed payloads without validation
   - Malformed data silently corrupts state

7. **Dual State Ownership (MEDIUM)**
   - `capture.isCapturing` set by both backend events AND frontend directly
   - Can lead to state desynchronization

### Naming Mismatches Across Layers

| Go Field | JSON Key | TypeScript Expects | Layer |
|----------|----------|-------------------|-------|
| `PacketCount` | `packet_count` | `packets.total` | Stats |
| `ByteCount` | `byte_count` | `bytes.total` | Stats |
| `FlowCount` | `flow_count` | `flows.total` | Stats |
| `DroppedPackets` | `dropped_packets` | `packetsDropped` | Capture |
| `PacketCount` | `packet_count` | `packetCount` | Flow |
| `ByteCount` | `byte_count` | `byteCount` | Flow |

### Implicit Assumptions

1. **Frontend assumes nested Statistics structure** - backend provides flat
2. **Frontend assumes ML alerts will fire** - ML is never instantiated
3. **Frontend assumes TopTalkers populated** - never tracked
4. **Frontend assumes inbound/outbound tracked** - never classified

---

## Phase 7: Minimal Corrective Actions

### Fix 1: Statistics Contract Alignment (CRITICAL)

**Option A:** Transform backend response in frontend
```typescript
const handleStatsUpdate = useCallback((data: unknown) => {
  const raw = data as { stats: StatsDTO }
  const transformed: Statistics = {
    packets: { total: raw.stats.packet_count, tcp: 0, udp: 0, icmp: 0, other: 0 },
    bytes: { total: raw.stats.byte_count, inbound: 0, outbound: 0 },
    flows: { total: raw.stats.flow_count, active: 0, completed: 0 },
    protocols: {},
    topTalkers: [],
    topPorts: [],
  }
  updateStatistics(transformed)
}, [updateStatistics])
```

**Option B:** Change backend to emit nested structure

### Fix 2: Propagate Kernel Drop Stats (CRITICAL)

```go
// gui_app.go - Add to statsUpdater()
if a.engine != nil {
    engineStats := a.engine.Stats()
    a.statsMu.Lock()
    a.droppedPackets = int64(engineStats.PacketsDropped)
    a.statsMu.Unlock()
}
```

### Fix 3: Wire ML Pipeline or Remove Alert UI (CRITICAL)

**Option A:** Wire ML pipeline
```go
import "github.com/cvalentine99/nfa-linux/internal/ml"

// In NewApp()
mlConfig := ml.DefaultPipelineConfig()
a.mlPipeline, _ = ml.NewMLPipeline(mlConfig)

// In startup()
a.mlPipeline.Start(ctx)

// In handlePacketData() - process flows through ML
```

**Option B:** Remove alert count from UI until ML is wired

### Fix 4: Add Event Payload Validation (MEDIUM)

```typescript
function isValidPacketBatch(data: unknown): data is PacketBatchPayload {
  return typeof data === 'object' && data !== null &&
    'packets' in data && Array.isArray((data as any).packets)
}

const handlePacketBatch = useCallback((data: unknown) => {
  if (!isValidPacketBatch(data)) {
    console.error('Invalid packet batch received')
    return
  }
  // ... rest of handler
}, [scheduleFlush])
```

### Fix 5: Add Staleness Detection (MEDIUM)

```typescript
// Track last update time
const lastUpdateRef = useRef<number>(Date.now())

// In event handlers
lastUpdateRef.current = Date.now()

// Check for staleness
useEffect(() => {
  const interval = setInterval(() => {
    const stale = Date.now() - lastUpdateRef.current > 5000
    if (stale && capture.isCapturing) {
      console.warn('No updates received in 5 seconds')
      // Show warning indicator
    }
  }, 1000)
  return () => clearInterval(interval)
}, [capture.isCapturing])
```

---

## Severity-Ranked Defect List

### CRITICAL (Blocks Forensic Use)

| ID | Defect | Impact | Location |
|----|--------|--------|----------|
| C1 | Statistics contract mismatch | All stats undefined in frontend | `gui_app.go` StatsDTO vs `types/index.ts` Statistics |
| C2 | ML pipeline never instantiated | Alert detection is dead code | `gui_app.go` - no ml import |
| C3 | Kernel drop stats never propagated | False confidence in capture completeness | `gui_app.go` statsUpdater() |
| C4 | View components are placeholders | Dashboard shows nothing | `App.tsx` view components |

### HIGH (Operational Misleading)

| ID | Defect | Impact | Location |
|----|--------|--------|----------|
| H1 | TopTalkers/TopPorts never populated | Frontend expects data that doesn't exist | `gui_app.go` - no tracking |
| H2 | Inbound/Outbound bytes never tracked | Stats widget shows 0/0 | `gui_app.go` handlePacketData() |
| H3 | Missing GetTopology method | Topology view cannot function | `gui_app.go` - method missing |
| H4 | Missing ExportEvidence method | Evidence export impossible | `gui_app.go` - method missing |

### MEDIUM (Data Integrity)

| ID | Defect | Impact | Location |
|----|--------|--------|----------|
| M1 | No event payload validation | Malformed data corrupts state | `useWailsEvents.ts` handlers |
| M2 | JSON field name mismatches | Deserialization may fail | Multiple files |
| M3 | Dual capture state ownership | State desynchronization | `App.tsx` + events |
| M4 | No staleness detection | Cannot detect backend failure | `useWailsEvents.ts` |

### LOW (UX/Quality)

| ID | Defect | Impact | Location |
|----|--------|--------|----------|
| L1 | Empty state messages absent | No guidance when data missing | View components |
| L2 | No error boundaries | Single failure crashes dashboard | `App.tsx` |

---

## Unverifiable Claims Made by UI

1. **Packet count** - Shows `packetIds.length`, not verified against backend
2. **Flow count** - Shows `flowIds.length`, not verified against backend
3. **Alert count** - Will always be 0 because ML is dead code
4. **File count** - Only counts files that carver happened to extract
5. **"Capturing" status** - Does not prove packets are being received
6. **Interface "Up" status** - Does not prove capture will work on that interface

---

## Truth Table: Dashboard Elements to Real Data Sources

| Dashboard Element | Claimed Source | Actual Source | Data Flow | Verdict |
|-------------------|----------------|---------------|-----------|---------|
| Packet Count (header) | Backend stats | `packetIds.length` | Event → Store → Selector | ⚠️ DERIVED |
| Flow Count (header) | Backend stats | `flowIds.length` | Event → Store → Selector | ⚠️ DERIVED |
| Alert Count (header) | Backend alerts | `alertIds.length` | Event → Store → Selector | ❌ ALWAYS 0 |
| File Count (header) | Backend files | `files.size` | Event → Store → Selector | ⚠️ CONDITIONAL |
| Interface List | System | `net.Interfaces()` | Method call → State | ✅ REAL |
| Capture Status | Backend | `capture.isCapturing` | Event + Direct set | ⚠️ DUAL OWNED |
| Dashboard Widgets | Backend stats | NONE | N/A | ❌ PLACEHOLDER |
| Statistics | Backend | Mismatched contract | Event → Store | ❌ BROKEN |
| TopTalkers | Backend | Never populated | N/A | ❌ NEVER SET |
| TopPorts | Backend | Never populated | N/A | ❌ NEVER SET |
| Drop Rate | Kernel | Never retrieved | N/A | ❌ NEVER SET |

---

## Conclusion

This application **cannot be trusted for forensic work** in its current state. The dashboard is a façade over disconnected components.

**Critical Issues:**
1. Statistics contract is completely broken - frontend expects different structure than backend provides
2. ML pipeline is dead code - alert detection will never fire
3. Kernel drop stats are never retrieved - false confidence in capture completeness
4. All view components are placeholders - dashboard shows nothing

**Before any production use:**
1. Fix statistics contract mismatch (C1)
2. Either wire ML pipeline or remove alert UI (C2)
3. Propagate kernel drop stats (C3)
4. Implement actual view components (C4)
5. Add staleness detection (M4)

The code quality of individual components (capture engine, ML algorithms, parsers) appears good. The failure is in integration - sophisticated parts that are simply never connected.

---

## Progress Tracking

| Defect | Status | Commit | Date |
|--------|--------|--------|------|
| C1 | ⬜ TODO | - | - |
| C2 | ⬜ TODO | - | - |
| C3 | ⬜ TODO | - | - |
| C4 | ⬜ TODO | - | - |
| H1 | ⬜ TODO | - | - |
| H2 | ⬜ TODO | - | - |
| H3 | ⬜ TODO | - | - |
| H4 | ⬜ TODO | - | - |
| M1 | ⬜ TODO | - | - |
| M2 | ⬜ TODO | - | - |
| M3 | ⬜ TODO | - | - |
| M4 | ⬜ TODO | - | - |
| L1 | ⬜ TODO | - | - |
| L2 | ⬜ TODO | - | - |

**Legend:** ⬜ TODO | 🔄 IN PROGRESS | ✅ DONE | ❌ BLOCKED
