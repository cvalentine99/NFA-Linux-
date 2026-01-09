# NFA-Linux Defect Remediation Checklist

**Project:** NFA-Linux - Network Forensic Analyzer  
**Created:** January 8, 2026  
**Status:** IN PROGRESS  
**Source:** NFA-LINUX-TRUTH-AUDIT-REPORT.md

---

## CRITICAL DEFECTS (Blocks Forensic Use)

### C1: main.go binds stub App, not real App
- [ ] **Status:** NOT FIXED
- **Impact:** Entire Wails UI is non-functional
- **Location:** `main.go:508` defines stub, `main.go:99` uses stub
- **Fix Required:**
  - Move real App from `gui_app.go` or wire properly
  - Ensure `NewApp()` returns fully functional App with capture engine
  - Verify all 18 Wails-exposed methods are bound
- **Verification:** Start capture, verify packets appear in dashboard

### C2: Evidence export writes empty files
- [ ] **Status:** NOT FIXED
- **Impact:** Forensic output is invalid
- **Location:** `ExportEvidence()` function
- **Fix Required:**
  - Add captured packets to packager
  - Add flow data to packager
  - Add alerts to packager
  - Add extracted files to packager
  - Add statistics to packager
- **Verification:** Export evidence, verify non-empty CASE/UCO JSON

### C3: Packet drop stats never propagated
- [ ] **Status:** NOT FIXED
- **Impact:** False confidence in capture completeness
- **Location:** `AFPacketEngine.Stats()` has data, `gui_app.go` never calls it
- **Fix Required:**
  ```go
  // In statsUpdateLoop()
  if a.captureEngine != nil {
      engineStats := a.captureEngine.Stats()
      a.statsMu.Lock()
      a.stats.PacketsDropped = engineStats.PacketsDropped
      a.statsMu.Unlock()
  }
  ```
- **Verification:** Capture high-rate traffic, verify drop rate > 0 when expected

### C4: ML pipeline never instantiated
- [ ] **Status:** NOT FIXED
- **Impact:** All threat detection is dead code (DGA, DNS tunneling, anomaly)
- **Location:** `internal/ml/` exists but never imported in main.go or gui_app.go
- **Fix Required:**
  - Import `internal/ml` package
  - Instantiate `MLPipeline` in `NewApp()`
  - Wire packet/flow data to ML pipeline
  - Emit alerts when ML detects anomalies
- **Verification:** Generate DGA-like DNS traffic, verify alert fires

---

## HIGH DEFECTS (Operational Misleading)

### H1: TopTalkers/TopPorts never populated
- [ ] **Status:** NOT FIXED
- **Impact:** Dashboard shows misleading "no data"
- **Location:** `stats.TopTalkers` never set in `updateStats()`
- **Fix Required:**
  - Track per-IP packet/byte counts
  - Sort and populate TopTalkers array
  - Track per-port packet counts
  - Sort and populate TopPorts array
- **Verification:** Capture traffic, verify TopTalkers widget shows IPs

### H2: Inbound/Outbound bytes never set
- [ ] **Status:** NOT FIXED
- **Impact:** Stats widget shows false breakdown (always 0)
- **Location:** `stats.bytes.inbound/outbound` never set
- **Fix Required:**
  - Determine local network (from interface IP)
  - Classify packets as inbound/outbound
  - Increment appropriate counters
- **Verification:** Capture traffic, verify ↑/↓ bytes are non-zero

### H3: Flows.active/completed never updated
- [ ] **Status:** NOT FIXED
- **Impact:** Flow metrics are always zero
- **Location:** `stats.flows.active/completed` never set
- **Fix Required:**
  - Track flow creation/completion in reassembly
  - Update stats.flows.active on new flow
  - Update stats.flows.completed on flow close
- **Verification:** Capture TCP connections, verify flow counts update

### H4: TCP count displayed as "per second"
- [ ] **Status:** NOT FIXED
- **Impact:** Metric label is a lie
- **Location:** Frontend trend indicator
- **Fix Required:**
  - Calculate actual packets per second (delta / time)
  - Display correct PPS value
  - Or use backend-provided `PacketsPerSecond` field
- **Verification:** Verify trend shows actual rate, not cumulative count

---

## MEDIUM DEFECTS (Data Integrity)

### M1: No event payload validation
- [ ] **Status:** NOT FIXED
- **Impact:** Malformed data corrupts state silently
- **Location:** `useWailsEvents.ts` - all handlers cast `unknown` without validation
- **Fix Required:**
  ```typescript
  const handlePacketBatch = (data: unknown) => {
      if (!isValidPacketBatch(data)) {
          console.error('Invalid packet batch received');
          return;
      }
      // ... rest of handler
  }
  ```
- **Verification:** Send malformed event, verify graceful handling

### M2: JSON field name mismatches
- [ ] **Status:** NOT FIXED
- **Impact:** Deserialization failures possible
- **Mismatches:**
  | Go Field | TypeScript Expects | Fix |
  |----------|-------------------|-----|
  | `bytes` | `byteCount` | Add `json:"byteCount"` tag |
  | `packets` | `packetCount` | Add `json:"packetCount"` tag |
  | `start_time_nano` | `startTimeNano` | Verify camelCase |
- **Verification:** Capture traffic, verify all fields populate correctly

### M3: Alert acknowledgment is client-only
- [ ] **Status:** NOT FIXED
- **Impact:** Acknowledgments not persisted
- **Fix Required:**
  - Add `AcknowledgeAlert(id string)` backend method
  - Persist acknowledgment state
  - Restore acknowledged state on reload
- **Verification:** Acknowledge alert, reload app, verify still acknowledged

### M4: Mock data in dev mode
- [ ] **Status:** NOT FIXED
- **Impact:** Cannot test real behavior in development
- **Location:** `main.tsx:7-11`, `mockData.ts`
- **Fix Required:**
  - Add flag to disable mock data
  - Or remove mock data injection entirely
  - Ensure dev mode can test real backend
- **Verification:** Run in dev mode, verify real backend data flows

---

## LOW DEFECTS (UX/Quality)

### L1: No staleness indicators
- [ ] **Status:** NOT FIXED
- **Impact:** Cannot detect backend failure
- **Fix Required:**
  - Track last update timestamp
  - Show warning if no updates for N seconds
  - Distinguish "no data" from "backend disconnected"
- **Verification:** Kill backend, verify frontend shows disconnected state

### L2: Empty state messages misleading
- [ ] **Status:** NOT FIXED
- **Impact:** "No data yet" implies waiting helps
- **Fix Required:**
  - Change message to indicate actual state
  - "Capture not started" vs "No traffic detected"
- **Verification:** Review all empty state messages

### L3: No error boundaries on widgets
- [ ] **Status:** NOT FIXED
- **Impact:** Single failure crashes dashboard
- **Fix Required:**
  - Add React error boundaries around widgets
  - Show graceful error state per widget
- **Verification:** Inject error, verify only affected widget shows error

---

## WIRING VERIFICATION CHECKLIST

### Backend Methods (gui_app.go)
- [ ] `ListInterfaces()` - returns real interfaces
- [ ] `StartCapture(iface)` - starts AF_PACKET capture
- [ ] `StopCapture()` - stops capture cleanly
- [ ] `IsCapturing()` - returns true when capturing
- [ ] `GetPackets(offset, limit)` - returns captured packets
- [ ] `GetPacketCount()` - returns total packet count
- [ ] `GetFlows()` - returns flow data
- [ ] `GetAlerts()` - returns alerts (ML-generated)
- [ ] `GetFiles()` - returns carved files
- [ ] `GetStats()` - returns statistics with all fields populated
- [ ] `GetTopology()` - returns topology with TopTalkers
- [ ] `LoadPCAP(path)` - loads and parses PCAP file
- [ ] `ExportEvidence(path)` - exports non-empty evidence
- [ ] `AcknowledgeAlert(id)` - persists acknowledgment

### Frontend Event Listeners (useWailsEvents.ts)
- [ ] `capture:state` - updates capture state
- [ ] `packet:batch` - adds packets to store
- [ ] `flow:update` - updates flow data
- [ ] `alert:new` - adds new alert
- [ ] `stats:update` - updates statistics
- [ ] `topology:update` - updates topology
- [ ] `file:extracted` - adds extracted file
- [ ] `error` - shows error notification

### Dashboard Widgets
- [ ] Total Packets - shows real count
- [ ] Active Flows - shows real count (not always 0)
- [ ] Data Processed - shows inbound/outbound breakdown
- [ ] Alerts - shows ML-generated alerts
- [ ] Top Talkers - shows actual IP addresses
- [ ] Protocol Distribution - shows real protocol breakdown
- [ ] Packet Drop Rate - shows kernel-reported drops
- [ ] Traffic Timeline - shows real time-series data

---

## PROGRESS TRACKING

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
| L3 | ⬜ TODO | - | - |

**Legend:** ⬜ TODO | 🔄 IN PROGRESS | ✅ DONE | ❌ BLOCKED

---

## TESTING PROTOCOL

### Pre-Fix Baseline
1. Start app with `sudo ./nfa-linux`
2. Select interface, click Start Capture
3. Generate traffic: `curl https://example.com`
4. Document what shows zeros/empty

### Post-Fix Verification
1. Repeat baseline steps
2. Verify all widgets show real data
3. Verify drop rate reflects kernel stats
4. Verify ML alerts fire on suspicious traffic
5. Export evidence, verify non-empty
6. Load PCAP, verify parsing works

---

## CONTRACT OBLIGATIONS

Per project requirements:
- [ ] Application must actually capture packets
- [ ] Application must parse protocols
- [ ] Application must display real data
- [ ] Application must work on WebKit2GTK 2.50.x
- [ ] Application must support sudo/root for capture
- [ ] Dashboard must not show false/misleading data
- [ ] Evidence export must produce valid forensic output
