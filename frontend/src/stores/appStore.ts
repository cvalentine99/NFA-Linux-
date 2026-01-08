import { create } from 'zustand'
import { immer } from 'zustand/middleware/immer'
import { shallow } from 'zustand/shallow'
import { useMemo, useRef } from 'react'
import type {
  Packet, Flow, ExtractedFile, Alert, Statistics,
  CaptureState, ViewState, FilterState, TimeRange,
  TopologyData, ConnectionState
} from '../types'

// Maximum items to keep in memory for performance
const MAX_PACKETS = 100000
const MAX_FLOWS = 50000
const MAX_ALERTS = 10000

interface AppState {
  // Data stores
  packets: Map<string, Packet>
  packetIds: string[] // Ordered list for virtualization
  flows: Map<string, Flow>
  flowIds: string[]
  files: Map<string, ExtractedFile>
  alerts: Map<string, Alert>
  alertIds: string[]
  topology: TopologyData
  statistics: Statistics

  // Capture state
  capture: CaptureState

  // UI state
  view: ViewState

  // Connection and temporal state - CRITICAL for truth
  connectionState: ConnectionState
  lastEventTime: number // Timestamp of last event received

  // Version counters for memoization invalidation
  _packetVersion: number
  _flowVersion: number
  _alertVersion: number
  _filterVersion: number

  // Actions - Packets
  addPackets: (packets: Packet[]) => void
  clearPackets: () => void

  // Actions - Flows
  updateFlows: (flows: Flow[]) => void
  clearFlows: () => void

  // Actions - Files
  addFile: (file: ExtractedFile) => void
  clearFiles: () => void

  // Actions - Alerts
  addAlert: (alert: Alert) => void
  clearAlerts: () => void
  acknowledgeAlert: (id: string) => void

  // Actions - Statistics
  updateStatistics: (stats: Statistics) => void

  // Actions - Topology
  updateTopology: (data: TopologyData) => void

  // Actions - Capture
  updateCaptureState: (state: Partial<CaptureState>) => void
  startCapture: (iface: string) => void
  stopCapture: () => void

  // Actions - View
  setActiveView: (view: ViewState['activeView']) => void
  selectPacket: (id: string | null) => void
  selectFlow: (id: string | null) => void
  selectFile: (id: string | null) => void
  selectAlert: (id: string | null) => void

  // Actions - Filters
  setFilter: (filter: Partial<FilterState>) => void
  clearFilters: () => void
  setTimeRange: (range: TimeRange) => void

  // Actions - Connection/Temporal state
  setConnectionState: (state: ConnectionState) => void
  setLastEventTime: (time: number) => void
}

const initialStatistics: Statistics = {
  packets: { total: 0, tcp: 0, udp: 0, icmp: 0, other: 0 },
  bytes: { total: 0, inbound: 0, outbound: 0 },
  flows: { total: 0, active: 0, completed: 0 },
  protocols: {},
  topTalkers: [],
  topPorts: [],
}

const initialCaptureState: CaptureState = {
  isCapturing: false,
  interface: '',
  startTime: 0,
  packetsCaptured: 0,
  packetsDropped: 0,
  bytesProcessed: 0,
  flowsActive: 0,
  alertsGenerated: 0,
}

const initialViewState: ViewState = {
  activeView: 'dashboard',
  selectedPacketId: null,
  selectedFlowId: null,
  selectedFileId: null,
  selectedAlertId: null,
  filters: {
    search: '',
    protocols: [],
    severities: [],
    srcIP: '',
    dstIP: '',
    port: null,
    minBytes: null,
    maxBytes: null,
  },
  timeRange: {
    start: null,
    end: null,
    relative: 'all',
  },
}

export const useAppStore = create<AppState>()(
  immer((set) => ({
    // Initial state
    packets: new Map(),
    packetIds: [],
    flows: new Map(),
    flowIds: [],
    files: new Map(),
    alerts: new Map(),
    alertIds: [],
    topology: { nodes: [], links: [] },
    statistics: initialStatistics,
    capture: initialCaptureState,
    view: initialViewState,

    // Connection state - starts as disconnected until runtime confirms
    connectionState: 'disconnected' as ConnectionState,
    lastEventTime: 0,

    // Version counters for memoization
    _packetVersion: 0,
    _flowVersion: 0,
    _alertVersion: 0,
    _filterVersion: 0,
    
    // Packet actions
    addPackets: (newPackets) => set((state) => {
      for (const packet of newPackets) {
        state.packets.set(packet.id, packet)
        state.packetIds.push(packet.id)
      }
      
      // Trim if over limit (remove oldest)
      if (state.packetIds.length > MAX_PACKETS) {
        const toRemove = state.packetIds.splice(0, state.packetIds.length - MAX_PACKETS)
        for (const id of toRemove) {
          state.packets.delete(id)
        }
      }
      
      // Increment version for memoization
      state._packetVersion++
    }),
    
    clearPackets: () => set((state) => {
      state.packets.clear()
      state.packetIds = []
      state._packetVersion++
    }),
    
    // Flow actions
    updateFlows: (newFlows) => set((state) => {
      for (const flow of newFlows) {
        if (!state.flows.has(flow.id)) {
          state.flowIds.push(flow.id)
        }
        state.flows.set(flow.id, flow)
      }
      
      // Trim if over limit
      if (state.flowIds.length > MAX_FLOWS) {
        const toRemove = state.flowIds.splice(0, state.flowIds.length - MAX_FLOWS)
        for (const id of toRemove) {
          state.flows.delete(id)
        }
      }
      
      state._flowVersion++
    }),
    
    clearFlows: () => set((state) => {
      state.flows.clear()
      state.flowIds = []
      state._flowVersion++
    }),
    
    // File actions
    addFile: (file) => set((state) => {
      state.files.set(file.id, file)
    }),
    
    clearFiles: () => set((state) => {
      state.files.clear()
    }),
    
    // Alert actions
    addAlert: (alert) => set((state) => {
      state.alerts.set(alert.id, alert)
      state.alertIds.unshift(alert.id) // Newest first
      
      if (state.alertIds.length > MAX_ALERTS) {
        const toRemove = state.alertIds.splice(MAX_ALERTS)
        for (const id of toRemove) {
          state.alerts.delete(id)
        }
      }
      
      state._alertVersion++
    }),
    
    clearAlerts: () => set((state) => {
      state.alerts.clear()
      state.alertIds = []
      state._alertVersion++
    }),
    
    acknowledgeAlert: (id) => set((state) => {
      const alert = state.alerts.get(id)
      if (alert) {
        state.alerts.set(id, {
          ...alert,
          acknowledged: true,
          acknowledgedAt: Date.now() * 1000000,
        })
        state._alertVersion++
      }
    }),
    
    // Statistics actions
    updateStatistics: (stats) => set((state) => {
      state.statistics = stats
    }),
    
    // Topology actions
    updateTopology: (data) => set((state) => {
      state.topology = data
    }),
    
    // Capture actions
    updateCaptureState: (newState) => set((state) => {
      Object.assign(state.capture, newState)
    }),
    
    startCapture: (iface) => set((state) => {
      state.capture.isCapturing = true
      state.capture.interface = iface
      state.capture.startTime = Date.now()
      state.capture.packetsCaptured = 0
      state.capture.packetsDropped = 0
      state.capture.bytesProcessed = 0
    }),
    
    stopCapture: () => set((state) => {
      state.capture.isCapturing = false
    }),
    
    // View actions
    setActiveView: (view) => set((state) => {
      state.view.activeView = view
    }),
    
    selectPacket: (id) => set((state) => {
      state.view.selectedPacketId = id
    }),
    
    selectFlow: (id) => set((state) => {
      state.view.selectedFlowId = id
    }),
    
    selectFile: (id) => set((state) => {
      state.view.selectedFileId = id
    }),
    
    selectAlert: (id) => set((state) => {
      state.view.selectedAlertId = id
    }),
    
    // Filter actions
    setFilter: (filter) => set((state) => {
      Object.assign(state.view.filters, filter)
      state._filterVersion++
    }),
    
    clearFilters: () => set((state) => {
      state.view.filters = initialViewState.filters
      state._filterVersion++
    }),
    
    setTimeRange: (range) => set((state) => {
      state.view.timeRange = range
      state._filterVersion++
    }),

    // Connection state actions - CRITICAL for temporal truth
    setConnectionState: (connectionState) => set((state) => {
      state.connectionState = connectionState
    }),

    setLastEventTime: (time) => set((state) => {
      state.lastEventTime = time
      // If we're receiving events, we're connected
      if (state.connectionState === 'stale') {
        state.connectionState = 'connected'
      }
    }),
  }))
)

// =============================================================================
// Memoized Selector Hooks
// These hooks use version counters to avoid recomputing on every render
// =============================================================================

/**
 * Returns filtered packets with memoization.
 * Only recomputes when packets or filters change.
 */
export function useFilteredPackets(): Packet[] {
  const packets = useAppStore(state => state.packets)
  const packetIds = useAppStore(state => state.packetIds)
  const filters = useAppStore(state => state.view.filters, shallow)
  const timeRange = useAppStore(state => state.view.timeRange, shallow)
  const packetVersion = useAppStore(state => state._packetVersion)
  const filterVersion = useAppStore(state => state._filterVersion)
  
  // Cache for memoization
  const cacheRef = useRef<{
    packetVersion: number
    filterVersion: number
    result: Packet[]
  }>({ packetVersion: -1, filterVersion: -1, result: [] })
  
  return useMemo(() => {
    // Return cached result if versions match
    if (
      cacheRef.current.packetVersion === packetVersion &&
      cacheRef.current.filterVersion === filterVersion
    ) {
      return cacheRef.current.result
    }
    
    let result = packetIds
      .map(id => packets.get(id))
      .filter((p): p is Packet => p !== undefined)
    
    // Apply search filter
    if (filters.search) {
      const search = filters.search.toLowerCase()
      result = result.filter(p => 
        p.srcIP.includes(search) ||
        p.dstIP.includes(search) ||
        p.protocol.toLowerCase().includes(search)
      )
    }
    
    // Apply protocol filter
    if (filters.protocols.length > 0) {
      result = result.filter(p => filters.protocols.includes(p.protocol))
    }
    
    // Apply IP filters
    if (filters.srcIP) {
      result = result.filter(p => p.srcIP.includes(filters.srcIP))
    }
    if (filters.dstIP) {
      result = result.filter(p => p.dstIP.includes(filters.dstIP))
    }
    
    // Apply port filter
    if (filters.port !== null) {
      result = result.filter(p => 
        p.srcPort === filters.port || p.dstPort === filters.port
      )
    }
    
    // Apply time range
    if (timeRange.start !== null) {
      const start = timeRange.start
      result = result.filter(p => p.timestampNano >= start)
    }
    if (timeRange.end !== null) {
      const end = timeRange.end
      result = result.filter(p => p.timestampNano <= end)
    }
    
    // Update cache
    cacheRef.current = { packetVersion, filterVersion, result }
    
    return result
  }, [packets, packetIds, filters, timeRange, packetVersion, filterVersion])
}

/**
 * Returns filtered flows with memoization.
 * Only recomputes when flows or filters change.
 */
export function useFilteredFlows(): Flow[] {
  const flows = useAppStore(state => state.flows)
  const flowIds = useAppStore(state => state.flowIds)
  const filters = useAppStore(state => state.view.filters, shallow)
  const flowVersion = useAppStore(state => state._flowVersion)
  const filterVersion = useAppStore(state => state._filterVersion)
  
  const cacheRef = useRef<{
    flowVersion: number
    filterVersion: number
    result: Flow[]
  }>({ flowVersion: -1, filterVersion: -1, result: [] })
  
  return useMemo(() => {
    if (
      cacheRef.current.flowVersion === flowVersion &&
      cacheRef.current.filterVersion === filterVersion
    ) {
      return cacheRef.current.result
    }
    
    let result = flowIds
      .map(id => flows.get(id))
      .filter((f): f is Flow => f !== undefined)
    
    // Apply search filter
    if (filters.search) {
      const search = filters.search.toLowerCase()
      result = result.filter(f => 
        f.srcIP.includes(search) ||
        f.dstIP.includes(search) ||
        f.protocol.toLowerCase().includes(search) ||
        f.metadata.serverName?.toLowerCase().includes(search) ||
        f.metadata.httpHost?.toLowerCase().includes(search)
      )
    }
    
    // Apply protocol filter
    if (filters.protocols.length > 0) {
      result = result.filter(f => filters.protocols.includes(f.protocol))
    }
    
    // Apply byte range filters
    if (filters.minBytes !== null) {
      const minBytes = filters.minBytes
      result = result.filter(f => f.byteCount >= minBytes)
    }
    if (filters.maxBytes !== null) {
      const maxBytes = filters.maxBytes
      result = result.filter(f => f.byteCount <= maxBytes)
    }
    
    cacheRef.current = { flowVersion, filterVersion, result }
    
    return result
  }, [flows, flowIds, filters, flowVersion, filterVersion])
}

/**
 * Returns filtered alerts with memoization.
 * Only recomputes when alerts or filters change.
 */
export function useFilteredAlerts(): Alert[] {
  const alerts = useAppStore(state => state.alerts)
  const alertIds = useAppStore(state => state.alertIds)
  const filters = useAppStore(state => state.view.filters, shallow)
  const alertVersion = useAppStore(state => state._alertVersion)
  const filterVersion = useAppStore(state => state._filterVersion)
  
  const cacheRef = useRef<{
    alertVersion: number
    filterVersion: number
    result: Alert[]
  }>({ alertVersion: -1, filterVersion: -1, result: [] })
  
  return useMemo(() => {
    if (
      cacheRef.current.alertVersion === alertVersion &&
      cacheRef.current.filterVersion === filterVersion
    ) {
      return cacheRef.current.result
    }
    
    let result = alertIds
      .map(id => alerts.get(id))
      .filter((a): a is Alert => a !== undefined)
    
    // Apply severity filter
    if (filters.severities.length > 0) {
      result = result.filter(a => filters.severities.includes(a.severity))
    }
    
    // Apply search filter
    if (filters.search) {
      const search = filters.search.toLowerCase()
      result = result.filter(a => 
        a.title.toLowerCase().includes(search) ||
        a.description.toLowerCase().includes(search)
      )
    }
    
    cacheRef.current = { alertVersion, filterVersion, result }
    
    return result
  }, [alerts, alertIds, filters, alertVersion, filterVersion])
}

/**
 * Returns the selected packet with memoization.
 */
export function useSelectedPacket(): Packet | null {
  const selectedId = useAppStore(state => state.view.selectedPacketId)
  const packets = useAppStore(state => state.packets)
  
  return useMemo(() => {
    if (!selectedId) return null
    return packets.get(selectedId) ?? null
  }, [selectedId, packets])
}

/**
 * Returns the selected flow with memoization.
 */
export function useSelectedFlow(): Flow | null {
  const selectedId = useAppStore(state => state.view.selectedFlowId)
  const flows = useAppStore(state => state.flows)
  
  return useMemo(() => {
    if (!selectedId) return null
    return flows.get(selectedId) ?? null
  }, [selectedId, flows])
}

// =============================================================================
// Simple Selector Hooks (no filtering, just subscriptions)
// =============================================================================

export const usePacketCount = () => useAppStore(state => state.packetIds.length)
export const useFlowCount = () => useAppStore(state => state.flowIds.length)
export const useAlertCount = () => useAppStore(state => state.alertIds.length)
export const useCaptureState = () => useAppStore(state => state.capture)
export const useStatistics = () => useAppStore(state => state.statistics)
export const useActiveView = () => useAppStore(state => state.view.activeView)
export const useFilters = () => useAppStore(state => state.view.filters, shallow)
export const useTimeRange = () => useAppStore(state => state.view.timeRange, shallow)
export const useTopology = () => useAppStore(state => state.topology)

// Connection and temporal state selectors - CRITICAL for truth indicators
export const useConnectionState = () => useAppStore(state => state.connectionState)
export const useLastEventTime = () => useAppStore(state => state.lastEventTime)

/**
 * Returns true if data is stale (no updates while capturing)
 * This is the AUTHORITATIVE staleness indicator
 */
export const useIsDataStale = () => {
  const connectionState = useAppStore(state => state.connectionState)
  return connectionState === 'stale'
}

// =============================================================================
// Legacy getters for backward compatibility (deprecated, use hooks instead)
// =============================================================================

/** @deprecated Use useFilteredPackets() hook instead */
export const getFilteredPackets = () => {
  const state = useAppStore.getState()
  const { filters, timeRange } = state.view
  
  let packets = state.packetIds
    .map(id => state.packets.get(id))
    .filter((p): p is Packet => p !== undefined)
  
  if (filters.search) {
    const search = filters.search.toLowerCase()
    packets = packets.filter(p => 
      p.srcIP.includes(search) ||
      p.dstIP.includes(search) ||
      p.protocol.toLowerCase().includes(search)
    )
  }
  
  if (filters.protocols.length > 0) {
    packets = packets.filter(p => filters.protocols.includes(p.protocol))
  }
  
  if (filters.srcIP) {
    packets = packets.filter(p => p.srcIP.includes(filters.srcIP))
  }
  if (filters.dstIP) {
    packets = packets.filter(p => p.dstIP.includes(filters.dstIP))
  }
  
  if (filters.port !== null) {
    packets = packets.filter(p => 
      p.srcPort === filters.port || p.dstPort === filters.port
    )
  }
  
  if (timeRange.start !== null) {
    const start = timeRange.start
    packets = packets.filter(p => p.timestampNano >= start)
  }
  if (timeRange.end !== null) {
    const end = timeRange.end
    packets = packets.filter(p => p.timestampNano <= end)
  }
  
  return packets
}

/** @deprecated Use useFilteredFlows() hook instead */
export const getFilteredFlows = () => {
  const state = useAppStore.getState()
  const { filters } = state.view
  
  let flows = state.flowIds
    .map(id => state.flows.get(id))
    .filter((f): f is Flow => f !== undefined)
  
  if (filters.search) {
    const search = filters.search.toLowerCase()
    flows = flows.filter(f => 
      f.srcIP.includes(search) ||
      f.dstIP.includes(search) ||
      f.protocol.toLowerCase().includes(search) ||
      f.metadata.serverName?.toLowerCase().includes(search) ||
      f.metadata.httpHost?.toLowerCase().includes(search)
    )
  }
  
  if (filters.protocols.length > 0) {
    flows = flows.filter(f => filters.protocols.includes(f.protocol))
  }
  
  if (filters.minBytes !== null) {
    const minBytes = filters.minBytes
    flows = flows.filter(f => f.byteCount >= minBytes)
  }
  if (filters.maxBytes !== null) {
    const maxBytes = filters.maxBytes
    flows = flows.filter(f => f.byteCount <= maxBytes)
  }
  
  return flows
}

/** @deprecated Use useFilteredAlerts() hook instead */
export const getFilteredAlerts = () => {
  const state = useAppStore.getState()
  const { filters } = state.view
  
  let alerts = state.alertIds
    .map(id => state.alerts.get(id))
    .filter((a): a is Alert => a !== undefined)
  
  if (filters.severities.length > 0) {
    alerts = alerts.filter(a => filters.severities.includes(a.severity))
  }
  
  if (filters.search) {
    const search = filters.search.toLowerCase()
    alerts = alerts.filter(a => 
      a.title.toLowerCase().includes(search) ||
      a.description.toLowerCase().includes(search)
    )
  }
  
  return alerts
}
