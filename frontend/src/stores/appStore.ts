import { create } from 'zustand'
import { immer } from 'zustand/middleware/immer'
import type {
  Packet, Flow, ExtractedFile, Alert, Statistics,
  CaptureState, ViewState, FilterState, TimeRange,
  TopologyData
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
  
  // Computed selectors
  getFilteredPackets: () => Packet[]
  getFilteredFlows: () => Flow[]
  getFilteredAlerts: () => Alert[]
  getSelectedPacket: () => Packet | null
  getSelectedFlow: () => Flow | null
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
  immer((set, get) => ({
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
    }),
    
    clearPackets: () => set((state) => {
      state.packets.clear()
      state.packetIds = []
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
    }),
    
    clearFlows: () => set((state) => {
      state.flows.clear()
      state.flowIds = []
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
    }),
    
    clearAlerts: () => set((state) => {
      state.alerts.clear()
      state.alertIds = []
    }),
    
    acknowledgeAlert: (id) => set((state) => {
      const alert = state.alerts.get(id)
      if (alert) {
        // Update the alert with acknowledged status
        state.alerts.set(id, {
          ...alert,
          acknowledged: true,
          acknowledgedAt: Date.now() * 1000000, // Convert to nanoseconds
        })
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
    }),
    
    clearFilters: () => set((state) => {
      state.view.filters = initialViewState.filters
    }),
    
    setTimeRange: (range) => set((state) => {
      state.view.timeRange = range
    }),
    
    // Selectors
    getFilteredPackets: () => {
      const state = get()
      const { filters } = state.view
      // timeRange filtering can be added here if needed
      
      let packets = state.packetIds.map(id => state.packets.get(id)!).filter(Boolean)
      
      // Apply search filter
      if (filters.search) {
        const search = filters.search.toLowerCase()
        packets = packets.filter(p => 
          p.srcIP.includes(search) ||
          p.dstIP.includes(search) ||
          p.protocol.toLowerCase().includes(search)
        )
      }
      
      // Apply protocol filter
      if (filters.protocols.length > 0) {
        packets = packets.filter(p => filters.protocols.includes(p.protocol))
      }
      
      // Apply IP filters
      if (filters.srcIP) {
        packets = packets.filter(p => p.srcIP.includes(filters.srcIP))
      }
      if (filters.dstIP) {
        packets = packets.filter(p => p.dstIP.includes(filters.dstIP))
      }
      
      // Apply port filter
      if (filters.port !== null) {
        packets = packets.filter(p => 
          p.srcPort === filters.port || p.dstPort === filters.port
        )
      }
      
      // Apply time range
      const { timeRange } = state.view
      if (timeRange.start !== null) {
        packets = packets.filter(p => p.timestampNano >= timeRange.start!)
      }
      if (timeRange.end !== null) {
        packets = packets.filter(p => p.timestampNano <= timeRange.end!)
      }
      
      return packets
    },
    
    getFilteredFlows: () => {
      const state = get()
      const { filters } = state.view
      // timeRange filtering can be added here if needed
      
      let flows = state.flowIds.map(id => state.flows.get(id)!).filter(Boolean)
      
      // Apply search filter
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
      
      // Apply protocol filter
      if (filters.protocols.length > 0) {
        flows = flows.filter(f => filters.protocols.includes(f.protocol))
      }
      
      // Apply byte range filters
      if (filters.minBytes !== null) {
        flows = flows.filter(f => f.byteCount >= filters.minBytes!)
      }
      if (filters.maxBytes !== null) {
        flows = flows.filter(f => f.byteCount <= filters.maxBytes!)
      }
      
      return flows
    },
    
    getFilteredAlerts: () => {
      const state = get()
      const { filters } = state.view
      
      let alerts = state.alertIds.map(id => state.alerts.get(id)!).filter(Boolean)
      
      // Apply severity filter
      if (filters.severities.length > 0) {
        alerts = alerts.filter(a => filters.severities.includes(a.severity))
      }
      
      // Apply search filter
      if (filters.search) {
        const search = filters.search.toLowerCase()
        alerts = alerts.filter(a => 
          a.title.toLowerCase().includes(search) ||
          a.description.toLowerCase().includes(search)
        )
      }
      
      return alerts
    },
    
    getSelectedPacket: () => {
      const state = get()
      if (!state.view.selectedPacketId) return null
      return state.packets.get(state.view.selectedPacketId) || null
    },
    
    getSelectedFlow: () => {
      const state = get()
      if (!state.view.selectedFlowId) return null
      return state.flows.get(state.view.selectedFlowId) || null
    },
  }))
)

// Selector hooks for performance optimization
export const usePacketCount = () => useAppStore(state => state.packetIds.length)
export const useFlowCount = () => useAppStore(state => state.flowIds.length)
export const useAlertCount = () => useAppStore(state => state.alertIds.length)
export const useCaptureState = () => useAppStore(state => state.capture)
export const useStatistics = () => useAppStore(state => state.statistics)
export const useActiveView = () => useAppStore(state => state.view.activeView)
export const useFilters = () => useAppStore(state => state.view.filters)
