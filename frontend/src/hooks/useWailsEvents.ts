import { useEffect, useRef, useCallback } from 'react'
import { useAppStore } from '../stores/appStore'
import type {
  Packet, Flow, Alert, Statistics,
  TopologyData, ExtractedFile
} from '../types'

// Window type extensions are in types/index.ts
// Go bindings are available via window.go.main.App

// Event payload types matching backend DTOs
interface PacketDTO {
  id: string
  timestampNano: number
  length: number
  srcIP: string
  dstIP: string
  srcPort: number
  dstPort: number
  protocol: string
  appProtocol?: string
  info?: string
  payloadSize?: number
  flowID?: string
  direction?: string
}

interface FlowDTO {
  id: string
  srcIP: string
  dstIP: string
  srcPort: number
  dstPort: number
  protocol: string
  appProtocol?: string
  state: string
  packetCount: number
  byteCount: number
  startTimeNano: number
  endTimeNano: number
  duration: number
}

interface AlertDTO {
  id: string
  timestamp: number
  severity: string
  category: string
  title: string
  description: string
  srcIP?: string
  dstIP?: string
  flowID?: string
  packetID?: string
}

interface FileDTO {
  id: string
  name: string
  size: number
  mimeType: string
  md5?: string
  sha1?: string
  sha256: string
  timestamp: number
  flowID?: string
  path: string
}

// Stats DTO matching backend structure
interface StatsDTO {
  packets: {
    total: number
    tcp: number
    udp: number
    icmp: number
    other: number
  }
  bytes: {
    total: number
    inbound: number
    outbound: number
  }
  flows: {
    total: number
    active: number
    completed: number
  }
  protocols: Record<string, number>
  topTalkers: Array<{ ip: string; packets: number; bytes: number }>
  topPorts: Array<{ port: number; protocol: string; count: number }>
  alertCount: number
  fileCount: number
  droppedPackets: number
  packetsPerSec: number
  bytesPerSec: number
  memoryUsage: number
  captureTime: number
  interface: string
  isCapturing: boolean
}

interface PacketBatchPayload {
  packets: PacketDTO[]
  timestamp: number
}

interface FlowUpdatePayload {
  flows: FlowDTO[]
  timestamp: number
}

interface AlertPayload {
  alert: AlertDTO
  timestamp: number
}

interface StatsUpdatePayload {
  stats: StatsDTO
  timestamp: number
}

interface CaptureStatePayload {
  capturing: boolean
  interface?: string
  pcap?: string
  pcapComplete?: boolean
  stats?: StatsDTO
  timestamp: number
}

interface TopologyUpdatePayload {
  topology: TopologyData
  timestamp: number
}

interface FileExtractedPayload {
  file: FileDTO
  timestamp: number
}

interface ErrorPayload {
  message: string
  type?: string
}

// Event names from Go backend
const EVENTS = {
  PACKET_BATCH: 'packet:batch',
  FLOW_UPDATE: 'flow:update',
  ALERT_NEW: 'alert:new',
  STATS_UPDATE: 'stats:update',
  CAPTURE_STATE: 'capture:state',
  TOPOLOGY_UPDATE: 'topology:update',
  FILE_EXTRACTED: 'file:extracted',
  ERROR: 'error',
} as const

// Throttle configuration for high-frequency events
const THROTTLE_MS = 16 // ~60fps

// Validation functions
function isValidPacketBatch(data: unknown): data is PacketBatchPayload {
  if (typeof data !== 'object' || data === null) return false
  const d = data as Record<string, unknown>
  return 'packets' in d && Array.isArray(d.packets) && 'timestamp' in d
}

function isValidFlowUpdate(data: unknown): data is FlowUpdatePayload {
  if (typeof data !== 'object' || data === null) return false
  const d = data as Record<string, unknown>
  return 'flows' in d && Array.isArray(d.flows) && 'timestamp' in d
}

function isValidStatsUpdate(data: unknown): data is StatsUpdatePayload {
  if (typeof data !== 'object' || data === null) return false
  const d = data as Record<string, unknown>
  return 'stats' in d && typeof d.stats === 'object'
}

function isValidAlert(data: unknown): data is AlertPayload {
  if (typeof data !== 'object' || data === null) return false
  const d = data as Record<string, unknown>
  return 'alert' in d && typeof d.alert === 'object'
}

function isValidCaptureState(data: unknown): data is CaptureStatePayload {
  if (typeof data !== 'object' || data === null) return false
  const d = data as Record<string, unknown>
  return 'capturing' in d && typeof d.capturing === 'boolean'
}

function isValidFileExtracted(data: unknown): data is FileExtractedPayload {
  if (typeof data !== 'object' || data === null) return false
  const d = data as Record<string, unknown>
  return 'file' in d && typeof d.file === 'object'
}

// Transform backend DTO to frontend type
function transformPacket(dto: PacketDTO): Packet {
  return {
    id: dto.id,
    timestampNano: dto.timestampNano,
    srcIP: dto.srcIP,
    dstIP: dto.dstIP,
    srcPort: dto.srcPort,
    dstPort: dto.dstPort,
    protocol: dto.protocol as any,
    length: dto.length,
    payload: null,
    layers: [],
    metadata: {
      captureInterface: '',
      direction: (dto.direction as any) || 'unknown',
      checksumValid: true,
      truncated: false,
    },
  }
}

function transformFlow(dto: FlowDTO): Flow {
  return {
    id: dto.id,
    srcIP: dto.srcIP,
    dstIP: dto.dstIP,
    srcPort: dto.srcPort,
    dstPort: dto.dstPort,
    protocol: dto.protocol as any,
    startTimeNano: dto.startTimeNano,
    endTimeNano: dto.endTimeNano,
    packetCount: dto.packetCount,
    byteCount: dto.byteCount,
    state: dto.state as any,
    metadata: {
      applicationProtocol: dto.appProtocol,
    },
  }
}

function transformAlert(dto: AlertDTO): Alert {
  return {
    id: dto.id,
    timestampNano: dto.timestamp,
    severity: dto.severity as any,
    category: dto.category as any,
    title: dto.title,
    description: dto.description,
    sourceIP: dto.srcIP,
    destIP: dto.dstIP,
    relatedFlows: dto.flowID ? [dto.flowID] : [],
    indicators: [],
  }
}

function transformFile(dto: FileDTO): ExtractedFile {
  return {
    id: dto.id,
    fileName: dto.name,
    filePath: dto.path,
    mimeType: dto.mimeType,
    size: dto.size,
    sha256: dto.sha256,
    blake3: '',
    sourceFlow: dto.flowID || '',
    extractedAt: dto.timestamp,
    isSuspicious: false,
  }
}

function transformStats(dto: StatsDTO): Statistics {
  return {
    packets: dto.packets,
    bytes: dto.bytes,
    flows: dto.flows,
    protocols: dto.protocols || {},
    topTalkers: dto.topTalkers || [],
    topPorts: dto.topPorts || [],
  }
}

/**
 * Hook to initialize and manage Wails event listeners
 * Handles real-time data streaming from Go backend
 */
export function useWailsEvents() {
  const {
    addPackets,
    updateFlows,
    addAlert,
    updateStatistics,
    updateCaptureState,
    updateTopology,
    addFile,
  } = useAppStore()
  
  // Refs for throttling
  const packetBufferRef = useRef<Packet[]>([])
  const flowBufferRef = useRef<Flow[]>([])
  const lastFlushRef = useRef<number>(0)
  const rafRef = useRef<number | null>(null)
  
  // Staleness tracking
  const lastUpdateRef = useRef<number>(Date.now())
  
  // Flush buffered packets to store
  const flushPackets = useCallback(() => {
    if (packetBufferRef.current.length > 0) {
      addPackets(packetBufferRef.current)
      packetBufferRef.current = []
    }
    if (flowBufferRef.current.length > 0) {
      updateFlows(flowBufferRef.current)
      flowBufferRef.current = []
    }
    lastFlushRef.current = performance.now()
    rafRef.current = null
  }, [addPackets, updateFlows])
  
  // Schedule flush using requestAnimationFrame
  const scheduleFlush = useCallback(() => {
    if (rafRef.current === null) {
      const now = performance.now()
      const timeSinceLastFlush = now - lastFlushRef.current
      
      if (timeSinceLastFlush >= THROTTLE_MS) {
        // Flush immediately
        rafRef.current = requestAnimationFrame(flushPackets)
      } else {
        // Schedule for next frame
        rafRef.current = requestAnimationFrame(() => {
          rafRef.current = requestAnimationFrame(flushPackets)
        })
      }
    }
  }, [flushPackets])
  
  // Handle packet batch event with validation
  const handlePacketBatch = useCallback((data: unknown) => {
    if (!isValidPacketBatch(data)) {
      console.error('Invalid packet batch payload:', data)
      return
    }
    lastUpdateRef.current = Date.now()
    
    // Transform and buffer packets
    const packets = data.packets.map(transformPacket)
    packetBufferRef.current.push(...packets)
    scheduleFlush()
  }, [scheduleFlush])
  
  // Handle flow update event with validation
  const handleFlowUpdate = useCallback((data: unknown) => {
    if (!isValidFlowUpdate(data)) {
      console.error('Invalid flow update payload:', data)
      return
    }
    lastUpdateRef.current = Date.now()
    
    // Transform and buffer flows
    const flows = data.flows.map(transformFlow)
    flowBufferRef.current.push(...flows)
    scheduleFlush()
  }, [scheduleFlush])
  
  // Handle new alert event with validation
  const handleAlert = useCallback((data: unknown) => {
    if (!isValidAlert(data)) {
      console.error('Invalid alert payload:', data)
      return
    }
    lastUpdateRef.current = Date.now()
    
    const alert = transformAlert(data.alert)
    addAlert(alert)
    
    // Show notification for critical/high alerts
    if (alert.severity === 'critical' || alert.severity === 'high') {
      showAlertNotification(alert)
    }
  }, [addAlert])
  
  // Handle statistics update with validation
  const handleStatsUpdate = useCallback((data: unknown) => {
    if (!isValidStatsUpdate(data)) {
      console.error('Invalid stats update payload:', data)
      return
    }
    lastUpdateRef.current = Date.now()
    
    const stats = transformStats(data.stats)
    updateStatistics(stats)
    
    // Also update capture state from stats
    updateCaptureState({
      isCapturing: data.stats.isCapturing,
      interface: data.stats.interface,
      packetsCaptured: data.stats.packets.total,
      packetsDropped: data.stats.droppedPackets,
      bytesProcessed: data.stats.bytes.total,
      flowsActive: data.stats.flows.active,
      alertsGenerated: data.stats.alertCount,
    })
  }, [updateStatistics, updateCaptureState])
  
  // Handle capture state change with validation
  const handleCaptureState = useCallback((data: unknown) => {
    if (!isValidCaptureState(data)) {
      console.error('Invalid capture state payload:', data)
      return
    }
    lastUpdateRef.current = Date.now()
    
    updateCaptureState({
      isCapturing: data.capturing,
      interface: data.interface || '',
      pcapFile: data.pcap || '',
      isPcapComplete: data.pcapComplete || false,
    })
    
    if (data.stats) {
      updateStatistics(transformStats(data.stats))
    }
  }, [updateCaptureState, updateStatistics])
  
  // Handle topology update
  const handleTopologyUpdate = useCallback((data: unknown) => {
    const payload = data as TopologyUpdatePayload
    if (payload?.topology) {
      lastUpdateRef.current = Date.now()
      updateTopology(payload.topology)
    }
  }, [updateTopology])
  
  // Handle file extraction with validation
  const handleFileExtracted = useCallback((data: unknown) => {
    if (!isValidFileExtracted(data)) {
      console.error('Invalid file extracted payload:', data)
      return
    }
    lastUpdateRef.current = Date.now()
    
    const file = transformFile(data.file)
    addFile(file)
  }, [addFile])
  
  // Handle errors
  const handleError = useCallback((data: unknown) => {
    const payload = data as ErrorPayload
    console.error('Backend error:', payload?.message, payload?.type)
  }, [])
  
  // Initialize event listeners
  useEffect(() => {
    const runtime = window.runtime
    if (!runtime) {
      console.warn('Wails runtime not available, running in development mode')
      return
    }
    
    // Register event listeners
    const unsubscribers = [
      runtime.EventsOn(EVENTS.PACKET_BATCH, handlePacketBatch),
      runtime.EventsOn(EVENTS.FLOW_UPDATE, handleFlowUpdate),
      runtime.EventsOn(EVENTS.ALERT_NEW, handleAlert),
      runtime.EventsOn(EVENTS.STATS_UPDATE, handleStatsUpdate),
      runtime.EventsOn(EVENTS.CAPTURE_STATE, handleCaptureState),
      runtime.EventsOn(EVENTS.TOPOLOGY_UPDATE, handleTopologyUpdate),
      runtime.EventsOn(EVENTS.FILE_EXTRACTED, handleFileExtracted),
      runtime.EventsOn(EVENTS.ERROR, handleError),
    ]
    
    // Cleanup on unmount
    return () => {
      unsubscribers.forEach(unsub => unsub?.())
      if (rafRef.current !== null) {
        cancelAnimationFrame(rafRef.current)
      }
    }
  }, [
    handlePacketBatch,
    handleFlowUpdate,
    handleAlert,
    handleStatsUpdate,
    handleCaptureState,
    handleTopologyUpdate,
    handleFileExtracted,
    handleError,
  ])
  
  // Staleness detection
  useEffect(() => {
    const interval = setInterval(() => {
      const capture = useAppStore.getState().capture
      if (capture.isCapturing) {
        const timeSinceUpdate = Date.now() - lastUpdateRef.current
        if (timeSinceUpdate > 5000) {
          console.warn('No backend updates in 5 seconds - connection may be stale')
        }
      }
    }, 2000)
    return () => clearInterval(interval)
  }, [])
}

/**
 * Hook to call Go backend methods
 */
export function useWailsBackend() {
  const startCapture = useCallback(async (iface: string) => {
    const app = window.go?.main?.App
    if (app?.StartCapture) {
      await app.StartCapture(iface, '')  // iface, filter
    } else {
      console.warn('StartCapture not available')
    }
  }, [])
  
  const stopCapture = useCallback(async () => {
    const app = window.go?.main?.App
    if (app?.StopCapture) {
      await app.StopCapture()
    } else {
      console.warn('StopCapture not available')
    }
  }, [])
  
  const getInterfaces = useCallback(async (): Promise<string[]> => {
    const app = window.go?.main?.App
    if (app?.ListInterfaces) {
      const ifaces = await app.ListInterfaces()
      return ifaces.map((i: any) => i.name)
    }
    console.warn('ListInterfaces not available')
    return []
  }, [])
  
  const loadPCAP = useCallback(async (path: string) => {
    const app = window.go?.main?.App
    if (app?.LoadPCAP) {
      await app.LoadPCAP(path)
    } else {
      console.warn('LoadPCAP not available')
    }
  }, [])
  
  const exportEvidence = useCallback(async (path: string) => {
    const app = window.go?.main?.App
    if (app?.ExportEvidence) {
      await app.ExportEvidence(path)
    } else {
      console.warn('ExportEvidence not available')
    }
  }, [])
  
  return {
    startCapture,
    stopCapture,
    getInterfaces,
    loadPCAP,
    exportEvidence,
  }
}

/**
 * Show browser notification for critical alerts
 */
function showAlertNotification(alert: Alert) {
  if ('Notification' in window && Notification.permission === 'granted') {
    new Notification(`NFA Alert: ${alert.title}`, {
      body: alert.description,
      icon: '/nfa-icon.svg',
      tag: alert.id,
    })
  }
}

/**
 * Request notification permission
 */
export async function requestNotificationPermission(): Promise<boolean> {
  if (!('Notification' in window)) {
    return false
  }
  
  if (Notification.permission === 'granted') {
    return true
  }
  
  if (Notification.permission !== 'denied') {
    const permission = await Notification.requestPermission()
    return permission === 'granted'
  }
  
  return false
}
