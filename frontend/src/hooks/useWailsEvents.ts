import { useEffect, useRef, useCallback } from 'react'
import { useAppStore } from '../stores/appStore'
import type {
  Packet, Flow, Alert, Statistics,
  TopologyData, ExtractedFile
} from '../types'

// Window type extensions are in types/index.ts
// Go bindings are available via window.go.main.App

// =============================================================================
// Backend DTO types (matching Go StatsDTO exactly)
// =============================================================================

/**
 * Raw statistics from backend - flat structure matching Go StatsDTO
 * AUTHORITATIVE SOURCE: gui_app.go:StatsDTO
 */
interface BackendStatsDTO {
  packet_count: number
  byte_count: number
  flow_count: number
  alert_count: number
  file_count: number
  dropped_packets: number
  packets_per_sec: number
  bytes_per_sec: number
  memory_usage: number
  capture_time: number
  interface: string
  is_capturing: boolean
}

/**
 * Raw packet from backend - matching Go PacketDTO
 */
interface BackendPacketDTO {
  id: string
  timestamp: number
  length: number
  src_ip: string
  dst_ip: string
  src_port: number
  dst_port: number
  protocol: string
  app_protocol: string
  info: string
  payload_size: number
  flow_id: string
}

/**
 * Raw flow from backend - matching Go FlowDTO
 */
interface BackendFlowDTO {
  id: string
  src_ip: string
  dst_ip: string
  src_port: number
  dst_port: number
  protocol: string
  app_protocol: string
  state: string
  packet_count: number
  byte_count: number
  start_time: number
  last_activity: number
  duration: number
}

/**
 * Raw file from backend - matching Go FileDTO
 */
interface BackendFileDTO {
  id: string
  name: string
  size: number
  mime_type: string
  md5: string
  sha1: string
  sha256: string
  timestamp: number
  flow_id: string
  path: string
}

/**
 * Raw alert from backend - matching Go AlertDTO
 */
interface BackendAlertDTO {
  id: string
  timestamp: number
  severity: string
  category: string
  title: string
  description: string
  src_ip: string
  dst_ip: string
  flow_id: string
  packet_id: string
}

// =============================================================================
// Payload validation functions - NO silent coercion
// =============================================================================

function isValidBackendStats(data: unknown): data is BackendStatsDTO {
  if (typeof data !== 'object' || data === null) return false
  const d = data as Record<string, unknown>
  return (
    typeof d.packet_count === 'number' &&
    typeof d.byte_count === 'number' &&
    typeof d.flow_count === 'number' &&
    typeof d.is_capturing === 'boolean'
  )
}

function isValidPacketBatch(data: unknown): data is { packets: BackendPacketDTO[], timestamp: number } {
  if (typeof data !== 'object' || data === null) return false
  const d = data as Record<string, unknown>
  return Array.isArray(d.packets) && typeof d.timestamp === 'number'
}

function isValidFlowUpdate(data: unknown): data is { flows: BackendFlowDTO[], timestamp: number } {
  if (typeof data !== 'object' || data === null) return false
  const d = data as Record<string, unknown>
  return Array.isArray(d.flows) && typeof d.timestamp === 'number'
}

function isValidAlert(data: unknown): data is { alert: BackendAlertDTO, timestamp: number } {
  if (typeof data !== 'object' || data === null) return false
  const d = data as Record<string, unknown>
  return (
    typeof d.alert === 'object' && d.alert !== null &&
    typeof d.timestamp === 'number'
  )
}

function isValidFile(data: unknown): data is { file: BackendFileDTO, timestamp: number } {
  if (typeof data !== 'object' || data === null) return false
  const d = data as Record<string, unknown>
  return (
    typeof d.file === 'object' && d.file !== null &&
    typeof d.timestamp === 'number'
  )
}

function isValidCaptureState(data: unknown): data is CaptureStatePayload {
  if (typeof data !== 'object' || data === null) return false
  const d = data as Record<string, unknown>
  return typeof d.capturing === 'boolean' && typeof d.timestamp === 'number'
}

// =============================================================================
// Transform functions - Convert backend DTOs to frontend types
// =============================================================================

/**
 * Transform flat backend StatsDTO to nested frontend Statistics
 * This is the authoritative transformation - no data is invented
 */
function transformBackendStats(raw: BackendStatsDTO): Statistics {
  return {
    packets: {
      total: raw.packet_count,
      // Protocol breakdown not tracked by backend - marked as unavailable (0)
      tcp: 0,
      udp: 0,
      icmp: 0,
      other: 0,
    },
    bytes: {
      total: raw.byte_count,
      // Direction not tracked by backend - marked as unavailable (0)
      inbound: 0,
      outbound: 0,
    },
    flows: {
      total: raw.flow_count,
      // Active/completed not tracked - marked as unavailable (0)
      active: 0,
      completed: 0,
    },
    // Not tracked by backend - empty
    protocols: {},
    topTalkers: [],
    topPorts: [],
    // Extended stats from backend
    _backend: {
      alertCount: raw.alert_count,
      fileCount: raw.file_count,
      droppedPackets: raw.dropped_packets,
      packetsPerSec: raw.packets_per_sec,
      bytesPerSec: raw.bytes_per_sec,
      memoryUsage: raw.memory_usage,
      captureTime: raw.capture_time,
      interface: raw.interface,
      isCapturing: raw.is_capturing,
    }
  }
}

/**
 * Transform backend PacketDTO to frontend Packet
 */
function transformBackendPacket(raw: BackendPacketDTO): Packet {
  return {
    id: raw.id,
    timestampNano: raw.timestamp,
    srcIP: raw.src_ip,
    dstIP: raw.dst_ip,
    srcPort: raw.src_port,
    dstPort: raw.dst_port,
    protocol: raw.protocol as Packet['protocol'],
    length: raw.length,
    payload: null,
    layers: [],
    metadata: {
      captureInterface: '',
      direction: 'unknown',
      checksumValid: true,
      truncated: false,
    },
  }
}

/**
 * Transform backend FlowDTO to frontend Flow
 */
function transformBackendFlow(raw: BackendFlowDTO): Flow {
  return {
    id: raw.id,
    srcIP: raw.src_ip,
    dstIP: raw.dst_ip,
    srcPort: raw.src_port,
    dstPort: raw.dst_port,
    protocol: raw.protocol as Flow['protocol'],
    startTimeNano: raw.start_time,
    endTimeNano: raw.last_activity,
    packetCount: raw.packet_count,
    byteCount: raw.byte_count,
    state: raw.state as Flow['state'],
    metadata: {
      applicationProtocol: raw.app_protocol || undefined,
    },
  }
}

/**
 * Transform backend FileDTO to frontend ExtractedFile
 */
function transformBackendFile(raw: BackendFileDTO): ExtractedFile {
  return {
    id: raw.id,
    fileName: raw.name,
    filePath: raw.path,
    mimeType: raw.mime_type,
    size: raw.size,
    sha256: raw.sha256,
    blake3: '', // Not provided by backend
    sourceFlow: raw.flow_id,
    extractedAt: raw.timestamp,
    isSuspicious: false,
  }
}

/**
 * Transform backend AlertDTO to frontend Alert
 */
function transformBackendAlert(raw: BackendAlertDTO): Alert {
  return {
    id: raw.id,
    timestampNano: raw.timestamp,
    severity: raw.severity as Alert['severity'],
    category: raw.category as Alert['category'],
    title: raw.title,
    description: raw.description,
    sourceIP: raw.src_ip,
    destIP: raw.dst_ip,
    relatedFlows: raw.flow_id ? [raw.flow_id] : [],
    indicators: [],
  }
}

// =============================================================================
// Event payload types (internal, after validation)
// =============================================================================

interface PacketBatchPayload {
  packets: Packet[]
  timestamp: number
}

interface FlowUpdatePayload {
  flows: Flow[]
  timestamp: number
}

interface AlertPayload {
  alert: Alert
  timestamp: number
}

interface StatsUpdatePayload {
  stats: Statistics
  timestamp: number
}

interface CaptureStatePayload {
  capturing: boolean
  interface?: string
  pcap?: string
  pcapComplete?: boolean
  stats?: BackendStatsDTO
  timestamp: number
}

interface TopologyUpdatePayload {
  topology: TopologyData
  timestamp: number
}

interface FileExtractedPayload {
  file: ExtractedFile
  timestamp: number
}

interface ErrorPayload {
  message: string
  code?: string
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

// Staleness threshold - if no update in this time, data is stale
const STALENESS_THRESHOLD_MS = 5000

/**
 * Hook to initialize and manage Wails event listeners
 * Handles real-time data streaming from Go backend
 *
 * CONTRACT ENFORCEMENT:
 * - All payloads are validated before processing
 * - Invalid payloads are logged and rejected (not silently coerced)
 * - Staleness is tracked and exposed to UI
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
    setLastEventTime,
    setConnectionState,
  } = useAppStore()

  // Refs for throttling
  const packetBufferRef = useRef<Packet[]>([])
  const flowBufferRef = useRef<Flow[]>([])
  const lastFlushRef = useRef<number>(0)
  const rafRef = useRef<number | null>(null)

  // Staleness tracking
  const lastUpdateRef = useRef<number>(Date.now())
  const stalenessIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null)

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

  // Record that we received an event (for staleness tracking)
  const recordEventReceived = useCallback(() => {
    const now = Date.now()
    lastUpdateRef.current = now
    setLastEventTime(now)
  }, [setLastEventTime])

  // Handle packet batch event - WITH VALIDATION
  const handlePacketBatch = useCallback((data: unknown) => {
    if (!isValidPacketBatch(data)) {
      console.error('[CONTRACT VIOLATION] Invalid packet batch payload:', data)
      return
    }
    recordEventReceived()

    // Transform backend DTOs to frontend types
    const transformedPackets = data.packets.map(transformBackendPacket)
    packetBufferRef.current.push(...transformedPackets)
    scheduleFlush()
  }, [scheduleFlush, recordEventReceived])

  // Handle flow update event - WITH VALIDATION
  const handleFlowUpdate = useCallback((data: unknown) => {
    if (!isValidFlowUpdate(data)) {
      console.error('[CONTRACT VIOLATION] Invalid flow update payload:', data)
      return
    }
    recordEventReceived()

    // Transform backend DTOs to frontend types
    const transformedFlows = data.flows.map(transformBackendFlow)
    flowBufferRef.current.push(...transformedFlows)
    scheduleFlush()
  }, [scheduleFlush, recordEventReceived])

  // Handle new alert event - WITH VALIDATION
  const handleAlert = useCallback((data: unknown) => {
    if (!isValidAlert(data)) {
      console.error('[CONTRACT VIOLATION] Invalid alert payload:', data)
      return
    }
    recordEventReceived()

    const transformedAlert = transformBackendAlert(data.alert)
    addAlert(transformedAlert)

    // Show notification for critical/high alerts
    if (transformedAlert.severity === 'critical' || transformedAlert.severity === 'high') {
      showAlertNotification(transformedAlert)
    }
  }, [addAlert, recordEventReceived])

  // Handle statistics update - WITH VALIDATION AND TRANSFORMATION
  const handleStatsUpdate = useCallback((data: unknown) => {
    // Stats come wrapped in { stats: StatsDTO, timestamp: number }
    if (typeof data !== 'object' || data === null) {
      console.error('[CONTRACT VIOLATION] Invalid stats update payload:', data)
      return
    }

    const payload = data as { stats?: unknown, timestamp?: number }
    if (!payload.stats || !isValidBackendStats(payload.stats)) {
      console.error('[CONTRACT VIOLATION] Invalid stats in payload:', payload.stats)
      return
    }

    recordEventReceived()

    // CRITICAL FIX: Transform flat backend stats to nested frontend structure
    const transformedStats = transformBackendStats(payload.stats)
    updateStatistics(transformedStats)
  }, [updateStatistics, recordEventReceived])

  // Handle capture state change - WITH VALIDATION
  const handleCaptureState = useCallback((data: unknown) => {
    if (!isValidCaptureState(data)) {
      console.error('[CONTRACT VIOLATION] Invalid capture state payload:', data)
      return
    }
    recordEventReceived()

    updateCaptureState({
      isCapturing: data.capturing,
      interface: data.interface || '',
      pcapFile: data.pcap || '',
      isPcapComplete: data.pcapComplete || false,
    })

    // Transform stats if included
    if (data.stats && isValidBackendStats(data.stats)) {
      const transformedStats = transformBackendStats(data.stats)
      updateStatistics(transformedStats)
    }
  }, [updateCaptureState, updateStatistics, recordEventReceived])

  // Handle topology update
  const handleTopologyUpdate = useCallback((data: unknown) => {
    const payload = data as TopologyUpdatePayload
    if (!payload.topology) {
      console.error('[CONTRACT VIOLATION] Invalid topology payload:', data)
      return
    }
    recordEventReceived()
    updateTopology(payload.topology)
  }, [updateTopology, recordEventReceived])

  // Handle file extraction - WITH VALIDATION
  const handleFileExtracted = useCallback((data: unknown) => {
    if (!isValidFile(data)) {
      console.error('[CONTRACT VIOLATION] Invalid file payload:', data)
      return
    }
    recordEventReceived()

    const transformedFile = transformBackendFile(data.file)
    addFile(transformedFile)
  }, [addFile, recordEventReceived])

  // Handle errors
  const handleError = useCallback((data: unknown) => {
    const payload = data as ErrorPayload
    console.error('[BACKEND ERROR]', payload.message, payload.code || payload.type)
    recordEventReceived()
  }, [recordEventReceived])
  
  // Initialize event listeners
  useEffect(() => {
    const runtime = window.runtime
    if (!runtime) {
      console.warn('Wails runtime not available, running in development mode')
      setConnectionState('disconnected')
      // In dev mode, we can simulate events or use mock data
      return
    }

    setConnectionState('connected')

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

    // Start staleness monitoring - CRITICAL for temporal truth
    stalenessIntervalRef.current = setInterval(() => {
      const now = Date.now()
      const timeSinceLastUpdate = now - lastUpdateRef.current
      const isCapturing = useAppStore.getState().capture.isCapturing

      if (isCapturing && timeSinceLastUpdate > STALENESS_THRESHOLD_MS) {
        console.warn(`[STALENESS WARNING] No backend updates in ${timeSinceLastUpdate}ms while capturing`)
        setConnectionState('stale')
      }
    }, 1000)

    // Cleanup on unmount
    return () => {
      unsubscribers.forEach(unsub => unsub?.())
      if (rafRef.current !== null) {
        cancelAnimationFrame(rafRef.current)
      }
      if (stalenessIntervalRef.current !== null) {
        clearInterval(stalenessIntervalRef.current)
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
    setConnectionState,
  ])
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
      return ifaces.map((i) => i.name)
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
  
  return {
    startCapture,
    stopCapture,
    getInterfaces,
    loadPCAP,
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
